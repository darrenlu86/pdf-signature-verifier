import type {
  VerificationResult,
  SignatureResult,
  CertificateInfo,
  TimestampInfo,
  PdfSignatureField,
  EmbeddedRevocationInfo,
} from '@/types'
import {
  createPassedCheck,
  createFailedCheck,
  determineOverallStatus,
} from '@/types'

import { parsePdf } from './pdf/parser'
import { extractSignedBytes, validateByteRange } from './pdf/byte-range'
import { parsePkcs7, getSignedAttributesData } from './crypto/pkcs7-parser'
import { verifyMessageDigest, normalizeDigestAlgorithm, computeDigest } from './crypto/digest-verifier'
import { verifyPkcs7Signature, verifySignature } from './crypto/signature-verifier'
import { buildCertificateChain } from './certificate/chain-builder'
import { getCommonName, isCertificateValid } from './certificate/cert-utils'
import { checkOcspStatus } from './revocation/ocsp-client'
import { checkCrlStatus } from './revocation/crl-client'
import { checkEmbeddedRevocationStatus } from './revocation/embedded-reader'
import { verifyTimestamp, getEffectiveSigningTime } from './timestamp/tst-verifier'
import { checkLtvCompleteness, canTrustExpiredWithLtv } from './ltv/ltv-checker'

export interface VerificationOptions {
  checkOnlineRevocation?: boolean
  validateTimestamp?: boolean
  requireTrustedRoot?: boolean
}

/**
 * Verify all signatures in a PDF document
 */
export async function verifyPdfSignatures(
  pdfData: ArrayBuffer | Uint8Array,
  fileName: string,
  options: VerificationOptions = {}
): Promise<VerificationResult> {
  // Parse PDF
  const pdf = await parsePdf(pdfData)

  if (pdf.signatureFields.length === 0) {
    return {
      status: 'unknown',
      fileName,
      signatures: [],
      summary: '文件中未發現數位簽章',
    }
  }

  // Verify each signature
  const signatures: SignatureResult[] = []

  for (let i = 0; i < pdf.signatureFields.length; i++) {
    const sigField = pdf.signatureFields[i]
    const result = await verifySingleSignature(
      pdf.data,
      sigField,
      i,
      options,
      pdf.dssRevocationInfo
    )
    signatures.push(result)
  }

  // Determine overall status
  const status = determineOverallStatus(signatures)

  // Generate summary
  const summary =
    status === 'trusted'
      ? `全部 ${signatures.length} 個簽章均有效且可信`
      : status === 'failed'
      ? '一個或多個簽章驗證失敗'
      : '簽章無法完整驗證'

  return {
    status,
    fileName,
    signatures,
    summary,
  }
}

/**
 * Verify a single signature
 */
async function verifySingleSignature(
  pdfData: Uint8Array,
  sigField: PdfSignatureField,
  index: number,
  options: VerificationOptions,
  dssRevocationInfo: EmbeddedRevocationInfo | null = null
): Promise<SignatureResult> {
  const checks: SignatureResult['checks'] = {
    integrity: createFailedCheck('未驗證'),
    certificateChain: createFailedCheck('未驗證'),
    trustRoot: createFailedCheck('未驗證'),
    validity: createFailedCheck('未驗證'),
    revocation: createFailedCheck('未驗證'),
    timestamp: null,
    ltv: createFailedCheck('未驗證'),
  }

  let signerName = '未知'
  let signedAt: Date | null = null
  const certificateChain: CertificateInfo[] = []
  let timestampInfo: TimestampInfo | undefined

  try {
    // 1. Validate ByteRange
    const byteRangeValidation = validateByteRange(pdfData, sigField.byteRange)
    if (!byteRangeValidation.isValid) {
      checks.integrity = createFailedCheck(
        'ByteRange 驗證失敗',
        byteRangeValidation.errors.join('; ')
      )
      return createSignatureResult(index, signerName, signedAt, 'failed', checks, certificateChain)
    }

    // 2. Parse PKCS#7
    const pkcs7 = await parsePkcs7(sigField.contents)

    if (pkcs7.signerInfos.length === 0) {
      checks.integrity = createFailedCheck('簽章中無簽署者資訊')
      return createSignatureResult(index, signerName, signedAt, 'failed', checks, certificateChain)
    }

    const signerInfo = pkcs7.signerInfos[0]

    // Get signer name
    if (signerInfo.signerCertificate) {
      signerName = getCommonName(signerInfo.signerCertificate)
    }

    // Get signing time (prefer signingTime attribute, fallback to embedded timestamp time)
    signedAt = signerInfo.signingTime
    if (!signedAt && pkcs7.embeddedTimestamp) {
      signedAt = pkcs7.embeddedTimestamp.time
    }

    // 3. Verify message digest (integrity)
    const signedBytes = extractSignedBytes(pdfData, sigField.byteRange)

    if (signerInfo.messageDigest) {
      const digestResult = await verifyMessageDigest(
        signedBytes,
        signerInfo.messageDigest,
        signerInfo.digestAlgorithm
      )

      if (!digestResult.valid) {
        checks.integrity = createFailedCheck(
          '文件已被修改',
          '訊息摘要不符'
        )
        return createSignatureResult(index, signerName, signedAt, 'failed', checks, certificateChain)
      }

      // Verify cryptographic signature over signed attributes
      const signedAttrsData = getSignedAttributesData(pkcs7.signedData, 0)
      if (signedAttrsData && signerInfo.signerCertificate) {
        const sigResult = await verifySignature(
          signerInfo.signatureValue,
          signedAttrsData,
          signerInfo.signerCertificate,
          signerInfo.signatureAlgorithm,
          signerInfo.digestAlgorithm
        )

        if (sigResult.isValid) {
          checks.integrity = createPassedCheck('文件完整性與簽章已驗證')
        } else {
          checks.integrity = createFailedCheck(
            '簽章驗證失敗',
            sigResult.error || '密碼學簽章與簽署屬性不符'
          )
          return createSignatureResult(index, signerName, signedAt, 'failed', checks, certificateChain)
        }
      } else {
        checks.integrity = createPassedCheck('文件完整性已驗證（僅摘要）')
      }
    } else {
      // Direct signature verification
      const sigResult = await verifyPkcs7Signature(pkcs7.signedData, signedBytes, 0)
      if (sigResult.isValid) {
        checks.integrity = createPassedCheck('簽章已驗證')
      } else {
        checks.integrity = createFailedCheck('簽章驗證失敗', sigResult.error)
        return createSignatureResult(index, signerName, signedAt, 'failed', checks, certificateChain)
      }
    }

    // 4. Build and validate certificate chain
    if (!signerInfo.signerCertificate) {
      checks.certificateChain = createFailedCheck('找不到簽署者憑證')
      return createSignatureResult(index, signerName, signedAt, 'failed', checks, certificateChain)
    }

    const chain = await buildCertificateChain(
      signerInfo.signerCertificate,
      pkcs7.certificates,
      { fetchMissing: options.checkOnlineRevocation }
    )

    // Populate certificate chain info
    for (const cert of chain.certificates) {
      certificateChain.push({
        subject: cert.subject,
        issuer: cert.issuer,
        serialNumber: cert.serialNumber,
        notBefore: cert.notBefore,
        notAfter: cert.notAfter,
        isRoot: cert.isSelfSigned,
        isTrusted: cert.isSelfSigned && chain.isTrusted,
      })
    }

    if (chain.isComplete) {
      checks.certificateChain = createPassedCheck(
        '憑證鏈完整',
        `憑證鏈包含 ${chain.certificates.length} 張憑證`
      )
    } else {
      checks.certificateChain = createFailedCheck('憑證鏈不完整')
    }

    // 5. Check trust root (chain-based: complete chain to self-signed root = trusted)
    if (chain.isComplete && chain.root) {
      const rootName = getCommonName(chain.root)
      checks.trustRoot = createPassedCheck(
        '憑證鏈完整',
        `根 CA：${rootName}`
      )
    } else {
      checks.trustRoot = createFailedCheck(
        '憑證鏈不完整',
        '無法建立完整憑證鏈'
      )
    }

    // 6. Verify timestamp if present (default: always validate)
    if (pkcs7.embeddedTimestamp && options.validateTimestamp !== false) {
      // RFC 3161: The messageImprint in a signature timestamp is the hash
      // of the signatureValue bytes (the cryptographic signature output),
      // NOT the hash of the signed attributes.
      const tsHashAlg = normalizeDigestAlgorithm(pkcs7.embeddedTimestamp.hashAlgorithm || 'SHA-256')
      const tsDigest = await computeDigest(tsHashAlg, signerInfo.signatureValue)
      const tsResult = await verifyTimestamp(pkcs7.embeddedTimestamp.raw, tsDigest)

      if (tsResult.valid && tsResult.info) {
        timestampInfo = tsResult.info
        signedAt = tsResult.info.time
        checks.timestamp = createPassedCheck(
          '時戳已驗證',
          `時間：${tsResult.info.time.toISOString()}`
        )
      } else {
        checks.timestamp = createFailedCheck('時戳驗證失敗', tsResult.check.details)
      }
    } else if (!pkcs7.embeddedTimestamp) {
      checks.timestamp = createFailedCheck('無時戳', '簽章未包含 RFC 3161 時戳')
    }

    // 7. Check certificate validity
    const effectiveTime = getEffectiveSigningTime(signedAt, timestampInfo || null)
    const signerCert = signerInfo.signerCertificate

    if (isCertificateValid(signerCert, effectiveTime)) {
      checks.validity = createPassedCheck(
        '簽署時憑證有效',
        `有效期：${signerCert.notBefore.toLocaleDateString('zh-TW')} 至 ${signerCert.notAfter.toLocaleDateString('zh-TW')}`
      )
    } else if (isCertificateValid(signerCert, new Date())) {
      checks.validity = createPassedCheck('憑證目前有效')
    } else {
      // Check if LTV can help
      const ltvResult = checkLtvCompleteness(
        chain.certificates,
        mergeRevocationInfo(pkcs7.embeddedRevocationInfo, dssRevocationInfo),
        timestampInfo || null
      )

      const expiredTrust = canTrustExpiredWithLtv(signerCert, timestampInfo || null, ltvResult)

      if (expiredTrust.trusted) {
        checks.validity = createPassedCheck(
          '憑證已過期但簽章具備 LTV',
          expiredTrust.reason
        )
      } else {
        checks.validity = createFailedCheck(
          '憑證已過期',
          `過期日期：${signerCert.notAfter.toLocaleDateString('zh-TW')}`
        )
      }
    }

    // 8. Check revocation status
    // Merge per-signature embedded revocation info with DSS (Document Security Store)
    const mergedRevocationInfo = mergeRevocationInfo(pkcs7.embeddedRevocationInfo, dssRevocationInfo)

    if (mergedRevocationInfo) {
      const embeddedResult = checkEmbeddedRevocationStatus(signerCert, mergedRevocationInfo)

      if (embeddedResult.status === 'good') {
        checks.revocation = createPassedCheck('憑證未被撤銷（內嵌資料）', embeddedResult.details)
      } else if (embeddedResult.status === 'revoked') {
        checks.revocation = createFailedCheck('憑證已被撤銷', embeddedResult.details)
      } else if (options.checkOnlineRevocation) {
        // Try online check
        const issuerCert = chain.certificates[1] || signerCert
        const onlineResult = await checkOcspStatus(signerCert, issuerCert)

        if (onlineResult.status === 'good') {
          checks.revocation = createPassedCheck('憑證未被撤銷（OCSP）', onlineResult.details)
        } else if (onlineResult.status === 'revoked') {
          checks.revocation = createFailedCheck('憑證已被撤銷', onlineResult.details)
        } else {
          // Try CRL
          const crlResult = await checkCrlStatus(signerCert, issuerCert)
          if (crlResult.status === 'good') {
            checks.revocation = createPassedCheck('憑證未被撤銷（CRL）', crlResult.details)
          } else if (crlResult.status === 'revoked') {
            checks.revocation = createFailedCheck('憑證已被撤銷', crlResult.details)
          } else {
            checks.revocation = createFailedCheck('無法驗證撤銷狀態', 'OCSP 及 CRL 查詢均失敗')
          }
        }
      } else {
        checks.revocation = createPassedCheck('已內嵌撤銷資訊', '未啟用線上查詢')
      }
    } else if (options.checkOnlineRevocation) {
      const issuerCert = chain.certificates[1] || signerCert
      const ocspResult = await checkOcspStatus(signerCert, issuerCert)

      if (ocspResult.status === 'good') {
        checks.revocation = createPassedCheck('憑證未被撤銷', ocspResult.details)
      } else if (ocspResult.status === 'revoked') {
        checks.revocation = createFailedCheck('憑證已被撤銷', ocspResult.details)
      } else {
        checks.revocation = createFailedCheck('無法驗證撤銷狀態', ocspResult.details)
      }
    } else {
      checks.revocation = createPassedCheck('略過撤銷檢查', '未啟用線上查詢')
    }

    // 9. LTV check (use merged revocation info including DSS)
    const ltvResult = checkLtvCompleteness(
      chain.certificates,
      mergedRevocationInfo,
      timestampInfo || null
    )
    checks.ltv = ltvResult.check

    // Determine signature status
    const integrityFailed = !checks.integrity.passed
    const isRevoked = checks.revocation && !checks.revocation.passed && checks.revocation.message.includes('revoked')

    const status = integrityFailed || isRevoked
      ? 'failed'
      : !checks.certificateChain.passed || !checks.trustRoot.passed || !checks.validity.passed
      ? 'unknown'
      : 'trusted'

    return createSignatureResult(
      index,
      signerName,
      signedAt,
      status,
      checks,
      certificateChain,
      timestampInfo,
      sigField.reason
    )
  } catch (error) {
    checks.integrity = createFailedCheck(
      '驗證錯誤',
      error instanceof Error ? error.message : '未知錯誤'
    )
    return createSignatureResult(index, signerName, signedAt, 'failed', checks, certificateChain)
  }
}

/**
 * Merge per-signature embedded revocation info with document-level DSS data.
 * DSS (Document Security Store) stores OCSP/CRL at the PDF catalog level,
 * separate from the PKCS#7 signature's unsigned attributes.
 */
function mergeRevocationInfo(
  signatureInfo: EmbeddedRevocationInfo | null,
  dssInfo: EmbeddedRevocationInfo | null
): EmbeddedRevocationInfo | null {
  if (!signatureInfo && !dssInfo) {
    return null
  }

  return {
    ocspResponses: [
      ...(signatureInfo?.ocspResponses || []),
      ...(dssInfo?.ocspResponses || []),
    ],
    crls: [
      ...(signatureInfo?.crls || []),
      ...(dssInfo?.crls || []),
    ],
  }
}

function createSignatureResult(
  index: number,
  signerName: string,
  signedAt: Date | null,
  status: SignatureResult['status'],
  checks: SignatureResult['checks'],
  certificateChain: CertificateInfo[],
  timestampInfo?: TimestampInfo,
  reason?: string
): SignatureResult {
  return {
    index,
    signerName,
    signedAt,
    reason,
    status,
    checks,
    certificateChain,
    timestampInfo,
  }
}
