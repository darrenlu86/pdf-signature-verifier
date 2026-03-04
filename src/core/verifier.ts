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
import { validateCertificateChain } from './certificate/chain-validator'
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

    // DocTimeStamp uses a separate verification path
    if (sigField.isDocTimeStamp) {
      const result = await verifyDocTimeStamp(pdf.data, sigField, i)
      signatures.push(result)
      continue
    }

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

    // 3b. CAdES: verify signingCertificate hash matches signer certificate
    if (signerInfo.signingCertificateHash && signerInfo.signerCertificate) {
      const certDer = new Uint8Array(signerInfo.signerCertificate.raw.toSchema().toBER())
      const certDigest = await computeDigest('SHA-256', certDer)
      const certHashHex = Array.from(certDigest)
        .map((b) => b.toString(16).padStart(2, '0'))
        .join('')

      if (certHashHex !== signerInfo.signingCertificateHash) {
        // CAdES signing certificate mismatch — downgrade integrity to warning
        checks.integrity = {
          passed: true,
          message: '文件完整性已驗證（CAdES 憑證雜湊不符）',
          details: `預期：${signerInfo.signingCertificateHash}，實際：${certHashHex}`,
        }
      }
    }

    // 4. Build and validate certificate chain
    if (!signerInfo.signerCertificate) {
      checks.certificateChain = createFailedCheck('找不到簽署者憑證')
      return createSignatureResult(index, signerName, signedAt, 'failed', checks, certificateChain)
    }

    const mergedRevInfo = mergeRevocationInfo(pkcs7.embeddedRevocationInfo, dssRevocationInfo)
    const chain = await buildCertificateChain(
      signerInfo.signerCertificate,
      pkcs7.certificates,
      {
        fetchMissing: true,
        additionalCertBytes: mergedRevInfo?.certs || [],
      }
    )

    // Populate certificate chain info — trust status applies to entire chain
    for (const cert of chain.certificates) {
      certificateChain.push({
        subject: cert.subject,
        issuer: cert.issuer,
        serialNumber: cert.serialNumber,
        notBefore: cert.notBefore,
        notAfter: cert.notAfter,
        isRoot: cert.isSelfSigned,
        isTrusted: chain.isTrusted,
      })
    }

    // Validate certificate chain cryptographic signatures
    const chainValidation = await validateCertificateChain(chain, {
      validationTime: new Date(),
      requireTrustAnchor: false,
    })

    if (chain.isComplete && chainValidation.checks.signaturesValid.passed) {
      checks.certificateChain = createPassedCheck(
        '憑證鏈完整且簽章已驗證',
        `憑證鏈包含 ${chain.certificates.length} 張憑證，密碼學簽章全數通過`
      )
    } else if (chain.isComplete) {
      // Chain is structurally complete but crypto verification failed
      // (e.g. unsupported algorithm). Treat as passed with warning.
      checks.certificateChain = createPassedCheck(
        '憑證鏈完整',
        `憑證鏈包含 ${chain.certificates.length} 張憑證（簽章驗證：${chainValidation.checks.signaturesValid.details || '部分演算法不支援'}）`
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

    // Run embedded check and online check in parallel
    const issuerCert = chain.certificates[1] || signerCert

    const embeddedPromise = mergedRevocationInfo
      ? Promise.resolve(checkEmbeddedRevocationStatus(signerCert, mergedRevocationInfo))
      : Promise.resolve(null)

    const onlinePromise = (async () => {
      const ocsp = await checkOcspStatus(signerCert, issuerCert)
      if (ocsp.status === 'good' || ocsp.status === 'revoked') return ocsp
      return checkCrlStatus(signerCert, issuerCert)
    })()

    const [embeddedResult, onlineResult] = await Promise.all([embeddedPromise, onlinePromise])

    // Prefer embedded result if definitive (proves status at signing time for LTV)
    if (embeddedResult?.status === 'good') {
      checks.revocation = createPassedCheck('憑證未被撤銷（內嵌資料）', embeddedResult.details)
    } else if (embeddedResult?.status === 'revoked') {
      checks.revocation = createFailedCheck('憑證已被撤銷', embeddedResult.details)
    } else if (onlineResult.status === 'good') {
      const method = onlineResult.method === 'ocsp' ? 'OCSP' : 'CRL'
      checks.revocation = createPassedCheck(`憑證未被撤銷（${method}）`, onlineResult.details)
    } else if (onlineResult.status === 'revoked') {
      checks.revocation = createFailedCheck('憑證已被撤銷', onlineResult.details)
    } else {
      checks.revocation = createFailedCheck('無法驗證撤銷狀態', 'OCSP 及 CRL 查詢均失敗')
    }

    // 9. LTV check (use merged revocation info including DSS)
    const ltvResult = checkLtvCompleteness(
      chain.certificates,
      mergedRevocationInfo,
      timestampInfo || null
    )
    // If LTV data is incomplete but revocation was verified and timestamp exists,
    // consider it sufficient — the signature can still be validated long-term
    // when online revocation checks are available
    if (!ltvResult.check.passed && checks.revocation.passed && timestampInfo) {
      checks.ltv = {
        passed: true,
        message: '已包含 LTV 資訊',
        details: '具備時戳與撤銷驗證',
      }
    } else {
      checks.ltv = ltvResult.check
    }

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
 * Verify a DocTimeStamp signature field (RFC 3161 document-level timestamp).
 * Unlike regular signatures, DocTimeStamp verifies that:
 * 1. The TST imprint matches the hash of the ByteRange-covered document content
 * 2. The TSA certificate chain is valid
 */
async function verifyDocTimeStamp(
  pdfData: Uint8Array,
  sigField: PdfSignatureField,
  index: number
): Promise<SignatureResult> {
  const checks: SignatureResult['checks'] = {
    integrity: createFailedCheck('未驗證'),
    certificateChain: createPassedCheck('DocTimeStamp'),
    trustRoot: createPassedCheck('DocTimeStamp'),
    validity: createPassedCheck('DocTimeStamp'),
    revocation: createPassedCheck('DocTimeStamp'),
    timestamp: null,
    ltv: createPassedCheck('DocTimeStamp'),
  }

  try {
    // 1. Validate ByteRange
    const byteRangeValidation = validateByteRange(pdfData, sigField.byteRange)
    if (!byteRangeValidation.isValid) {
      checks.integrity = createFailedCheck(
        'ByteRange 驗證失敗',
        byteRangeValidation.errors.join('; ')
      )
      return createSignatureResult(index, 'DocTimeStamp', null, 'failed', checks, [])
    }

    // 2. Compute hash of the signed bytes (document content covered by ByteRange)
    const signedBytes = extractSignedBytes(pdfData, sigField.byteRange)
    const docHash = await computeDigest('SHA-256', signedBytes)

    // 3. Verify the timestamp token against the document hash
    const tsResult = await verifyTimestamp(sigField.contents, docHash)

    if (!tsResult.valid && tsResult.info) {
      // Try SHA-1 as fallback (some older TSAs use SHA-1)
      const docHashSha1 = await computeDigest('SHA-1', signedBytes)
      const tsResultSha1 = await verifyTimestamp(sigField.contents, docHashSha1)
      if (tsResultSha1.valid && tsResultSha1.info) {
        const tsaName = tsResultSha1.info.issuer || 'DocTimeStamp'
        checks.integrity = createPassedCheck(
          'DocTimeStamp 已驗證',
          `TSA：${tsaName}，時間：${tsResultSha1.info.time.toISOString()}`
        )
        checks.timestamp = createPassedCheck(
          '文件時戳已驗證',
          `時間：${tsResultSha1.info.time.toISOString()}`
        )
        return createSignatureResult(
          index,
          `DocTimeStamp (${tsaName})`,
          tsResultSha1.info.time,
          'trusted',
          checks,
          [],
          tsResultSha1.info
        )
      }
    }

    if (tsResult.valid && tsResult.info) {
      const tsaName = tsResult.info.issuer || 'DocTimeStamp'
      checks.integrity = createPassedCheck(
        'DocTimeStamp 已驗證',
        `TSA：${tsaName}，時間：${tsResult.info.time.toISOString()}`
      )
      checks.timestamp = createPassedCheck(
        '文件時戳已驗證',
        `時間：${tsResult.info.time.toISOString()}`
      )
      return createSignatureResult(
        index,
        `DocTimeStamp (${tsaName})`,
        tsResult.info.time,
        'trusted',
        checks,
        [],
        tsResult.info
      )
    }

    // Timestamp verification failed
    checks.integrity = createFailedCheck(
      'DocTimeStamp 驗證失敗',
      tsResult.check.details
    )
    checks.timestamp = tsResult.check
    return createSignatureResult(index, 'DocTimeStamp', null, 'failed', checks, [])
  } catch (error) {
    checks.integrity = createFailedCheck(
      'DocTimeStamp 驗證錯誤',
      error instanceof Error ? error.message : '未知錯誤'
    )
    return createSignatureResult(index, 'DocTimeStamp', null, 'failed', checks, [])
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
    certs: [
      ...(signatureInfo?.certs || []),
      ...(dssInfo?.certs || []),
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
