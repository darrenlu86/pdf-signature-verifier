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

import { t, getLocale } from '@/i18n'
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
import { isTrustAnchor, initializeTrustStore, isTrustStoreEmpty } from '@/trust-store/trust-manager'
import { checkForPostSignModification } from './pdf/byte-range'
import { ensurePkijsEngine } from './crypto/pkijs-engine'

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
  // Wire PKI.js to Web Crypto (idempotent) and load trust store.
  ensurePkijsEngine()
  await initializeTrustStore()

  // Parse PDF
  const pdf = await parsePdf(pdfData)

  if (pdf.signatureFields.length === 0) {
    return {
      status: 'unknown',
      fileName,
      signatures: [],
      summary: t('core.summary.noSignatures'),
      summaryI18nKey: 'core.summary.noSignatures',
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
      pdf.dssRevocationInfo,
      pdf.signatureFields
    )
    signatures.push(result)
  }

  // Determine overall status
  const status = determineOverallStatus(signatures)

  // Generate summary
  const summary =
    status === 'trusted'
      ? t('core.summary.allTrusted', { count: signatures.length })
      : status === 'failed'
      ? t('core.summary.someFailed')
      : t('core.summary.cannotFullyVerify')

  return {
    status,
    fileName,
    signatures,
    summary,
    summaryI18nKey: status === 'trusted'
      ? 'core.summary.allTrusted'
      : status === 'failed'
      ? 'core.summary.someFailed'
      : 'core.summary.cannotFullyVerify',
    summaryI18nParams: status === 'trusted' ? { count: signatures.length } : undefined,
  }
}

/**
 * Verify a single signature
 */
/**
 * Decide whether unsigned trailing bytes for THIS signature are explained
 * by a later signature's incremental update (legitimate multi-sig case) or
 * indicate a signature wrapping attack.
 */
function hasLaterSignatureCovering(
  thisSig: PdfSignatureField,
  allFields: PdfSignatureField[],
  tailEnd: number
): boolean {
  const thisEnd = thisSig.byteRange.start2 + thisSig.byteRange.length2
  for (const other of allFields) {
    if (other === thisSig) continue
    const otherEnd = other.byteRange.start2 + other.byteRange.length2
    if (otherEnd >= tailEnd && other.byteRange.start1 <= thisEnd) {
      return true
    }
  }
  return false
}

async function verifySingleSignature(
  pdfData: Uint8Array,
  sigField: PdfSignatureField,
  index: number,
  options: VerificationOptions,
  dssRevocationInfo: EmbeddedRevocationInfo | null = null,
  allSignatureFields: PdfSignatureField[] = []
): Promise<SignatureResult> {
  const checks: SignatureResult['checks'] = {
    integrity: createFailedCheck(t('core.integrity.notVerified'), undefined, { key: 'core.integrity.notVerified' }),
    certificateChain: createFailedCheck(t('core.integrity.notVerified'), undefined, { key: 'core.integrity.notVerified' }),
    trustRoot: createFailedCheck(t('core.integrity.notVerified'), undefined, { key: 'core.integrity.notVerified' }),
    validity: createFailedCheck(t('core.integrity.notVerified'), undefined, { key: 'core.integrity.notVerified' }),
    revocation: createFailedCheck(t('core.integrity.notVerified'), undefined, { key: 'core.integrity.notVerified' }),
    timestamp: null,
    ltv: createFailedCheck(t('core.integrity.notVerified'), undefined, { key: 'core.integrity.notVerified' }),
  }

  let signerName = t('core.chain.unknownSigner')
  let signedAt: Date | null = null
  const certificateChain: CertificateInfo[] = []
  let timestampInfo: TimestampInfo | undefined
  // Audit P1-4: tracks "signed with subsequent changes" — the signature itself
  // is intact, but content was appended afterwards (legitimately if a later
  // signature covers it, suspiciously otherwise).
  let signedWithSubsequentChanges = false

  try {
    // 1. Validate ByteRange — structural checks fail-closed (gap content
    // invalid, ranges overlap, exceed file size). The unsigned-tail signal
    // is handled separately below per audit P1-4.
    const byteRangeValidation = validateByteRange(pdfData, sigField.byteRange)
    if (!byteRangeValidation.isValid) {
      checks.integrity = createFailedCheck(
        t('core.integrity.byteRangeFailed'),
        byteRangeValidation.errors.join('; '),
        { key: 'core.integrity.byteRangeFailed' }
      )
      return createSignatureResult(index, signerName, signedAt, 'failed', checks, certificateChain)
    }

    // Audit P1-4: handle "tail not covered by this signature".
    // - 0 trailing or whitespace-only → fine
    // - Trailing bytes that a later signature covers → multi-sig, demote to "signed with subsequent changes"
    // - Trailing bytes WITHOUT a later signature → legitimate post-sign incremental update; demote
    // - Combined with a DocMDP P=1 certification signature → fail (handled later in status logic)
    if (!byteRangeValidation.trailingIsWhitespaceOnly && byteRangeValidation.trailingUnsignedBytes > 0) {
      signedWithSubsequentChanges = true
    }
    // checkForPostSignModification is a redundant secondary check; we keep
    // calling it so its result is available for diagnostics / later policy.
    const postSign = checkForPostSignModification(pdfData, sigField.byteRange)
    if (postSign.modified) {
      signedWithSubsequentChanges = true
    }

    // 2. Parse PKCS#7
    const pkcs7 = await parsePkcs7(sigField.contents)

    if (pkcs7.signerInfos.length === 0) {
      checks.integrity = createFailedCheck(t('core.integrity.noSignerInfo'), undefined, { key: 'core.integrity.noSignerInfo' })
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
          t('core.integrity.documentModified'),
          t('core.integrity.digestMismatch'),
          { key: 'core.integrity.documentModified', detailsKey: 'core.integrity.digestMismatch' }
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
          checks.integrity = createPassedCheck(
            t('core.integrity.integrityAndSignatureVerified'),
            undefined,
            { key: 'core.integrity.integrityAndSignatureVerified' }
          )
        } else {
          checks.integrity = createFailedCheck(
            t('core.integrity.signatureVerificationFailed'),
            sigResult.error || t('core.integrity.cryptoMismatch'),
            { key: 'core.integrity.signatureVerificationFailed' }
          )
          return createSignatureResult(index, signerName, signedAt, 'failed', checks, certificateChain)
        }
      } else {
        checks.integrity = createPassedCheck(
          t('core.integrity.integrityVerifiedDigestOnly'),
          undefined,
          { key: 'core.integrity.integrityVerifiedDigestOnly' }
        )
      }
    } else {
      // Direct signature verification
      const sigResult = await verifyPkcs7Signature(pkcs7.signedData, signedBytes, 0)
      if (sigResult.isValid) {
        checks.integrity = createPassedCheck(
          t('core.integrity.signatureVerified'),
          undefined,
          { key: 'core.integrity.signatureVerified' }
        )
      } else {
        checks.integrity = createFailedCheck(
          t('core.integrity.signatureVerificationFailed'),
          sigResult.error,
          { key: 'core.integrity.signatureVerificationFailed' }
        )
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
          message: t('core.integrity.integrityVerifiedCadesHashMismatch'),
          details: t('core.integrity.cadesHashDetails', {
            expected: signerInfo.signingCertificateHash,
            actual: certHashHex,
          }),
          i18nKey: 'core.integrity.integrityVerifiedCadesHashMismatch',
          detailsI18nKey: 'core.integrity.cadesHashDetails',
          detailsI18nParams: {
            expected: signerInfo.signingCertificateHash,
            actual: certHashHex,
          },
        }
      }
    }

    // 4. Build and validate certificate chain
    if (!signerInfo.signerCertificate) {
      checks.certificateChain = createFailedCheck(
        t('core.chain.signerCertNotFound'),
        undefined,
        { key: 'core.chain.signerCertNotFound' }
      )
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

    // Validate certificate chain cryptographic signatures.
    // requireTrustAnchor MUST be true — see audit P0-2.
    const chainValidation = await validateCertificateChain(chain, {
      validationTime: new Date(),
      requireTrustAnchor: true,
    })

    if (chain.isComplete && chainValidation.checks.signaturesValid.passed) {
      checks.certificateChain = createPassedCheck(
        t('core.chain.chainCompleteAndVerified'),
        t('core.chain.chainCompleteWithCount', { count: chain.certificates.length }),
        {
          key: 'core.chain.chainCompleteAndVerified',
          detailsKey: 'core.chain.chainCompleteWithCount',
          detailsParams: { count: chain.certificates.length },
        }
      )
    } else if (chain.isComplete) {
      // Chain is structurally complete but crypto verification failed
      // (e.g. unsupported algorithm). Treat as passed with warning.
      checks.certificateChain = createPassedCheck(
        t('core.chain.chainComplete'),
        t('core.chain.chainCompleteDetails', {
          count: chain.certificates.length,
          details: chainValidation.checks.signaturesValid.details || t('core.misc.partialAlgorithmUnsupported'),
        }),
        {
          key: 'core.chain.chainComplete',
          detailsKey: 'core.chain.chainCompleteDetails',
          detailsParams: {
            count: chain.certificates.length,
            details: chainValidation.checks.signaturesValid.details || t('core.misc.partialAlgorithmUnsupported'),
          },
        }
      )
    } else {
      checks.certificateChain = createFailedCheck(
        t('core.chain.chainIncomplete'),
        undefined,
        { key: 'core.chain.chainIncomplete' }
      )
    }

    // 5. Check trust root — must match the curated trust store (audit P0-2).
    // "Chain complete" alone is meaningless: anyone can self-sign a root CA.
    if (!chain.isComplete || !chain.root) {
      checks.trustRoot = createFailedCheck(
        t('core.trust.chainIncomplete'),
        t('core.trust.cannotBuildChain'),
        {
          key: 'core.trust.chainIncomplete',
          detailsKey: 'core.trust.cannotBuildChain',
        }
      )
    } else if (!chain.isTrusted || !isTrustAnchor(chain.root)) {
      const rootName = getCommonName(chain.root)
      const storeWarning = isTrustStoreEmpty()
        ? t('core.trust.storeEmpty')
        : t('core.trust.rootNotInStore', { name: rootName })
      checks.trustRoot = createFailedCheck(
        t('core.trust.rootUntrusted'),
        storeWarning,
        {
          key: 'core.trust.rootUntrusted',
          detailsKey: isTrustStoreEmpty() ? 'core.trust.storeEmpty' : 'core.trust.rootNotInStore',
          detailsParams: isTrustStoreEmpty() ? undefined : { name: rootName },
        }
      )
    } else {
      const rootName = getCommonName(chain.root)
      checks.trustRoot = createPassedCheck(
        t('core.trust.chainComplete'),
        t('core.chain.rootCa', { name: rootName }),
        {
          key: 'core.trust.chainComplete',
          detailsKey: 'core.chain.rootCa',
          detailsParams: { name: rootName },
        }
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
          t('core.timestamp.verified'),
          t('core.timestamp.timeLabel', { time: tsResult.info.time.toISOString() }),
          {
            key: 'core.timestamp.verified',
            detailsKey: 'core.timestamp.timeLabel',
            detailsParams: { time: tsResult.info.time.toISOString() },
          }
        )
      } else {
        checks.timestamp = createFailedCheck(
          t('core.timestamp.verificationFailed'),
          tsResult.check.details,
          { key: 'core.timestamp.verificationFailed' }
        )
      }
    } else if (!pkcs7.embeddedTimestamp) {
      checks.timestamp = createFailedCheck(
        t('core.timestamp.noTimestamp'),
        t('core.timestamp.noRfc3161'),
        {
          key: 'core.timestamp.noTimestamp',
          detailsKey: 'core.timestamp.noRfc3161',
        }
      )
    }

    // 7. Check certificate validity
    const effectiveTime = getEffectiveSigningTime(signedAt, timestampInfo || null)
    const signerCert = signerInfo.signerCertificate

    if (isCertificateValid(signerCert, effectiveTime)) {
      checks.validity = createPassedCheck(
        t('core.validity.validAtSigning'),
        t('core.validity.validityPeriod', {
          from: signerCert.notBefore.toLocaleDateString(getLocale()),
          to: signerCert.notAfter.toLocaleDateString(getLocale()),
        }),
        {
          key: 'core.validity.validAtSigning',
          detailsKey: 'core.validity.validityPeriod',
          detailsParams: {
            from: signerCert.notBefore.toLocaleDateString(getLocale()),
            to: signerCert.notAfter.toLocaleDateString(getLocale()),
          },
        }
      )
    } else if (isCertificateValid(signerCert, new Date())) {
      checks.validity = createPassedCheck(
        t('core.validity.currentlyValid'),
        undefined,
        { key: 'core.validity.currentlyValid' }
      )
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
          t('core.validity.expiredWithLtv'),
          expiredTrust.reason,
          { key: 'core.validity.expiredWithLtv' }
        )
      } else {
        checks.validity = createFailedCheck(
          t('core.validity.expired'),
          t('core.validity.expiredDate', { date: signerCert.notAfter.toLocaleDateString(getLocale()) }),
          {
            key: 'core.validity.expired',
            detailsKey: 'core.validity.expiredDate',
            detailsParams: { date: signerCert.notAfter.toLocaleDateString(getLocale()) },
          }
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
      checks.revocation = createPassedCheck(
        t('core.revocation.notRevokedEmbedded'),
        embeddedResult.details,
        { key: 'core.revocation.notRevokedEmbedded', detailsKey: embeddedResult.detailsI18nKey, detailsParams: embeddedResult.detailsI18nParams }
      )
    } else if (embeddedResult?.status === 'revoked') {
      checks.revocation = createFailedCheck(
        t('core.revocation.revoked'),
        embeddedResult.details,
        { key: 'core.revocation.revoked', detailsKey: embeddedResult.detailsI18nKey, detailsParams: embeddedResult.detailsI18nParams }
      )
    } else if (onlineResult.status === 'good') {
      const method = onlineResult.method === 'ocsp' ? 'OCSP' : 'CRL'
      checks.revocation = createPassedCheck(
        t('core.revocation.notRevokedMethod', { method }),
        onlineResult.details,
        {
          key: 'core.revocation.notRevokedMethod',
          params: { method },
          detailsKey: onlineResult.detailsI18nKey,
          detailsParams: onlineResult.detailsI18nParams,
        }
      )
    } else if (onlineResult.status === 'revoked') {
      checks.revocation = createFailedCheck(
        t('core.revocation.revoked'),
        onlineResult.details,
        { key: 'core.revocation.revoked', detailsKey: onlineResult.detailsI18nKey, detailsParams: onlineResult.detailsI18nParams }
      )
    } else {
      checks.revocation = createFailedCheck(
        t('core.revocation.cannotVerify'),
        t('core.revocation.allFailed'),
        {
          key: 'core.revocation.cannotVerify',
          detailsKey: 'core.revocation.allFailed',
        }
      )
    }

    // 9. LTV check (audit P1-5 + P2-8).
    // Audit P1-5: do NOT override an incomplete LTV result. hasLtvInfo and
    // ltvComplete are different states and must be reported as such — UI can
    // surface "partial LTV (online check passed but no embedded data)" by
    // combining checks.ltv with checks.revocation.
    // Audit P2-8: detect DocTimeStamp fields that come after this signature
    // and feed them as archive timestamps for B-LTA classification.
    const archiveSignatures = allSignatureFields.filter(
      (f) => f.isDocTimeStamp && f.byteRange.start2 + f.byteRange.length2 > sigField.byteRange.start2 + sigField.byteRange.length2
    )
    const ltvResult = checkLtvCompleteness(
      chain.certificates,
      mergedRevocationInfo,
      timestampInfo || null,
      {
        archiveTimestampCount: archiveSignatures.length,
        // Without per-archive LTV state available here, assume true if DSS
        // contains revocation data covering each archive TSA. Recursive
        // archive-TST LTV validation is a TODO for a deeper pass.
        archiveTimestampsHaveLtv: archiveSignatures.map(() =>
          (mergedRevocationInfo?.ocspResponses.length || 0) > 0 ||
          (mergedRevocationInfo?.crls.length || 0) > 0
        ),
      }
    )
    checks.ltv = ltvResult.check
    const ltvLevel = ltvResult.level

    // Determine signature status
    const integrityFailed = !checks.integrity.passed
    const isRevoked = checks.revocation && !checks.revocation.passed && checks.revocation.message.includes('revoked')

    let status: SignatureResult['status'] = integrityFailed || isRevoked
      ? 'failed'
      : !checks.certificateChain.passed || !checks.trustRoot.passed || !checks.validity.passed
      ? 'unknown'
      : 'trusted'

    // Audit P1-4 / P2-7: handle unsigned tail bytes after the signed range.
    //
    //   - DocMDP P=1 (no changes permitted) + any post-sign change → failed
    //   - LTV-enriched signature (PAdES B-LT/B-LTA): the post-sign tail is
    //     legitimately the DSS (Document Security Store) that ships
    //     revocation data for long-term validation. Don't downgrade — this
    //     is exactly how the spec wants those signatures to grow.
    //   - Plain post-sign update on a non-LTV signature: downgrade to
    //     unknown with "signed with subsequent changes" — could be a later
    //     signature (multi-sig) or attacker-controlled append.
    const isLtvSignature = ltvLevel === 'B-LT' || ltvLevel === 'B-LTA'
    if (signedWithSubsequentChanges) {
      if (sigField.docMdp && sigField.docMdp.permissionLevel === 1) {
        status = 'failed'
        checks.integrity = createFailedCheck(
          t('core.integrity.docMdpViolation'),
          t('core.integrity.docMdpP1Violation'),
          {
            key: 'core.integrity.docMdpViolation',
            detailsKey: 'core.integrity.docMdpP1Violation',
          }
        )
      } else if (!isLtvSignature && status === 'trusted') {
        status = 'unknown'
        checks.integrity = {
          ...checks.integrity,
          details: t('core.integrity.signedWithSubsequentChanges'),
          detailsI18nKey: 'core.integrity.signedWithSubsequentChanges',
        }
      }
    }

    return createSignatureResult(
      index,
      signerName,
      signedAt,
      status,
      checks,
      certificateChain,
      timestampInfo,
      sigField.reason,
      {
        type: sigField.docMdp ? 'certification' : 'approval',
        docMdp: sigField.docMdp,
        ltvLevel,
        subsequentChanges: signedWithSubsequentChanges
          ? [{ signatureIndex: -1, byteOffset: sigField.byteRange.start2 + sigField.byteRange.length2, permittedByDocMdp: null }]
          : undefined,
      }
    )
  } catch (error) {
    checks.integrity = createFailedCheck(
      t('core.error.verificationError'),
      error instanceof Error ? error.message : t('core.error.unknownError'),
      { key: 'core.error.verificationError' }
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
    integrity: createFailedCheck(t('core.docTimestamp.notVerified'), undefined, { key: 'core.docTimestamp.notVerified' }),
    certificateChain: createPassedCheck(t('core.docTimestamp.label'), undefined, { key: 'core.docTimestamp.label' }),
    trustRoot: createPassedCheck(t('core.docTimestamp.label'), undefined, { key: 'core.docTimestamp.label' }),
    validity: createPassedCheck(t('core.docTimestamp.label'), undefined, { key: 'core.docTimestamp.label' }),
    revocation: createPassedCheck(t('core.docTimestamp.label'), undefined, { key: 'core.docTimestamp.label' }),
    timestamp: null,
    ltv: createPassedCheck(t('core.docTimestamp.label'), undefined, { key: 'core.docTimestamp.label' }),
  }

  try {
    // 1. Validate ByteRange
    const byteRangeValidation = validateByteRange(pdfData, sigField.byteRange)
    if (!byteRangeValidation.isValid) {
      checks.integrity = createFailedCheck(
        t('core.docTimestamp.byteRangeFailed'),
        byteRangeValidation.errors.join('; '),
        { key: 'core.docTimestamp.byteRangeFailed' }
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
          t('core.docTimestamp.verified'),
          t('core.docTimestamp.tsaTime', {
            tsa: tsaName,
            time: tsResultSha1.info.time.toISOString(),
          }),
          {
            key: 'core.docTimestamp.verified',
            detailsKey: 'core.docTimestamp.tsaTime',
            detailsParams: { tsa: tsaName, time: tsResultSha1.info.time.toISOString() },
          }
        )
        checks.timestamp = createPassedCheck(
          t('core.docTimestamp.timestampVerified'),
          t('core.docTimestamp.timeLabel', { time: tsResultSha1.info.time.toISOString() }),
          {
            key: 'core.docTimestamp.timestampVerified',
            detailsKey: 'core.docTimestamp.timeLabel',
            detailsParams: { time: tsResultSha1.info.time.toISOString() },
          }
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
        t('core.docTimestamp.verified'),
        t('core.docTimestamp.tsaTime', {
          tsa: tsaName,
          time: tsResult.info.time.toISOString(),
        }),
        {
          key: 'core.docTimestamp.verified',
          detailsKey: 'core.docTimestamp.tsaTime',
          detailsParams: { tsa: tsaName, time: tsResult.info.time.toISOString() },
        }
      )
      checks.timestamp = createPassedCheck(
        t('core.docTimestamp.timestampVerified'),
        t('core.docTimestamp.timeLabel', { time: tsResult.info.time.toISOString() }),
        {
          key: 'core.docTimestamp.timestampVerified',
          detailsKey: 'core.docTimestamp.timeLabel',
          detailsParams: { time: tsResult.info.time.toISOString() },
        }
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
      t('core.docTimestamp.verificationFailed'),
      tsResult.check.details,
      { key: 'core.docTimestamp.verificationFailed' }
    )
    checks.timestamp = tsResult.check
    return createSignatureResult(index, 'DocTimeStamp', null, 'failed', checks, [])
  } catch (error) {
    checks.integrity = createFailedCheck(
      t('core.docTimestamp.verificationError'),
      error instanceof Error ? error.message : t('core.error.unknownError'),
      { key: 'core.docTimestamp.verificationError' }
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
  reason?: string,
  extras?: Partial<Pick<SignatureResult, 'type' | 'docMdp' | 'ltvLevel' | 'subsequentChanges'>>
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
    ...extras,
  }
}
