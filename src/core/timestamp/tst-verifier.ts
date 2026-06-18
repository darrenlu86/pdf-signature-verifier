import * as asn1js from 'asn1js'
import * as pkijs from 'pkijs'
import type { TimestampInfo, CheckResult, ParsedCertificate } from '@/types'
import { createPassedCheck, createFailedCheck } from '@/types'
import { parseCertificate } from '../certificate/cert-utils'
import { t } from '@/i18n'
import { isTsaTrustAnchor, isTsaTrustStoreEmpty } from '@/trust-store/trust-manager'

const { ContentInfo, SignedData, Certificate } = pkijs

/**
 * Internal parsed TSTInfo per RFC 3161 Section 2.4.2
 */
interface TstInfoParsed {
  version: number
  policy: string
  messageImprint: {
    algorithm: string
    hash: Uint8Array
  }
  serialNumber: string
  time: Date
}

/**
 * Verify RFC 3161 timestamp token
 */
export async function verifyTimestamp(
  timestampData: Uint8Array,
  messageImprint: Uint8Array
): Promise<{
  valid: boolean
  info: TimestampInfo | null
  check: CheckResult
}> {
  try {
    const buffer = timestampData.buffer.slice(
      timestampData.byteOffset,
      timestampData.byteOffset + timestampData.byteLength
    )
    const asn1 = asn1js.fromBER(buffer)
    if (asn1.offset === -1) {
      return {
        valid: false,
        info: null,
        check: createFailedCheck(
          t('core.timestampVerifier.cannotParseAsn1'),
          undefined,
          { key: 'core.timestampVerifier.cannotParseAsn1' }
        ),
      }
    }

    // Parse ContentInfo
    const contentInfo = new ContentInfo({ schema: asn1.result })
    if (contentInfo.contentType !== '1.2.840.113549.1.7.2') {
      return {
        valid: false,
        info: null,
        check: createFailedCheck(
          t('core.timestampVerifier.notSignedData'),
          undefined,
          { key: 'core.timestampVerifier.notSignedData' }
        ),
      }
    }

    // Parse SignedData
    const signedData = new SignedData({ schema: contentInfo.content })

    // Get TSTInfo
    if (!signedData.encapContentInfo?.eContent) {
      return {
        valid: false,
        info: null,
        check: createFailedCheck(
          t('core.timestampVerifier.noTstInfo'),
          undefined,
          { key: 'core.timestampVerifier.noTstInfo' }
        ),
      }
    }

    const tstInfoData = signedData.encapContentInfo.eContent.valueBlock.valueHexView
    const tstInfo = parseTstInfo(tstInfoData)

    if (!tstInfo) {
      return {
        valid: false,
        info: null,
        check: createFailedCheck(
          t('core.timestampVerifier.cannotParseTstInfo'),
          undefined,
          { key: 'core.timestampVerifier.cannotParseTstInfo' }
        ),
      }
    }

    // Verify message imprint matches
    const imprintMatch = verifyMessageImprint(tstInfo.messageImprint, messageImprint)
    if (!imprintMatch) {
      const tsaInfo = await getTsaInfoFromSignedData(signedData)
      const info = toTimestampInfo(tstInfo, tsaInfo.name, false)
      return {
        valid: false,
        info,
        check: createFailedCheck(
          t('core.timestampVerifier.digestMismatch'),
          t('core.timestampVerifier.digestMismatchDetails'),
          { key: 'core.timestampVerifier.digestMismatch', detailsKey: 'core.timestampVerifier.digestMismatchDetails' }
        ),
      }
    }

    // Get TSA info
    const tsaInfo = await getTsaInfoFromSignedData(signedData)

    // Verify TSA signature — audit P0-3: failure must mean invalid, no fallback.
    const sigResult = await verifyTsaSignature(signedData, tsaInfo.certificate)
    if (!sigResult.valid) {
      const info = toTimestampInfo(tstInfo, tsaInfo.name, false)
      return {
        valid: false,
        info,
        check: createFailedCheck(
          t('core.timestampVerifier.tsaSignatureInvalid'),
          sigResult.reason || t('core.timestampVerifier.tsaSignatureInvalidDetails'),
          {
            key: 'core.timestampVerifier.tsaSignatureInvalid',
            detailsKey: sigResult.reasonKey || 'core.timestampVerifier.tsaSignatureInvalidDetails',
            detailsParams: sigResult.reasonParams,
          }
        ),
      }
    }

    // Audit P2-6: TSA trust anchor — even if the TSA signature cryptographically
    // checks out, the TSA's own certificate chain must terminate at a TRUSTED TSA
    // anchor (not a signing-CA anchor). When the TSA trust store is empty we
    // still return the time but flag isValid:false so the verifier downgrades.
    let tsaTrusted = false
    let tsaTrustReason = ''
    if (tsaInfo.certificate) {
      // Direct anchor match (self-signed root in store) — most common for TSAs
      // distributed as a single self-signed root.
      if (isTsaTrustAnchor(tsaInfo.certificate)) {
        tsaTrusted = true
      } else {
        // Walk up the certificates bundled in the TST until we find one in the
        // TSA trust store. We don't fetch issuers over the network here —
        // the TST is expected to embed its own chain.
        for (const cert of signedData.certificates || []) {
          if (cert instanceof Certificate) {
            const parsed = await parseCertificate(cert)
            if (isTsaTrustAnchor(parsed)) {
              tsaTrusted = true
              break
            }
          }
        }
      }
      if (!tsaTrusted) {
        tsaTrustReason = isTsaTrustStoreEmpty()
          ? t('core.timestampVerifier.tsaTrustStoreEmpty')
          : t('core.timestampVerifier.tsaUntrusted', { tsa: tsaInfo.name })
      }
    } else {
      tsaTrustReason = t('core.timestampVerifier.tsaCertMissing')
    }

    const info = toTimestampInfo(tstInfo, tsaInfo.name, tsaTrusted)

    if (!tsaTrusted) {
      // Time is mathematically attested but the TSA anchor isn't in our store.
      // Return valid:false so the verifier doesn't accept this for LTV trust.
      return {
        valid: false,
        info,
        check: createFailedCheck(
          t('core.timestampVerifier.tsaUntrusted', { tsa: tsaInfo.name }),
          tsaTrustReason,
          {
            key: 'core.timestampVerifier.tsaUntrusted',
            params: { tsa: tsaInfo.name },
            detailsKey: isTsaTrustStoreEmpty()
              ? 'core.timestampVerifier.tsaTrustStoreEmpty'
              : 'core.timestampVerifier.tsaUntrustedDetails',
            detailsParams: isTsaTrustStoreEmpty() ? undefined : { tsa: tsaInfo.name },
          }
        ),
      }
    }

    return {
      valid: true,
      info,
      check: createPassedCheck(
        t('core.timestampVerifier.verifiedWithDigest'),
        t('core.timestampVerifier.verifiedTime', { time: info.time.toISOString() }),
        { key: 'core.timestampVerifier.verifiedWithDigest', detailsKey: 'core.timestampVerifier.verifiedTime', detailsParams: { time: info.time.toISOString() } }
      ),
    }
  } catch (error) {
    return {
      valid: false,
      info: null,
      check: createFailedCheck(
        t('core.timestampVerifier.verificationError'),
        error instanceof Error ? error.message : t('core.error.unknownError'),
        { key: 'core.timestampVerifier.verificationError' }
      ),
    }
  }
}

/**
 * Verify TSA signature using two strategies in sequence. Returns a structured
 * result so callers can distinguish "cryptographically invalid" from
 * "unsupported algorithm" — audit P0-3 requires unsupported-algorithm to be
 * reported as a specific error, not silently downgraded to "trusted".
 */
interface TsaSigResult {
  valid: boolean
  /** Pre-rendered detail string for log/UI. */
  reason?: string
  /** i18n key for the failure reason, when applicable. */
  reasonKey?: string
  reasonParams?: Record<string, string | number>
}

async function verifyTsaSignature(
  signedData: pkijs.SignedData,
  tsaCert: ParsedCertificate | null
): Promise<TsaSigResult> {
  let pkijsError: string | null = null

  // Strategy 1: PKI.js built-in verify
  try {
    const result = await signedData.verify({
      signer: 0,
      checkChain: false,
    })
    if (result) return { valid: true }
  } catch (err) {
    pkijsError = err instanceof Error ? err.message : String(err)
  }

  // Strategy 2: Direct Web Crypto verify
  if (tsaCert?.publicKey) {
    const signerInfo = signedData.signerInfos[0]
    if (!signerInfo) {
      return {
        valid: false,
        reason: t('core.timestampVerifier.tsaNoSignerInfo'),
        reasonKey: 'core.timestampVerifier.tsaNoSignerInfo',
      }
    }
    const signedAttrs = signerInfo.signedAttrs
    if (!signedAttrs) {
      return {
        valid: false,
        reason: t('core.timestampVerifier.tsaNoSignedAttrs'),
        reasonKey: 'core.timestampVerifier.tsaNoSignedAttrs',
      }
    }

    const signedAttrsEncoded = signedAttrs.toSchema().toBER(false)
    const signedAttrsBytes = new Uint8Array(signedAttrsEncoded)
    signedAttrsBytes[0] = 0x31 // CONTEXT [0] -> SET

    const signatureValue = signerInfo.signature.valueBlock.valueHexView
    const algOid = signerInfo.signatureAlgorithm.algorithmId
    const digestAlgOid = signerInfo.digestAlgorithm.algorithmId

    const verifyAlg = getWebCryptoAlgorithm(algOid, digestAlgOid)
    if (!verifyAlg) {
      return {
        valid: false,
        reason: t('core.timestampVerifier.tsaAlgorithmUnsupported', {
          alg: algOid,
          digest: digestAlgOid,
        }),
        reasonKey: 'core.timestampVerifier.tsaAlgorithmUnsupported',
        reasonParams: { alg: algOid, digest: digestAlgOid },
      }
    }

    try {
      const valid = await crypto.subtle.verify(
        verifyAlg,
        tsaCert.publicKey,
        signatureValue,
        signedAttrsBytes
      )
      if (valid) return { valid: true }
      return {
        valid: false,
        reason: t('core.timestampVerifier.tsaSignatureMismatch'),
        reasonKey: 'core.timestampVerifier.tsaSignatureMismatch',
      }
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err)
      return {
        valid: false,
        reason: t('core.timestampVerifier.tsaCryptoError', { error: msg }),
        reasonKey: 'core.timestampVerifier.tsaCryptoError',
        reasonParams: { error: msg },
      }
    }
  }

  // No TSA cert and PKI.js failed
  return {
    valid: false,
    reason: pkijsError
      ? t('core.timestampVerifier.tsaPkijsError', { error: pkijsError })
      : t('core.timestampVerifier.tsaCertMissing'),
    reasonKey: pkijsError
      ? 'core.timestampVerifier.tsaPkijsError'
      : 'core.timestampVerifier.tsaCertMissing',
    reasonParams: pkijsError ? { error: pkijsError } : undefined,
  }
}

/**
 * Map signature algorithm OIDs to Web Crypto parameters
 */
function getWebCryptoAlgorithm(
  sigAlgOid: string,
  digestAlgOid: string
): AlgorithmIdentifier | RsaPssParams | EcdsaParams | null {
  const digestMap: Record<string, string> = {
    '1.3.14.3.2.26': 'SHA-1',
    '2.16.840.1.101.3.4.2.1': 'SHA-256',
    '2.16.840.1.101.3.4.2.2': 'SHA-384',
    '2.16.840.1.101.3.4.2.3': 'SHA-512',
  }
  const digest = digestMap[digestAlgOid] || 'SHA-256'

  // RSA PKCS#1 v1.5
  if (['1.2.840.113549.1.1.5', '1.2.840.113549.1.1.11',
       '1.2.840.113549.1.1.12', '1.2.840.113549.1.1.13',
       '1.2.840.113549.1.1.1'].includes(sigAlgOid)) {
    return { name: 'RSASSA-PKCS1-v1_5' }
  }

  // RSA-PSS
  if (sigAlgOid === '1.2.840.113549.1.1.10') {
    const saltLengths: Record<string, number> = {
      'SHA-1': 20, 'SHA-256': 32, 'SHA-384': 48, 'SHA-512': 64,
    }
    return {
      name: 'RSA-PSS',
      saltLength: saltLengths[digest] || 32,
    } as RsaPssParams
  }

  // ECDSA
  if (['1.2.840.10045.4.1', '1.2.840.10045.4.3.2',
       '1.2.840.10045.4.3.3', '1.2.840.10045.4.3.4'].includes(sigAlgOid)) {
    return { name: 'ECDSA', hash: digest } as EcdsaParams
  }

  return null
}

/**
 * Parse TSTInfo structure per RFC 3161 Section 2.4.2
 */
function parseTstInfo(data: ArrayBuffer | Uint8Array): TstInfoParsed | null {
  try {
    const buffer = data instanceof Uint8Array
      ? data.buffer.slice(data.byteOffset, data.byteOffset + data.byteLength)
      : data
    const asn1 = asn1js.fromBER(buffer)
    if (asn1.offset === -1) {
      return null
    }

    const seq = asn1.result
    if (!(seq instanceof asn1js.Sequence)) {
      return null
    }

    const values = seq.valueBlock.value
    if (values.length < 5) {
      return null
    }

    // Field 0: version INTEGER
    const versionItem = values[0]
    if (!(versionItem instanceof asn1js.Integer)) {
      return null
    }
    const version = versionItem.valueBlock.valueDec

    // Field 1: policy OBJECT IDENTIFIER
    const policyItem = values[1]
    if (!(policyItem instanceof asn1js.ObjectIdentifier)) {
      return null
    }
    const policy = policyItem.valueBlock.toString()

    // Field 2: messageImprint SEQUENCE { hashAlgorithm, hashedMessage }
    const msgImprintItem = values[2]
    if (!(msgImprintItem instanceof asn1js.Sequence)) {
      return null
    }
    const msgImprintValues = msgImprintItem.valueBlock.value
    if (msgImprintValues.length < 2) {
      return null
    }

    const algIdItem = msgImprintValues[0]
    if (!(algIdItem instanceof asn1js.Sequence)) {
      return null
    }
    const algOidItem = algIdItem.valueBlock.value[0]
    if (!(algOidItem instanceof asn1js.ObjectIdentifier)) {
      return null
    }
    const algorithm = getAlgorithmName(algOidItem.valueBlock.toString())

    const hashItem = msgImprintValues[1]
    if (!(hashItem instanceof asn1js.OctetString)) {
      return null
    }
    const hash = new Uint8Array(hashItem.valueBlock.valueHexView)

    // Field 3: serialNumber INTEGER
    const serialItem = values[3]
    if (!(serialItem instanceof asn1js.Integer)) {
      return null
    }
    const serialNumber = bufferToHex(serialItem.valueBlock.valueHexView)

    // Field 4: genTime GeneralizedTime
    const genTimeItem = values[4]
    if (!(genTimeItem instanceof asn1js.GeneralizedTime)) {
      return null
    }
    const time = genTimeItem.toDate()

    return {
      version,
      policy,
      messageImprint: { algorithm, hash },
      serialNumber,
      time,
    }
  } catch {
    return null
  }
}

function toTimestampInfo(
  tstInfo: TstInfoParsed,
  issuer: string,
  isValid: boolean
): TimestampInfo {
  return {
    time: tstInfo.time,
    issuer,
    serialNumber: tstInfo.serialNumber,
    hashAlgorithm: tstInfo.messageImprint.algorithm,
    isValid,
  }
}

function verifyMessageImprint(
  imprint: { algorithm: string; hash: Uint8Array },
  expectedHash: Uint8Array
): boolean {
  if (imprint.hash.length !== expectedHash.length) {
    return false
  }
  let result = 0
  for (let i = 0; i < imprint.hash.length; i++) {
    result |= imprint.hash[i] ^ expectedHash[i]
  }
  return result === 0
}

/**
 * Find the certificate that actually signed the SignedData.
 * Earlier code grabbed certificates[0] which is typically the ROOT CA (the
 * top of the bundled chain). The right cert is the one identified by the
 * SignerInfo's `sid` field — either by IssuerAndSerialNumber or by
 * SubjectKeyIdentifier. Using the wrong public key makes every signature
 * fail verification, which is exactly what was happening for real TWCA
 * TSP timestamps.
 */
function findSignerCertificate(signedData: pkijs.SignedData): pkijs.Certificate | null {
  const certs = (signedData.certificates || []).filter(
    (c): c is pkijs.Certificate => c instanceof Certificate
  )
  if (certs.length === 0) return null

  const signerInfo = signedData.signerInfos[0]
  if (!signerInfo) return certs[0]
  const sid = signerInfo.sid

  // Case 1: sid is IssuerAndSerialNumber — match issuer DN + serial.
  if (sid instanceof pkijs.IssuerAndSerialNumber) {
    const wantedSerial = new Uint8Array(sid.serialNumber.valueBlock.valueHexView)
    const wantedIssuerHex = Array.from(
      new Uint8Array(sid.issuer.toSchema().toBER(false))
    ).join(',')
    for (const cert of certs) {
      const certSerial = new Uint8Array(cert.serialNumber.valueBlock.valueHexView)
      if (
        certSerial.length === wantedSerial.length &&
        certSerial.every((b, i) => b === wantedSerial[i])
      ) {
        const certIssuerHex = Array.from(
          new Uint8Array(cert.issuer.toSchema().toBER(false))
        ).join(',')
        if (certIssuerHex === wantedIssuerHex) {
          return cert
        }
      }
    }
  }

  // Case 2: sid is SubjectKeyIdentifier — match SKI extension on each cert.
  // pkijs exposes sid as an OctetString in this case.
  if (sid && 'valueBlock' in sid && sid.idBlock && (sid.idBlock as { tagNumber?: number }).tagNumber === 0) {
    const wantedSki = new Uint8Array((sid as unknown as { valueBlock: { valueHexView: ArrayBuffer } }).valueBlock.valueHexView)
    for (const cert of certs) {
      const skiExt = cert.extensions?.find((e) => e.extnID === '2.5.29.14')
      if (!skiExt) continue
      // SKI extension value is OctetString wrapping another OctetString
      try {
        const inner = (skiExt.parsedValue as unknown as { valueBlock?: { valueHexView?: ArrayBuffer } })
          ?.valueBlock?.valueHexView
        if (!inner) continue
        const skiBytes = new Uint8Array(inner)
        if (
          skiBytes.length === wantedSki.length &&
          skiBytes.every((b, i) => b === wantedSki[i])
        ) {
          return cert
        }
      } catch {
        continue
      }
    }
  }

  // Last-resort fallback: pick the first non-CA certificate (TSA leaves
  // typically have basicConstraints CA=false). If none match, return the
  // first cert and let the signature verification fail with a clear error.
  for (const cert of certs) {
    const bc = cert.extensions?.find((e) => e.extnID === '2.5.29.19')
    if (bc) {
      const parsed = bc.parsedValue as unknown as { cA?: boolean }
      if (parsed && parsed.cA === false) return cert
    }
  }
  return certs[0]
}

async function getTsaInfoFromSignedData(
  signedData: pkijs.SignedData
): Promise<{ name: string; certificate: ParsedCertificate | null }> {
  try {
    const tsaCert = findSignerCertificate(signedData)
    if (!tsaCert) {
      return { name: t('core.timestampVerifier.unknownTsa'), certificate: null }
    }

    const parsed = await parseCertificate(tsaCert)
    const name = getCommonName(parsed.subject)

    return { name, certificate: parsed }
  } catch {
    return { name: t('core.timestampVerifier.unknownTsa'), certificate: null }
  }
}

export async function getTsaInfo(
  timestampData: Uint8Array
): Promise<{ name: string; certificate: ParsedCertificate | null }> {
  try {
    const asn1 = asn1js.fromBER(timestampData.buffer)
    if (asn1.offset === -1) {
      return { name: t('core.timestampVerifier.unknownTsa'), certificate: null }
    }

    const contentInfo = new ContentInfo({ schema: asn1.result })
    const signedData = new SignedData({ schema: contentInfo.content })

    return getTsaInfoFromSignedData(signedData)
  } catch {
    return { name: t('core.timestampVerifier.unknownTsa'), certificate: null }
  }
}

export function isTimestampWithinCertValidity(
  timestampTime: Date,
  certificate: ParsedCertificate
): boolean {
  return timestampTime >= certificate.notBefore && timestampTime <= certificate.notAfter
}

export function getEffectiveSigningTime(
  signingTime: Date | null,
  timestampInfo: TimestampInfo | null
): Date {
  if (timestampInfo?.time) {
    return timestampInfo.time
  }
  if (signingTime) {
    return signingTime
  }
  return new Date()
}

function getAlgorithmName(oid: string): string {
  const names: Record<string, string> = {
    '2.16.840.1.101.3.4.2.1': 'SHA-256',
    '2.16.840.1.101.3.4.2.2': 'SHA-384',
    '2.16.840.1.101.3.4.2.3': 'SHA-512',
    '1.3.14.3.2.26': 'SHA-1',
  }
  return names[oid] || oid
}

function getCommonName(subject: string): string {
  const match = subject.match(/CN=([^,]+)/)
  return match ? match[1] : subject
}

function bufferToHex(buffer: ArrayBuffer | Uint8Array): string {
  const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer)
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')
}
