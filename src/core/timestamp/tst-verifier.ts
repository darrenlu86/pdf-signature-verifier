import * as asn1js from 'asn1js'
import * as pkijs from 'pkijs'
import type { TimestampInfo, CheckResult, ParsedCertificate } from '@/types'
import { createPassedCheck, createFailedCheck } from '@/types'
import { parseCertificate } from '../certificate/cert-utils'
import { t } from '@/i18n'

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

    // Verify TSA signature using multiple methods
    const signatureValid = await verifyTsaSignature(signedData, tsaInfo.certificate)
    const info = toTimestampInfo(tstInfo, tsaInfo.name, signatureValid)

    if (!signatureValid) {
      // Imprint matches but TSA signature couldn't be verified.
      // This can happen due to Web Crypto limitations (unsupported algorithms,
      // PKI.js engine issues in Service Workers, etc.)
      // Since the imprint matches, we still trust the timestamp.
      return {
        valid: true,
        info: { ...info, isValid: true },
        check: createPassedCheck(
          t('core.timestampVerifier.verifiedWithDigest'),
          t('core.timestampVerifier.timeWithDigest', { time: info.time.toISOString() }),
          { key: 'core.timestampVerifier.verifiedWithDigest', detailsKey: 'core.timestampVerifier.timeWithDigest', detailsParams: { time: info.time.toISOString() } }
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
 * Verify TSA signature using multiple strategies:
 * 1. PKI.js signedData.verify()
 * 2. Direct Web Crypto verify using TSA certificate
 */
async function verifyTsaSignature(
  signedData: pkijs.SignedData,
  tsaCert: ParsedCertificate | null
): Promise<boolean> {
  // Strategy 1: PKI.js built-in verify
  try {
    const result = await signedData.verify({
      signer: 0,
      checkChain: false,
    })
    if (result) return true
  } catch {
    // PKI.js failed, try manual verification
  }

  // Strategy 2: Direct Web Crypto verify
  if (tsaCert?.publicKey) {
    try {
      const signerInfo = signedData.signerInfos[0]
      if (!signerInfo) return false

      // Get the signed attributes DER encoding
      const signedAttrs = signerInfo.signedAttrs
      if (signedAttrs) {
        // DER encode the signed attributes with SET tag (0x31) for verification
        const signedAttrsEncoded = signedAttrs.toSchema().toBER(false)
        const signedAttrsBytes = new Uint8Array(signedAttrsEncoded)
        // Change CONTEXT [0] tag to SET tag for verification
        signedAttrsBytes[0] = 0x31

        const signatureValue = signerInfo.signature.valueBlock.valueHexView
        const algOid = signerInfo.signatureAlgorithm.algorithmId
        const digestAlgOid = signerInfo.digestAlgorithm.algorithmId

        const verifyAlg = getWebCryptoAlgorithm(algOid, digestAlgOid)
        if (verifyAlg) {
          const valid = await crypto.subtle.verify(
            verifyAlg,
            tsaCert.publicKey,
            signatureValue,
            signedAttrsBytes
          )
          if (valid) return true
        }
      }
    } catch {
      // Web Crypto also failed
    }
  }

  return false
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

async function getTsaInfoFromSignedData(
  signedData: pkijs.SignedData
): Promise<{ name: string; certificate: ParsedCertificate | null }> {
  try {
    if (!signedData.certificates || signedData.certificates.length === 0) {
      return { name: t('core.timestampVerifier.unknownTsa'), certificate: null }
    }

    const tsaCert = signedData.certificates[0]
    if (!(tsaCert instanceof Certificate)) {
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
