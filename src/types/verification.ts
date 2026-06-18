export type VerificationStatus = 'trusted' | 'unknown' | 'failed'

export type I18nParams = Record<string, string | number>

export interface VerificationResult {
  status: VerificationStatus
  fileName: string
  signatures: SignatureResult[]
  summary: string
  summaryI18nKey?: string
  summaryI18nParams?: I18nParams
}

export type SignatureType = 'approval' | 'certification' | 'timestamp'

/** PAdES level per ETSI EN 319 142 — informational classification. */
export type LtvLevel = 'none' | 'B-B' | 'B-T' | 'B-LT' | 'B-LTA'

export interface DocMdpInfo {
  /** 1 = No changes; 2 = Form fill-in & signatures allowed; 3 = above + annotations. */
  permissionLevel: 1 | 2 | 3
  /** From /Reference /DigestMethod */
  digestMethod?: string
}

export interface SubsequentChange {
  /** Index of the later signature that introduced the change. */
  signatureIndex: number
  /** Byte range that the change occupies. */
  byteOffset: number
  /** True if the later signature's incremental update is consistent with DocMDP. */
  permittedByDocMdp: boolean | null
}

export interface SignatureResult {
  index: number
  signerName: string
  signedAt: Date | null
  reason?: string
  location?: string
  status: VerificationStatus

  /** Signature semantic type per PDF spec. */
  type?: SignatureType
  /** When type='certification', the DocMDP permission level. */
  docMdp?: DocMdpInfo
  /** PAdES LTV level for THIS signature. */
  ltvLevel?: LtvLevel
  /** Incremental updates that happened after this signature, if any. */
  subsequentChanges?: SubsequentChange[]

  checks: {
    integrity: CheckResult
    certificateChain: CheckResult
    trustRoot: CheckResult
    validity: CheckResult
    revocation: CheckResult
    timestamp: CheckResult | null
    ltv: CheckResult
  }

  certificateChain: CertificateInfo[]
  timestampInfo?: TimestampInfo
  rawSignature?: Uint8Array
}

export interface CheckResult {
  passed: boolean
  message: string
  details?: string
  i18nKey?: string
  i18nParams?: I18nParams
  detailsI18nKey?: string
  detailsI18nParams?: I18nParams
}

export interface CertificateInfo {
  subject: string
  issuer: string
  serialNumber: string
  notBefore: Date
  notAfter: Date
  isRoot: boolean
  isTrusted: boolean
  fingerprint?: string
  keyUsage?: string[]
  extKeyUsage?: string[]
}

export interface TimestampInfo {
  time: Date
  issuer: string
  serialNumber: string
  hashAlgorithm: string
  isValid: boolean
}

export interface LtvInfo {
  hasEmbeddedOcsp: boolean
  hasEmbeddedCrl: boolean
  ocspResponses: OcspResponse[]
  crls: CrlInfo[]
}

export interface OcspResponse {
  producedAt: Date
  thisUpdate: Date
  nextUpdate?: Date
  certStatus: 'good' | 'revoked' | 'unknown'
  responderName: string
}

export interface CrlInfo {
  issuer: string
  thisUpdate: Date
  nextUpdate?: Date
  serialNumbers: string[]
}

export function createFailedCheck(
  message: string,
  details?: string,
  i18n?: { key: string; params?: I18nParams; detailsKey?: string; detailsParams?: I18nParams }
): CheckResult {
  return {
    passed: false,
    message,
    details,
    i18nKey: i18n?.key,
    i18nParams: i18n?.params,
    detailsI18nKey: i18n?.detailsKey,
    detailsI18nParams: i18n?.detailsParams,
  }
}

export function createPassedCheck(
  message: string,
  details?: string,
  i18n?: { key: string; params?: I18nParams; detailsKey?: string; detailsParams?: I18nParams }
): CheckResult {
  return {
    passed: true,
    message,
    details,
    i18nKey: i18n?.key,
    i18nParams: i18n?.params,
    detailsI18nKey: i18n?.detailsKey,
    detailsI18nParams: i18n?.detailsParams,
  }
}

export function determineOverallStatus(signatures: SignatureResult[]): VerificationStatus {
  if (signatures.length === 0) {
    return 'unknown'
  }

  const hasFailure = signatures.some((sig) => sig.status === 'failed')
  if (hasFailure) {
    return 'failed'
  }

  const hasUnknown = signatures.some((sig) => sig.status === 'unknown')
  if (hasUnknown) {
    return 'unknown'
  }

  return 'trusted'
}
