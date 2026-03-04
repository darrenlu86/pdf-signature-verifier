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

export interface SignatureResult {
  index: number
  signerName: string
  signedAt: Date | null
  reason?: string
  location?: string
  status: VerificationStatus

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
