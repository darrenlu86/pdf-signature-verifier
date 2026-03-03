export type VerificationStatus = 'trusted' | 'unknown' | 'failed'

export interface VerificationResult {
  status: VerificationStatus
  fileName: string
  signatures: SignatureResult[]
  summary: string
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

export function createFailedCheck(message: string, details?: string): CheckResult {
  return { passed: false, message, details }
}

export function createPassedCheck(message: string, details?: string): CheckResult {
  return { passed: true, message, details }
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
