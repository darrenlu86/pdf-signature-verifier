import type {
  EmbeddedRevocationInfo,
  RevocationResult,
  ParsedCertificate,
  CrlInfo,
} from '@/types'
import { parseEmbeddedOcspResponse } from './ocsp-client'
import { parseEmbeddedCrl, isSerialInCrl, isCrlValid } from './crl-client'

/**
 * Check revocation status using embedded PDF revocation info
 */
export function checkEmbeddedRevocationStatus(
  certificate: ParsedCertificate,
  embeddedInfo: EmbeddedRevocationInfo | null
): RevocationResult {
  if (!embeddedInfo) {
    return {
      status: 'unknown',
      checkedAt: new Date(),
      method: 'embedded',
      details: 'No embedded revocation information in PDF',
    }
  }

  // Try OCSP responses first (they're more specific)
  for (const ocspData of embeddedInfo.ocspResponses) {
    try {
      const result = parseEmbeddedOcspResponse(ocspData)
      if (result.status === 'good' || result.status === 'revoked') {
        return result
      }
    } catch {
      continue
    }
  }

  // Try CRLs
  const serialNumber = certificate.serialNumber
  for (const crlData of embeddedInfo.crls) {
    try {
      const crlInfo = parseEmbeddedCrl(crlData)

      if (!isCrlValid(crlInfo)) {
        continue
      }

      if (isSerialInCrl(serialNumber, crlInfo)) {
        return {
          status: 'revoked',
          checkedAt: new Date(),
          method: 'embedded',
          details: 'Certificate found in embedded CRL',
        }
      }

      // If CRL is valid and cert not in it, it's good
      return {
        status: 'good',
        checkedAt: new Date(),
        method: 'embedded',
        details: 'Certificate not found in embedded CRL',
      }
    } catch {
      continue
    }
  }

  return {
    status: 'unknown',
    checkedAt: new Date(),
    method: 'embedded',
    details: 'Could not determine status from embedded revocation info',
  }
}

/**
 * Extract embedded revocation info statistics
 */
export function getEmbeddedRevocationStats(
  embeddedInfo: EmbeddedRevocationInfo | null
): {
  hasOcsp: boolean
  hasCrl: boolean
  ocspCount: number
  crlCount: number
  crlInfos: CrlInfo[]
} {
  if (!embeddedInfo) {
    return {
      hasOcsp: false,
      hasCrl: false,
      ocspCount: 0,
      crlCount: 0,
      crlInfos: [],
    }
  }

  const crlInfos: CrlInfo[] = []
  for (const crlData of embeddedInfo.crls) {
    try {
      crlInfos.push(parseEmbeddedCrl(crlData))
    } catch {
      continue
    }
  }

  return {
    hasOcsp: embeddedInfo.ocspResponses.length > 0,
    hasCrl: embeddedInfo.crls.length > 0,
    ocspCount: embeddedInfo.ocspResponses.length,
    crlCount: embeddedInfo.crls.length,
    crlInfos,
  }
}

/**
 * Check if embedded revocation info is sufficient for LTV
 */
export function isLtvComplete(
  chain: ParsedCertificate[],
  embeddedInfo: EmbeddedRevocationInfo | null
): { complete: boolean; missing: string[] } {
  const missing: string[] = []

  if (!embeddedInfo) {
    for (const cert of chain) {
      if (!cert.isSelfSigned) {
        missing.push(`Revocation info for ${getCommonName(cert.subject)}`)
      }
    }
    return { complete: false, missing }
  }

  // For each non-root certificate, we need revocation info
  for (let i = 0; i < chain.length - 1; i++) {
    const cert = chain[i]
    const result = checkEmbeddedRevocationStatus(cert, embeddedInfo)

    if (result.status === 'unknown' || result.status === 'error') {
      missing.push(`Revocation info for ${getCommonName(cert.subject)}`)
    }
  }

  return {
    complete: missing.length === 0,
    missing,
  }
}

/**
 * Get revocation info validity window
 */
export function getRevocationInfoValidity(
  embeddedInfo: EmbeddedRevocationInfo | null
): { validFrom: Date | null; validUntil: Date | null } {
  if (!embeddedInfo) {
    return { validFrom: null, validUntil: null }
  }

  let validFrom: Date | null = null
  let validUntil: Date | null = null

  // Check CRLs for validity windows
  for (const crlData of embeddedInfo.crls) {
    try {
      const crlInfo = parseEmbeddedCrl(crlData)

      if (!validFrom || crlInfo.thisUpdate > validFrom) {
        validFrom = crlInfo.thisUpdate
      }

      if (crlInfo.nextUpdate) {
        if (!validUntil || crlInfo.nextUpdate < validUntil) {
          validUntil = crlInfo.nextUpdate
        }
      }
    } catch {
      continue
    }
  }

  return { validFrom, validUntil }
}

function getCommonName(subject: string): string {
  const match = subject.match(/CN=([^,]+)/)
  return match ? match[1] : subject
}
