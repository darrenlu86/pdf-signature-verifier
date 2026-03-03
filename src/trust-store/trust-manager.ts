import type { ParsedCertificate, TrustAnchor } from '@/types'
import { parseCertificateFromBytes, pemToDer } from '@/core/certificate/cert-utils'
import { TAIWAN_ROOT_CERTIFICATES } from './taiwan-roots'

let trustAnchorsCache: ParsedCertificate[] | null = null

/**
 * Initialize and get all trust anchors
 */
export async function initializeTrustStore(): Promise<ParsedCertificate[]> {
  if (trustAnchorsCache) {
    return trustAnchorsCache
  }

  const anchors: ParsedCertificate[] = []

  for (const rootCert of TAIWAN_ROOT_CERTIFICATES) {
    try {
      const der = pemToDer(rootCert.pem)
      const parsed = await parseCertificateFromBytes(der)
      anchors.push(parsed)
    } catch (error) {
      console.warn(`Failed to parse ${rootCert.name}:`, error)
    }
  }

  trustAnchorsCache = anchors
  return anchors
}

/**
 * Get trust anchors (must call initializeTrustStore first)
 */
export function getTrustAnchors(): ParsedCertificate[] {
  if (!trustAnchorsCache) {
    // Return empty array if not initialized
    // Caller should call initializeTrustStore() first
    return []
  }
  return trustAnchorsCache
}

/**
 * Check if a certificate is a trust anchor
 */
export function isTrustAnchor(cert: ParsedCertificate): boolean {
  const anchors = getTrustAnchors()
  return anchors.some(
    (anchor) =>
      anchor.fingerprint === cert.fingerprint ||
      (anchor.subject === cert.subject && anchor.serialNumber === cert.serialNumber)
  )
}

/**
 * Find trust anchor for a certificate
 */
export function findTrustAnchor(cert: ParsedCertificate): ParsedCertificate | null {
  const anchors = getTrustAnchors()

  // Direct match by fingerprint
  const direct = anchors.find((a) => a.fingerprint === cert.fingerprint)
  if (direct) {
    return direct
  }

  // Match as issuer
  const issuer = anchors.find((a) => a.subject === cert.issuer)
  if (issuer) {
    // Verify key identifier match if available
    if (cert.authorityKeyIdentifier && issuer.subjectKeyIdentifier) {
      if (cert.authorityKeyIdentifier === issuer.subjectKeyIdentifier) {
        return issuer
      }
    } else {
      return issuer
    }
  }

  return null
}

/**
 * Get trust anchor info for display
 */
export function getTrustAnchorInfo(): TrustAnchor[] {
  const anchors = getTrustAnchors()
  return anchors.map((cert) => ({
    name: getCommonName(cert.subject),
    certificate: cert,
    fingerprint: cert.fingerprint,
  }))
}

/**
 * Check if certificate chain terminates at trust anchor
 */
export function isChainTrusted(chain: ParsedCertificate[]): boolean {
  if (chain.length === 0) {
    return false
  }

  // Check if last certificate is a trust anchor
  const lastCert = chain[chain.length - 1]
  if (isTrustAnchor(lastCert)) {
    return true
  }

  // Check if any certificate in chain is issued by a trust anchor
  for (const cert of chain) {
    const anchor = findTrustAnchor(cert)
    if (anchor) {
      return true
    }
  }

  return false
}

/**
 * Get issuer name for a trusted certificate
 */
export function getTrustedIssuerName(cert: ParsedCertificate): string {
  const anchor = findTrustAnchor(cert)
  if (anchor) {
    return getCommonName(anchor.subject)
  }
  return 'Unknown'
}

/**
 * Extract common name from DN
 */
function getCommonName(dn: string): string {
  const match = dn.match(/CN=([^,]+)/)
  if (match) {
    return match[1].trim()
  }

  const oMatch = dn.match(/O=([^,]+)/)
  if (oMatch) {
    return oMatch[1].trim()
  }

  return dn
}

/**
 * Add custom trust anchor (for testing)
 */
export async function addCustomTrustAnchor(pem: string): Promise<void> {
  if (!trustAnchorsCache) {
    await initializeTrustStore()
  }

  const der = pemToDer(pem)
  const parsed = await parseCertificateFromBytes(der)
  trustAnchorsCache!.push(parsed)
}

/**
 * Clear trust anchor cache (for testing)
 */
export function clearTrustAnchors(): void {
  trustAnchorsCache = null
}

/**
 * Get statistics about trust store
 */
export function getTrustStoreStats(): {
  totalAnchors: number
  anchors: Array<{ name: string; validUntil: Date; fingerprint: string }>
} {
  const anchors = getTrustAnchors()
  return {
    totalAnchors: anchors.length,
    anchors: anchors.map((a) => ({
      name: getCommonName(a.subject),
      validUntil: a.notAfter,
      fingerprint: a.fingerprint.slice(0, 16) + '...',
    })),
  }
}
