import type { ParsedCertificate, TrustAnchor } from '@/types'
import { parseCertificateFromBytes, pemToDer } from '@/core/certificate/cert-utils'
import {
  TAIWAN_ROOT_CERTIFICATES,
  type TrustAnchorEntry,
  hasAnyEmbeddedPem,
} from './taiwan-roots'
import {
  TAIWAN_TSA_ROOT_CERTIFICATES,
  hasAnyEmbeddedTsaPem,
} from './taiwan-tsa-roots'

let signingTrustCache: ParsedCertificate[] | null = null
let tsaTrustCache: ParsedCertificate[] | null = null
let initWarnings: string[] = []

/**
 * Convert a fingerprint string (with or without colons) to a normalized
 * lowercase hex string for comparison.
 */
function normalizeFingerprint(fp: string): string {
  return fp.toLowerCase().replace(/[^0-9a-f]/g, '')
}

async function loadEntries(
  entries: TrustAnchorEntry[],
  storeLabel: string
): Promise<{ anchors: ParsedCertificate[]; warnings: string[] }> {
  const anchors: ParsedCertificate[] = []
  const warnings: string[] = []

  const populated = entries.filter((e) => e.pem.trim().length > 0)
  if (populated.length === 0) {
    warnings.push(
      `[${storeLabel}] Trust store is EMPTY — no root anchors loaded. ` +
        `All signatures will report "trust anchor not found". ` +
        `Populate src/trust-store/taiwan-roots.ts (or taiwan-tsa-roots.ts) with verified PEM bodies.`
    )
    return { anchors, warnings }
  }

  for (const entry of populated) {
    try {
      const der = pemToDer(entry.pem)
      const parsed = await parseCertificateFromBytes(der)

      // Fingerprint pinning: if the entry declares an expected fingerprint,
      // reject the PEM unless it matches. This catches accidental swap-ins
      // and supply-chain tampering of the source file.
      if (entry.expectedFingerprint && entry.expectedFingerprint.trim().length > 0) {
        const expected = normalizeFingerprint(entry.expectedFingerprint)
        const actual = normalizeFingerprint(parsed.fingerprint)
        if (expected !== actual) {
          warnings.push(
            `[${storeLabel}] Refusing to trust "${entry.name}": ` +
              `fingerprint mismatch (expected ${expected.slice(0, 16)}..., got ${actual.slice(0, 16)}...)`
          )
          continue
        }
      }

      anchors.push(parsed)
    } catch (error) {
      warnings.push(
        `[${storeLabel}] Failed to parse "${entry.name}": ${
          error instanceof Error ? error.message : String(error)
        }`
      )
    }
  }

  return { anchors, warnings }
}

/**
 * Initialize trust stores (signing CAs + TSAs).
 * Idempotent — second call returns the cached anchors.
 */
export async function initializeTrustStore(): Promise<ParsedCertificate[]> {
  if (signingTrustCache && tsaTrustCache) {
    return signingTrustCache
  }

  initWarnings = []

  const signing = await loadEntries(TAIWAN_ROOT_CERTIFICATES, 'signing-ca')
  signingTrustCache = signing.anchors
  initWarnings.push(...signing.warnings)

  const tsa = await loadEntries(TAIWAN_TSA_ROOT_CERTIFICATES, 'tsa')
  tsaTrustCache = tsa.anchors
  initWarnings.push(...tsa.warnings)

  // Emit warnings to console so developers see them at build/load time.
  if (initWarnings.length > 0) {
    for (const w of initWarnings) {
      console.warn(w)
    }
  }

  return signingTrustCache
}

/**
 * Get warnings raised during the last initializeTrustStore() call.
 * UI surfaces these so users know the trust store is incomplete.
 */
export function getTrustStoreWarnings(): string[] {
  return [...initWarnings]
}

export function isTrustStoreEmpty(): boolean {
  return !hasAnyEmbeddedPem()
}

export function isTsaTrustStoreEmpty(): boolean {
  return !hasAnyEmbeddedTsaPem()
}

/**
 * Get signing CA trust anchors (must call initializeTrustStore first).
 */
export function getTrustAnchors(): ParsedCertificate[] {
  if (!signingTrustCache) return []
  return signingTrustCache
}

/**
 * Get TSA trust anchors (must call initializeTrustStore first).
 */
export function getTsaTrustAnchors(): ParsedCertificate[] {
  if (!tsaTrustCache) return []
  return tsaTrustCache
}

/**
 * Match by fingerprint (preferred) with a fallback to subject+serial.
 * Returns true ONLY if at least one anchor in the store matches the cert.
 */
function matchAnchor(cert: ParsedCertificate, anchors: ParsedCertificate[]): boolean {
  if (anchors.length === 0) return false
  const certFp = normalizeFingerprint(cert.fingerprint)
  return anchors.some((anchor) => {
    if (normalizeFingerprint(anchor.fingerprint) === certFp) return true
    return anchor.subject === cert.subject && anchor.serialNumber === cert.serialNumber
  })
}

/**
 * Check if a certificate is a trust anchor (signing CA store).
 */
export function isTrustAnchor(cert: ParsedCertificate): boolean {
  return matchAnchor(cert, getTrustAnchors())
}

/**
 * Check if a certificate is a TSA trust anchor.
 */
export function isTsaTrustAnchor(cert: ParsedCertificate): boolean {
  return matchAnchor(cert, getTsaTrustAnchors())
}

/**
 * Find trust anchor for a certificate (signing store).
 */
export function findTrustAnchor(cert: ParsedCertificate): ParsedCertificate | null {
  const anchors = getTrustAnchors()
  const certFp = normalizeFingerprint(cert.fingerprint)

  const direct = anchors.find((a) => normalizeFingerprint(a.fingerprint) === certFp)
  if (direct) return direct

  const issuer = anchors.find((a) => a.subject === cert.issuer)
  if (issuer) {
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

export function getTrustAnchorInfo(): TrustAnchor[] {
  const anchors = getTrustAnchors()
  return anchors.map((cert) => ({
    name: getCommonName(cert.subject),
    certificate: cert,
    fingerprint: cert.fingerprint,
  }))
}

/**
 * Strictly check if a chain terminates at a trust anchor in the signing store.
 * Used in place of the old isComplete-as-trust check.
 */
export function isChainTrusted(chain: ParsedCertificate[]): boolean {
  if (chain.length === 0) return false
  const anchors = getTrustAnchors()
  if (anchors.length === 0) return false

  // The chain's last cert must be (or be issued by) a trust anchor.
  const lastCert = chain[chain.length - 1]
  if (isTrustAnchor(lastCert)) return true

  // If the last cert is self-signed but NOT in trust store, the chain is
  // structurally complete but the root is unknown — fail closed.
  return false
}

export function getTrustedIssuerName(cert: ParsedCertificate): string {
  const anchor = findTrustAnchor(cert)
  if (anchor) {
    return getCommonName(anchor.subject)
  }
  return 'Unknown'
}

function getCommonName(dn: string): string {
  const match = dn.match(/CN=([^,]+)/)
  if (match) return match[1].trim()
  const oMatch = dn.match(/O=([^,]+)/)
  if (oMatch) return oMatch[1].trim()
  return dn
}

/**
 * Add a custom trust anchor (used by tests and the runtime manifest loader).
 */
export async function addCustomTrustAnchor(pem: string): Promise<void> {
  if (!signingTrustCache) {
    await initializeTrustStore()
  }
  const der = pemToDer(pem)
  const parsed = await parseCertificateFromBytes(der)
  signingTrustCache!.push(parsed)
}

export async function addCustomTsaTrustAnchor(pem: string): Promise<void> {
  if (!tsaTrustCache) {
    await initializeTrustStore()
  }
  const der = pemToDer(pem)
  const parsed = await parseCertificateFromBytes(der)
  tsaTrustCache!.push(parsed)
}

export function clearTrustAnchors(): void {
  signingTrustCache = null
  tsaTrustCache = null
  initWarnings = []
}

export function getTrustStoreStats(): {
  totalAnchors: number
  totalTsaAnchors: number
  signingAnchors: Array<{ name: string; validUntil: Date; fingerprint: string }>
  tsaAnchors: Array<{ name: string; validUntil: Date; fingerprint: string }>
  warnings: string[]
} {
  const signing = getTrustAnchors()
  const tsa = getTsaTrustAnchors()
  return {
    totalAnchors: signing.length,
    totalTsaAnchors: tsa.length,
    signingAnchors: signing.map((a) => ({
      name: getCommonName(a.subject),
      validUntil: a.notAfter,
      fingerprint: a.fingerprint.slice(0, 16) + '...',
    })),
    tsaAnchors: tsa.map((a) => ({
      name: getCommonName(a.subject),
      validUntil: a.notAfter,
      fingerprint: a.fingerprint.slice(0, 16) + '...',
    })),
    warnings: getTrustStoreWarnings(),
  }
}
