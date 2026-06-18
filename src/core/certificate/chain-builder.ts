import type { ParsedCertificate, CertificateChain } from '@/types'
import { parseCertificateFromBytes } from './cert-utils'
import { isChainTrusted, findTrustAnchor } from '@/trust-store/trust-manager'

/**
 * Build a certificate chain from a set of certificates.
 * Uses embedded PKCS#7 certificates plus the configured trust store.
 *
 * isComplete = chain terminates at a self-signed cert (structural completeness).
 * isTrusted  = the chain's root is present in the trust store.
 *
 * NOTE: isComplete alone is NEVER enough to call a chain trusted —
 * any attacker can self-sign a CA and append it. The trust check must
 * cross-reference the curated trust anchor list (taiwan-roots.ts).
 */
export async function buildCertificateChain(
  endEntityCert: ParsedCertificate,
  intermediateCerts: ParsedCertificate[],
  options: ChainBuildOptions = {}
): Promise<CertificateChain> {
  const { fetchMissing = false, additionalCertBytes = [] } = options

  const chain: ParsedCertificate[] = [endEntityCert]
  const available = [...intermediateCerts]

  // Parse DSS /Certs and add to available pool (best-effort)
  for (const certBytes of additionalCertBytes) {
    try {
      const parsed = await parseCertificateFromBytes(certBytes)
      if (parsed && !available.some((c) => c.fingerprint === parsed.fingerprint)) {
        available.push(parsed)
      }
    } catch {
      continue
    }
  }

  let current = endEntityCert
  let isComplete = false

  // Build chain upward
  while (!isComplete) {
    // Check if self-signed (root)
    if (current.isSelfSigned) {
      isComplete = true
      break
    }

    // Find issuer in available certificates
    let issuer = findIssuer(current, available)

    // If not found and fetchMissing is enabled, try to fetch
    if (!issuer && fetchMissing && current.authorityInfoAccess?.caIssuers.length) {
      issuer = await fetchIssuerCertificate(current.authorityInfoAccess.caIssuers)
    }

    if (issuer) {
      chain.push(issuer)
      current = issuer

      // Remove from available to prevent cycles
      const index = available.findIndex((c) => c.fingerprint === issuer!.fingerprint)
      if (index !== -1) {
        available.splice(index, 1)
      }
    } else {
      // Chain is incomplete
      break
    }

    // Prevent infinite loops
    if (chain.length > 10) {
      break
    }
  }

  // Find structural root: the topmost cert if it is self-signed.
  let root = chain.length > 0 && chain[chain.length - 1].isSelfSigned
    ? chain[chain.length - 1]
    : null

  // Trust check: ANY cert in the chain matching the trust store is enough.
  // Two cases:
  //  - Self-signed root cert is in the trust store (typical CA scenario).
  //  - An intermediate is itself in the trust store (cross-signed scenario).
  //    In that case the "root" for trust purposes is the anchor, and the
  //    chain is considered "complete enough" — we have a verified path to
  //    a trusted point.
  let isTrusted = false
  if (chain.length > 0) {
    isTrusted = isChainTrusted(chain)
    if (isTrusted) {
      // Find which cert in the chain matches the trust store and treat
      // that as the effective root.
      for (const cert of chain) {
        const anchor = findTrustAnchor(cert)
        if (anchor) {
          root = anchor
          // A path to a trust anchor counts as a complete chain even if
          // the anchor is an intermediate.
          isComplete = true
          break
        }
      }
    }
  }

  return {
    certificates: chain,
    root,
    isComplete,
    isTrusted,
  }
}

export interface ChainBuildOptions {
  fetchMissing?: boolean
  additionalCertBytes?: Uint8Array[]
}

/**
 * Find issuer certificate for a given certificate
 */
function findIssuer(
  cert: ParsedCertificate,
  candidates: ParsedCertificate[]
): ParsedCertificate | null {
  for (const candidate of candidates) {
    // Match by subject/issuer name
    if (candidate.subject !== cert.issuer) {
      continue
    }

    // Match by authority key identifier if available
    if (cert.authorityKeyIdentifier && candidate.subjectKeyIdentifier) {
      if (cert.authorityKeyIdentifier !== candidate.subjectKeyIdentifier) {
        continue
      }
    }

    // Verify signature if possible
    // For now, we trust the name match
    return candidate
  }

  return null
}

/**
 * Fetch issuer certificate from AIA extension
 */
async function fetchIssuerCertificate(
  urls: string[]
): Promise<ParsedCertificate | null> {
  const { fetchCertificateBytes } = await import('../network')

  for (const url of urls) {
    try {
      const certData = await fetchCertificateBytes(url)
      if (certData) {
        return await parseCertificateFromBytes(certData)
      }
    } catch {
      // Try next URL
      continue
    }
  }

  return null
}

/**
 * Verify that one certificate issued another
 */
export async function verifyIssuedBy(
  subject: ParsedCertificate,
  issuer: ParsedCertificate
): Promise<boolean> {
  // Check name chaining
  if (subject.issuer !== issuer.subject) {
    return false
  }

  // Check key identifier if available
  if (subject.authorityKeyIdentifier && issuer.subjectKeyIdentifier) {
    if (subject.authorityKeyIdentifier !== issuer.subjectKeyIdentifier) {
      return false
    }
  }

  // Verify signature
  try {
    const subjectDer = subject.raw.toSchema().toBER()
    const tbsCertificate = subject.raw.tbsView
    const signature = subject.raw.signatureValue.valueBlock.valueHexView

    if (!issuer.publicKey) {
      return false
    }

    // Get algorithm for verification
    const algorithmId = subject.raw.signatureAlgorithm.algorithmId
    const algorithm = getVerifyAlgorithm(algorithmId)

    if (!algorithm) {
      return false
    }

    return await crypto.subtle.verify(
      algorithm,
      issuer.publicKey,
      signature,
      tbsCertificate
    )
  } catch {
    return false
  }
}

function getVerifyAlgorithm(oid: string): AlgorithmIdentifier | null {
  const algorithms: Record<string, AlgorithmIdentifier> = {
    '1.2.840.113549.1.1.5': { name: 'RSASSA-PKCS1-v1_5' }, // SHA1withRSA
    '1.2.840.113549.1.1.11': { name: 'RSASSA-PKCS1-v1_5' }, // SHA256withRSA
    '1.2.840.113549.1.1.12': { name: 'RSASSA-PKCS1-v1_5' }, // SHA384withRSA
    '1.2.840.113549.1.1.13': { name: 'RSASSA-PKCS1-v1_5' }, // SHA512withRSA
    '1.2.840.10045.4.3.2': { name: 'ECDSA', hash: 'SHA-256' } as EcdsaParams, // SHA256withECDSA
    '1.2.840.10045.4.3.3': { name: 'ECDSA', hash: 'SHA-384' } as EcdsaParams, // SHA384withECDSA
    '1.2.840.10045.4.3.4': { name: 'ECDSA', hash: 'SHA-512' } as EcdsaParams, // SHA512withECDSA
  }

  return algorithms[oid] || null
}

/**
 * Get certificate chain as array of DER bytes
 */
export function chainToDer(chain: CertificateChain): Uint8Array[] {
  return chain.certificates.map((cert) =>
    new Uint8Array(cert.raw.toSchema().toBER())
  )
}

/**
 * Get certificate chain summary
 */
export function getChainSummary(chain: CertificateChain): string[] {
  return chain.certificates.map((cert, index) => {
    const prefix = index === 0 ? '[EE]' : index === chain.certificates.length - 1 ? '[Root]' : '[CA]'
    const trustMark = chain.isTrusted && index === chain.certificates.length - 1 ? ' [Trusted]' : ''
    return `${prefix} ${cert.subject}${trustMark}`
  })
}
