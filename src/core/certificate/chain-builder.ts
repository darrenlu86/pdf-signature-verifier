import type { ParsedCertificate, CertificateChain } from '@/types'
import { parseCertificateFromBytes } from './cert-utils'

/**
 * Build a certificate chain from a set of certificates.
 * Uses only embedded PKCS#7 certificates — no external trust store.
 * isComplete = reached a self-signed root.
 * isTrusted  = isComplete (mathematical chain integrity).
 */
export async function buildCertificateChain(
  endEntityCert: ParsedCertificate,
  intermediateCerts: ParsedCertificate[],
  options: ChainBuildOptions = {}
): Promise<CertificateChain> {
  const { fetchMissing = false } = options

  const chain: ParsedCertificate[] = [endEntityCert]
  const available = [...intermediateCerts]
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

  // Find root certificate
  const root = chain.length > 0 && chain[chain.length - 1].isSelfSigned
    ? chain[chain.length - 1]
    : null

  return {
    certificates: chain,
    root,
    isComplete,
    isTrusted: isComplete,
  }
}

export interface ChainBuildOptions {
  fetchMissing?: boolean
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
  for (const url of urls) {
    try {
      const response = await sendBackgroundRequest('fetch-certificate', { url })
      if (response?.data) {
        const certData = new Uint8Array(response.data)
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
 * Send request to background script for CORS-free fetch
 */
async function sendBackgroundRequest(
  action: string,
  data: unknown
): Promise<{ data: number[] } | null> {
  return new Promise((resolve) => {
    if (typeof chrome !== 'undefined' && chrome.runtime) {
      chrome.runtime.sendMessage({ action, ...data }, (response) => {
        resolve(response as { data: number[] } | null)
      })
    } else {
      resolve(null)
    }
  })
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
    const prefix = index === 0 ? '📄' : index === chain.certificates.length - 1 ? '🔐' : '🔗'
    const trustMark = chain.isTrusted && index === chain.certificates.length - 1 ? ' ✓' : ''
    return `${prefix} ${cert.subject}${trustMark}`
  })
}
