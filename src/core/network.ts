/**
 * Shared network helper.
 *
 * In MV3, the background service worker can fetch() cross-origin without
 * host_permissions. OCSP/CRL requests are made from the background context.
 */

async function directFetchBytes(url: string, init?: RequestInit): Promise<Uint8Array | null> {
  try {
    const response = await fetch(url, init)
    if (!response.ok) return null
    const buffer = await response.arrayBuffer()
    return new Uint8Array(buffer)
  } catch {
    return null
  }
}

/**
 * Fetch arbitrary binary data (CRL, certificate, etc.)
 */
export async function fetchBinary(url: string): Promise<Uint8Array | null> {
  return directFetchBytes(url)
}

/**
 * Fetch a certificate by URL.
 */
export async function fetchCertificateBytes(url: string): Promise<Uint8Array | null> {
  return directFetchBytes(url)
}

/**
 * Send an OCSP request and return the raw response bytes.
 */
export async function fetchOcspResponse(
  url: string,
  requestBytes: Uint8Array
): Promise<Uint8Array | null> {
  return directFetchBytes(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/ocsp-request' },
    body: requestBytes as unknown as BodyInit,
  })
}
