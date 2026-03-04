/**
 * Shared network helper.
 *
 * The extension declares host_permissions: ['<all_urls>'], so direct fetch()
 * works from every context (background service worker, popup, content script).
 * No chrome.runtime.sendMessage relay needed.
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
