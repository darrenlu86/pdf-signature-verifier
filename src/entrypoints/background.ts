export default defineBackground(() => {
  console.log('PDF Signature Verifier background script loaded')

  // Handle messages from popup and content scripts
  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    handleMessage(message, sender).then(sendResponse)
    return true // Keep channel open for async response
  })
})

async function handleMessage(
  message: { action: string; [key: string]: unknown },
  sender: chrome.runtime.MessageSender
): Promise<unknown> {
  switch (message.action) {
    case 'ocsp-request':
      return handleOcspRequest(message.url as string, message.data as number[])

    case 'fetch-crl':
      return handleCrlFetch(message.url as string)

    case 'fetch-certificate':
      return handleCertificateFetch(message.url as string)

    case 'fetch-pdf-url':
      return handleFetchPdfUrl(message.url as string)

    case 'verify-pdf':
      return handlePdfVerification(message.data as number[], message.fileName as string)

    default:
      return { error: `Unknown action: ${message.action}` }
  }
}

async function handleOcspRequest(
  url: string,
  data: number[]
): Promise<{ data: number[] } | { error: string }> {
  try {
    const response = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/ocsp-request',
      },
      body: new Uint8Array(data),
    })

    if (!response.ok) {
      return { error: `OCSP request failed: ${response.status}` }
    }

    const buffer = await response.arrayBuffer()
    return { data: Array.from(new Uint8Array(buffer)) }
  } catch (error) {
    return { error: error instanceof Error ? error.message : 'OCSP request failed' }
  }
}

async function handleCrlFetch(url: string): Promise<{ data: number[] } | { error: string }> {
  try {
    const response = await fetch(url)

    if (!response.ok) {
      return { error: `CRL fetch failed: ${response.status}` }
    }

    const buffer = await response.arrayBuffer()
    return { data: Array.from(new Uint8Array(buffer)) }
  } catch (error) {
    return { error: error instanceof Error ? error.message : 'CRL fetch failed' }
  }
}

async function handleCertificateFetch(url: string): Promise<{ data: number[] } | { error: string }> {
  try {
    const response = await fetch(url)

    if (!response.ok) {
      return { error: `Certificate fetch failed: ${response.status}` }
    }

    const buffer = await response.arrayBuffer()
    return { data: Array.from(new Uint8Array(buffer)) }
  } catch (error) {
    return { error: error instanceof Error ? error.message : 'Certificate fetch failed' }
  }
}

async function handleFetchPdfUrl(
  url: string
): Promise<{ data: number[] } | { error: string }> {
  try {
    const response = await fetch(url)
    if (!response.ok) {
      return { error: `PDF fetch failed: ${response.status}` }
    }
    const buffer = await response.arrayBuffer()
    return { data: Array.from(new Uint8Array(buffer)) }
  } catch (error) {
    return { error: error instanceof Error ? error.message : 'PDF fetch failed' }
  }
}

async function handlePdfVerification(
  data: number[],
  fileName: string
): Promise<{ result: unknown } | { error: string }> {
  try {
    // Import verifier dynamically to avoid loading everything upfront
    const { verifyPdfSignatures } = await import('@/core/verifier')
    const result = await verifyPdfSignatures(new Uint8Array(data), fileName)
    return { result }
  } catch (error) {
    return { error: error instanceof Error ? error.message : 'Verification failed' }
  }
}
