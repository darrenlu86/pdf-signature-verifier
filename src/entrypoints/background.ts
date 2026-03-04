import { t, setLocale, detectBrowserLocale } from '@/i18n'
import type { Locale } from '@/i18n'

export default defineBackground(() => {
  // Initialize locale
  const initLocale = async () => {
    try {
      const result = await chrome.storage.local.get('pdf-verifier-settings')
      const settings = result['pdf-verifier-settings']
      if (settings?.language) {
        setLocale(settings.language as Locale)
      } else {
        setLocale(detectBrowserLocale())
      }
    } catch {
      setLocale(detectBrowserLocale())
    }
  }
  initLocale()
  console.log('PDF Signature Verifier background script loaded')

  // Handle messages from popup and content scripts
  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    handleMessage(message, sender)
      .then(sendResponse)
      .catch((err) => {
        sendResponse({ error: err instanceof Error ? err.message : 'Unknown error' })
      })
    return true // Keep channel open for async response
  })
})

async function handleMessage(
  message: { action: string; [key: string]: unknown },
  _sender: chrome.runtime.MessageSender
): Promise<unknown> {
  switch (message.action) {
    case 'verify-pdf-url':
      return handlePdfUrlVerification(message.url as string, message.fileName as string)

    case 'verify-pdf':
      return handlePdfVerification(message.data as number[], message.fileName as string)

    default:
      return { error: `Unknown action: ${message.action}` }
  }
}

async function handlePdfUrlVerification(
  url: string,
  fileName: string
): Promise<{ result: unknown } | { error: string }> {
  try {
    const response = await fetch(url)
    if (!response.ok) {
      return { error: t('core.misc.pdfDownloadFailed', { status: String(response.status) }) }
    }
    const buffer = await response.arrayBuffer()
    const { verifyPdfSignatures } = await import('@/core/verifier')
    const result = await verifyPdfSignatures(new Uint8Array(buffer), fileName)
    return { result }
  } catch (error) {
    return { error: error instanceof Error ? error.message : 'Verification failed' }
  }
}

async function handlePdfVerification(
  data: number[],
  fileName: string
): Promise<{ result: unknown } | { error: string }> {
  try {
    const { verifyPdfSignatures } = await import('@/core/verifier')
    const result = await verifyPdfSignatures(new Uint8Array(data), fileName)
    return { result }
  } catch (error) {
    return { error: error instanceof Error ? error.message : 'Verification failed' }
  }
}
