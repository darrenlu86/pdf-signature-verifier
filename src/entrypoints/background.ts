import { t, setLocale, detectBrowserLocale } from '@/i18n'
import type { Locale } from '@/i18n'

/**
 * Service worker keep-alive (audit P3-10).
 *
 * MV3 reaps the service worker after ~30s of idle time, which can interrupt
 * a long verification (OCSP fetch waiting on a slow responder, large CRL
 * download, etc.). While a verification is in flight, we keep the worker
 * alive by registering a no-op alarm and tracking active job count.
 */
let activeJobs = 0
const KEEPALIVE_ALARM = 'pdf-verifier-keepalive'

async function startKeepAlive(): Promise<void> {
  activeJobs++
  if (activeJobs === 1) {
    try {
      await chrome.alarms.create(KEEPALIVE_ALARM, { periodInMinutes: 0.5 })
    } catch {
      // alarms permission missing — no-op
    }
  }
}

async function endKeepAlive(): Promise<void> {
  activeJobs = Math.max(0, activeJobs - 1)
  if (activeJobs === 0) {
    try {
      await chrome.alarms.clear(KEEPALIVE_ALARM)
    } catch {
      // ignore
    }
  }
}

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

  // Eagerly load the trust store on startup so the first verification doesn't
  // pay parsing cost. Warnings (empty store, fingerprint mismatch, etc.) go
  // to console.warn here so developers see them during dev mode reloads.
  void (async () => {
    const { initializeTrustStore, getTrustStoreWarnings } = await import('@/trust-store/trust-manager')
    await initializeTrustStore()
    const warnings = getTrustStoreWarnings()
    if (warnings.length > 0) {
      console.warn('[PDFtrust] Trust store warnings:')
      for (const w of warnings) console.warn('  -', w)
    }
  })()

  console.log('PDF Signature Verifier background script loaded')

  // No-op alarm listener — its existence keeps the SW awake.
  chrome.alarms.onAlarm.addListener(() => {})

  // Handle messages from popup, content scripts, and upload window
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
      return handlePdfVerification(
        message.data as number[],
        message.fileName as string,
        message.options as Record<string, unknown> | undefined
      )

    case 'open-panel-window':
      return handleOpenPanelWindow(message.result as unknown)

    case 'open-upload-window':
      return handleOpenUploadWindow()

    case 'open-popup':
      return handleOpenPopup()

    case 'get-trust-store-status':
      return handleGetTrustStoreStatus()

    default:
      return { error: `Unknown action: ${message.action}` }
  }
}

async function handlePdfUrlVerification(
  url: string,
  fileName: string
): Promise<{ result: unknown } | { error: string }> {
  await startKeepAlive()
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
  } finally {
    await endKeepAlive()
  }
}

async function handleOpenPanelWindow(
  result?: unknown
): Promise<{ ok: boolean }> {
  // Result may be passed via message (legacy) or pre-stored in chrome.storage.local
  if (result !== undefined && result !== null) {
    await chrome.storage.local.set({ 'pdf-panel-result': result })
  }
  await chrome.windows.create({
    url: chrome.runtime.getURL('/panel.html?source=popup'),
    type: 'popup',
    width: 440,
    height: 700,
  })
  return { ok: true }
}

async function handleOpenUploadWindow(): Promise<{ ok: boolean }> {
  await chrome.windows.create({
    url: chrome.runtime.getURL('/popup.html?source=tab'),
    type: 'popup',
    width: 460,
    height: 500,
  })
  return { ok: true }
}

async function handleOpenPopup(): Promise<{ ok: boolean }> {
  try {
    await chrome.action.openPopup()
  } catch {
    // Fallback: open popup as a window if openPopup() is not supported
    await chrome.windows.create({
      url: chrome.runtime.getURL('/popup.html?source=tab'),
      type: 'popup',
      width: 460,
      height: 500,
    })
  }
  return { ok: true }
}

async function handlePdfVerification(
  data: number[],
  fileName: string,
  options?: Record<string, unknown>
): Promise<{ result: unknown } | { error: string }> {
  await startKeepAlive()
  try {
    const { verifyPdfSignatures } = await import('@/core/verifier')
    const result = await verifyPdfSignatures(new Uint8Array(data), fileName, options)
    return { result }
  } catch (error) {
    return { error: error instanceof Error ? error.message : 'Verification failed' }
  } finally {
    await endKeepAlive()
  }
}

async function handleGetTrustStoreStatus(): Promise<{
  isEmpty: boolean
  isTsaEmpty: boolean
  warnings: string[]
  stats: unknown
}> {
  const {
    initializeTrustStore,
    isTrustStoreEmpty,
    isTsaTrustStoreEmpty,
    getTrustStoreWarnings,
    getTrustStoreStats,
  } = await import('@/trust-store/trust-manager')
  await initializeTrustStore()
  return {
    isEmpty: isTrustStoreEmpty(),
    isTsaEmpty: isTsaTrustStoreEmpty(),
    warnings: getTrustStoreWarnings(),
    stats: getTrustStoreStats(),
  }
}
