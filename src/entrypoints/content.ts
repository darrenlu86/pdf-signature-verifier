export default defineContentScript({
  matches: ['<all_urls>'],
  runAt: 'document_idle',

  main() {
    // Detect PDF files in the page
    detectPdfLinks()
    detectEmbeddedPdfs()

    // Watch for dynamically added content
    const observer = new MutationObserver((mutations) => {
      for (const mutation of mutations) {
        if (mutation.addedNodes.length > 0) {
          detectPdfLinks()
          detectEmbeddedPdfs()
        }
      }
    })

    observer.observe(document.body, {
      childList: true,
      subtree: true,
    })

    // Listen for panel messages
    window.addEventListener('message', (event) => {
      if (event.data?.type === 'pdf-panel-close') {
        closePanel()
      }
    })
  },
})

// ─── Panel Management ───────────────────────────────────────────

let panelContainer: HTMLDivElement | null = null
let pendingResult: unknown = null

function showPanel(result: unknown) {
  // Close existing panel if open
  closePanel()

  pendingResult = result

  // Create overlay container
  panelContainer = document.createElement('div')
  panelContainer.id = 'pdf-verifier-panel-overlay'
  panelContainer.style.cssText = `
    position: fixed;
    top: 0;
    right: 0;
    width: 420px;
    height: 100vh;
    z-index: 2147483647;
    box-shadow: -4px 0 24px rgba(0,0,0,0.15);
    background: white;
    display: flex;
    flex-direction: column;
    transition: transform 0.25s ease;
    transform: translateX(100%);
  `

  // Create iframe pointing to our panel page
  const iframe = document.createElement('iframe')
  iframe.src = chrome.runtime.getURL('/panel.html')
  iframe.style.cssText = `
    width: 100%;
    height: 100%;
    border: none;
  `

  // Listen for panel ready signal BEFORE iframe loads to avoid race condition
  const handlePanelReady = (event: MessageEvent) => {
    if (event.data?.type === 'pdf-panel-ready') {
      iframe.contentWindow?.postMessage(
        { type: 'pdf-verification-result', result: pendingResult },
        '*'
      )
      window.removeEventListener('message', handlePanelReady)
    }
  }
  window.addEventListener('message', handlePanelReady)

  panelContainer.appendChild(iframe)
  document.body.appendChild(panelContainer)

  // Slide in animation
  requestAnimationFrame(() => {
    requestAnimationFrame(() => {
      if (panelContainer) {
        panelContainer.style.transform = 'translateX(0)'
      }
    })
  })

  // Close on Escape key
  const handleEscape = (e: KeyboardEvent) => {
    if (e.key === 'Escape') {
      closePanel()
      document.removeEventListener('keydown', handleEscape)
    }
  }
  document.addEventListener('keydown', handleEscape)
}

function closePanel() {
  if (panelContainer) {
    panelContainer.style.transform = 'translateX(100%)'
    const container = panelContainer
    setTimeout(() => {
      container.remove()
    }, 250)
    panelContainer = null
  }
  pendingResult = null
}

// ─── PDF Detection ──────────────────────────────────────────────

function detectPdfLinks() {
  const links = document.querySelectorAll('a[href$=".pdf"], a[href*=".pdf?"]')

  links.forEach((link) => {
    if (link.hasAttribute('data-pdf-verifier')) {
      return
    }

    link.setAttribute('data-pdf-verifier', 'detected')

    // Add verification button next to PDF links
    const button = createVerifyButton(link as HTMLAnchorElement)
    link.parentNode?.insertBefore(button, link.nextSibling)
  })
}

function detectEmbeddedPdfs() {
  // Check for PDF viewer (Chrome's built-in PDF viewer)
  if (
    document.contentType === 'application/pdf' ||
    window.location.href.endsWith('.pdf')
  ) {
    injectPdfViewerButton()
  }

  // Check for embed/object elements
  const embeds = document.querySelectorAll(
    'embed[type="application/pdf"], object[type="application/pdf"]'
  )

  embeds.forEach((embed) => {
    if (embed.hasAttribute('data-pdf-verifier')) {
      return
    }

    embed.setAttribute('data-pdf-verifier', 'detected')

    const button = createEmbedVerifyButton(embed as HTMLEmbedElement)
    embed.parentNode?.insertBefore(button, embed)
  })
}

// ─── Message Helpers ─────────────────────────────────────────────

const VERIFY_TIMEOUT_MS = 30_000

function sendMessageWithTimeout<T>(
  message: Record<string, unknown>,
  timeoutMs: number = VERIFY_TIMEOUT_MS
): Promise<T> {
  return new Promise((resolve, reject) => {
    // Check if extension context is still valid
    if (!chrome.runtime?.id) {
      reject(new Error('擴充功能已更新，請重新整理頁面'))
      return
    }

    const timer = setTimeout(() => {
      reject(new Error('驗證逾時，請稍後再試'))
    }, timeoutMs)

    try {
      chrome.runtime.sendMessage(message, (response: T) => {
        clearTimeout(timer)
        // Always read lastError to suppress console warning
        const err = chrome.runtime.lastError
        if (err) {
          reject(new Error(err.message))
          return
        }
        resolve(response)
      })
    } catch {
      clearTimeout(timer)
      reject(new Error('擴充功能連線失敗，請重新整理頁面'))
    }
  })
}

// ─── Button Creators ────────────────────────────────────────────

function createVerifyButton(link: HTMLAnchorElement): HTMLButtonElement {
  const button = document.createElement('button')
  button.innerHTML = `${svgSearch()} 驗證簽章`
  button.style.cssText = `
    margin-left: 8px;
    padding: 2px 8px;
    font-size: 12px;
    background: #3b82f6;
    color: white;
    border: none;
    border-radius: 4px;
    cursor: pointer;
    display: inline-flex;
    align-items: center;
    gap: 4px;
  `

  button.addEventListener('click', async (e) => {
    e.preventDefault()
    e.stopPropagation()

    button.innerHTML = `${svgLoading()} 驗證中...`
    button.disabled = true

    try {
      const result = await sendMessageWithTimeout<{ result?: unknown; error?: string }>({
        action: 'verify-pdf-url',
        url: link.href,
        fileName: getFileName(link.href),
      })

      if (!result || result.error) {
        button.innerHTML = `${svgX()} 驗證失敗`
        button.title = result?.error || '無回應'
      } else {
        updateButtonWithResult(button, result.result as VerifyResult)
        showPanel(result.result)
      }
    } catch (error) {
      button.innerHTML = `${svgX()} 錯誤`
      button.title = error instanceof Error ? error.message : '未知錯誤'
    }

    button.disabled = false
  })

  return button
}

function createEmbedVerifyButton(embed: HTMLEmbedElement): HTMLButtonElement {
  const button = document.createElement('button')
  button.innerHTML = `${svgSearch()} 驗證 PDF 簽章`
  button.style.cssText = `
    display: inline-flex;
    align-items: center;
    gap: 4px;
    margin: 8px 0;
    padding: 4px 12px;
    font-size: 14px;
    background: #3b82f6;
    color: white;
    border: none;
    border-radius: 4px;
    cursor: pointer;
  `

  button.addEventListener('click', async () => {
    const src = embed.src || embed.getAttribute('data')
    if (!src) {
      button.innerHTML = `${svgX()} 無法取得 PDF`
      return
    }

    button.innerHTML = `${svgLoading()} 驗證中...`
    button.disabled = true

    try {
      const result = await sendMessageWithTimeout<{ result?: unknown; error?: string }>({
        action: 'verify-pdf-url',
        url: src,
        fileName: getFileName(src),
      })

      if (!result || result.error) {
        button.innerHTML = `${svgX()} 驗證失敗`
      } else {
        updateButtonWithResult(button, result.result as VerifyResult)
        showPanel(result.result)
      }
    } catch {
      button.innerHTML = `${svgX()} 錯誤`
    }

    button.disabled = false
  })

  return button
}

function getPdfViewerToolbarHeight(): number {
  // Chrome's PDF viewer embed element sits below the toolbar;
  // its top offset reveals the actual toolbar height.
  const embed = document.querySelector('embed[type="application/pdf"]')
  if (embed) {
    const top = embed.getBoundingClientRect().top
    if (top > 0) return top
  }

  // Firefox / other viewers: look for common toolbar containers
  for (const sel of ['#toolbarContainer', '#toolbarViewer', '[role="toolbar"]']) {
    const el = document.querySelector(sel)
    if (el) {
      const h = el.getBoundingClientRect().height
      if (h > 0) return h
    }
  }

  // Fallback: typical Chrome PDF viewer toolbar height
  return 44
}

function injectPdfViewerButton() {
  // Only inject once
  if (document.getElementById('pdf-verifier-floating-button')) {
    return
  }

  const BUTTON_HEIGHT = 36
  const toolbarHeight = getPdfViewerToolbarHeight()
  const topOffset = Math.max(0, Math.round((toolbarHeight - BUTTON_HEIGHT) / 2))

  const button = document.createElement('button')
  button.id = 'pdf-verifier-floating-button'
  button.innerHTML = `${svgSearch()} 驗證簽章`
  button.style.cssText = `
    position: fixed;
    top: ${topOffset}px;
    right: 16px;
    z-index: 999999;
    padding: 8px 16px;
    font-size: 14px;
    line-height: 20px;
    background: #3b82f6;
    color: white;
    border: none;
    border-radius: 8px;
    cursor: pointer;
    box-shadow: 0 2px 8px rgba(0,0,0,0.2);
    display: inline-flex;
    align-items: center;
    gap: 4px;
    height: ${BUTTON_HEIGHT}px;
  `

  button.addEventListener('click', async () => {
    button.innerHTML = `${svgLoading()} 驗證中...`
    button.disabled = true

    try {
      const pdfUrl = window.location.href
      const fileName = getFileName(pdfUrl)

      const result = await sendMessageWithTimeout<{ result?: unknown; error?: string }>({
        action: 'verify-pdf-url',
        url: pdfUrl,
        fileName,
      })

      if (!result || result.error) {
        button.innerHTML = `${svgX()} 驗證失敗`
        button.title = result?.error || '無回應'
      } else {
        updateButtonWithResult(button, result.result as VerifyResult)
        showPanel(result.result)
      }
    } catch (error) {
      button.innerHTML = `${svgX()} 錯誤`
      button.title = error instanceof Error ? error.message : '未知錯誤'
    }

    button.disabled = false
  })

  document.body.appendChild(button)
}

// ─── Result Display Helpers ─────────────────────────────────────

interface VerifyResult {
  status: string
  summary: string
  signatures?: Array<{
    signerName: string
    certificateChain?: Array<{ subject: string; isRoot: boolean }>
  }>
}

function updateButtonWithResult(
  button: HTMLButtonElement,
  result: VerifyResult
) {
  const status = result?.status
  if (status === 'trusted') {
    button.innerHTML = `${svgCheck()} 文件可信`
    button.style.background = '#22c55e'
  } else if (status === 'failed') {
    button.innerHTML = `${svgX()} 驗證失敗`
    button.style.background = '#ef4444'
  } else {
    button.innerHTML = `${svgWarning()} 來源未知`
    button.style.background = '#eab308'
  }

  button.title = buildTooltip(result)
}

function buildTooltip(result: VerifyResult): string {
  const signatures = result?.signatures
  if (!signatures || signatures.length === 0) {
    return result?.summary || ''
  }

  const parts: string[] = []

  const signerNames = signatures.map((s) => s.signerName).filter(Boolean)
  if (signerNames.length > 0) {
    parts.push(`簽署者：${signerNames.join(', ')}`)
  }

  const rootCAs = new Set<string>()
  for (const sig of signatures) {
    const rootCert = sig.certificateChain?.find((c) => c.isRoot)
    if (rootCert) {
      const cn = rootCert.subject.match(/CN=([^,]+)/)?.[1]
      if (cn) rootCAs.add(cn)
    }
  }
  if (rootCAs.size > 0) {
    parts.push(`根 CA：${[...rootCAs].join(', ')}`)
  }

  const statusText =
    result.status === 'trusted'
      ? '全部有效'
      : result.status === 'failed'
        ? '驗證失敗'
        : '來源未知'
  parts.push(`${signatures.length} 個簽章${statusText}`)

  return parts.join(' | ')
}

// ─── Inline SVG Helpers (content script, no React) ──────────────

function svgCheck(): string {
  return '<svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:middle;flex-shrink:0;"><path d="M3 8.5l3.5 3.5L13 4"/></svg>'
}

function svgX(): string {
  return '<svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:middle;flex-shrink:0;"><path d="M4 4l8 8M12 4l-8 8"/></svg>'
}

function svgWarning(): string {
  return '<svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:middle;flex-shrink:0;"><path d="M8 1.5L1 14h14L8 1.5z"/><path d="M8 6v3.5"/><circle cx="8" cy="12" r="0.5" fill="currentColor" stroke="none"/></svg>'
}

function svgSearch(): string {
  return '<svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:middle;flex-shrink:0;"><circle cx="7" cy="7" r="4.5"/><path d="M10.5 10.5L14 14"/></svg>'
}

function svgLoading(): string {
  return '<svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" style="vertical-align:middle;flex-shrink:0;animation:pdf-verifier-spin 1s linear infinite;"><style>@keyframes pdf-verifier-spin{to{transform:rotate(360deg)}}</style><path d="M8 1.5a6.5 6.5 0 11-6.5 6.5" stroke-linecap="round"/></svg>'
}

function getFileName(url: string): string {
  try {
    const pathname = new URL(url).pathname
    const encoded = pathname.split('/').pop() || 'document.pdf'
    return decodeURIComponent(encoded)
  } catch {
    return 'document.pdf'
  }
}
