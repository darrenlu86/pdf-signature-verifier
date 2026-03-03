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

  iframe.addEventListener('load', () => {
    // Wait for panel to signal it's ready, then send the result
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
  })

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

// ─── Button Creators ────────────────────────────────────────────

function createVerifyButton(link: HTMLAnchorElement): HTMLButtonElement {
  const button = document.createElement('button')
  button.textContent = '🔍 驗證簽章'
  button.style.cssText = `
    margin-left: 8px;
    padding: 2px 8px;
    font-size: 12px;
    background: #3b82f6;
    color: white;
    border: none;
    border-radius: 4px;
    cursor: pointer;
  `

  button.addEventListener('click', async (e) => {
    e.preventDefault()
    e.stopPropagation()

    button.textContent = '⏳ 驗證中...'
    button.disabled = true

    try {
      const response = await fetch(link.href)
      const buffer = await response.arrayBuffer()

      const result = await chrome.runtime.sendMessage({
        action: 'verify-pdf',
        data: Array.from(new Uint8Array(buffer)),
        fileName: getFileName(link.href),
      })

      if (result.error) {
        button.textContent = '❌ 驗證失敗'
        button.title = result.error
      } else {
        updateButtonWithResult(button, result.result)
        showPanel(result.result)
      }
    } catch (error) {
      button.textContent = '❌ 錯誤'
      button.title = error instanceof Error ? error.message : '未知錯誤'
    }

    button.disabled = false
  })

  return button
}

function createEmbedVerifyButton(embed: HTMLEmbedElement): HTMLButtonElement {
  const button = document.createElement('button')
  button.textContent = '🔍 驗證 PDF 簽章'
  button.style.cssText = `
    display: block;
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
      button.textContent = '❌ 無法取得 PDF'
      return
    }

    button.textContent = '⏳ 驗證中...'
    button.disabled = true

    try {
      const response = await fetch(src)
      const buffer = await response.arrayBuffer()

      const result = await chrome.runtime.sendMessage({
        action: 'verify-pdf',
        data: Array.from(new Uint8Array(buffer)),
        fileName: getFileName(src),
      })

      if (result.error) {
        button.textContent = '❌ 驗證失敗'
      } else {
        updateButtonWithResult(button, result.result)
        showPanel(result.result)
      }
    } catch (error) {
      button.textContent = '❌ 錯誤'
    }

    button.disabled = false
  })

  return button
}

function injectPdfViewerButton() {
  // Only inject once
  if (document.getElementById('pdf-verifier-floating-button')) {
    return
  }

  const button = document.createElement('button')
  button.id = 'pdf-verifier-floating-button'
  button.textContent = '🔍 驗證簽章'
  button.style.cssText = `
    position: fixed;
    top: 16px;
    right: 16px;
    z-index: 999999;
    padding: 8px 16px;
    font-size: 14px;
    background: #3b82f6;
    color: white;
    border: none;
    border-radius: 8px;
    cursor: pointer;
    box-shadow: 0 2px 8px rgba(0,0,0,0.2);
  `

  button.addEventListener('click', async () => {
    button.textContent = '⏳ 驗證中...'
    button.disabled = true

    try {
      const pdfUrl = window.location.href
      const fileName = getFileName(pdfUrl)

      // Try fetching PDF from content script first
      let pdfData: number[] | null = null
      try {
        const response = await fetch(pdfUrl)
        if (response.ok) {
          const buffer = await response.arrayBuffer()
          // Verify it's actually PDF data (starts with %PDF)
          const header = new Uint8Array(buffer.slice(0, 5))
          if (header[0] === 0x25 && header[1] === 0x50 && header[2] === 0x44 && header[3] === 0x46) {
            pdfData = Array.from(new Uint8Array(buffer))
          }
        }
      } catch {
        // Content script fetch failed (e.g. file:// URL), will try background
      }

      // If content script couldn't get PDF, ask background to fetch it
      if (!pdfData) {
        const fetchResult = await chrome.runtime.sendMessage({
          action: 'fetch-pdf-url',
          url: pdfUrl,
        })
        if (fetchResult?.data) {
          pdfData = fetchResult.data
        }
      }

      if (!pdfData) {
        button.textContent = '❌ 無法取得 PDF'
        button.title = '無法從此 URL 取得 PDF 資料'
        button.disabled = false
        return
      }

      const result = await chrome.runtime.sendMessage({
        action: 'verify-pdf',
        data: pdfData,
        fileName,
      })

      if (result.error) {
        button.textContent = '❌ 驗證失敗'
        button.title = result.error
      } else {
        updateButtonWithResult(button, result.result)
        showPanel(result.result)
      }
    } catch (error) {
      button.textContent = '❌ 錯誤'
      button.title = error instanceof Error ? error.message : '未知錯誤'
    }

    button.disabled = false
  })

  document.body.appendChild(button)
}

// ─── Result Display Helpers ─────────────────────────────────────

function updateButtonWithResult(
  button: HTMLButtonElement,
  result: {
    status: string
    summary: string
    signatures?: Array<{
      signerName: string
      certificateChain?: Array<{ subject: string; isRoot: boolean }>
    }>
  }
) {
  const status = result?.status
  if (status === 'trusted') {
    button.textContent = '✓ 文件可信'
    button.style.background = '#22c55e'
  } else if (status === 'failed') {
    button.textContent = '✗ 驗證失敗'
    button.style.background = '#ef4444'
  } else {
    button.textContent = '⚠ 來源未知'
    button.style.background = '#eab308'
  }

  button.title = buildTooltip(result)
}

function buildTooltip(result: {
  status: string
  summary: string
  signatures?: Array<{
    signerName: string
    certificateChain?: Array<{ subject: string; isRoot: boolean }>
  }>
}): string {
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

function getFileName(url: string): string {
  try {
    const pathname = new URL(url).pathname
    const encoded = pathname.split('/').pop() || 'document.pdf'
    return decodeURIComponent(encoded)
  } catch {
    return 'document.pdf'
  }
}
