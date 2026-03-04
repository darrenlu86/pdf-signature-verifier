import { useState, useEffect } from 'react'
import type { VerificationResult } from '@/types'
import { StatusBadge, SignatureList, ExportButton } from './components'
import { DocumentIcon } from './components/icons'

export function PanelApp() {
  const [result, setResult] = useState<VerificationResult | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    // Listen for verification results from the content script
    const handleMessage = (event: MessageEvent) => {
      if (event.data?.type === 'pdf-verification-result') {
        const raw = event.data.result as VerificationResult
        // Restore Date objects from serialized JSON
        const restored = restoreDates(raw)
        setResult(restored)
        setLoading(false)
      }
    }

    window.addEventListener('message', handleMessage)

    // Signal that the panel is ready to receive data
    window.parent.postMessage({ type: 'pdf-panel-ready' }, '*')

    // Timeout: stop loading spinner after 15s if no result received
    const timeout = setTimeout(() => {
      setLoading(false)
    }, 15_000)

    return () => {
      window.removeEventListener('message', handleMessage)
      clearTimeout(timeout)
    }
  }, [])

  const handleClose = () => {
    window.parent.postMessage({ type: 'pdf-panel-close' }, '*')
  }

  if (loading) {
    return (
      <div className="h-screen flex items-center justify-center">
        <div className="text-center">
          <div className="animate-spin w-8 h-8 border-2 border-blue-500 border-t-transparent rounded-full mx-auto mb-3" />
          <div className="text-sm text-gray-500">載入驗證結果...</div>
        </div>
      </div>
    )
  }

  if (!result) {
    return (
      <div className="h-screen flex items-center justify-center">
        <div className="text-center text-gray-500">
          <div className="flex justify-center mb-2">
            <DocumentIcon className="w-10 h-10 text-gray-400" />
          </div>
          <div>無驗證結果</div>
        </div>
      </div>
    )
  }

  return (
    <div className="min-h-screen bg-white">
      {/* Header */}
      <header className="sticky top-0 z-10 flex items-center justify-between px-4 py-3 border-b border-gray-200 bg-white">
        <h1 className="text-base font-semibold text-gray-900">簽章驗證結果</h1>
        <div className="flex items-center gap-2">
          <a
            href="mailto:bussiness@darrenlu.com"
            className="inline-flex items-center gap-1 px-2 py-1 text-xs text-gray-500 bg-gray-100 rounded-md hover:bg-gray-200 transition-colors"
            title="商業合作 / 購買授權"
          >
            <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 8l7.89 5.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
            </svg>
            bussiness@darrenlu.com
          </a>
          <button
            onClick={handleClose}
            className="p-1 rounded hover:bg-gray-100 transition-colors"
            title="關閉面板"
          >
            <svg className="w-5 h-5 text-gray-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>
      </header>

      {/* Content */}
      <main className="p-4 space-y-4">
        {/* File Info */}
        <div className="flex items-center gap-3">
          <DocumentIcon className="w-5 h-5 text-gray-500 flex-shrink-0" />
          <div className="flex-1 min-w-0">
            <div className="font-medium text-gray-900 truncate text-sm">{result.fileName}</div>
          </div>
        </div>

        {/* Status Summary */}
        <div className="p-3 rounded-lg bg-gray-50 border border-gray-200">
          <div className="flex items-center justify-between">
            <StatusBadge status={result.status} size="lg" />
            <ExportButton result={result} />
          </div>
          <div className="mt-2 text-sm text-gray-600">{result.summary}</div>
        </div>

        {/* Signature List */}
        <SignatureList signatures={result.signatures} />
      </main>

      {/* Footer */}
      <footer className="px-4 py-2 text-center text-xs text-gray-400 border-t border-gray-100 space-y-1">
        <div>CMS/PKCS#7 簽章驗證 · X.509 憑證鏈 · RFC 3161 時戳</div>
        <div>
          <a href="https://www.buymeacoffee.com/darrenlu" target="_blank" rel="noopener noreferrer">
            <img
              src="https://img.buymeacoffee.com/button-api/?text=Buy me a coffee&emoji=&slug=darrenlu&button_colour=FFDD00&font_colour=000000&font_family=Cookie&outline_colour=000000&coffee_colour=ffffff"
              alt="Buy me a coffee"
              className="inline-block h-7"
            />
          </a>
        </div>
      </footer>
    </div>
  )
}

/**
 * Restore Date objects from serialized JSON (chrome.storage serializes Dates as strings)
 */
function restoreDates(result: VerificationResult): VerificationResult {
  return {
    ...result,
    signatures: result.signatures.map((sig) => ({
      ...sig,
      signedAt: sig.signedAt ? new Date(sig.signedAt) : null,
      certificateChain: sig.certificateChain.map((cert) => ({
        ...cert,
        notBefore: new Date(cert.notBefore),
        notAfter: new Date(cert.notAfter),
      })),
      timestampInfo: sig.timestampInfo
        ? {
            ...sig.timestampInfo,
            time: new Date(sig.timestampInfo.time),
          }
        : undefined,
    })),
  }
}
