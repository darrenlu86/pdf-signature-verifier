import { useState } from 'react'
import { StatusBadge, SignatureList, DropZone, LoadingSpinner, ExportButton } from './components'
import { useVerification } from './hooks/useVerification'
import { useSettings } from './hooks/useSettings'
import { DocumentIcon, XIcon } from './components/icons'

export function App() {
  const { result, isLoading, error, verify, reset } = useVerification()
  const { settings, updateSettings } = useSettings()
  const [showSettings, setShowSettings] = useState(false)

  const handleFileSelect = async (file: File) => {
    await verify(file, {
      checkOnlineRevocation: true,
    })
  }

  return (
    <div className="w-[400px] min-h-[300px] bg-white">
      {/* Header */}
      <header className="flex items-center justify-between px-4 py-3 border-b border-gray-200">
        <h1 className="text-lg font-semibold text-gray-900">PDF 數位簽章驗證</h1>
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
            onClick={() => setShowSettings(!showSettings)}
            className="p-1.5 rounded-md hover:bg-gray-100 transition-colors"
            title="設定"
          >
            <svg className="w-5 h-5 text-gray-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z" />
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
            </svg>
          </button>
        </div>
      </header>

      {/* Settings Panel */}
      {showSettings && (
        <div className="px-4 py-3 border-b border-gray-200 bg-gray-50">
          <div className="space-y-3">
            <label className="flex items-center gap-2 cursor-pointer">
              <input
                type="checkbox"
                checked={settings.autoVerify}
                onChange={(e) => updateSettings({ autoVerify: e.target.checked })}
                className="rounded border-gray-300 text-blue-600 focus:ring-blue-500"
              />
              <span className="text-sm text-gray-700">自動驗證頁面中的 PDF</span>
            </label>
          </div>
        </div>
      )}

      {/* Main Content */}
      <main className="p-4">
        {isLoading ? (
          <LoadingSpinner />
        ) : error ? (
          <div className="text-center py-6">
            <div className="flex justify-center mb-2">
              <XIcon className="w-10 h-10 text-red-500" />
            </div>
            <div className="text-red-600 font-medium mb-1">驗證失敗</div>
            <div className="text-sm text-gray-500">{error}</div>
            <button
              onClick={reset}
              className="mt-4 px-4 py-2 bg-gray-100 text-gray-700 rounded-md hover:bg-gray-200 transition-colors text-sm"
            >
              重新選擇檔案
            </button>
          </div>
        ) : result ? (
          <div className="space-y-4">
            {/* File Info */}
            <div className="flex items-center gap-3">
              <DocumentIcon className="w-6 h-6 text-gray-500 flex-shrink-0" />
              <div className="flex-1 min-w-0">
                <div className="font-medium text-gray-900 truncate">{result.fileName}</div>
              </div>
            </div>

            {/* Status Summary */}
            <div className="p-4 rounded-lg bg-gray-50 border border-gray-200">
              <div className="flex items-center justify-between">
                <StatusBadge status={result.status} size="lg" />
                <div className="flex items-center gap-3">
                  <ExportButton result={result} />
                  <button
                    onClick={reset}
                    className="text-sm text-blue-600 hover:text-blue-700"
                  >
                    驗證其他檔案
                  </button>
                </div>
              </div>
              <div className="mt-2 text-sm text-gray-600">{result.summary}</div>
            </div>

            {/* Signature List */}
            <SignatureList signatures={result.signatures} />
          </div>
        ) : (
          <DropZone onFileSelect={handleFileSelect} />
        )}
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

export default App
