import type { VerificationResult } from '@/types'
import { generateVerificationReport } from '@/core/report/html-report-generator'

interface ExportButtonProps {
  result: VerificationResult
}

export function ExportButton({ result }: ExportButtonProps) {
  const handleExport = () => {
    const html = generateVerificationReport(result)
    const blob = new Blob([html], { type: 'text/html;charset=utf-8' })
    const url = URL.createObjectURL(blob)

    const now = new Date()
    const dateStr = `${now.getFullYear()}${String(now.getMonth() + 1).padStart(2, '0')}${String(now.getDate()).padStart(2, '0')}`
    const fileName = `驗證報告_${result.fileName.replace(/\.pdf$/i, '')}_${dateStr}.html`

    const a = document.createElement('a')
    a.href = url
    a.download = fileName
    document.body.appendChild(a)
    a.click()
    document.body.removeChild(a)
    URL.revokeObjectURL(url)
  }

  return (
    <button
      onClick={handleExport}
      className="text-sm text-blue-600 hover:text-blue-700"
      title="匯出 HTML 驗證報告"
    >
      匯出報告
    </button>
  )
}
