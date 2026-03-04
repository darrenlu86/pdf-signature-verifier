import { useState } from 'react'
import type { VerificationResult } from '@/types'
import { generateVerificationReport } from '@/core/report/html-report-generator'

interface ExportButtonProps {
  result: VerificationResult
}

export function ExportButton({ result }: ExportButtonProps) {
  const [exporting, setExporting] = useState(false)

  const handleExport = async () => {
    if (exporting) return
    setExporting(true)

    try {
      const html = generateVerificationReport(result)

      // Render HTML in a hidden iframe to capture as PDF
      const iframe = document.createElement('iframe')
      iframe.style.position = 'fixed'
      iframe.style.left = '-9999px'
      iframe.style.top = '-9999px'
      iframe.style.width = '794px' // A4 width at 96dpi
      iframe.style.height = '1123px'
      document.body.appendChild(iframe)

      const iframeDoc = iframe.contentDocument || iframe.contentWindow?.document
      if (!iframeDoc) {
        throw new Error('Cannot access iframe document')
      }
      iframeDoc.open()
      iframeDoc.write(html)
      iframeDoc.close()

      // Wait for content to render
      await new Promise((resolve) => setTimeout(resolve, 500))

      const { default: html2canvas } = await import('html2canvas')
      const { jsPDF } = await import('jspdf')

      const body = iframeDoc.body
      const canvas = await html2canvas(body, {
        scale: 2,
        useCORS: true,
        logging: false,
        width: 794,
        windowWidth: 794,
      })

      document.body.removeChild(iframe)

      // A4 dimensions in mm
      const pageWidth = 210
      const pageHeight = 297
      const margin = 10
      const contentWidth = pageWidth - margin * 2
      const contentHeight = pageHeight - margin * 2

      const imgWidth = contentWidth
      const imgHeight = (canvas.height * imgWidth) / canvas.width

      const pdf = new jsPDF('p', 'mm', 'a4')
      let heightLeft = imgHeight
      let position = margin

      pdf.addImage(
        canvas.toDataURL('image/png'),
        'PNG',
        margin,
        position,
        imgWidth,
        imgHeight,
      )
      heightLeft -= contentHeight

      while (heightLeft > 0) {
        position = margin - (imgHeight - heightLeft)
        pdf.addPage()
        pdf.addImage(
          canvas.toDataURL('image/png'),
          'PNG',
          margin,
          position,
          imgWidth,
          imgHeight,
        )
        heightLeft -= contentHeight
      }

      const pdfBlob = pdf.output('blob')
      const blobUrl = URL.createObjectURL(pdfBlob)

      const now = new Date()
      const dateStr = `${now.getFullYear()}${String(now.getMonth() + 1).padStart(2, '0')}${String(now.getDate()).padStart(2, '0')}`
      const fileName = `驗證報告_${result.fileName.replace(/\.pdf$/i, '')}_${dateStr}.pdf`

      // Use chrome.downloads API for save dialog
      if (typeof chrome !== 'undefined' && chrome.downloads) {
        chrome.downloads.download(
          { url: blobUrl, filename: fileName, saveAs: true },
          () => URL.revokeObjectURL(blobUrl),
        )
      } else {
        // Fallback for non-extension context
        const a = document.createElement('a')
        a.href = blobUrl
        a.download = fileName
        document.body.appendChild(a)
        a.click()
        document.body.removeChild(a)
        URL.revokeObjectURL(blobUrl)
      }
    } catch (error) {
      console.error('PDF export failed:', error)
    } finally {
      setExporting(false)
    }
  }

  return (
    <button
      onClick={handleExport}
      disabled={exporting}
      className="text-sm text-blue-600 hover:text-blue-700 disabled:text-gray-400 disabled:cursor-not-allowed"
      title="匯出驗證報告 PDF"
    >
      {exporting ? '匯出中...' : '匯出報告'}
    </button>
  )
}
