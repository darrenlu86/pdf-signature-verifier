import { useState } from 'react'
import type { VerificationResult } from '@/types'
import { t } from '@/i18n'
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

      // Resize iframe to fit full content
      const body = iframeDoc.body
      const scrollH = body.scrollHeight
      iframe.style.height = `${scrollH}px`

      // Wait for resize to take effect
      await new Promise((resolve) => setTimeout(resolve, 200))

      const { default: html2canvas } = await import('html2canvas')
      const { jsPDF } = await import('jspdf')

      // A4 dimensions in mm
      const pageWidth = 210
      const pageHeight = 297
      const margin = 10
      const contentWidth = pageWidth - margin * 2
      const contentHeight = pageHeight - margin * 2

      // Collect top-level sections for break-aware pagination
      const sections = Array.from(body.children) as HTMLElement[]

      // Calculate scale: how many mm per pixel
      const pxPerMm = 794 / pageWidth
      const pageContentPx = contentHeight * pxPerMm

      // Group sections into pages based on their positions
      const pages: { startPx: number; endPx: number }[] = []
      let currentPageStart = 0

      for (const section of sections) {
        const top = section.offsetTop
        const height = section.offsetHeight

        // If this section would overflow the current page
        if (top + height - currentPageStart > pageContentPx && top > currentPageStart) {
          // End current page just before this section
          pages.push({ startPx: currentPageStart, endPx: top })
          currentPageStart = top
        }
      }
      // Last page
      pages.push({ startPx: currentPageStart, endPx: scrollH })

      // Capture the full page as one canvas
      const fullCanvas = await html2canvas(body, {
        scale: 2,
        useCORS: true,
        logging: false,
        width: 794,
        height: scrollH,
        windowWidth: 794,
      })

      document.body.removeChild(iframe)

      const pdf = new jsPDF('p', 'mm', 'a4')
      const canvasWidthPx = fullCanvas.width
      const imgWidth = contentWidth

      for (let i = 0; i < pages.length; i++) {
        if (i > 0) {
          pdf.addPage()
        }

        const { startPx, endPx } = pages[i]
        const sliceHeightPx = endPx - startPx

        // Create a canvas for this page slice
        const pageCanvas = document.createElement('canvas')
        pageCanvas.width = canvasWidthPx
        pageCanvas.height = Math.round(sliceHeightPx * (canvasWidthPx / 794))

        const ctx = pageCanvas.getContext('2d')
        if (!ctx) continue

        // Draw the relevant portion of the full canvas
        const srcY = Math.round(startPx * (fullCanvas.height / scrollH))
        const srcH = Math.round(sliceHeightPx * (fullCanvas.height / scrollH))

        ctx.drawImage(
          fullCanvas,
          0, srcY, canvasWidthPx, srcH,
          0, 0, pageCanvas.width, pageCanvas.height,
        )

        const imgHeight = (pageCanvas.height * imgWidth) / pageCanvas.width
        pdf.addImage(
          pageCanvas.toDataURL('image/png'),
          'PNG',
          margin,
          margin,
          imgWidth,
          imgHeight,
        )
      }

      const pdfBlob = pdf.output('blob')
      const blobUrl = URL.createObjectURL(pdfBlob)

      const now = new Date()
      const dateStr = `${now.getFullYear()}${String(now.getMonth() + 1).padStart(2, '0')}${String(now.getDate()).padStart(2, '0')}`
      const fileName = `${t('export.reportFilename')}_${result.fileName.replace(/\.pdf$/i, '')}_${dateStr}.pdf`

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
      title={t('export.title')}
    >
      {exporting ? t('export.exporting') : t('export.button')}
    </button>
  )
}
