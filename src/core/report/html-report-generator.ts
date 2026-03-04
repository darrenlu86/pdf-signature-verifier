import type { VerificationResult, SignatureResult, CertificateInfo } from '@/types'

function formatDate(date: Date | null | undefined): string {
  if (!date) return '-'
  try {
    return new Date(date).toLocaleString('zh-TW', {
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
      hour12: false,
    })
  } catch {
    return String(date)
  }
}

function escapeHtml(str: string): string {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
}

function statusColor(status: string): string {
  switch (status) {
    case 'trusted':
      return '#16a34a'
    case 'failed':
      return '#dc2626'
    default:
      return '#d97706'
  }
}

function statusLabel(status: string): string {
  switch (status) {
    case 'trusted':
      return 'TRUSTED'
    case 'failed':
      return 'FAILED'
    default:
      return 'UNKNOWN'
  }
}

function statusLabelZh(status: string): string {
  switch (status) {
    case 'trusted':
      return '可信任'
    case 'failed':
      return '驗證失敗'
    default:
      return '未知'
  }
}

function checkIcon(passed: boolean): string {
  return passed ? '<span style="color:#16a34a;">&#10003;</span>' : '<span style="color:#dc2626;">&#10007;</span>'
}

function renderCheckRow(label: string, check: { passed: boolean; message: string; details?: string } | null): string {
  if (!check) return ''
  return `
    <tr>
      <td style="padding:6px 12px;border:1px solid #e5e7eb;">${checkIcon(check.passed)}</td>
      <td style="padding:6px 12px;border:1px solid #e5e7eb;">${escapeHtml(label)}</td>
      <td style="padding:6px 12px;border:1px solid #e5e7eb;">${escapeHtml(check.message)}${check.details ? `<br><span style="color:#6b7280;font-size:0.85em;">${escapeHtml(check.details)}</span>` : ''}</td>
    </tr>`
}

function renderCertTable(certs: CertificateInfo[]): string {
  if (certs.length === 0) return '<p style="color:#6b7280;">無憑證鏈資訊</p>'

  const rows = certs
    .map(
      (cert) => `
    <tr>
      <td style="padding:6px 12px;border:1px solid #e5e7eb;">${escapeHtml(cert.subject)}</td>
      <td style="padding:6px 12px;border:1px solid #e5e7eb;">${escapeHtml(cert.issuer)}</td>
      <td style="padding:6px 12px;border:1px solid #e5e7eb;white-space:nowrap;">${formatDate(cert.notBefore)}</td>
      <td style="padding:6px 12px;border:1px solid #e5e7eb;white-space:nowrap;">${formatDate(cert.notAfter)}</td>
      <td style="padding:6px 12px;border:1px solid #e5e7eb;text-align:center;">${cert.isRoot ? 'Root' : ''} ${cert.isTrusted ? checkIcon(true) : checkIcon(false)}</td>
    </tr>`
    )
    .join('')

  return `
    <table style="width:100%;border-collapse:collapse;font-size:0.85em;margin-top:8px;">
      <thead>
        <tr style="background:#f3f4f6;">
          <th style="padding:6px 12px;border:1px solid #e5e7eb;text-align:left;">主體</th>
          <th style="padding:6px 12px;border:1px solid #e5e7eb;text-align:left;">簽發者</th>
          <th style="padding:6px 12px;border:1px solid #e5e7eb;text-align:left;">生效日</th>
          <th style="padding:6px 12px;border:1px solid #e5e7eb;text-align:left;">到期日</th>
          <th style="padding:6px 12px;border:1px solid #e5e7eb;text-align:center;">信任</th>
        </tr>
      </thead>
      <tbody>${rows}</tbody>
    </table>`
}

function renderSignature(sig: SignatureResult, index: number): string {
  const checks = sig.checks

  return `
    <div style="margin-bottom:24px;page-break-inside:avoid;">
      <h3 style="font-size:1.1em;margin:0 0 12px 0;padding-bottom:8px;border-bottom:2px solid ${statusColor(sig.status)};">
        簽章 #${index + 1}
        <span style="float:right;color:${statusColor(sig.status)};font-weight:600;">${statusLabelZh(sig.status)}</span>
      </h3>

      <table style="width:100%;border-collapse:collapse;margin-bottom:12px;">
        <tr>
          <td style="padding:4px 0;color:#6b7280;width:100px;">簽署者</td>
          <td style="padding:4px 0;font-weight:500;">${escapeHtml(sig.signerName)}</td>
        </tr>
        <tr>
          <td style="padding:4px 0;color:#6b7280;">簽署時間</td>
          <td style="padding:4px 0;">${formatDate(sig.signedAt)}</td>
        </tr>
        ${sig.reason ? `<tr><td style="padding:4px 0;color:#6b7280;">簽署原因</td><td style="padding:4px 0;">${escapeHtml(sig.reason)}</td></tr>` : ''}
        ${sig.location ? `<tr><td style="padding:4px 0;color:#6b7280;">簽署地點</td><td style="padding:4px 0;">${escapeHtml(sig.location)}</td></tr>` : ''}
      </table>

      <h4 style="font-size:0.95em;margin:16px 0 8px 0;">驗證結果</h4>
      <table style="width:100%;border-collapse:collapse;font-size:0.9em;">
        <thead>
          <tr style="background:#f3f4f6;">
            <th style="padding:6px 12px;border:1px solid #e5e7eb;width:30px;"></th>
            <th style="padding:6px 12px;border:1px solid #e5e7eb;text-align:left;width:120px;">項目</th>
            <th style="padding:6px 12px;border:1px solid #e5e7eb;text-align:left;">說明</th>
          </tr>
        </thead>
        <tbody>
          ${renderCheckRow('完整性', checks.integrity)}
          ${renderCheckRow('憑證鏈', checks.certificateChain)}
          ${renderCheckRow('信任根', checks.trustRoot)}
          ${renderCheckRow('有效期', checks.validity)}
          ${renderCheckRow('撤銷狀態', checks.revocation)}
          ${renderCheckRow('時間戳記', checks.timestamp)}
          ${renderCheckRow('長期驗證', checks.ltv)}
        </tbody>
      </table>

      <h4 style="font-size:0.95em;margin:16px 0 8px 0;">憑證鏈</h4>
      ${renderCertTable(sig.certificateChain)}

      ${
        sig.timestampInfo
          ? `
        <h4 style="font-size:0.95em;margin:16px 0 8px 0;">時間戳記資訊</h4>
        <table style="width:100%;border-collapse:collapse;font-size:0.9em;">
          <tr>
            <td style="padding:4px 0;color:#6b7280;width:120px;">時間戳記時間</td>
            <td style="padding:4px 0;">${formatDate(sig.timestampInfo.time)}</td>
          </tr>
          <tr>
            <td style="padding:4px 0;color:#6b7280;">簽發者</td>
            <td style="padding:4px 0;">${escapeHtml(sig.timestampInfo.issuer)}</td>
          </tr>
          <tr>
            <td style="padding:4px 0;color:#6b7280;">雜湊演算法</td>
            <td style="padding:4px 0;">${escapeHtml(sig.timestampInfo.hashAlgorithm)}</td>
          </tr>
          <tr>
            <td style="padding:4px 0;color:#6b7280;">驗證狀態</td>
            <td style="padding:4px 0;">${sig.timestampInfo.isValid ? checkIcon(true) + ' 有效' : checkIcon(false) + ' 無效'}</td>
          </tr>
        </table>`
          : ''
      }
    </div>`
}

export function generateVerificationReport(result: VerificationResult): string {
  const now = formatDate(new Date())
  const color = statusColor(result.status)

  const signaturesHtml = result.signatures.map((sig, i) => renderSignature(sig, i)).join('')

  return `<!DOCTYPE html>
<html lang="zh-TW">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>PDF 數位簽章驗證報告 - ${escapeHtml(result.fileName)}</title>
  <style>
    @media print {
      body { margin: 0; padding: 20px; }
      .no-print { display: none !important; }
      @page { size: A4; margin: 15mm; }
    }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", "Microsoft JhengHei", "PingFang TC", sans-serif;
      color: #1f2937;
      line-height: 1.6;
      max-width: 800px;
      margin: 0 auto;
      padding: 40px 24px;
      background: #fff;
    }
    h1 { font-size: 1.5em; margin: 0; }
    h2 { font-size: 1.2em; margin: 32px 0 16px 0; padding-bottom: 8px; border-bottom: 1px solid #e5e7eb; }
  </style>
</head>
<body>
  <div style="text-align:center;margin-bottom:32px;">
    <h1>PDF 數位簽章驗證報告</h1>
    <p style="color:#6b7280;margin:8px 0 0 0;font-size:0.9em;">PDF Digital Signature Verification Report</p>
  </div>

  <div style="background:#f9fafb;border:1px solid #e5e7eb;border-radius:8px;padding:16px 20px;margin-bottom:24px;">
    <table style="width:100%;border-collapse:collapse;">
      <tr>
        <td style="padding:4px 0;color:#6b7280;width:100px;">檔案名稱</td>
        <td style="padding:4px 0;font-weight:500;">${escapeHtml(result.fileName)}</td>
      </tr>
      <tr>
        <td style="padding:4px 0;color:#6b7280;">驗證時間</td>
        <td style="padding:4px 0;">${now}</td>
      </tr>
      <tr>
        <td style="padding:4px 0;color:#6b7280;">總體狀態</td>
        <td style="padding:4px 0;">
          <span style="display:inline-block;padding:2px 12px;border-radius:4px;color:#fff;background:${color};font-weight:600;font-size:0.9em;">
            ${statusLabel(result.status)} - ${statusLabelZh(result.status)}
          </span>
        </td>
      </tr>
      <tr>
        <td style="padding:4px 0;color:#6b7280;">簽章數量</td>
        <td style="padding:4px 0;">${result.signatures.length}</td>
      </tr>
      <tr>
        <td style="padding:4px 0;color:#6b7280;">摘要</td>
        <td style="padding:4px 0;">${escapeHtml(result.summary)}</td>
      </tr>
    </table>
  </div>

  <h2>簽章詳細資訊</h2>
  ${signaturesHtml}

  <div style="margin-top:40px;padding-top:16px;border-top:1px solid #e5e7eb;text-align:center;color:#9ca3af;font-size:0.8em;">
    <p>報告產生時間：${now}</p>
    <p>由 PDF 數位簽章驗證器 產生</p>
  </div>

  <div class="no-print" style="text-align:center;margin-top:24px;">
    <button onclick="window.print()" style="padding:8px 24px;background:#2563eb;color:#fff;border:none;border-radius:6px;cursor:pointer;font-size:0.9em;">
      列印 / 儲存為 PDF
    </button>
  </div>
</body>
</html>`
}
