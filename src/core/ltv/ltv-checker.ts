import type {
  ParsedCertificate,
  EmbeddedRevocationInfo,
  TimestampInfo,
  CheckResult,
  LtvInfo,
  CrlInfo,
} from '@/types'
import { createPassedCheck, createFailedCheck } from '@/types'
import {
  isLtvComplete,
  getEmbeddedRevocationStats,
  getRevocationInfoValidity,
} from '../revocation/embedded-reader'

export interface LtvCheckResult {
  hasLtv: boolean
  isComplete: boolean
  check: CheckResult
  info: LtvInfo
  details: LtvDetails
}

export interface LtvDetails {
  hasTimestamp: boolean
  hasOcsp: boolean
  hasCrl: boolean
  ocspCount: number
  crlCount: number
  validityWindow: {
    from: Date | null
    until: Date | null
  }
  missingItems: string[]
}

/**
 * Check if PDF signature has complete LTV (Long-Term Validation) information
 */
export function checkLtvCompleteness(
  chain: ParsedCertificate[],
  embeddedInfo: EmbeddedRevocationInfo | null,
  timestampInfo: TimestampInfo | null
): LtvCheckResult {
  const stats = getEmbeddedRevocationStats(embeddedInfo)
  const validityWindow = getRevocationInfoValidity(embeddedInfo)
  const completeness = isLtvComplete(chain, embeddedInfo)

  const hasLtv = stats.hasOcsp || stats.hasCrl
  const hasTimestamp = timestampInfo !== null && timestampInfo.isValid

  const details: LtvDetails = {
    hasTimestamp,
    hasOcsp: stats.hasOcsp,
    hasCrl: stats.hasCrl,
    ocspCount: stats.ocspCount,
    crlCount: stats.crlCount,
    validityWindow: {
      from: validityWindow.validFrom,
      until: validityWindow.validUntil,
    },
    missingItems: completeness.missing,
  }

  const info: LtvInfo = {
    hasEmbeddedOcsp: stats.hasOcsp,
    hasEmbeddedCrl: stats.hasCrl,
    ocspResponses: [],
    crls: stats.crlInfos,
  }

  // Determine check result
  let check: CheckResult

  if (!hasLtv && !hasTimestamp) {
    check = createFailedCheck(
      '無 LTV 資訊',
      '文件缺少內嵌撤銷資料及時戳'
    )
  } else if (hasLtv && completeness.complete && hasTimestamp) {
    check = createPassedCheck(
      'LTV 簽章完整',
      '文件可進行長期驗證'
    )
  } else if (hasLtv && completeness.complete) {
    check = createPassedCheck(
      '已包含 LTV 資訊',
      '已內嵌撤銷資料，但無時戳'
    )
  } else if (hasLtv && !completeness.complete) {
    check = createFailedCheck(
      'LTV 資訊不完整',
      `缺少：${completeness.missing.join(', ')}`
    )
  } else if (hasTimestamp && !hasLtv) {
    check = createFailedCheck(
      '有時戳但無撤銷資料',
      '長期驗證可能失敗'
    )
  } else {
    check = createFailedCheck(
      'LTV 檢查失敗',
      '無法判定 LTV 狀態'
    )
  }

  return {
    hasLtv,
    isComplete: completeness.complete && hasTimestamp,
    check,
    info,
    details,
  }
}

/**
 * Check if signature can be validated at a future date
 */
export function canValidateAtDate(
  ltvResult: LtvCheckResult,
  targetDate: Date
): { valid: boolean; reason: string } {
  if (!ltvResult.hasLtv) {
    return {
      valid: false,
      reason: '無內嵌撤銷資訊',
    }
  }

  if (!ltvResult.details.hasTimestamp) {
    return {
      valid: false,
      reason: '無時戳可確認簽署時間',
    }
  }

  const { from, until } = ltvResult.details.validityWindow

  if (from && targetDate < from) {
    return {
      valid: false,
      reason: '目標日期早於撤銷資訊有效期',
    }
  }

  if (until && targetDate > until) {
    return {
      valid: false,
      reason: '撤銷資訊已過期',
    }
  }

  if (!ltvResult.isComplete) {
    return {
      valid: false,
      reason: `缺少：${ltvResult.details.missingItems.join('、')}`,
    }
  }

  return {
    valid: true,
    reason: '簽章可於目標日期驗證',
  }
}

/**
 * Get LTV status for display
 */
export function getLtvStatusText(ltvResult: LtvCheckResult): string {
  if (ltvResult.isComplete) {
    return 'LTV 已啟用'
  }

  if (ltvResult.hasLtv) {
    return 'LTV 部分啟用'
  }

    return '未啟用 LTV'
}

/**
 * Get LTV details for display
 */
export function getLtvDetailsText(ltvResult: LtvCheckResult): string[] {
  const lines: string[] = []

  if (ltvResult.details.hasTimestamp) {
    lines.push('[OK] 已包含時戳')
  } else {
    lines.push('[FAIL] 無時戳')
  }

  if (ltvResult.details.hasOcsp) {
    lines.push(`[OK] 內嵌 ${ltvResult.details.ocspCount} 個 OCSP 回應`)
  }

  if (ltvResult.details.hasCrl) {
    lines.push(`[OK] 內嵌 ${ltvResult.details.crlCount} 個 CRL`)
  }

  if (!ltvResult.details.hasOcsp && !ltvResult.details.hasCrl) {
    lines.push('[FAIL] 無內嵌撤銷資料')
  }

  if (ltvResult.details.missingItems.length > 0) {
    lines.push(`缺少：${ltvResult.details.missingItems.join('、')}`)
  }

  if (ltvResult.details.validityWindow.until) {
    lines.push(`有效至：${ltvResult.details.validityWindow.until.toLocaleDateString()}`)
  }

  return lines
}

/**
 * Determine if expired certificate can still be trusted via LTV
 */
export function canTrustExpiredWithLtv(
  certificate: ParsedCertificate,
  timestampInfo: TimestampInfo | null,
  ltvResult: LtvCheckResult
): { trusted: boolean; reason: string } {
  // Certificate must be expired
  if (new Date() <= certificate.notAfter) {
    return {
      trusted: true,
      reason: '憑證未過期',
    }
  }

  // Must have timestamp
  if (!timestampInfo || !timestampInfo.time) {
    return {
      trusted: false,
      reason: '無時戳可證明簽署時間',
    }
  }

  // Timestamp must be within certificate validity
  if (timestampInfo.time < certificate.notBefore || timestampInfo.time > certificate.notAfter) {
    return {
      trusted: false,
      reason: '時戳不在憑證有效期間內',
    }
  }

  // LTV must be complete
  if (!ltvResult.isComplete) {
    return {
      trusted: false,
      reason: 'LTV 資訊不完整',
    }
  }

  return {
    trusted: true,
    reason: '簽章於憑證有效期間內建立（經 LTV 驗證）',
  }
}
