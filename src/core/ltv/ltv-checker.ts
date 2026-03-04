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
      reason: 'No embedded revocation information',
    }
  }

  if (!ltvResult.details.hasTimestamp) {
    return {
      valid: false,
      reason: 'No timestamp to establish signing time',
    }
  }

  const { from, until } = ltvResult.details.validityWindow

  if (from && targetDate < from) {
    return {
      valid: false,
      reason: 'Target date is before revocation info validity',
    }
  }

  if (until && targetDate > until) {
    return {
      valid: false,
      reason: 'Revocation information has expired',
    }
  }

  if (!ltvResult.isComplete) {
    return {
      valid: false,
      reason: `Missing: ${ltvResult.details.missingItems.join(', ')}`,
    }
  }

  return {
    valid: true,
    reason: 'Signature can be validated at target date',
  }
}

/**
 * Get LTV status for display
 */
export function getLtvStatusText(ltvResult: LtvCheckResult): string {
  if (ltvResult.isComplete) {
    return 'LTV-enabled'
  }

  if (ltvResult.hasLtv) {
    return 'Partial LTV'
  }

  return 'No LTV'
}

/**
 * Get LTV details for display
 */
export function getLtvDetailsText(ltvResult: LtvCheckResult): string[] {
  const lines: string[] = []

  if (ltvResult.details.hasTimestamp) {
    lines.push('[OK] Timestamp present')
  } else {
    lines.push('[FAIL] No timestamp')
  }

  if (ltvResult.details.hasOcsp) {
    lines.push(`[OK] ${ltvResult.details.ocspCount} OCSP response(s) embedded`)
  }

  if (ltvResult.details.hasCrl) {
    lines.push(`[OK] ${ltvResult.details.crlCount} CRL(s) embedded`)
  }

  if (!ltvResult.details.hasOcsp && !ltvResult.details.hasCrl) {
    lines.push('[FAIL] No revocation data embedded')
  }

  if (ltvResult.details.missingItems.length > 0) {
    lines.push(`Missing: ${ltvResult.details.missingItems.join(', ')}`)
  }

  if (ltvResult.details.validityWindow.until) {
    lines.push(`Valid until: ${ltvResult.details.validityWindow.until.toLocaleDateString()}`)
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
      reason: 'Certificate is not expired',
    }
  }

  // Must have timestamp
  if (!timestampInfo || !timestampInfo.time) {
    return {
      trusted: false,
      reason: 'No timestamp to prove signing time',
    }
  }

  // Timestamp must be within certificate validity
  if (timestampInfo.time < certificate.notBefore || timestampInfo.time > certificate.notAfter) {
    return {
      trusted: false,
      reason: 'Timestamp is outside certificate validity period',
    }
  }

  // LTV must be complete
  if (!ltvResult.isComplete) {
    return {
      trusted: false,
      reason: 'LTV information is incomplete',
    }
  }

  return {
    trusted: true,
    reason: 'Signature was created while certificate was valid (verified via LTV)',
  }
}
