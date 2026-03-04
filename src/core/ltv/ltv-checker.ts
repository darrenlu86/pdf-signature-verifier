import type {
  ParsedCertificate,
  EmbeddedRevocationInfo,
  TimestampInfo,
  CheckResult,
  LtvInfo,
  CrlInfo,
} from '@/types'
import { createPassedCheck, createFailedCheck } from '@/types'
import { t } from '@/i18n'
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
      t('core.ltv.noLtvInfo'),
      t('core.ltv.noLtvInfoDetails'),
      { key: 'core.ltv.noLtvInfo', detailsKey: 'core.ltv.noLtvInfoDetails' }
    )
  } else if (hasLtv && completeness.complete && hasTimestamp) {
    check = createPassedCheck(
      t('core.ltv.ltvComplete'),
      t('core.ltv.canLongTermVerify'),
      { key: 'core.ltv.ltvComplete', detailsKey: 'core.ltv.canLongTermVerify' }
    )
  } else if (hasLtv && completeness.complete) {
    check = createPassedCheck(
      t('core.ltv.hasLtvInfo'),
      t('core.ltv.hasRevocationNoTimestamp'),
      { key: 'core.ltv.hasLtvInfo', detailsKey: 'core.ltv.hasRevocationNoTimestamp' }
    )
  } else if (hasLtv && !completeness.complete) {
    check = createFailedCheck(
      t('core.ltv.ltvIncomplete'),
      t('core.ltv.missing', { items: completeness.missing.join(', ') }),
      { key: 'core.ltv.ltvIncomplete', detailsKey: 'core.ltv.missing', detailsParams: { items: completeness.missing.join(', ') } }
    )
  } else if (hasTimestamp && !hasLtv) {
    check = createFailedCheck(
      t('core.ltv.hasTimestampNoRevocation'),
      t('core.ltv.longTermMayFail'),
      { key: 'core.ltv.hasTimestampNoRevocation', detailsKey: 'core.ltv.longTermMayFail' }
    )
  } else {
    check = createFailedCheck(
      t('core.ltv.ltvCheckFailed'),
      t('core.ltv.cannotDetermine'),
      { key: 'core.ltv.ltvCheckFailed', detailsKey: 'core.ltv.cannotDetermine' }
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
      reason: t('core.ltv.noEmbeddedRevocation'),
    }
  }

  if (!ltvResult.details.hasTimestamp) {
    return {
      valid: false,
      reason: t('core.ltv.noTimestampForTime'),
    }
  }

  const { from, until } = ltvResult.details.validityWindow

  if (from && targetDate < from) {
    return {
      valid: false,
      reason: t('core.ltv.targetBeforeValidity'),
    }
  }

  if (until && targetDate > until) {
    return {
      valid: false,
      reason: t('core.ltv.revocationExpired'),
    }
  }

  if (!ltvResult.isComplete) {
    return {
      valid: false,
      reason: t('core.ltv.missing', { items: ltvResult.details.missingItems.join(', ') }),
    }
  }

  return {
    valid: true,
    reason: t('core.ltv.canValidateAtDate'),
  }
}

/**
 * Get LTV status for display
 */
export function getLtvStatusText(ltvResult: LtvCheckResult): string {
  if (ltvResult.isComplete) {
    return t('core.ltv.ltvEnabled')
  }

  if (ltvResult.hasLtv) {
    return t('core.ltv.ltvPartial')
  }

    return t('core.ltv.ltvNotEnabled')
}

/**
 * Get LTV details for display
 */
export function getLtvDetailsText(ltvResult: LtvCheckResult): string[] {
  const lines: string[] = []

  if (ltvResult.details.hasTimestamp) {
    lines.push(t('core.ltv.hasTimestamp'))
  } else {
    lines.push(t('core.ltv.noTimestamp'))
  }

  if (ltvResult.details.hasOcsp) {
    lines.push(t('core.ltv.embeddedOcsp', { count: ltvResult.details.ocspCount }))
  }

  if (ltvResult.details.hasCrl) {
    lines.push(t('core.ltv.embeddedCrl', { count: ltvResult.details.crlCount }))
  }

  if (!ltvResult.details.hasOcsp && !ltvResult.details.hasCrl) {
    lines.push(t('core.ltv.noEmbeddedRevocationData'))
  }

  if (ltvResult.details.missingItems.length > 0) {
    lines.push(t('core.ltv.missing', { items: ltvResult.details.missingItems.join(', ') }))
  }

  if (ltvResult.details.validityWindow.until) {
    lines.push(t('core.ltv.validUntil', { date: ltvResult.details.validityWindow.until.toLocaleDateString() }))
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
      reason: t('core.ltv.certNotExpired'),
    }
  }

  // Must have timestamp
  if (!timestampInfo || !timestampInfo.time) {
    return {
      trusted: false,
      reason: t('core.ltv.noTimestampForProof'),
    }
  }

  // Timestamp must be within certificate validity
  if (timestampInfo.time < certificate.notBefore || timestampInfo.time > certificate.notAfter) {
    return {
      trusted: false,
      reason: t('core.ltv.timestampOutsideValidity'),
    }
  }

  // LTV must be complete
  if (!ltvResult.isComplete) {
    return {
      trusted: false,
      reason: t('core.ltv.ltvInfoIncomplete'),
    }
  }

  return {
    trusted: true,
    reason: t('core.ltv.signedWithinValidity'),
  }
}
