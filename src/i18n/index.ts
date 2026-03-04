import zhTW from './zh-TW.json'
import en from './en.json'

export type Locale = 'zh-TW' | 'en'

export type TranslationKeys = typeof zhTW

const translations: Record<Locale, TranslationKeys> = {
  'zh-TW': zhTW,
  en: en as unknown as TranslationKeys,
}

let currentLocale: Locale = 'zh-TW'

export function setLocale(locale: Locale): void {
  currentLocale = locale
}

export function getLocale(): Locale {
  return currentLocale
}

export function t(key: string, params?: Record<string, string | number>): string {
  const keys = key.split('.')
  let result: unknown = translations[currentLocale]

  for (const k of keys) {
    if (result && typeof result === 'object' && k in result) {
      result = (result as Record<string, unknown>)[k]
    } else {
      return key
    }
  }

  if (typeof result !== 'string') {
    return key
  }

  if (!params) {
    return result
  }

  return result.replace(/\{(\w+)\}/g, (_, paramKey) => {
    return paramKey in params ? String(params[paramKey]) : `{${paramKey}}`
  })
}

export function detectBrowserLocale(): Locale {
  const lang = navigator.language.toLowerCase()

  if (lang.startsWith('zh')) {
    return 'zh-TW'
  }

  return 'en'
}

/**
 * Resolve a CheckResult's message/details using i18n keys if available.
 * Falls back to the stored message string if no i18n key is present.
 */
export function resolveCheck(check: {
  message: string
  details?: string
  i18nKey?: string
  i18nParams?: Record<string, string | number>
  detailsI18nKey?: string
  detailsI18nParams?: Record<string, string | number>
}): { message: string; details?: string } {
  const message = check.i18nKey ? t(check.i18nKey, check.i18nParams) : check.message
  const details = check.detailsI18nKey
    ? t(check.detailsI18nKey, check.detailsI18nParams)
    : check.details
  return { message, details }
}

/**
 * Resolve a VerificationResult's summary using i18n keys if available.
 */
export function resolveSummary(result: {
  summary: string
  summaryI18nKey?: string
  summaryI18nParams?: Record<string, string | number>
}): string {
  return result.summaryI18nKey
    ? t(result.summaryI18nKey, result.summaryI18nParams)
    : result.summary
}

export { zhTW, en }
