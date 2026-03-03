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

export function t(key: string): string {
  const keys = key.split('.')
  let result: unknown = translations[currentLocale]

  for (const k of keys) {
    if (result && typeof result === 'object' && k in result) {
      result = (result as Record<string, unknown>)[k]
    } else {
      return key
    }
  }

  return typeof result === 'string' ? result : key
}

export function detectBrowserLocale(): Locale {
  const lang = navigator.language.toLowerCase()

  if (lang.startsWith('zh')) {
    return 'zh-TW'
  }

  return 'en'
}

export { zhTW, en }
