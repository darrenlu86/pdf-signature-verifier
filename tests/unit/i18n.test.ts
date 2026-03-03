import { describe, it, expect, beforeEach } from 'vitest'
import { t, setLocale, getLocale, detectBrowserLocale, zhTW, en } from '@/i18n'

describe('i18n', () => {
  beforeEach(() => {
    setLocale('zh-TW')
  })

  describe('setLocale and getLocale', () => {
    it('should set and get locale', () => {
      setLocale('en')
      expect(getLocale()).toBe('en')

      setLocale('zh-TW')
      expect(getLocale()).toBe('zh-TW')
    })
  })

  describe('t function', () => {
    it('should return translated string for zh-TW', () => {
      setLocale('zh-TW')
      expect(t('app.title')).toBe('PDF 數位簽章驗證')
    })

    it('should return translated string for en', () => {
      setLocale('en')
      expect(t('app.title')).toBe('PDF Digital Signature Verifier')
    })

    it('should handle nested keys', () => {
      setLocale('zh-TW')
      expect(t('status.trusted')).toBe('文件可信')
      expect(t('checks.integrity')).toBe('文件完整性')
    })

    it('should return key if not found', () => {
      expect(t('nonexistent.key')).toBe('nonexistent.key')
    })

    it('should return key if partial path', () => {
      expect(t('app')).toBe('app')
    })
  })

  describe('translation files', () => {
    it('should have same structure for zh-TW and en', () => {
      const zhKeys = getAllKeys(zhTW)
      const enKeys = getAllKeys(en)

      for (const key of zhKeys) {
        expect(enKeys).toContain(key)
      }
    })

    it('should have all required app keys', () => {
      const requiredKeys = [
        'app.title',
        'status.trusted',
        'status.unknown',
        'status.failed',
        'verification.loading',
        'checks.integrity',
        'dropzone.message',
        'settings.checkOnlineRevocation',
      ]

      for (const key of requiredKeys) {
        expect(t(key)).not.toBe(key)
      }
    })
  })
})

function getAllKeys(obj: Record<string, unknown>, prefix = ''): string[] {
  const keys: string[] = []

  for (const [key, value] of Object.entries(obj)) {
    const fullKey = prefix ? `${prefix}.${key}` : key

    if (typeof value === 'object' && value !== null) {
      keys.push(...getAllKeys(value as Record<string, unknown>, fullKey))
    } else {
      keys.push(fullKey)
    }
  }

  return keys
}
