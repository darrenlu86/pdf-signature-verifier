import { describe, it, expect, vi } from 'vitest'
import type { ParsedCertificate, KeyUsageFlags, TimestampInfo, EmbeddedRevocationInfo } from '@/types'

// Mock i18n
vi.mock('@/i18n', () => ({
  t: (key: string, params?: Record<string, unknown>) => {
    if (params) {
      return `${key}:${JSON.stringify(params)}`
    }
    return key
  },
}))

// Mock embedded-reader with controllable returns
const mockIsLtvComplete = vi.fn()
const mockGetEmbeddedRevocationStats = vi.fn()
const mockGetRevocationInfoValidity = vi.fn()

vi.mock('@/core/revocation/embedded-reader', () => ({
  isLtvComplete: (...args: unknown[]) => mockIsLtvComplete(...args),
  getEmbeddedRevocationStats: (...args: unknown[]) => mockGetEmbeddedRevocationStats(...args),
  getRevocationInfoValidity: (...args: unknown[]) => mockGetRevocationInfoValidity(...args),
}))

function createEmptyKeyUsage(): KeyUsageFlags {
  return {
    digitalSignature: false,
    nonRepudiation: false,
    keyEncipherment: false,
    dataEncipherment: false,
    keyAgreement: false,
    keyCertSign: false,
    crlSign: false,
    encipherOnly: false,
    decipherOnly: false,
  }
}

function createMockCert(overrides: Partial<ParsedCertificate>): ParsedCertificate {
  return {
    raw: {} as ParsedCertificate['raw'],
    subject: 'CN=Test',
    issuer: 'CN=Test CA',
    serialNumber: '01',
    notBefore: new Date('2024-01-01'),
    notAfter: new Date('2025-12-31'),
    publicKey: null,
    fingerprint: 'aabb',
    isCA: false,
    isSelfSigned: false,
    keyUsage: createEmptyKeyUsage(),
    extKeyUsage: [],
    authorityInfoAccess: null,
    crlDistributionPoints: [],
    subjectKeyIdentifier: null,
    authorityKeyIdentifier: null,
    ...overrides,
  }
}

describe('ltv-checker', () => {
  beforeEach(() => {
    vi.clearAllMocks()

    // Default mock returns
    mockGetEmbeddedRevocationStats.mockReturnValue({
      hasOcsp: false,
      hasCrl: false,
      ocspCount: 0,
      crlCount: 0,
      crlInfos: [],
    })
    mockGetRevocationInfoValidity.mockReturnValue({
      validFrom: null,
      validUntil: null,
    })
    mockIsLtvComplete.mockReturnValue({
      complete: false,
      missing: [],
    })
  })

  describe('checkLtvCompleteness', () => {
    it('should return failed when no LTV info and no timestamp', async () => {
      const { checkLtvCompleteness } = await import('@/core/ltv/ltv-checker')

      const chain = [createMockCert({})]
      const result = checkLtvCompleteness(chain, null, null)

      expect(result.hasLtv).toBe(false)
      expect(result.isComplete).toBe(false)
      expect(result.check.passed).toBe(false)
    })

    it('should return passed when LTV is complete with timestamp', async () => {
      const { checkLtvCompleteness } = await import('@/core/ltv/ltv-checker')

      mockGetEmbeddedRevocationStats.mockReturnValue({
        hasOcsp: true,
        hasCrl: false,
        ocspCount: 1,
        crlCount: 0,
        crlInfos: [],
      })
      mockIsLtvComplete.mockReturnValue({ complete: true, missing: [] })

      const chain = [createMockCert({})]
      const tsInfo: TimestampInfo = {
        time: new Date('2024-06-15'),
        issuer: 'TSA',
        serialNumber: '01',
        hashAlgorithm: 'SHA-256',
        isValid: true,
      }

      const result = checkLtvCompleteness(chain, { ocspResponses: [new Uint8Array(1)], crls: [], certs: [] }, tsInfo)

      expect(result.hasLtv).toBe(true)
      expect(result.isComplete).toBe(true)
      expect(result.check.passed).toBe(true)
    })

    it('should return passed but not complete when LTV exists but no timestamp', async () => {
      const { checkLtvCompleteness } = await import('@/core/ltv/ltv-checker')

      mockGetEmbeddedRevocationStats.mockReturnValue({
        hasOcsp: true,
        hasCrl: false,
        ocspCount: 1,
        crlCount: 0,
        crlInfos: [],
      })
      mockIsLtvComplete.mockReturnValue({ complete: true, missing: [] })

      const chain = [createMockCert({})]
      const result = checkLtvCompleteness(chain, { ocspResponses: [new Uint8Array(1)], crls: [], certs: [] }, null)

      expect(result.hasLtv).toBe(true)
      expect(result.isComplete).toBe(false) // No timestamp means not fully complete
      expect(result.check.passed).toBe(true)
    })

    it('should return failed when LTV is incomplete (missing items)', async () => {
      const { checkLtvCompleteness } = await import('@/core/ltv/ltv-checker')

      mockGetEmbeddedRevocationStats.mockReturnValue({
        hasOcsp: true,
        hasCrl: false,
        ocspCount: 1,
        crlCount: 0,
        crlInfos: [],
      })
      mockIsLtvComplete.mockReturnValue({
        complete: false,
        missing: ['Revocation info for CN=Intermediate'],
      })

      const chain = [createMockCert({})]
      const tsInfo: TimestampInfo = {
        time: new Date('2024-06-15'),
        issuer: 'TSA',
        serialNumber: '01',
        hashAlgorithm: 'SHA-256',
        isValid: true,
      }

      const result = checkLtvCompleteness(chain, { ocspResponses: [new Uint8Array(1)], crls: [], certs: [] }, tsInfo)

      expect(result.check.passed).toBe(false)
      expect(result.details.missingItems).toHaveLength(1)
    })

    it('should return failed when only timestamp but no revocation', async () => {
      const { checkLtvCompleteness } = await import('@/core/ltv/ltv-checker')

      const chain = [createMockCert({})]
      const tsInfo: TimestampInfo = {
        time: new Date('2024-06-15'),
        issuer: 'TSA',
        serialNumber: '01',
        hashAlgorithm: 'SHA-256',
        isValid: true,
      }

      const result = checkLtvCompleteness(chain, null, tsInfo)

      expect(result.hasLtv).toBe(false)
      expect(result.check.passed).toBe(false)
    })

    it('should populate details correctly', async () => {
      const { checkLtvCompleteness } = await import('@/core/ltv/ltv-checker')

      mockGetEmbeddedRevocationStats.mockReturnValue({
        hasOcsp: true,
        hasCrl: true,
        ocspCount: 2,
        crlCount: 1,
        crlInfos: [],
      })
      mockIsLtvComplete.mockReturnValue({ complete: true, missing: [] })
      mockGetRevocationInfoValidity.mockReturnValue({
        validFrom: new Date('2024-01-01'),
        validUntil: new Date('2025-01-01'),
      })

      const chain = [createMockCert({})]
      const tsInfo: TimestampInfo = {
        time: new Date('2024-06-15'),
        issuer: 'TSA',
        serialNumber: '01',
        hashAlgorithm: 'SHA-256',
        isValid: true,
      }

      const result = checkLtvCompleteness(
        chain,
        { ocspResponses: [new Uint8Array(1), new Uint8Array(1)], crls: [new Uint8Array(1)], certs: [] },
        tsInfo
      )

      expect(result.details.hasTimestamp).toBe(true)
      expect(result.details.hasOcsp).toBe(true)
      expect(result.details.hasCrl).toBe(true)
      expect(result.details.ocspCount).toBe(2)
      expect(result.details.crlCount).toBe(1)
      expect(result.details.validityWindow.from).toEqual(new Date('2024-01-01'))
      expect(result.details.validityWindow.until).toEqual(new Date('2025-01-01'))
    })
  })

  describe('canValidateAtDate', () => {
    it('should return false when no LTV info', async () => {
      const { checkLtvCompleteness, canValidateAtDate } = await import('@/core/ltv/ltv-checker')

      const chain = [createMockCert({})]
      const ltvResult = checkLtvCompleteness(chain, null, null)
      const result = canValidateAtDate(ltvResult, new Date('2030-01-01'))

      expect(result.valid).toBe(false)
    })

    it('should return false when no timestamp', async () => {
      const { checkLtvCompleteness, canValidateAtDate } = await import('@/core/ltv/ltv-checker')

      mockGetEmbeddedRevocationStats.mockReturnValue({
        hasOcsp: true, hasCrl: false, ocspCount: 1, crlCount: 0, crlInfos: [],
      })
      mockIsLtvComplete.mockReturnValue({ complete: true, missing: [] })

      const chain = [createMockCert({})]
      const ltvResult = checkLtvCompleteness(
        chain,
        { ocspResponses: [new Uint8Array(1)], crls: [], certs: [] },
        null
      )
      const result = canValidateAtDate(ltvResult, new Date('2030-01-01'))

      expect(result.valid).toBe(false)
    })

    it('should return true when all conditions are met', async () => {
      const { checkLtvCompleteness, canValidateAtDate } = await import('@/core/ltv/ltv-checker')

      mockGetEmbeddedRevocationStats.mockReturnValue({
        hasOcsp: true, hasCrl: false, ocspCount: 1, crlCount: 0, crlInfos: [],
      })
      mockIsLtvComplete.mockReturnValue({ complete: true, missing: [] })
      mockGetRevocationInfoValidity.mockReturnValue({
        validFrom: new Date('2024-01-01'),
        validUntil: new Date('2030-12-31'),
      })

      const chain = [createMockCert({})]
      const tsInfo: TimestampInfo = {
        time: new Date('2024-06-15'),
        issuer: 'TSA',
        serialNumber: '01',
        hashAlgorithm: 'SHA-256',
        isValid: true,
      }

      const ltvResult = checkLtvCompleteness(
        chain,
        { ocspResponses: [new Uint8Array(1)], crls: [], certs: [] },
        tsInfo
      )
      const result = canValidateAtDate(ltvResult, new Date('2025-06-15'))

      expect(result.valid).toBe(true)
    })
  })

  describe('getLtvStatusText', () => {
    it('should return ltvEnabled when complete', async () => {
      const { checkLtvCompleteness, getLtvStatusText } = await import('@/core/ltv/ltv-checker')

      mockGetEmbeddedRevocationStats.mockReturnValue({
        hasOcsp: true, hasCrl: false, ocspCount: 1, crlCount: 0, crlInfos: [],
      })
      mockIsLtvComplete.mockReturnValue({ complete: true, missing: [] })

      const chain = [createMockCert({})]
      const tsInfo: TimestampInfo = {
        time: new Date('2024-06-15'),
        issuer: 'TSA',
        serialNumber: '01',
        hashAlgorithm: 'SHA-256',
        isValid: true,
      }

      const ltvResult = checkLtvCompleteness(
        chain,
        { ocspResponses: [new Uint8Array(1)], crls: [], certs: [] },
        tsInfo
      )
      const text = getLtvStatusText(ltvResult)

      expect(text).toBe('core.ltv.ltvEnabled')
    })

    it('should return ltvPartial when has LTV but not complete', async () => {
      const { checkLtvCompleteness, getLtvStatusText } = await import('@/core/ltv/ltv-checker')

      mockGetEmbeddedRevocationStats.mockReturnValue({
        hasOcsp: true, hasCrl: false, ocspCount: 1, crlCount: 0, crlInfos: [],
      })
      mockIsLtvComplete.mockReturnValue({ complete: false, missing: ['something'] })

      const chain = [createMockCert({})]
      const ltvResult = checkLtvCompleteness(
        chain,
        { ocspResponses: [new Uint8Array(1)], crls: [], certs: [] },
        null
      )
      const text = getLtvStatusText(ltvResult)

      expect(text).toBe('core.ltv.ltvPartial')
    })

    it('should return ltvNotEnabled when no LTV', async () => {
      const { checkLtvCompleteness, getLtvStatusText } = await import('@/core/ltv/ltv-checker')

      const chain = [createMockCert({})]
      const ltvResult = checkLtvCompleteness(chain, null, null)
      const text = getLtvStatusText(ltvResult)

      expect(text).toBe('core.ltv.ltvNotEnabled')
    })
  })

  describe('canTrustExpiredWithLtv', () => {
    it('should return trusted when cert is not expired', async () => {
      const { checkLtvCompleteness, canTrustExpiredWithLtv } = await import('@/core/ltv/ltv-checker')

      const cert = createMockCert({
        notAfter: new Date('2099-12-31'),
      })

      const chain = [cert]
      const ltvResult = checkLtvCompleteness(chain, null, null)
      const result = canTrustExpiredWithLtv(cert, null, ltvResult)

      expect(result.trusted).toBe(true)
    })

    it('should return false when cert is expired and no timestamp', async () => {
      const { checkLtvCompleteness, canTrustExpiredWithLtv } = await import('@/core/ltv/ltv-checker')

      const cert = createMockCert({
        notBefore: new Date('2020-01-01'),
        notAfter: new Date('2022-12-31'),
      })

      const chain = [cert]
      const ltvResult = checkLtvCompleteness(chain, null, null)
      const result = canTrustExpiredWithLtv(cert, null, ltvResult)

      expect(result.trusted).toBe(false)
    })

    it('should return false when timestamp is outside cert validity', async () => {
      const { checkLtvCompleteness, canTrustExpiredWithLtv } = await import('@/core/ltv/ltv-checker')

      mockGetEmbeddedRevocationStats.mockReturnValue({
        hasOcsp: true, hasCrl: false, ocspCount: 1, crlCount: 0, crlInfos: [],
      })
      mockIsLtvComplete.mockReturnValue({ complete: true, missing: [] })

      const cert = createMockCert({
        notBefore: new Date('2020-01-01'),
        notAfter: new Date('2022-12-31'),
      })

      const tsInfo: TimestampInfo = {
        time: new Date('2023-06-15'), // After cert expired
        issuer: 'TSA',
        serialNumber: '01',
        hashAlgorithm: 'SHA-256',
        isValid: true,
      }

      const chain = [cert]
      const ltvResult = checkLtvCompleteness(
        chain,
        { ocspResponses: [new Uint8Array(1)], crls: [], certs: [] },
        tsInfo
      )
      const result = canTrustExpiredWithLtv(cert, tsInfo, ltvResult)

      expect(result.trusted).toBe(false)
    })
  })

  describe('getLtvDetailsText', () => {
    it('should include timestamp status line', async () => {
      const { checkLtvCompleteness, getLtvDetailsText } = await import('@/core/ltv/ltv-checker')

      const chain = [createMockCert({})]
      const ltvResult = checkLtvCompleteness(chain, null, null)
      const lines = getLtvDetailsText(ltvResult)

      expect(lines.length).toBeGreaterThan(0)
      expect(lines.some((l) => l.includes('core.ltv.noTimestamp'))).toBe(true)
    })

    it('should include missing items when present', async () => {
      const { checkLtvCompleteness, getLtvDetailsText } = await import('@/core/ltv/ltv-checker')

      mockGetEmbeddedRevocationStats.mockReturnValue({
        hasOcsp: true, hasCrl: false, ocspCount: 1, crlCount: 0, crlInfos: [],
      })
      mockIsLtvComplete.mockReturnValue({
        complete: false,
        missing: ['Revocation info for CN=Test'],
      })

      const chain = [createMockCert({})]
      const ltvResult = checkLtvCompleteness(
        chain,
        { ocspResponses: [new Uint8Array(1)], crls: [], certs: [] },
        null
      )
      const lines = getLtvDetailsText(ltvResult)

      expect(lines.some((l) => l.includes('core.ltv.missing'))).toBe(true)
    })
  })
})
