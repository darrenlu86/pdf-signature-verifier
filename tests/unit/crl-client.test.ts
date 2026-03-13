import { describe, it, expect, vi } from 'vitest'
import type { ParsedCertificate, KeyUsageFlags, CrlInfo } from '@/types'

// Mock i18n
vi.mock('@/i18n', () => ({
  t: (key: string, params?: Record<string, unknown>) => {
    if (params) {
      return `${key}:${JSON.stringify(params)}`
    }
    return key
  },
}))

// Mock network
vi.mock('@/core/network', () => ({
  fetchBinary: vi.fn(() => Promise.resolve(null)),
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
    serialNumber: '0102',
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

describe('crl-client', () => {
  describe('checkCrlStatus', () => {
    it('should return unknown when no CRL distribution points exist', async () => {
      const { checkCrlStatus } = await import('@/core/revocation/crl-client')

      const cert = createMockCert({ crlDistributionPoints: [] })
      const issuer = createMockCert({})

      const result = await checkCrlStatus(cert, issuer)

      expect(result.status).toBe('unknown')
      expect(result.method).toBe('crl')
    })

    it('should return error when all CRL fetches fail', async () => {
      const { checkCrlStatus } = await import('@/core/revocation/crl-client')

      const cert = createMockCert({
        crlDistributionPoints: ['http://crl.example.com/test.crl'],
      })
      const issuer = createMockCert({})

      const result = await checkCrlStatus(cert, issuer)

      expect(result.status).toBe('error')
      expect(result.method).toBe('crl')
    })

    it('should include checkedAt on result', async () => {
      const { checkCrlStatus } = await import('@/core/revocation/crl-client')

      const cert = createMockCert({ crlDistributionPoints: [] })
      const issuer = createMockCert({})

      const result = await checkCrlStatus(cert, issuer)

      expect(result.checkedAt).toBeInstanceOf(Date)
    })

    it('should have detailsI18nKey for no distribution points', async () => {
      const { checkCrlStatus } = await import('@/core/revocation/crl-client')

      const cert = createMockCert({ crlDistributionPoints: [] })
      const issuer = createMockCert({})

      const result = await checkCrlStatus(cert, issuer)

      expect(result.detailsI18nKey).toBe('core.revocation.noCrlDistPoints')
    })

    it('should try multiple CRL URLs before returning error', async () => {
      const { checkCrlStatus } = await import('@/core/revocation/crl-client')

      const cert = createMockCert({
        crlDistributionPoints: [
          'http://crl1.example.com/test.crl',
          'http://crl2.example.com/test.crl',
        ],
      })
      const issuer = createMockCert({})

      const result = await checkCrlStatus(cert, issuer)

      expect(result.status).toBe('error')
      expect(result.detailsI18nKey).toBe('core.revocation.allCrlFailed')
    })
  })

  describe('isSerialInCrl', () => {
    it('should find serial number in CRL', async () => {
      const { isSerialInCrl } = await import('@/core/revocation/crl-client')

      const crlInfo: CrlInfo = {
        issuer: 'CN=Test CA',
        thisUpdate: new Date('2024-01-01'),
        nextUpdate: new Date('2025-01-01'),
        serialNumbers: ['abc123', 'def456', '789000'],
      }

      expect(isSerialInCrl('abc123', crlInfo)).toBe(true)
    })

    it('should return false when serial is not in CRL', async () => {
      const { isSerialInCrl } = await import('@/core/revocation/crl-client')

      const crlInfo: CrlInfo = {
        issuer: 'CN=Test CA',
        thisUpdate: new Date('2024-01-01'),
        nextUpdate: new Date('2025-01-01'),
        serialNumbers: ['abc123', 'def456'],
      }

      expect(isSerialInCrl('999999', crlInfo)).toBe(false)
    })

    it('should normalize serial numbers (case insensitive)', async () => {
      const { isSerialInCrl } = await import('@/core/revocation/crl-client')

      const crlInfo: CrlInfo = {
        issuer: 'CN=Test CA',
        thisUpdate: new Date('2024-01-01'),
        serialNumbers: ['ABC123'],
      }

      expect(isSerialInCrl('abc123', crlInfo)).toBe(true)
    })

    it('should strip leading zeros during comparison', async () => {
      const { isSerialInCrl } = await import('@/core/revocation/crl-client')

      const crlInfo: CrlInfo = {
        issuer: 'CN=Test CA',
        thisUpdate: new Date('2024-01-01'),
        serialNumbers: ['00abc123'],
      }

      expect(isSerialInCrl('abc123', crlInfo)).toBe(true)
    })

    it('should handle empty CRL serial list', async () => {
      const { isSerialInCrl } = await import('@/core/revocation/crl-client')

      const crlInfo: CrlInfo = {
        issuer: 'CN=Test CA',
        thisUpdate: new Date('2024-01-01'),
        serialNumbers: [],
      }

      expect(isSerialInCrl('abc123', crlInfo)).toBe(false)
    })
  })

  describe('isCrlValid', () => {
    it('should return true for a currently valid CRL', async () => {
      const { isCrlValid } = await import('@/core/revocation/crl-client')

      const crlInfo: CrlInfo = {
        issuer: 'CN=Test CA',
        thisUpdate: new Date('2020-01-01'),
        nextUpdate: new Date('2030-12-31'),
        serialNumbers: [],
      }

      expect(isCrlValid(crlInfo)).toBe(true)
    })

    it('should return false for an expired CRL', async () => {
      const { isCrlValid } = await import('@/core/revocation/crl-client')

      const crlInfo: CrlInfo = {
        issuer: 'CN=Test CA',
        thisUpdate: new Date('2020-01-01'),
        nextUpdate: new Date('2021-01-01'),
        serialNumbers: [],
      }

      expect(isCrlValid(crlInfo)).toBe(false)
    })

    it('should return false for a not-yet-valid CRL', async () => {
      const { isCrlValid } = await import('@/core/revocation/crl-client')

      const crlInfo: CrlInfo = {
        issuer: 'CN=Test CA',
        thisUpdate: new Date('2099-01-01'),
        nextUpdate: new Date('2100-01-01'),
        serialNumbers: [],
      }

      expect(isCrlValid(crlInfo)).toBe(false)
    })

    it('should return true when nextUpdate is absent and thisUpdate is in the past', async () => {
      const { isCrlValid } = await import('@/core/revocation/crl-client')

      const crlInfo: CrlInfo = {
        issuer: 'CN=Test CA',
        thisUpdate: new Date('2020-01-01'),
        serialNumbers: [],
      }

      expect(isCrlValid(crlInfo)).toBe(true)
    })
  })

  describe('getCrlCacheKey', () => {
    it('should return a cache key prefixed with crl:', async () => {
      const { getCrlCacheKey } = await import('@/core/revocation/crl-client')

      const key = getCrlCacheKey('http://crl.example.com/test.crl')
      expect(key).toBe('crl:http://crl.example.com/test.crl')
    })

    it('should handle different URLs', async () => {
      const { getCrlCacheKey } = await import('@/core/revocation/crl-client')

      const key1 = getCrlCacheKey('http://a.com/1.crl')
      const key2 = getCrlCacheKey('http://b.com/2.crl')

      expect(key1).not.toBe(key2)
    })
  })

  describe('parseCrl', () => {
    it('should throw for invalid ASN.1 data', async () => {
      const { parseCrl } = await import('@/core/revocation/crl-client')

      expect(() => parseCrl(new Uint8Array([0x00, 0x01]))).toThrow()
    })

    it('should throw for empty data', async () => {
      const { parseCrl } = await import('@/core/revocation/crl-client')

      expect(() => parseCrl(new Uint8Array(0))).toThrow()
    })
  })
})
