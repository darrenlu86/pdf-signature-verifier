import { describe, it, expect, vi } from 'vitest'
import type { ParsedCertificate, KeyUsageFlags, TimestampInfo } from '@/types'

// Mock i18n
vi.mock('@/i18n', () => ({
  t: (key: string, params?: Record<string, unknown>) => {
    if (params) {
      return `${key}:${JSON.stringify(params)}`
    }
    return key
  },
}))

// Mock cert-utils
vi.mock('@/core/certificate/cert-utils', () => ({
  parseCertificate: vi.fn(async () => ({
    raw: {},
    subject: 'CN=TSA Test',
    issuer: 'CN=TSA CA',
    serialNumber: '01',
    notBefore: new Date('2024-01-01'),
    notAfter: new Date('2025-12-31'),
    publicKey: null,
    fingerprint: 'tsa-fp',
    isCA: false,
    isSelfSigned: false,
    keyUsage: {
      digitalSignature: true,
      nonRepudiation: false,
      keyEncipherment: false,
      dataEncipherment: false,
      keyAgreement: false,
      keyCertSign: false,
      crlSign: false,
      encipherOnly: false,
      decipherOnly: false,
    },
    extKeyUsage: ['timeStamping'],
    authorityInfoAccess: null,
    crlDistributionPoints: [],
    subjectKeyIdentifier: null,
    authorityKeyIdentifier: null,
  })),
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

describe('tst-verifier', () => {
  describe('verifyTimestamp', () => {
    it('should return failed for invalid ASN.1 data', async () => {
      const { verifyTimestamp } = await import('@/core/timestamp/tst-verifier')

      const result = await verifyTimestamp(
        new Uint8Array([0x00, 0x01, 0x02]),
        new Uint8Array(32)
      )

      expect(result.valid).toBe(false)
      expect(result.info).toBeNull()
      expect(result.check.passed).toBe(false)
    })

    it('should return failed for empty timestamp data', async () => {
      const { verifyTimestamp } = await import('@/core/timestamp/tst-verifier')

      const result = await verifyTimestamp(
        new Uint8Array(0),
        new Uint8Array(32)
      )

      expect(result.valid).toBe(false)
      expect(result.check.passed).toBe(false)
    })

    it('should return failed for random noise', async () => {
      const { verifyTimestamp } = await import('@/core/timestamp/tst-verifier')

      const noise = new Uint8Array(128)
      for (let i = 0; i < noise.length; i++) {
        noise[i] = Math.floor(Math.random() * 256)
      }

      const result = await verifyTimestamp(noise, new Uint8Array(32))

      expect(result.valid).toBe(false)
    })

    it('should include check result with message', async () => {
      const { verifyTimestamp } = await import('@/core/timestamp/tst-verifier')

      const result = await verifyTimestamp(
        new Uint8Array([0xff]),
        new Uint8Array(32)
      )

      expect(result.check).toBeDefined()
      expect(typeof result.check.message).toBe('string')
      expect(result.check.passed).toBe(false)
    })

    it('should handle non-SignedData content type gracefully', async () => {
      const { verifyTimestamp } = await import('@/core/timestamp/tst-verifier')
      const asn1js = await import('asn1js')

      // Build a minimal ContentInfo with Data OID (not SignedData) using raw ASN.1
      const oid = new asn1js.ObjectIdentifier({ value: '1.2.840.113549.1.7.1' })
      const content = new asn1js.Constructed({
        idBlock: { tagClass: 3, tagNumber: 0 },
        value: [new asn1js.OctetString({ valueHex: new ArrayBuffer(4) })],
      })
      const seq = new asn1js.Sequence({ value: [oid, content] })
      const encoded = new Uint8Array(seq.toBER())

      const result = await verifyTimestamp(encoded, new Uint8Array(32))

      expect(result.valid).toBe(false)
      expect(result.check.passed).toBe(false)
    })
  })

  describe('isTimestampWithinCertValidity', () => {
    it('should return true when timestamp is within cert validity', async () => {
      const { isTimestampWithinCertValidity } = await import('@/core/timestamp/tst-verifier')

      const cert = createMockCert({
        notBefore: new Date('2024-01-01'),
        notAfter: new Date('2025-12-31'),
      })

      expect(isTimestampWithinCertValidity(new Date('2024-06-15'), cert)).toBe(true)
    })

    it('should return false when timestamp is before cert notBefore', async () => {
      const { isTimestampWithinCertValidity } = await import('@/core/timestamp/tst-verifier')

      const cert = createMockCert({
        notBefore: new Date('2024-01-01'),
        notAfter: new Date('2025-12-31'),
      })

      expect(isTimestampWithinCertValidity(new Date('2023-06-15'), cert)).toBe(false)
    })

    it('should return false when timestamp is after cert notAfter', async () => {
      const { isTimestampWithinCertValidity } = await import('@/core/timestamp/tst-verifier')

      const cert = createMockCert({
        notBefore: new Date('2024-01-01'),
        notAfter: new Date('2025-12-31'),
      })

      expect(isTimestampWithinCertValidity(new Date('2026-06-15'), cert)).toBe(false)
    })

    it('should return true on exact boundary dates', async () => {
      const { isTimestampWithinCertValidity } = await import('@/core/timestamp/tst-verifier')

      const notBefore = new Date('2024-01-01T00:00:00Z')
      const notAfter = new Date('2025-12-31T23:59:59Z')
      const cert = createMockCert({ notBefore, notAfter })

      expect(isTimestampWithinCertValidity(notBefore, cert)).toBe(true)
      expect(isTimestampWithinCertValidity(notAfter, cert)).toBe(true)
    })
  })

  describe('getEffectiveSigningTime', () => {
    it('should prefer timestamp time over signing time', async () => {
      const { getEffectiveSigningTime } = await import('@/core/timestamp/tst-verifier')

      const signingTime = new Date('2024-03-01')
      const tsInfo: TimestampInfo = {
        time: new Date('2024-03-02'),
        issuer: 'TSA',
        serialNumber: '01',
        hashAlgorithm: 'SHA-256',
        isValid: true,
      }

      const result = getEffectiveSigningTime(signingTime, tsInfo)
      expect(result).toEqual(tsInfo.time)
    })

    it('should use signing time when no timestamp is available', async () => {
      const { getEffectiveSigningTime } = await import('@/core/timestamp/tst-verifier')

      const signingTime = new Date('2024-03-01')

      const result = getEffectiveSigningTime(signingTime, null)
      expect(result).toEqual(signingTime)
    })

    it('should use current time when neither signing time nor timestamp is available', async () => {
      const { getEffectiveSigningTime } = await import('@/core/timestamp/tst-verifier')

      const before = new Date()
      const result = getEffectiveSigningTime(null, null)
      const after = new Date()

      expect(result.getTime()).toBeGreaterThanOrEqual(before.getTime())
      expect(result.getTime()).toBeLessThanOrEqual(after.getTime())
    })

    it('should use timestamp time even when signing time is null', async () => {
      const { getEffectiveSigningTime } = await import('@/core/timestamp/tst-verifier')

      const tsInfo: TimestampInfo = {
        time: new Date('2024-05-15'),
        issuer: 'TSA',
        serialNumber: '01',
        hashAlgorithm: 'SHA-256',
        isValid: true,
      }

      const result = getEffectiveSigningTime(null, tsInfo)
      expect(result).toEqual(tsInfo.time)
    })
  })
})
