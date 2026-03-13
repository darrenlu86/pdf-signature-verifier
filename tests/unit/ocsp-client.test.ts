import { describe, it, expect, vi } from 'vitest'
import type { ParsedCertificate, KeyUsageFlags } from '@/types'

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
  fetchOcspResponse: vi.fn(() => Promise.resolve(null)),
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
    raw: {
      subject: { toSchema: () => ({ toBER: () => new ArrayBuffer(10) }) },
      subjectPublicKeyInfo: {
        subjectPublicKey: {
          valueBlock: { valueHexView: new Uint8Array(32) },
        },
      },
      serialNumber: {
        valueBlock: { valueHexView: new Uint8Array([0x01, 0x02]) },
      },
    } as unknown as ParsedCertificate['raw'],
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

describe('ocsp-client', () => {
  describe('checkOcspStatus', () => {
    it('should return unknown when no OCSP URLs are available', async () => {
      const { checkOcspStatus } = await import('@/core/revocation/ocsp-client')

      const cert = createMockCert({ authorityInfoAccess: null })
      const issuer = createMockCert({})

      const result = await checkOcspStatus(cert, issuer)

      expect(result.status).toBe('unknown')
      expect(result.method).toBe('ocsp')
    })

    it('should return unknown when OCSP URLs is empty', async () => {
      const { checkOcspStatus } = await import('@/core/revocation/ocsp-client')

      const cert = createMockCert({
        authorityInfoAccess: { ocsp: [], caIssuers: [] },
      })
      const issuer = createMockCert({})

      const result = await checkOcspStatus(cert, issuer)

      expect(result.status).toBe('unknown')
    })

    it('should return error when all OCSP queries fail', async () => {
      const { checkOcspStatus } = await import('@/core/revocation/ocsp-client')

      const cert = createMockCert({
        authorityInfoAccess: {
          ocsp: ['http://ocsp.example.com', 'http://ocsp2.example.com'],
          caIssuers: [],
        },
      })
      const issuer = createMockCert({})

      const result = await checkOcspStatus(cert, issuer)

      expect(result.status).toBe('error')
      expect(result.method).toBe('ocsp')
    })

    it('should include checkedAt timestamp', async () => {
      const { checkOcspStatus } = await import('@/core/revocation/ocsp-client')

      const before = new Date()
      const cert = createMockCert({ authorityInfoAccess: null })
      const issuer = createMockCert({})
      const result = await checkOcspStatus(cert, issuer)
      const after = new Date()

      expect(result.checkedAt.getTime()).toBeGreaterThanOrEqual(before.getTime())
      expect(result.checkedAt.getTime()).toBeLessThanOrEqual(after.getTime())
    })

    it('should include details string', async () => {
      const { checkOcspStatus } = await import('@/core/revocation/ocsp-client')

      const cert = createMockCert({ authorityInfoAccess: null })
      const issuer = createMockCert({})
      const result = await checkOcspStatus(cert, issuer)

      expect(result.details).toBeDefined()
      expect(typeof result.details).toBe('string')
    })
  })

  describe('parseEmbeddedOcspResponse', () => {
    it('should return error for completely invalid data', async () => {
      const { parseEmbeddedOcspResponse } = await import('@/core/revocation/ocsp-client')

      const result = parseEmbeddedOcspResponse(new Uint8Array([0x00, 0x01, 0x02]))

      expect(result.status).toBe('error')
      expect(result.method).toBe('embedded')
    })

    it('should return error for empty data', async () => {
      const { parseEmbeddedOcspResponse } = await import('@/core/revocation/ocsp-client')

      const result = parseEmbeddedOcspResponse(new Uint8Array(0))

      expect(result.status).toBe('error')
      expect(result.method).toBe('embedded')
    })

    it('should return error for truncated ASN.1', async () => {
      const { parseEmbeddedOcspResponse } = await import('@/core/revocation/ocsp-client')

      // Truncated sequence header
      const result = parseEmbeddedOcspResponse(new Uint8Array([0x30, 0x82, 0x01]))

      expect(result.status).toBe('error')
    })

    it('should have detailsI18nKey on error result', async () => {
      const { parseEmbeddedOcspResponse } = await import('@/core/revocation/ocsp-client')

      const result = parseEmbeddedOcspResponse(new Uint8Array([0xff]))

      expect(result.detailsI18nKey).toBe('core.revocation.cannotParseEmbeddedOcsp')
    })

    it('should include checkedAt on error result', async () => {
      const { parseEmbeddedOcspResponse } = await import('@/core/revocation/ocsp-client')

      const result = parseEmbeddedOcspResponse(new Uint8Array([0x00]))

      expect(result.checkedAt).toBeInstanceOf(Date)
    })
  })
})
