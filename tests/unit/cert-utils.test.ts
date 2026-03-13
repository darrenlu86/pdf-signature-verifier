import { describe, it, expect } from 'vitest'
import type { ParsedCertificate, KeyUsageFlags } from '@/types'

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
    subject: 'CN=Test User, O=Test Org',
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

describe('cert-utils', () => {
  describe('isCertificateValid', () => {
    it('should return true when date is within validity period', async () => {
      const { isCertificateValid } = await import('@/core/certificate/cert-utils')

      const cert = createMockCert({
        notBefore: new Date('2024-01-01'),
        notAfter: new Date('2025-12-31'),
      })

      expect(isCertificateValid(cert, new Date('2024-06-15'))).toBe(true)
    })

    it('should return false when date is before notBefore', async () => {
      const { isCertificateValid } = await import('@/core/certificate/cert-utils')

      const cert = createMockCert({
        notBefore: new Date('2024-01-01'),
        notAfter: new Date('2025-12-31'),
      })

      expect(isCertificateValid(cert, new Date('2023-06-15'))).toBe(false)
    })

    it('should return false when date is after notAfter', async () => {
      const { isCertificateValid } = await import('@/core/certificate/cert-utils')

      const cert = createMockCert({
        notBefore: new Date('2024-01-01'),
        notAfter: new Date('2025-12-31'),
      })

      expect(isCertificateValid(cert, new Date('2026-06-15'))).toBe(false)
    })

    it('should return true on exact notBefore boundary', async () => {
      const { isCertificateValid } = await import('@/core/certificate/cert-utils')

      const notBefore = new Date('2024-01-01T00:00:00Z')
      const cert = createMockCert({
        notBefore,
        notAfter: new Date('2025-12-31'),
      })

      expect(isCertificateValid(cert, notBefore)).toBe(true)
    })

    it('should return true on exact notAfter boundary', async () => {
      const { isCertificateValid } = await import('@/core/certificate/cert-utils')

      const notAfter = new Date('2025-12-31T23:59:59Z')
      const cert = createMockCert({
        notBefore: new Date('2024-01-01'),
        notAfter,
      })

      expect(isCertificateValid(cert, notAfter)).toBe(true)
    })
  })

  describe('canSignDocuments', () => {
    it('should return true when cert has digitalSignature and is not CA', async () => {
      const { canSignDocuments } = await import('@/core/certificate/cert-utils')

      const cert = createMockCert({
        keyUsage: { ...createEmptyKeyUsage(), digitalSignature: true },
        isCA: false,
      })

      expect(canSignDocuments(cert)).toBe(true)
    })

    it('should return true when cert has nonRepudiation and is not CA', async () => {
      const { canSignDocuments } = await import('@/core/certificate/cert-utils')

      const cert = createMockCert({
        keyUsage: { ...createEmptyKeyUsage(), nonRepudiation: true },
        isCA: false,
      })

      expect(canSignDocuments(cert)).toBe(true)
    })

    it('should return false when cert has no signing key usage', async () => {
      const { canSignDocuments } = await import('@/core/certificate/cert-utils')

      const cert = createMockCert({
        keyUsage: createEmptyKeyUsage(),
        isCA: false,
      })

      expect(canSignDocuments(cert)).toBe(false)
    })

    it('should return false when cert is CA even with digitalSignature', async () => {
      const { canSignDocuments } = await import('@/core/certificate/cert-utils')

      const cert = createMockCert({
        keyUsage: { ...createEmptyKeyUsage(), digitalSignature: true },
        isCA: true,
      })

      expect(canSignDocuments(cert)).toBe(false)
    })

    it('should return false when cert has only keyEncipherment', async () => {
      const { canSignDocuments } = await import('@/core/certificate/cert-utils')

      const cert = createMockCert({
        keyUsage: { ...createEmptyKeyUsage(), keyEncipherment: true },
        isCA: false,
      })

      expect(canSignDocuments(cert)).toBe(false)
    })
  })

  describe('getCommonName', () => {
    it('should extract CN from subject', async () => {
      const { getCommonName } = await import('@/core/certificate/cert-utils')

      const cert = createMockCert({
        subject: 'CN=John Doe, O=ACME Corp',
      })

      expect(getCommonName(cert)).toBe('John Doe')
    })

    it('should return full subject when CN is not present', async () => {
      const { getCommonName } = await import('@/core/certificate/cert-utils')

      const cert = createMockCert({
        subject: 'O=ACME Corp, C=TW',
      })

      expect(getCommonName(cert)).toBe('O=ACME Corp, C=TW')
    })

    it('should handle CN as the only field', async () => {
      const { getCommonName } = await import('@/core/certificate/cert-utils')

      const cert = createMockCert({
        subject: 'CN=Simple Name',
      })

      expect(getCommonName(cert)).toBe('Simple Name')
    })

    it('should handle CN with special characters', async () => {
      const { getCommonName } = await import('@/core/certificate/cert-utils')

      const cert = createMockCert({
        subject: 'CN=Name (Test), O=Org',
      })

      expect(getCommonName(cert)).toBe('Name (Test)')
    })

    it('should return first CN when subject has multiple parts', async () => {
      const { getCommonName } = await import('@/core/certificate/cert-utils')

      const cert = createMockCert({
        subject: 'C=TW, O=Org, CN=My Cert Name',
      })

      expect(getCommonName(cert)).toBe('My Cert Name')
    })
  })

  describe('pemToDer', () => {
    it('should convert a valid PEM to DER bytes', async () => {
      const { pemToDer } = await import('@/core/certificate/cert-utils')

      // Simple base64-encoded data
      const data = new Uint8Array([0x30, 0x03, 0x01, 0x01, 0xff])
      const base64 = btoa(String.fromCharCode(...data))
      const pem = `-----BEGIN CERTIFICATE-----\n${base64}\n-----END CERTIFICATE-----`

      const der = pemToDer(pem)
      expect(der).toEqual(data)
    })

    it('should handle multi-line PEM', async () => {
      const { pemToDer } = await import('@/core/certificate/cert-utils')

      const data = new Uint8Array(100)
      for (let i = 0; i < data.length; i++) {
        data[i] = i
      }
      const base64 = btoa(String.fromCharCode(...data))
      // Split into 64-char lines
      const lines = []
      for (let i = 0; i < base64.length; i += 64) {
        lines.push(base64.slice(i, i + 64))
      }
      const pem = `-----BEGIN CERTIFICATE-----\n${lines.join('\n')}\n-----END CERTIFICATE-----`

      const der = pemToDer(pem)
      expect(der).toEqual(data)
    })

    it('should ignore lines before BEGIN marker', async () => {
      const { pemToDer } = await import('@/core/certificate/cert-utils')

      const data = new Uint8Array([0x30, 0x03])
      const base64 = btoa(String.fromCharCode(...data))
      const pem = `Some header text\n-----BEGIN CERTIFICATE-----\n${base64}\n-----END CERTIFICATE-----`

      const der = pemToDer(pem)
      expect(der).toEqual(data)
    })
  })

  describe('derToPem', () => {
    it('should convert DER bytes to PEM format', async () => {
      const { derToPem } = await import('@/core/certificate/cert-utils')

      const der = new Uint8Array([0x30, 0x03, 0x01, 0x01, 0xff])
      const pem = derToPem(der)

      expect(pem).toContain('-----BEGIN CERTIFICATE-----')
      expect(pem).toContain('-----END CERTIFICATE-----')
    })

    it('should produce valid base64 in PEM', async () => {
      const { derToPem, pemToDer } = await import('@/core/certificate/cert-utils')

      const original = new Uint8Array([0x30, 0x82, 0x01, 0x00, 0xab, 0xcd, 0xef])
      const pem = derToPem(original)
      const roundTripped = pemToDer(pem)

      expect(roundTripped).toEqual(original)
    })
  })
})
