import { describe, it, expect, vi } from 'vitest'
import type { ParsedCertificate, KeyUsageFlags } from '@/types'

// Mock network module to prevent actual fetches
vi.mock('@/core/network', () => ({
  fetchCertificateBytes: vi.fn(() => Promise.resolve(null)),
}))

// Mock cert-utils parseCertificateFromBytes
vi.mock('@/core/certificate/cert-utils', async (importOriginal) => {
  const actual = await importOriginal<Record<string, unknown>>()
  return {
    ...actual,
    parseCertificateFromBytes: vi.fn(() => Promise.resolve(null)),
  }
})

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

describe('chain-builder', () => {
  describe('buildCertificateChain', () => {
    it('should return a single-cert chain for a self-signed certificate', async () => {
      const { buildCertificateChain } = await import('@/core/certificate/chain-builder')

      const selfSigned = createMockCert({
        subject: 'CN=Root CA',
        issuer: 'CN=Root CA',
        isSelfSigned: true,
        fingerprint: 'root-fp',
      })

      const chain = await buildCertificateChain(selfSigned, [])

      expect(chain.certificates).toHaveLength(1)
      expect(chain.isComplete).toBe(true)
      expect(chain.isTrusted).toBe(true)
      expect(chain.root).toBe(selfSigned)
    })

    it('should build a chain from end entity through intermediate to root', async () => {
      const { buildCertificateChain } = await import('@/core/certificate/chain-builder')

      const root = createMockCert({
        subject: 'CN=Root CA',
        issuer: 'CN=Root CA',
        isSelfSigned: true,
        fingerprint: 'root-fp',
        subjectKeyIdentifier: 'root-ski',
      })

      const intermediate = createMockCert({
        subject: 'CN=Intermediate CA',
        issuer: 'CN=Root CA',
        isSelfSigned: false,
        fingerprint: 'int-fp',
        subjectKeyIdentifier: 'int-ski',
        authorityKeyIdentifier: 'root-ski',
      })

      const endEntity = createMockCert({
        subject: 'CN=Signer',
        issuer: 'CN=Intermediate CA',
        isSelfSigned: false,
        fingerprint: 'ee-fp',
        authorityKeyIdentifier: 'int-ski',
      })

      const chain = await buildCertificateChain(endEntity, [intermediate, root])

      expect(chain.certificates).toHaveLength(3)
      expect(chain.certificates[0].subject).toBe('CN=Signer')
      expect(chain.certificates[1].subject).toBe('CN=Intermediate CA')
      expect(chain.certificates[2].subject).toBe('CN=Root CA')
      expect(chain.isComplete).toBe(true)
      expect(chain.isTrusted).toBe(true)
      expect(chain.root?.subject).toBe('CN=Root CA')
    })

    it('should return incomplete chain when issuer is missing', async () => {
      const { buildCertificateChain } = await import('@/core/certificate/chain-builder')

      const endEntity = createMockCert({
        subject: 'CN=Signer',
        issuer: 'CN=Unknown CA',
        isSelfSigned: false,
        fingerprint: 'ee-fp',
      })

      const chain = await buildCertificateChain(endEntity, [])

      expect(chain.certificates).toHaveLength(1)
      expect(chain.isComplete).toBe(false)
      expect(chain.isTrusted).toBe(false)
      expect(chain.root).toBeNull()
    })

    it('should not create cycles when duplicate certs are in pool', async () => {
      const { buildCertificateChain } = await import('@/core/certificate/chain-builder')

      const root = createMockCert({
        subject: 'CN=Root CA',
        issuer: 'CN=Root CA',
        isSelfSigned: true,
        fingerprint: 'root-fp',
      })

      const endEntity = createMockCert({
        subject: 'CN=Signer',
        issuer: 'CN=Root CA',
        isSelfSigned: false,
        fingerprint: 'ee-fp',
      })

      // Provide the root twice
      const chain = await buildCertificateChain(endEntity, [root, root])

      expect(chain.certificates.length).toBeLessThanOrEqual(3)
      expect(chain.isComplete).toBe(true)
    })

    it('should stop building chain when exceeding max length (10)', async () => {
      const { buildCertificateChain } = await import('@/core/certificate/chain-builder')

      // Create a long chain of CAs
      const certs: ParsedCertificate[] = []
      for (let i = 0; i < 15; i++) {
        certs.push(
          createMockCert({
            subject: `CN=CA-${i}`,
            issuer: `CN=CA-${i + 1}`,
            isSelfSigned: false,
            fingerprint: `fp-${i}`,
          })
        )
      }

      const endEntity = createMockCert({
        subject: 'CN=Signer',
        issuer: 'CN=CA-0',
        isSelfSigned: false,
        fingerprint: 'ee-fp',
      })

      const chain = await buildCertificateChain(endEntity, certs)

      // Should cap at 11 (1 end entity + 10 iterations max)
      expect(chain.certificates.length).toBeLessThanOrEqual(11)
    })

    it('should skip mismatched authority key identifiers', async () => {
      const { buildCertificateChain } = await import('@/core/certificate/chain-builder')

      const wrongIssuer = createMockCert({
        subject: 'CN=Root CA',
        issuer: 'CN=Root CA',
        isSelfSigned: true,
        fingerprint: 'wrong-fp',
        subjectKeyIdentifier: 'wrong-ski',
      })

      const endEntity = createMockCert({
        subject: 'CN=Signer',
        issuer: 'CN=Root CA',
        isSelfSigned: false,
        fingerprint: 'ee-fp',
        authorityKeyIdentifier: 'correct-ski',
      })

      const chain = await buildCertificateChain(endEntity, [wrongIssuer])

      // Should not match because AKI doesn't match SKI
      expect(chain.certificates).toHaveLength(1)
      expect(chain.isComplete).toBe(false)
    })
  })

  describe('getChainSummary', () => {
    it('should label end entity as [EE] and root as [Root]', async () => {
      const { getChainSummary } = await import('@/core/certificate/chain-builder')

      const chain = {
        certificates: [
          createMockCert({ subject: 'CN=Signer' }),
          createMockCert({ subject: 'CN=Root CA', isSelfSigned: true }),
        ],
        root: createMockCert({ subject: 'CN=Root CA' }),
        isComplete: true,
        isTrusted: true,
      }

      const summary = getChainSummary(chain)
      expect(summary).toHaveLength(2)
      expect(summary[0]).toContain('[EE]')
      expect(summary[0]).toContain('CN=Signer')
      expect(summary[1]).toContain('[Root]')
      expect(summary[1]).toContain('CN=Root CA')
      expect(summary[1]).toContain('[Trusted]')
    })

    it('should label middle certs as [CA]', async () => {
      const { getChainSummary } = await import('@/core/certificate/chain-builder')

      const chain = {
        certificates: [
          createMockCert({ subject: 'CN=Signer' }),
          createMockCert({ subject: 'CN=Intermediate' }),
          createMockCert({ subject: 'CN=Root CA' }),
        ],
        root: createMockCert({ subject: 'CN=Root CA' }),
        isComplete: true,
        isTrusted: true,
      }

      const summary = getChainSummary(chain)
      expect(summary[1]).toContain('[CA]')
      expect(summary[1]).toContain('CN=Intermediate')
    })

    it('should not show [Trusted] on root if chain is not trusted', async () => {
      const { getChainSummary } = await import('@/core/certificate/chain-builder')

      const chain = {
        certificates: [
          createMockCert({ subject: 'CN=Signer' }),
          createMockCert({ subject: 'CN=Root CA' }),
        ],
        root: null,
        isComplete: false,
        isTrusted: false,
      }

      const summary = getChainSummary(chain)
      expect(summary[1]).not.toContain('[Trusted]')
    })
  })

  describe('verifyIssuedBy', () => {
    it('should return false when issuer name does not match subject', async () => {
      const { verifyIssuedBy } = await import('@/core/certificate/chain-builder')

      const subject = createMockCert({
        issuer: 'CN=Real CA',
      })
      const issuer = createMockCert({
        subject: 'CN=Different CA',
      })

      const result = await verifyIssuedBy(subject, issuer)
      expect(result).toBe(false)
    })

    it('should return false when AKI does not match SKI', async () => {
      const { verifyIssuedBy } = await import('@/core/certificate/chain-builder')

      const subject = createMockCert({
        issuer: 'CN=CA',
        authorityKeyIdentifier: 'aaa',
      })
      const issuer = createMockCert({
        subject: 'CN=CA',
        subjectKeyIdentifier: 'bbb',
      })

      const result = await verifyIssuedBy(subject, issuer)
      expect(result).toBe(false)
    })
  })
})
