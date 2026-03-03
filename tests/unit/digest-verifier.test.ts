import { describe, it, expect } from 'vitest'
import {
  computeDigest,
  compareBytes,
  normalizeDigestAlgorithm,
  getDigestLength,
  formatDigest,
  parseHexDigest,
} from '@/core/crypto/digest-verifier'

describe('computeDigest', () => {
  it('should compute SHA-256 digest', async () => {
    const data = new TextEncoder().encode('Hello, World!')
    const digest = await computeDigest('SHA-256', data)

    expect(digest).toBeInstanceOf(Uint8Array)
    expect(digest.length).toBe(32) // SHA-256 produces 32 bytes
  })

  it('should compute SHA-1 digest', async () => {
    const data = new TextEncoder().encode('Hello, World!')
    const digest = await computeDigest('SHA-1', data)

    expect(digest).toBeInstanceOf(Uint8Array)
    expect(digest.length).toBe(20) // SHA-1 produces 20 bytes
  })

  it('should produce different digests for different data', async () => {
    const data1 = new TextEncoder().encode('Hello')
    const data2 = new TextEncoder().encode('World')

    const digest1 = await computeDigest('SHA-256', data1)
    const digest2 = await computeDigest('SHA-256', data2)

    expect(compareBytes(digest1, digest2)).toBe(false)
  })

  it('should produce same digest for same data', async () => {
    const data = new TextEncoder().encode('Test data')

    const digest1 = await computeDigest('SHA-256', data)
    const digest2 = await computeDigest('SHA-256', data)

    expect(compareBytes(digest1, digest2)).toBe(true)
  })
})

describe('compareBytes', () => {
  it('should return true for identical arrays', () => {
    const a = new Uint8Array([1, 2, 3, 4, 5])
    const b = new Uint8Array([1, 2, 3, 4, 5])

    expect(compareBytes(a, b)).toBe(true)
  })

  it('should return false for different arrays', () => {
    const a = new Uint8Array([1, 2, 3, 4, 5])
    const b = new Uint8Array([1, 2, 3, 4, 6])

    expect(compareBytes(a, b)).toBe(false)
  })

  it('should return false for arrays of different lengths', () => {
    const a = new Uint8Array([1, 2, 3])
    const b = new Uint8Array([1, 2, 3, 4])

    expect(compareBytes(a, b)).toBe(false)
  })

  it('should return true for empty arrays', () => {
    const a = new Uint8Array([])
    const b = new Uint8Array([])

    expect(compareBytes(a, b)).toBe(true)
  })
})

describe('normalizeDigestAlgorithm', () => {
  it('should normalize SHA256 to SHA-256', () => {
    expect(normalizeDigestAlgorithm('SHA256')).toBe('SHA-256')
  })

  it('should normalize sha-256 to SHA-256', () => {
    expect(normalizeDigestAlgorithm('sha-256')).toBe('SHA-256')
  })

  it('should normalize SHA1 to SHA-1', () => {
    expect(normalizeDigestAlgorithm('SHA1')).toBe('SHA-1')
  })

  it('should throw for unsupported algorithms', () => {
    expect(() => normalizeDigestAlgorithm('MD5')).toThrow()
  })
})

describe('getDigestLength', () => {
  it('should return 20 for SHA-1', () => {
    expect(getDigestLength('SHA-1')).toBe(20)
  })

  it('should return 32 for SHA-256', () => {
    expect(getDigestLength('SHA-256')).toBe(32)
  })

  it('should return 48 for SHA-384', () => {
    expect(getDigestLength('SHA-384')).toBe(48)
  })

  it('should return 64 for SHA-512', () => {
    expect(getDigestLength('SHA-512')).toBe(64)
  })
})

describe('formatDigest', () => {
  it('should format digest as hex string', () => {
    const digest = new Uint8Array([0x12, 0x34, 0xab, 0xcd])
    expect(formatDigest(digest)).toBe('1234abcd')
  })

  it('should pad single digit bytes with zero', () => {
    const digest = new Uint8Array([0x01, 0x02, 0x0a, 0x0f])
    expect(formatDigest(digest)).toBe('01020a0f')
  })
})

describe('parseHexDigest', () => {
  it('should parse hex string to bytes', () => {
    const hex = '1234abcd'
    const bytes = parseHexDigest(hex)

    expect(bytes).toEqual(new Uint8Array([0x12, 0x34, 0xab, 0xcd]))
  })

  it('should handle uppercase hex', () => {
    const hex = '1234ABCD'
    const bytes = parseHexDigest(hex)

    expect(bytes).toEqual(new Uint8Array([0x12, 0x34, 0xab, 0xcd]))
  })

  it('should strip non-hex characters', () => {
    const hex = '12:34:ab:cd'
    const bytes = parseHexDigest(hex)

    expect(bytes).toEqual(new Uint8Array([0x12, 0x34, 0xab, 0xcd]))
  })
})
