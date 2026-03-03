import { describe, it, expect } from 'vitest'
import {
  validateByteRange,
  extractSignedBytes,
  checkForPostSignModification,
  getByteRangeDiagnostics,
} from '@/core/pdf/byte-range'
import type { ByteRange } from '@/types'

describe('validateByteRange', () => {
  it('should validate a correct ByteRange', () => {
    // Create mock PDF data with valid structure
    const pdfContent = 'PDF content before signature'
    const signatureHex = '<' + '00'.repeat(100) + '>'
    const pdfContent2 = 'PDF content after signature'

    const fullContent = pdfContent + signatureHex + pdfContent2
    const data = new TextEncoder().encode(fullContent)

    const byteRange: ByteRange = {
      start1: 0,
      length1: pdfContent.length,
      start2: pdfContent.length + signatureHex.length,
      length2: pdfContent2.length,
    }

    const result = validateByteRange(data, byteRange)

    expect(result.isValid).toBe(true)
    expect(result.errors).toHaveLength(0)
  })

  it('should fail if start1 is not 0', () => {
    const data = new Uint8Array(1000)

    const byteRange: ByteRange = {
      start1: 10, // Should be 0
      length1: 100,
      start2: 200,
      length2: 800,
    }

    const result = validateByteRange(data, byteRange)

    expect(result.isValid).toBe(false)
    expect(result.errors.some((e) => e.includes('start1 should be 0'))).toBe(true)
  })

  it('should fail if ranges overlap', () => {
    const data = new Uint8Array(1000)

    const byteRange: ByteRange = {
      start1: 0,
      length1: 200,
      start2: 150, // Overlaps with first range
      length2: 100,
    }

    const result = validateByteRange(data, byteRange)

    expect(result.isValid).toBe(false)
    expect(result.errors.some((e) => e.includes('overlap'))).toBe(true)
  })

  it('should fail if range exceeds file size', () => {
    const data = new Uint8Array(100)

    const byteRange: ByteRange = {
      start1: 0,
      length1: 50,
      start2: 60,
      length2: 100, // Exceeds file size
    }

    const result = validateByteRange(data, byteRange)

    expect(result.isValid).toBe(false)
    expect(result.errors.some((e) => e.includes('exceeds file size'))).toBe(true)
  })
})

describe('extractSignedBytes', () => {
  it('should extract correct signed bytes', () => {
    const data = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 10])

    const byteRange: ByteRange = {
      start1: 0,
      length1: 3, // bytes 1, 2, 3
      start2: 5,
      length2: 3, // bytes 6, 7, 8
    }

    const result = extractSignedBytes(data, byteRange)

    expect(result).toEqual(new Uint8Array([1, 2, 3, 6, 7, 8]))
  })
})

describe('checkForPostSignModification', () => {
  it('should detect no modification when ByteRange covers entire file', () => {
    const data = new Uint8Array(1000)

    const byteRange: ByteRange = {
      start1: 0,
      length1: 400,
      start2: 500,
      length2: 500, // Ends at position 1000
    }

    const result = checkForPostSignModification(data, byteRange)

    expect(result.modified).toBe(false)
    expect(result.additionalBytes).toBe(0)
  })

  it('should detect modification when file has extra content', () => {
    const data = new Uint8Array(1100)

    const byteRange: ByteRange = {
      start1: 0,
      length1: 400,
      start2: 500,
      length2: 500, // Ends at position 1000, but file is 1100
    }

    const result = checkForPostSignModification(data, byteRange)

    expect(result.modified).toBe(true)
    expect(result.additionalBytes).toBe(100)
  })

  it('should allow small trailing content', () => {
    const data = new Uint8Array(1005)

    const byteRange: ByteRange = {
      start1: 0,
      length1: 400,
      start2: 500,
      length2: 500,
    }

    const result = checkForPostSignModification(data, byteRange)

    expect(result.modified).toBe(false) // 5 bytes is within tolerance
    expect(result.additionalBytes).toBe(5)
  })
})

describe('getByteRangeDiagnostics', () => {
  it('should return correct diagnostics', () => {
    const data = new Uint8Array(1000)

    const byteRange: ByteRange = {
      start1: 0,
      length1: 400,
      start2: 500,
      length2: 500,
    }

    const result = getByteRangeDiagnostics(data, byteRange)

    expect(result.fileSize).toBe(1000)
    expect(result.range1).toEqual({ start: 0, end: 400, size: 400 })
    expect(result.range2).toEqual({ start: 500, end: 1000, size: 500 })
    expect(result.gap).toEqual({ start: 400, end: 500, size: 100 })
    expect(result.signedBytes).toBe(900)
    expect(result.unsignedBytes).toBe(100)
    expect(result.coveragePercent).toBe(90)
  })
})
