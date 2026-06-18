import type { ByteRange } from '@/types'

export interface ByteRangeValidation {
  isValid: boolean
  errors: string[]
  warnings: string[]
  /**
   * Audit P1-4: bytes after the signed range. Separated from `errors` so
   * the verifier can decide policy (multi-sig demote vs wrapping fail).
   */
  trailingUnsignedBytes: number
  /** True if the trailing bytes are only EOL whitespace (allowed). */
  trailingIsWhitespaceOnly: boolean
}

/**
 * Validate ByteRange integrity
 * Checks that the ByteRange covers the entire document except the signature contents
 */
export function validateByteRange(
  data: Uint8Array,
  byteRange: ByteRange
): ByteRangeValidation {
  const errors: string[] = []
  const warnings: string[] = []

  const { start1, length1, start2, length2 } = byteRange
  const fileSize = data.length

  // Check start1 should be 0
  if (start1 !== 0) {
    errors.push(`ByteRange start1 should be 0, got ${start1}`)
  }

  // Check that start2 > start1 + length1
  if (start2 <= start1 + length1) {
    errors.push('ByteRange ranges overlap or are not sequential')
  }

  // Check that ranges don't exceed file size
  if (start1 + length1 > fileSize) {
    errors.push('First ByteRange exceeds file size')
  }

  if (start2 + length2 > fileSize) {
    errors.push('Second ByteRange exceeds file size')
  }

  // Audit P1-4: report the unsigned tail but DON'T fail validation here.
  // The verifier decides whether the tail is benign (post-sign incremental
  // updates allowed by DocMDP, or covered by a later signature) or malicious
  // (signature wrapping). Validation only fails for structural errors.
  const coveredEnd = start2 + length2
  const trailing = Math.max(0, fileSize - coveredEnd)
  let trailingIsWhitespaceOnly = false
  if (trailing > 0) {
    const tail = data.slice(coveredEnd, fileSize)
    trailingIsWhitespaceOnly =
      trailing <= 2 &&
      Array.from(tail).every((b) => b === 0x0a || b === 0x0d)
    if (!trailingIsWhitespaceOnly) {
      warnings.push(
        `ByteRange ends ${trailing} bytes before file end (covered ${coveredEnd}, size ${fileSize}). ` +
          `Caller must verify this is a permitted post-sign change or a later-signature update.`
      )
    }
  } else {
    trailingIsWhitespaceOnly = true
  }

  // Verify the gap contains the signature hex string
  const gapStart = start1 + length1
  const gapEnd = start2
  const gapContent = data.slice(gapStart, gapEnd)

  if (!isValidSignatureGap(gapContent)) {
    errors.push('Gap between ByteRanges does not contain valid hex signature')
  }

  return {
    isValid: errors.length === 0,
    errors,
    warnings,
    trailingUnsignedBytes: trailing,
    trailingIsWhitespaceOnly,
  }
}

/**
 * Check if the gap content is a valid hex-encoded signature
 */
function isValidSignatureGap(gapContent: Uint8Array): boolean {
  const text = new TextDecoder('latin1').decode(gapContent)

  // Should start with < and end with >
  const trimmed = text.trim()
  if (!trimmed.startsWith('<') || !trimmed.endsWith('>')) {
    return false
  }

  // Content between < > should be hex characters (or whitespace/padding)
  const hexContent = trimmed.slice(1, -1)
  const isHex = /^[0-9A-Fa-f\s]*$/.test(hexContent)

  return isHex
}

/**
 * Extract the signed byte ranges from the PDF data
 */
export function extractSignedBytes(
  data: Uint8Array,
  byteRange: ByteRange
): Uint8Array {
  const { start1, length1, start2, length2 } = byteRange

  const result = new Uint8Array(length1 + length2)
  result.set(data.slice(start1, start1 + length1), 0)
  result.set(data.slice(start2, start2 + length2), length1)

  return result
}

/**
 * Check if document has been modified after signing
 * by examining if there's content after the last ByteRange.
 *
 * Returns `modified: true` for ANY non-whitespace byte after the signed range,
 * tightened from the original 10-byte tolerance (audit P1-4). Trailing
 * whitespace (≤2 bytes of LF/CR) is permitted to match PDF EOL conventions.
 */
export function checkForPostSignModification(
  data: Uint8Array,
  byteRange: ByteRange
): { modified: boolean; additionalBytes: number; tailIsWhitespaceOnly: boolean } {
  const { start2, length2 } = byteRange
  const signedEnd = start2 + length2
  const fileSize = data.length

  const additionalBytes = Math.max(0, fileSize - signedEnd)
  if (additionalBytes === 0) {
    return { modified: false, additionalBytes: 0, tailIsWhitespaceOnly: true }
  }

  const tail = data.slice(signedEnd, fileSize)
  const tailIsWhitespaceOnly =
    additionalBytes <= 2 &&
    Array.from(tail).every((b) => b === 0x0a || b === 0x0d)

  return {
    modified: !tailIsWhitespaceOnly,
    additionalBytes,
    tailIsWhitespaceOnly,
  }
}

/**
 * Extract the raw signature contents from the gap
 */
export function extractSignatureContents(
  data: Uint8Array,
  byteRange: ByteRange
): Uint8Array {
  const { start1, length1, start2 } = byteRange

  const gapStart = start1 + length1
  const gapContent = data.slice(gapStart, start2)

  // Remove < > and decode hex
  const text = new TextDecoder('latin1').decode(gapContent)
  const hexMatch = text.match(/<([0-9A-Fa-f\s]+)>/)

  if (!hexMatch) {
    throw new Error('Invalid signature contents format')
  }

  const hex = hexMatch[1].replace(/\s/g, '')
  const bytes = new Uint8Array(hex.length / 2)

  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16)
  }

  // Remove trailing zeros (padding)
  let end = bytes.length
  while (end > 0 && bytes[end - 1] === 0) {
    end--
  }

  return bytes.slice(0, end)
}

/**
 * Get diagnostic information about the ByteRange
 */
export function getByteRangeDiagnostics(
  data: Uint8Array,
  byteRange: ByteRange
): {
  fileSize: number
  range1: { start: number; end: number; size: number }
  range2: { start: number; end: number; size: number }
  gap: { start: number; end: number; size: number }
  signedBytes: number
  unsignedBytes: number
  coveragePercent: number
} {
  const { start1, length1, start2, length2 } = byteRange
  const fileSize = data.length

  const range1End = start1 + length1
  const range2End = start2 + length2
  const gapSize = start2 - range1End
  const signedBytes = length1 + length2
  const unsignedBytes = fileSize - signedBytes

  return {
    fileSize,
    range1: { start: start1, end: range1End, size: length1 },
    range2: { start: start2, end: range2End, size: length2 },
    gap: { start: range1End, end: start2, size: gapSize },
    signedBytes,
    unsignedBytes,
    coveragePercent: (signedBytes / fileSize) * 100,
  }
}
