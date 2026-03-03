import { describe, it, expect } from 'vitest'
import {
  createFailedCheck,
  createPassedCheck,
  determineOverallStatus,
  type SignatureResult,
  type CheckResult,
} from '@/types'

describe('createFailedCheck', () => {
  it('should create a failed check with message', () => {
    const check = createFailedCheck('Test failure')
    expect(check.passed).toBe(false)
    expect(check.message).toBe('Test failure')
    expect(check.details).toBeUndefined()
  })

  it('should create a failed check with details', () => {
    const check = createFailedCheck('Test failure', 'Additional details')
    expect(check.passed).toBe(false)
    expect(check.message).toBe('Test failure')
    expect(check.details).toBe('Additional details')
  })
})

describe('createPassedCheck', () => {
  it('should create a passed check with message', () => {
    const check = createPassedCheck('Test passed')
    expect(check.passed).toBe(true)
    expect(check.message).toBe('Test passed')
    expect(check.details).toBeUndefined()
  })

  it('should create a passed check with details', () => {
    const check = createPassedCheck('Test passed', 'Additional info')
    expect(check.passed).toBe(true)
    expect(check.message).toBe('Test passed')
    expect(check.details).toBe('Additional info')
  })
})

describe('determineOverallStatus', () => {
  const createMockSignature = (status: 'trusted' | 'unknown' | 'failed'): SignatureResult => ({
    index: 0,
    signerName: 'Test',
    signedAt: null,
    status,
    checks: {
      integrity: createPassedCheck('OK'),
      certificateChain: createPassedCheck('OK'),
      trustRoot: createPassedCheck('OK'),
      validity: createPassedCheck('OK'),
      revocation: createPassedCheck('OK'),
      timestamp: null,
      ltv: createPassedCheck('OK'),
    },
    certificateChain: [],
  })

  it('should return unknown for empty signatures', () => {
    expect(determineOverallStatus([])).toBe('unknown')
  })

  it('should return trusted when all signatures are trusted', () => {
    const signatures = [
      createMockSignature('trusted'),
      createMockSignature('trusted'),
    ]
    expect(determineOverallStatus(signatures)).toBe('trusted')
  })

  it('should return failed when any signature failed', () => {
    const signatures = [
      createMockSignature('trusted'),
      createMockSignature('failed'),
    ]
    expect(determineOverallStatus(signatures)).toBe('failed')
  })

  it('should return unknown when any signature is unknown (but none failed)', () => {
    const signatures = [
      createMockSignature('trusted'),
      createMockSignature('unknown'),
    ]
    expect(determineOverallStatus(signatures)).toBe('unknown')
  })

  it('should return failed over unknown', () => {
    const signatures = [
      createMockSignature('unknown'),
      createMockSignature('failed'),
    ]
    expect(determineOverallStatus(signatures)).toBe('failed')
  })
})
