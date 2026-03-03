import { describe, it, expect, beforeEach } from 'vitest'
import {
  initializeTrustStore,
  getTrustAnchors,
  clearTrustAnchors,
  getTrustStoreStats,
  TAIWAN_ROOT_CERTIFICATES,
} from '@/trust-store'

describe('Trust Store', () => {
  beforeEach(() => {
    clearTrustAnchors()
  })

  describe('TAIWAN_ROOT_CERTIFICATES', () => {
    it('should be an empty array (trust model uses embedded chain verification)', () => {
      expect(TAIWAN_ROOT_CERTIFICATES).toEqual([])
    })
  })

  describe('initializeTrustStore', () => {
    it('should initialize with empty anchors (no pre-loaded CAs)', async () => {
      const anchors = await initializeTrustStore()
      expect(anchors).toEqual([])
    })

    it('should return cached anchors on subsequent calls', async () => {
      const anchors1 = await initializeTrustStore()
      const anchors2 = await initializeTrustStore()
      expect(anchors1).toBe(anchors2)
    })
  })

  describe('getTrustAnchors', () => {
    it('should return empty array before initialization', () => {
      const anchors = getTrustAnchors()
      expect(anchors).toEqual([])
    })

    it('should return empty array after initialization (no pre-loaded CAs)', async () => {
      await initializeTrustStore()
      const anchors = getTrustAnchors()
      expect(anchors).toEqual([])
    })
  })

  describe('getTrustStoreStats', () => {
    it('should return zero anchors', async () => {
      await initializeTrustStore()
      const stats = getTrustStoreStats()
      expect(stats.totalAnchors).toBe(0)
      expect(stats.anchors).toEqual([])
    })
  })

  describe('clearTrustAnchors', () => {
    it('should clear the trust anchor cache', async () => {
      await initializeTrustStore()
      clearTrustAnchors()
      expect(getTrustAnchors()).toEqual([])
    })
  })
})
