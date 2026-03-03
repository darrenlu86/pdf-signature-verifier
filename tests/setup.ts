import { vi } from 'vitest'

// Mock browser extension APIs
const mockStorage = new Map<string, unknown>()

globalThis.chrome = {
  storage: {
    local: {
      get: vi.fn((keys) => {
        if (typeof keys === 'string') {
          return Promise.resolve({ [keys]: mockStorage.get(keys) })
        }
        const result: Record<string, unknown> = {}
        for (const key of keys) {
          result[key] = mockStorage.get(key)
        }
        return Promise.resolve(result)
      }),
      set: vi.fn((items) => {
        for (const [key, value] of Object.entries(items)) {
          mockStorage.set(key, value)
        }
        return Promise.resolve()
      }),
      remove: vi.fn((keys) => {
        const keyArray = typeof keys === 'string' ? [keys] : keys
        for (const key of keyArray) {
          mockStorage.delete(key)
        }
        return Promise.resolve()
      }),
      clear: vi.fn(() => {
        mockStorage.clear()
        return Promise.resolve()
      }),
    },
    sync: {
      get: vi.fn(() => Promise.resolve({})),
      set: vi.fn(() => Promise.resolve()),
    },
  },
  runtime: {
    sendMessage: vi.fn(() => Promise.resolve()),
    onMessage: {
      addListener: vi.fn(),
      removeListener: vi.fn(),
    },
    getURL: vi.fn((path: string) => `chrome-extension://mock-id/${path}`),
  },
  tabs: {
    query: vi.fn(() => Promise.resolve([])),
    sendMessage: vi.fn(() => Promise.resolve()),
  },
} as unknown as typeof chrome

// Mock crypto.subtle for Node.js environment
if (typeof globalThis.crypto === 'undefined') {
  const { webcrypto } = await import('crypto')
  globalThis.crypto = webcrypto as Crypto
}

// Clear storage between tests
beforeEach(() => {
  mockStorage.clear()
  vi.clearAllMocks()
})
