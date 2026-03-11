import { useState, useCallback } from 'react'
import type { VerificationResult } from '@/types'
import type { VerificationOptions } from '@/core/verifier'
import { t } from '@/i18n'

export interface UseVerificationReturn {
  result: VerificationResult | null
  isLoading: boolean
  error: string | null
  verify: (file: File, options?: VerificationOptions) => Promise<void>
  reset: () => void
}

export function useVerification(): UseVerificationReturn {
  const [result, setResult] = useState<VerificationResult | null>(null)
  const [isLoading, setIsLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const verify = useCallback(async (file: File, options?: VerificationOptions) => {
    setIsLoading(true)
    setError(null)
    setResult(null)

    try {
      const arrayBuffer = await file.arrayBuffer()

      // Run verification directly (works in both popup and tab contexts)
      const { verifyPdfSignatures } = await import('@/core/verifier')
      const verificationResult = await verifyPdfSignatures(
        new Uint8Array(arrayBuffer),
        file.name,
        options
      )
      setResult(verificationResult)
    } catch (err) {
      const message = err instanceof Error ? err.message : t('core.misc.verificationProcessError')
      setError(message)
    } finally {
      setIsLoading(false)
    }
  }, [])

  const reset = useCallback(() => {
    setResult(null)
    setError(null)
    setIsLoading(false)
  }, [])

  return {
    result,
    isLoading,
    error,
    verify,
    reset,
  }
}
