import { t } from '@/i18n'

interface LoadingSpinnerProps {
  message?: string
}

export function LoadingSpinner({ message }: LoadingSpinnerProps) {
  const displayMessage = message || t('verification.loading')
  return (
    <div className="flex flex-col items-center justify-center py-8">
      <div className="relative w-10 h-10">
        <div className="absolute inset-0 border-4 border-blue-200 rounded-full"></div>
        <div className="absolute inset-0 border-4 border-transparent border-t-blue-600 rounded-full animate-spin"></div>
      </div>
      <div className="mt-3 text-sm text-gray-600">{displayMessage}</div>
    </div>
  )
}
