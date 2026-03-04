import type { SignatureResult } from '@/types'
import { SignatureCard } from './SignatureCard'
import { DocumentIcon } from './icons'
import { t } from '@/i18n'

interface SignatureListProps {
  signatures: SignatureResult[]
}

export function SignatureList({ signatures }: SignatureListProps) {
  if (signatures.length === 0) {
    return (
      <div className="text-center py-8 text-gray-500">
        <div className="flex justify-center mb-2">
          <DocumentIcon className="w-10 h-10 text-gray-400" />
        </div>
        <div>{t('verification.noSignatures')}</div>
      </div>
    )
  }

  return (
    <div className="space-y-3">
      {signatures.map((sig) => (
        <SignatureCard key={sig.index} signature={sig} />
      ))}
    </div>
  )
}
