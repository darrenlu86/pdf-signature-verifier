import type { SignatureResult } from '@/types'
import { SignatureCard } from './SignatureCard'

interface SignatureListProps {
  signatures: SignatureResult[]
}

export function SignatureList({ signatures }: SignatureListProps) {
  if (signatures.length === 0) {
    return (
      <div className="text-center py-8 text-gray-500">
        <div className="text-4xl mb-2">📄</div>
        <div>此文件沒有數位簽章</div>
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
