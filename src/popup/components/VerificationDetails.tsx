import { useState } from 'react'
import type { CheckResult, SignatureResult } from '@/types'

interface VerificationDetailsProps {
  checks: SignatureResult['checks']
  chainLength?: number
  rootCA?: string | null
}

interface CheckRowProps {
  label: string
  check: CheckResult
  summary?: string
}

function CheckRow({ label, check, summary }: CheckRowProps) {
  const [expanded, setExpanded] = useState(false)

  const icon = check.passed ? '✓' : '✗'
  const iconColor = check.passed ? 'text-green-600' : 'text-red-600'
  const hasDetails = Boolean(check.details)

  return (
    <div className="border-b border-gray-100 last:border-b-0">
      <button
        onClick={() => hasDetails && setExpanded(!expanded)}
        className={`w-full flex items-center gap-2 px-2 py-1.5 text-left text-sm ${
          hasDetails ? 'hover:bg-gray-50 cursor-pointer' : 'cursor-default'
        }`}
      >
        {/* Expand indicator */}
        <span className="text-gray-400 text-xs w-3 flex-shrink-0">
          {hasDetails ? (expanded ? '▾' : '▸') : ' '}
        </span>

        {/* Label */}
        <span className="text-gray-700 flex-1 truncate">{label}</span>

        {/* Short summary on right */}
        <span className={`${iconColor} flex-shrink-0 text-xs font-medium flex items-center gap-1`}>
          <span className="font-bold">{icon}</span>
          <span className="max-w-[140px] truncate">{summary || check.message}</span>
        </span>
      </button>

      {/* Expanded details */}
      {expanded && check.details && (
        <div className="px-7 pb-2 text-xs text-gray-500 leading-relaxed whitespace-pre-wrap">
          {check.details}
        </div>
      )}
    </div>
  )
}

export function VerificationDetails({ checks, chainLength, rootCA }: VerificationDetailsProps) {
  const getSummary = (key: string, check: CheckResult): string => {
    if (!check.passed) {
      return check.message
    }

    switch (key) {
      case 'integrity':
        return '已驗證'
      case 'certificateChain':
        return chainLength ? `完整 (${chainLength}張)` : '已驗證'
      case 'trustRoot':
        return rootCA ? truncate(rootCA, 18) : '已信任'
      case 'validity':
        return '有效'
      case 'revocation':
        return '未撤銷'
      case 'timestamp':
        return '已驗證'
      case 'ltv':
        return '完整'
      default:
        return check.message
    }
  }

  const checkItems: { key: keyof typeof checks; label: string }[] = [
    { key: 'integrity', label: '文件完整性' },
    { key: 'certificateChain', label: '簽署者身分' },
    { key: 'trustRoot', label: '根憑證' },
    { key: 'validity', label: '有效期限' },
    { key: 'revocation', label: '撤銷狀態' },
    { key: 'timestamp', label: '時戳' },
    { key: 'ltv', label: 'LTV' },
  ]

  return (
    <div>
      <div className="border border-gray-200 rounded-lg overflow-hidden bg-white">
        {checkItems.map(({ key, label }) => {
          const check = checks[key]
          if (!check) return null
          return (
            <CheckRow
              key={key}
              label={label}
              check={check}
              summary={getSummary(key, check)}
            />
          )
        })}
      </div>
    </div>
  )
}

function truncate(str: string, max: number): string {
  if (str.length <= max) return str
  return `${str.slice(0, max)}..`
}
