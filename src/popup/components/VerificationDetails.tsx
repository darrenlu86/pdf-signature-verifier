import { useState } from 'react'
import type { CheckResult, SignatureResult } from '@/types'
import { t, resolveCheck } from '@/i18n'
import { CheckIcon, XIcon, ChevronRightIcon, ChevronDownIcon } from './icons'

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
  const resolved = resolveCheck(check)

  const StatusIcon = check.passed ? CheckIcon : XIcon
  const iconColor = check.passed ? 'text-green-600' : 'text-red-600'
  const hasDetails = Boolean(resolved.details)

  return (
    <div className="border-b border-gray-100 last:border-b-0">
      <button
        onClick={() => hasDetails && setExpanded(!expanded)}
        className={`w-full flex items-center gap-2 px-2 py-1.5 text-left text-sm ${
          hasDetails ? 'hover:bg-gray-50 cursor-pointer' : 'cursor-default'
        }`}
      >
        {/* Expand indicator */}
        <span className="text-gray-400 w-3 flex-shrink-0">
          {hasDetails ? (
            expanded ? <ChevronDownIcon className="w-3 h-3" /> : <ChevronRightIcon className="w-3 h-3" />
          ) : (
            <span className="inline-block w-3" />
          )}
        </span>

        {/* Label */}
        <span className="text-gray-700 flex-1 truncate">{label}</span>

        {/* Short summary on right */}
        <span className={`${iconColor} flex-shrink-0 text-xs font-medium flex items-center gap-1`}>
          <StatusIcon className="w-3.5 h-3.5 inline-block" />
          <span className="max-w-[140px] truncate">{summary || resolved.message}</span>
        </span>
      </button>

      {/* Expanded details */}
      {expanded && resolved.details && (
        <div className="px-7 pb-2 text-xs text-gray-500 leading-relaxed whitespace-pre-wrap">
          {resolved.details}
        </div>
      )}
    </div>
  )
}

export function VerificationDetails({ checks, chainLength, rootCA }: VerificationDetailsProps) {
  const getSummary = (key: string, check: CheckResult): string => {
    if (!check.passed) {
      return resolveCheck(check).message
    }

    switch (key) {
      case 'integrity':
        return t('checks.verified')
      case 'certificateChain':
        return chainLength ? t('checks.chainComplete', { count: chainLength }) : t('checks.verified')
      case 'trustRoot':
        return rootCA ? truncate(rootCA, 18) : t('checks.trusted')
      case 'validity':
        return t('checks.valid')
      case 'revocation':
        return t('checks.notRevoked')
      case 'timestamp':
        return t('checks.verified')
      case 'ltv':
        return t('checks.complete')
      default:
        return resolveCheck(check).message
    }
  }

  const checkItems: { key: keyof typeof checks; label: string }[] = [
    { key: 'integrity', label: t('checks.integrity') },
    { key: 'certificateChain', label: t('checks.signerIdentity') },
    { key: 'trustRoot', label: t('checks.rootCert') },
    { key: 'validity', label: t('checks.validity') },
    { key: 'revocation', label: t('checks.revocation') },
    { key: 'timestamp', label: t('checks.timestamp') },
    { key: 'ltv', label: t('checks.ltv') },
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
