import type { VerificationStatus } from '@/types'
import { CheckIcon, XIcon, WarningIcon } from './icons'

interface StatusBadgeProps {
  status: VerificationStatus
  size?: 'sm' | 'md' | 'lg'
}

const statusConfig = {
  trusted: {
    Icon: CheckIcon,
    label: '文件可信',
    labelEn: 'Trusted',
    className: 'bg-green-100 text-green-800',
  },
  unknown: {
    Icon: WarningIcon,
    label: '來源未知',
    labelEn: 'Unknown',
    className: 'bg-yellow-100 text-yellow-800',
  },
  failed: {
    Icon: XIcon,
    label: '驗證失敗',
    labelEn: 'Failed',
    className: 'bg-red-100 text-red-800',
  },
}

const sizeClasses = {
  sm: 'text-xs px-2 py-0.5',
  md: 'text-sm px-2.5 py-1',
  lg: 'text-base px-3 py-1.5',
}

export function StatusBadge({ status, size = 'md' }: StatusBadgeProps) {
  const config = statusConfig[status]
  const { Icon } = config

  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-full font-medium ${config.className} ${sizeClasses[size]}`}
    >
      <Icon className="inline-block" />
      <span>{config.label}</span>
    </span>
  )
}

interface StatusIconProps {
  status: VerificationStatus
  size?: 'sm' | 'md' | 'lg'
}

const iconSizes = {
  sm: 'text-sm',
  md: 'text-base',
  lg: 'text-lg',
}

export function StatusIcon({ status, size = 'md' }: StatusIconProps) {
  const config = statusConfig[status]
  const { Icon } = config

  const colorClass =
    status === 'trusted'
      ? 'text-green-600'
      : status === 'unknown'
      ? 'text-yellow-600'
      : 'text-red-600'

  return (
    <span className={`${colorClass} ${iconSizes[size]}`}>
      <Icon className="inline-block" />
    </span>
  )
}
