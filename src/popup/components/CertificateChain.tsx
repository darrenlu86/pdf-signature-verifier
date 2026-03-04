import { useState } from 'react'
import type { CertificateInfo } from '@/types'
import { t, getLocale } from '@/i18n'
import { DocumentIcon, LockIcon, ChainIcon, CheckIcon, ChevronRightIcon, ChevronDownIcon } from './icons'

interface CertificateChainProps {
  certificates: CertificateInfo[]
}

export function CertificateChain({ certificates }: CertificateChainProps) {
  if (certificates.length === 0) {
    return null
  }

  return (
    <div>
      <div className="text-xs font-medium text-gray-500 uppercase tracking-wider mb-2">
        {t('certificate.chainDetails')}
      </div>
      <div className="space-y-1">
        {certificates.map((cert, index) => (
          <CertificateItem
            key={index}
            certificate={cert}
            index={index}
            total={certificates.length}
          />
        ))}
      </div>
    </div>
  )
}

interface CertificateItemProps {
  certificate: CertificateInfo
  index: number
  total: number
}

function CertificateItem({ certificate, index, total }: CertificateItemProps) {
  const [expanded, setExpanded] = useState(false)

  const isEndEntity = index === 0
  const isRoot = index === total - 1 && (certificate.isRoot || total > 1)
  const isIntermediate = !isEndEntity && !isRoot

  const Icon = isEndEntity ? DocumentIcon : isRoot ? LockIcon : ChainIcon

  const roleLabel = isRoot
    ? t('certificate.roleRoot')
    : isIntermediate
      ? t('certificate.roleIntermediate')
      : t('certificate.roleEndEntity')

  const isSelfSigned = certificate.subject === certificate.issuer

  const getCN = (dn: string) => {
    const cn = dn.match(/CN=([^,]+)/)?.[1]
    return cn || dn.split(',')[0]
  }

  const formatDate = (date: Date) => {
    return date.toLocaleDateString(getLocale(), {
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
    })
  }

  return (
    <div className="relative">
      {/* Indentation connector lines */}
      {index > 0 && (
        <div
          className="absolute top-0 bottom-0 border-l-2 border-gray-200"
          style={{ left: `${(index - 1) * 12 + 10}px` }}
        />
      )}

      <div style={{ paddingLeft: `${index * 12}px` }}>
        <button
          onClick={() => setExpanded(!expanded)}
          className="w-full flex items-center gap-2 px-2 py-1.5 rounded hover:bg-gray-50 text-left group"
        >
          <Icon className="flex-shrink-0 text-gray-500" />
          <span className="text-sm font-medium text-gray-900 truncate flex-1">
            {getCN(certificate.subject)}
          </span>

          {/* Role badge */}
          <span className="text-[10px] px-1.5 py-0.5 rounded bg-gray-100 text-gray-500 flex-shrink-0">
            {roleLabel}
          </span>

          {isRoot && isSelfSigned && (
            <span className="text-[10px] px-1.5 py-0.5 rounded bg-blue-50 text-blue-600 flex-shrink-0">
              {t('certificate.selfSigned')}
            </span>
          )}

          {certificate.isTrusted && (
            <CheckIcon className="text-green-600 flex-shrink-0" />
          )}

          <span className="text-gray-400 flex-shrink-0">
            {expanded ? <ChevronDownIcon className="w-3 h-3" /> : <ChevronRightIcon className="w-3 h-3" />}
          </span>
        </button>

        {/* Expanded certificate details */}
        {expanded && (
          <div className="ml-8 mb-2 p-3 bg-gray-50 rounded-lg text-xs space-y-2 border border-gray-100">
            {/* Subject */}
            <div>
              <div className="text-gray-400 mb-0.5">{t('certificate.subject')}</div>
              <div className="text-gray-900 font-medium">{getCN(certificate.subject)}</div>
              <div className="text-gray-500 text-[10px] break-all">{certificate.subject}</div>
            </div>

            {/* Issuer */}
            <div>
              <div className="text-gray-400 mb-0.5">{t('certificate.issuer')}</div>
              <div className="text-gray-900 font-medium">{getCN(certificate.issuer)}</div>
              <div className="text-gray-500 text-[10px] break-all">{certificate.issuer}</div>
            </div>

            {/* Serial number - full, not truncated */}
            <div>
              <div className="text-gray-400 mb-0.5">{t('certificate.serial')}</div>
              <div className="text-gray-800 font-mono text-[10px] break-all select-all">
                {certificate.serialNumber}
              </div>
            </div>

            {/* Validity period */}
            <div>
              <div className="text-gray-400 mb-0.5">{t('certificate.validity')}</div>
              <div className="text-gray-800">
                {t('core.misc.validityTo', { from: formatDate(certificate.notBefore), to: formatDate(certificate.notAfter) })}
              </div>
            </div>

            {/* Fingerprint */}
            {certificate.fingerprint && (
              <div>
                <div className="text-gray-400 mb-0.5">{t('certificate.fingerprint')}</div>
                <div className="text-gray-800 font-mono text-[10px] break-all select-all">
                  {certificate.fingerprint}
                </div>
              </div>
            )}

            {/* Key Usage */}
            {certificate.keyUsage && certificate.keyUsage.length > 0 && (
              <div>
                <div className="text-gray-400 mb-0.5">{t('certificate.keyUsage')}</div>
                <div className="text-gray-800 text-[10px]">
                  {certificate.keyUsage.join(', ')}
                </div>
              </div>
            )}

            {/* Extended Key Usage */}
            {certificate.extKeyUsage && certificate.extKeyUsage.length > 0 && (
              <div>
                <div className="text-gray-400 mb-0.5">{t('certificate.extKeyUsage')}</div>
                <div className="text-gray-800 text-[10px]">
                  {certificate.extKeyUsage.join(', ')}
                </div>
              </div>
            )}

            {/* Trust status */}
            {certificate.isTrusted && (
              <div className="flex items-center gap-1 text-green-600 pt-1 border-t border-gray-200">
                <CheckIcon className="inline-block" />
                <span>{t('certificate.inTrustStore')}</span>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  )
}
