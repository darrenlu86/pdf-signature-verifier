import { useState } from 'react'
import type { CertificateInfo } from '@/types'

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
        憑證鏈詳情
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

  const icon = isEndEntity ? '📄' : isRoot ? '🔐' : '🔗'

  const roleLabel = isRoot
    ? '根 CA'
    : isIntermediate
      ? '中間 CA'
      : '簽署者憑證'

  const isSelfSigned = certificate.subject === certificate.issuer

  const getCN = (dn: string) => {
    const cn = dn.match(/CN=([^,]+)/)?.[1]
    return cn || dn.split(',')[0]
  }

  const formatDate = (date: Date) => {
    return date.toLocaleDateString('zh-TW', {
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
          <span className="flex-shrink-0">{icon}</span>
          <span className="text-sm font-medium text-gray-900 truncate flex-1">
            {getCN(certificate.subject)}
          </span>

          {/* Role badge */}
          <span className="text-[10px] px-1.5 py-0.5 rounded bg-gray-100 text-gray-500 flex-shrink-0">
            {roleLabel}
          </span>

          {isRoot && isSelfSigned && (
            <span className="text-[10px] px-1.5 py-0.5 rounded bg-blue-50 text-blue-600 flex-shrink-0">
              自簽
            </span>
          )}

          {certificate.isTrusted && (
            <span className="text-green-600 text-xs flex-shrink-0">✓</span>
          )}

          <span className="text-gray-400 text-xs flex-shrink-0">
            {expanded ? '▾' : '▸'}
          </span>
        </button>

        {/* Expanded certificate details */}
        {expanded && (
          <div className="ml-8 mb-2 p-3 bg-gray-50 rounded-lg text-xs space-y-2 border border-gray-100">
            {/* Subject */}
            <div>
              <div className="text-gray-400 mb-0.5">主體</div>
              <div className="text-gray-900 font-medium">{getCN(certificate.subject)}</div>
              <div className="text-gray-500 text-[10px] break-all">{certificate.subject}</div>
            </div>

            {/* Issuer */}
            <div>
              <div className="text-gray-400 mb-0.5">發行者</div>
              <div className="text-gray-900 font-medium">{getCN(certificate.issuer)}</div>
              <div className="text-gray-500 text-[10px] break-all">{certificate.issuer}</div>
            </div>

            {/* Serial number - full, not truncated */}
            <div>
              <div className="text-gray-400 mb-0.5">序號</div>
              <div className="text-gray-800 font-mono text-[10px] break-all select-all">
                {certificate.serialNumber}
              </div>
            </div>

            {/* Validity period */}
            <div>
              <div className="text-gray-400 mb-0.5">有效期</div>
              <div className="text-gray-800">
                {formatDate(certificate.notBefore)} 至 {formatDate(certificate.notAfter)}
              </div>
            </div>

            {/* Fingerprint */}
            {certificate.fingerprint && (
              <div>
                <div className="text-gray-400 mb-0.5">指紋</div>
                <div className="text-gray-800 font-mono text-[10px] break-all select-all">
                  {certificate.fingerprint}
                </div>
              </div>
            )}

            {/* Key Usage */}
            {certificate.keyUsage && certificate.keyUsage.length > 0 && (
              <div>
                <div className="text-gray-400 mb-0.5">金鑰用途</div>
                <div className="text-gray-800 text-[10px]">
                  {certificate.keyUsage.join(', ')}
                </div>
              </div>
            )}

            {/* Extended Key Usage */}
            {certificate.extKeyUsage && certificate.extKeyUsage.length > 0 && (
              <div>
                <div className="text-gray-400 mb-0.5">延伸金鑰用途</div>
                <div className="text-gray-800 text-[10px]">
                  {certificate.extKeyUsage.join(', ')}
                </div>
              </div>
            )}

            {/* Trust status */}
            {certificate.isTrusted && (
              <div className="flex items-center gap-1 text-green-600 pt-1 border-t border-gray-200">
                <span>✓</span>
                <span>此憑證存在於信任儲存庫中</span>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  )
}
