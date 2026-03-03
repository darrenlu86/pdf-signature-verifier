import * as asn1js from 'asn1js'
import * as pkijs from 'pkijs'
import type { ParsedCertificate, RevocationResult, RevocationReason } from '@/types'

const { OCSPRequest, OCSPResponse, BasicOCSPResponse, CertID } = pkijs

/**
 * Check certificate revocation status via OCSP
 */
export async function checkOcspStatus(
  certificate: ParsedCertificate,
  issuerCertificate: ParsedCertificate
): Promise<RevocationResult> {
  const ocspUrls = certificate.authorityInfoAccess?.ocsp || []

  if (ocspUrls.length === 0) {
    return {
      status: 'unknown',
      checkedAt: new Date(),
      method: 'ocsp',
      details: 'No OCSP responder URL in certificate',
    }
  }

  for (const url of ocspUrls) {
    try {
      const result = await queryOcsp(url, certificate, issuerCertificate)
      return result
    } catch (error) {
      console.warn(`OCSP query to ${url} failed:`, error)
      continue
    }
  }

  return {
    status: 'error',
    checkedAt: new Date(),
    method: 'ocsp',
    details: 'All OCSP responders failed',
  }
}

/**
 * Query a single OCSP responder
 */
async function queryOcsp(
  url: string,
  certificate: ParsedCertificate,
  issuerCertificate: ParsedCertificate
): Promise<RevocationResult> {
  // Build OCSP request
  const ocspRequest = await buildOcspRequest(certificate, issuerCertificate)
  const requestData = ocspRequest.toSchema().toBER()

  // Send request via background script (to avoid CORS issues)
  const response = await sendOcspRequest(url, new Uint8Array(requestData))

  if (!response) {
    throw new Error('No response from OCSP responder')
  }

  // Parse response
  return parseOcspResponse(response)
}

/**
 * Build OCSP request for a certificate
 */
async function buildOcspRequest(
  certificate: ParsedCertificate,
  issuerCertificate: ParsedCertificate
): Promise<pkijs.OCSPRequest> {
  // Create CertID
  const certId = new CertID()

  // Set hash algorithm (SHA-1 is standard for OCSP)
  certId.hashAlgorithm = new pkijs.AlgorithmIdentifier({
    algorithmId: '1.3.14.3.2.26', // SHA-1
  })

  // Hash issuer name
  const issuerNameHash = await crypto.subtle.digest(
    'SHA-1',
    issuerCertificate.raw.subject.toSchema().toBER()
  )
  certId.issuerNameHash = new asn1js.OctetString({
    valueHex: issuerNameHash,
  })

  // Hash issuer public key
  const issuerKeyHash = await crypto.subtle.digest(
    'SHA-1',
    issuerCertificate.raw.subjectPublicKeyInfo.subjectPublicKey.valueBlock.valueHexView
  )
  certId.issuerKeyHash = new asn1js.OctetString({
    valueHex: issuerKeyHash,
  })

  // Set serial number
  certId.serialNumber = certificate.raw.serialNumber

  // Create request
  const ocspRequest = new OCSPRequest()
  ocspRequest.tbsRequest = new pkijs.TBSRequest({
    requestList: [
      new pkijs.Request({
        reqCert: certId,
      }),
    ],
  })

  return ocspRequest
}

/**
 * Parse OCSP response
 */
function parseOcspResponse(data: Uint8Array): RevocationResult {
  const asn1 = asn1js.fromBER(data.buffer)
  if (asn1.offset === -1) {
    throw new Error('Failed to parse OCSP response ASN.1')
  }

  const ocspResponse = new OCSPResponse({ schema: asn1.result })

  // Check response status
  const responseStatus = ocspResponse.responseStatus.valueBlock.valueDec
  if (responseStatus !== 0) {
    // 0 = successful
    return {
      status: 'error',
      checkedAt: new Date(),
      method: 'ocsp',
      details: `OCSP response status: ${getOcspStatusText(responseStatus)}`,
    }
  }

  // Parse basic response
  if (!ocspResponse.responseBytes) {
    throw new Error('No response bytes in OCSP response')
  }

  const responseData = ocspResponse.responseBytes.response.valueBlock.valueHexView
  const basicAsn1 = asn1js.fromBER(responseData)
  if (basicAsn1.offset === -1) {
    throw new Error('Failed to parse BasicOCSPResponse')
  }

  const basicResponse = new BasicOCSPResponse({ schema: basicAsn1.result })
  const tbsResponseData = basicResponse.tbsResponseData

  // Get single response (we only query for one certificate)
  if (tbsResponseData.responses.length === 0) {
    throw new Error('No responses in BasicOCSPResponse')
  }

  const singleResponse = tbsResponseData.responses[0]
  const certStatus = singleResponse.certStatus

  // Parse cert status
  if (certStatus.idBlock.tagNumber === 0) {
    // Good
    return {
      status: 'good',
      checkedAt: new Date(),
      method: 'ocsp',
      details: 'Certificate is valid',
    }
  } else if (certStatus.idBlock.tagNumber === 1) {
    // Revoked
    const revokedInfo = certStatus as asn1js.Constructed

    let revokedAt: Date | undefined
    let reason: RevocationReason | undefined

    for (const item of revokedInfo.valueBlock.value) {
      if (item instanceof asn1js.GeneralizedTime) {
        revokedAt = item.toDate()
      } else if (item instanceof asn1js.Enumerated) {
        reason = getRevocationReason(item.valueBlock.valueDec)
      }
    }

    return {
      status: 'revoked',
      checkedAt: new Date(),
      method: 'ocsp',
      revokedAt,
      reason,
      details: `Certificate was revoked${reason ? ` (${reason})` : ''}`,
    }
  } else {
    // Unknown
    return {
      status: 'unknown',
      checkedAt: new Date(),
      method: 'ocsp',
      details: 'Certificate status is unknown',
    }
  }
}

/**
 * Send OCSP request via background script
 */
async function sendOcspRequest(url: string, data: Uint8Array): Promise<Uint8Array | null> {
  return new Promise((resolve) => {
    if (typeof chrome !== 'undefined' && chrome.runtime) {
      chrome.runtime.sendMessage(
        {
          action: 'ocsp-request',
          url,
          data: Array.from(data),
        },
        (response: { data: number[] } | null) => {
          if (response?.data) {
            resolve(new Uint8Array(response.data))
          } else {
            resolve(null)
          }
        }
      )
    } else {
      // Direct fetch for testing
      fetch(url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/ocsp-request',
        },
        body: data,
      })
        .then((res) => res.arrayBuffer())
        .then((buf) => resolve(new Uint8Array(buf)))
        .catch(() => resolve(null))
    }
  })
}

function getOcspStatusText(status: number): string {
  const statuses: Record<number, string> = {
    0: 'successful',
    1: 'malformedRequest',
    2: 'internalError',
    3: 'tryLater',
    5: 'sigRequired',
    6: 'unauthorized',
  }
  return statuses[status] || `unknown (${status})`
}

function getRevocationReason(code: number): RevocationReason {
  const reasons: Record<number, RevocationReason> = {
    0: 'unspecified',
    1: 'keyCompromise',
    2: 'caCompromise',
    3: 'affiliationChanged',
    4: 'superseded',
    5: 'cessationOfOperation',
    6: 'certificateHold',
    8: 'removeFromCRL',
    9: 'privilegeWithdrawn',
    10: 'aaCompromise',
  }
  return reasons[code] || 'unspecified'
}

/**
 * Parse embedded OCSP response from PDF.
 * DSS (Document Security Store) may embed either:
 * 1. Full OCSPResponse (SEQUENCE { responseStatus, responseBytes })
 * 2. Raw BasicOCSPResponse directly (without OCSPResponse wrapper)
 */
export function parseEmbeddedOcspResponse(data: Uint8Array): RevocationResult {
  // Try full OCSPResponse first
  try {
    return parseOcspResponse(data)
  } catch {
    // Fall through to try BasicOCSPResponse
  }

  // Try parsing as raw BasicOCSPResponse (common in DSS)
  try {
    return parseBasicOcspResponse(data)
  } catch {
    // Fall through
  }

  return {
    status: 'error',
    checkedAt: new Date(),
    method: 'embedded',
    details: '無法解析內嵌 OCSP 回應',
  }
}

/**
 * Parse a raw BasicOCSPResponse (without OCSPResponse wrapper)
 */
function parseBasicOcspResponse(data: Uint8Array): RevocationResult {
  const asn1 = asn1js.fromBER(data.buffer.slice(data.byteOffset, data.byteOffset + data.byteLength))
  if (asn1.offset === -1) {
    throw new Error('Failed to parse BasicOCSPResponse ASN.1')
  }

  const basicResponse = new BasicOCSPResponse({ schema: asn1.result })
  const tbsResponseData = basicResponse.tbsResponseData

  if (tbsResponseData.responses.length === 0) {
    throw new Error('No responses in BasicOCSPResponse')
  }

  const singleResponse = tbsResponseData.responses[0]
  const certStatus = singleResponse.certStatus

  if (certStatus.idBlock.tagNumber === 0) {
    return {
      status: 'good',
      checkedAt: new Date(),
      method: 'embedded',
      details: '憑證未被撤銷（內嵌 OCSP）',
    }
  } else if (certStatus.idBlock.tagNumber === 1) {
    const revokedInfo = certStatus as asn1js.Constructed

    let revokedAt: Date | undefined
    let reason: RevocationReason | undefined

    for (const item of revokedInfo.valueBlock.value) {
      if (item instanceof asn1js.GeneralizedTime) {
        revokedAt = item.toDate()
      } else if (item instanceof asn1js.Enumerated) {
        reason = getRevocationReason(item.valueBlock.valueDec)
      }
    }

    return {
      status: 'revoked',
      checkedAt: new Date(),
      method: 'embedded',
      revokedAt,
      reason,
      details: `憑證已被撤銷${reason ? `（${reason}）` : ''}`,
    }
  } else {
    return {
      status: 'unknown',
      checkedAt: new Date(),
      method: 'embedded',
      details: '憑證撤銷狀態未知',
    }
  }
}
