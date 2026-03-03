/**
 * Taiwan PKI Root Certificates
 *
 * This module contains the root certificates for Taiwan's PKI infrastructure:
 * - TWCA (Taiwan-CA) - Commercial CA
 * - GRCA (Government Root Certification Authority) - Government PKI
 * - MOICA (Ministry of Interior Certification Authority) - Citizen digital certificates
 *
 * Note: Root certificates need to be obtained from official sources:
 * - TWCA: https://www.twca.com.tw/
 * - GCA: https://gca.nat.gov.tw/
 * - MOICA: https://moica.nat.gov.tw/
 */

// Placeholder - certificates will be loaded dynamically or added later
export const TAIWAN_ROOT_CERTIFICATES: Array<{ name: string; pem: string }> = []

/**
 * Get all root certificate PEM strings
 */
export function getAllRootCertificates(): string[] {
  return TAIWAN_ROOT_CERTIFICATES.map((cert) => cert.pem)
}

/**
 * Get root certificate names
 */
export function getRootCertificateNames(): string[] {
  return TAIWAN_ROOT_CERTIFICATES.map((cert) => cert.name)
}
