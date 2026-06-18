export {
  TAIWAN_ROOT_CERTIFICATES,
  getAllRootCertificates,
  getRootCertificateNames,
  hasAnyEmbeddedPem,
  getPopulatedEntries,
} from './taiwan-roots'
export type { TrustAnchorEntry } from './taiwan-roots'

export {
  TAIWAN_TSA_ROOT_CERTIFICATES,
  getPopulatedTsaEntries,
  hasAnyEmbeddedTsaPem,
} from './taiwan-tsa-roots'

export {
  initializeTrustStore,
  getTrustAnchors,
  getTsaTrustAnchors,
  isTrustAnchor,
  isTsaTrustAnchor,
  findTrustAnchor,
  getTrustAnchorInfo,
  isChainTrusted,
  getTrustedIssuerName,
  addCustomTrustAnchor,
  addCustomTsaTrustAnchor,
  clearTrustAnchors,
  getTrustStoreStats,
  getTrustStoreWarnings,
  isTrustStoreEmpty,
  isTsaTrustStoreEmpty,
} from './trust-manager'
