# CLAUDE.md - PDF Signature Verifier

## Project Overview

Browser extension that verifies PDF digital signatures with X.509 certificate support. Built as a Chrome MV3 extension using WXT framework. UI is primarily in Traditional Chinese (zh-TW) with English fallback.

## Tech Stack

- **Framework**: WXT 0.19 (browser extension framework)
- **UI**: React 18 + Tailwind CSS 3
- **Language**: TypeScript (strict mode, ESNext target)
- **Crypto**: asn1js + pkijs (ASN.1 parsing, PKCS#7, X.509)
- **State**: Zustand
- **Build**: Vite (via WXT)
- **Test**: Vitest (unit/integration) + Playwright (e2e)
- **Target**: Chrome MV3 (also supports Firefox)

## Key Directories

```
src/
  entrypoints/         # WXT entry points (background.ts, content.ts)
  core/                # Verification engine (pure logic, no UI)
    pdf/               # PDF parser, xref, byte-range, signature extractor
    crypto/            # PKCS#7 parser, digest & signature verification
    certificate/       # Chain building, validation, cert utilities
    revocation/        # OCSP client, CRL client, embedded reader
    timestamp/         # RFC 3161 timestamp verification
    ltv/               # Long-Term Validation checks
    report/            # HTML verification report generator (zero npm deps)
    verifier.ts        # Main orchestrator - ties all steps together
  types/               # TypeScript interfaces (verification, certificate, signature)
  trust-store/         # Taiwan root CA certificates + trust manager
  popup/               # React UI components and hooks
    components/        # StatusBadge, SignatureCard, CertificateChain, DropZone, ExportButton, etc.
    hooks/             # useVerification, useSettings
  i18n/                # zh-TW.json, en.json, translation utilities
tests/
  unit/                # Unit tests
  integration/         # Integration tests
  e2e/                 # Playwright E2E tests
  fixtures/            # Test PDF samples
```

## Build Commands

```bash
npm run dev              # Dev mode (Chrome)
npm run dev:firefox      # Dev mode (Firefox)
npm run build            # Production build (Chrome)
npm run build:firefox    # Production build (Firefox)
npm run build:all        # Build both browsers
npm run compile          # TypeScript type check (no emit)
npm run test             # Vitest watch mode
npm run test:unit        # Vitest single run
npm run test:coverage    # Vitest with v8 coverage (80% threshold)
npm run test:e2e         # Playwright E2E
```

## Architecture: Verification Pipeline

The main entry point is `verifyPdfSignatures()` in `src/core/verifier.ts`. For each signature field found in the PDF, it runs these steps in order:

1. **ByteRange validation** - Verify the byte range covers the document correctly
2. **PKCS#7 parsing** - Parse the CMS/PKCS#7 SignedData structure
3. **Integrity check** - Verify message digest, then cryptographic signature over signed attributes
4. **Certificate chain** - Build chain from signer cert through intermediates to root
5. **Trust root** - Check if chain terminates at a known root (self-signed CA)
6. **Timestamp** - Verify embedded RFC 3161 timestamp (hash of signatureValue bytes)
7. **Validity** - Check certificate was valid at signing time (with LTV fallback for expired certs)
8. **Revocation** - Check embedded OCSP/CRL, then optionally online OCSP/CRL
9. **LTV** - Check Long-Term Validation completeness (embedded revocation + timestamp)

Each step produces a `CheckResult` (`{ passed, message, details }`). The overall status is `trusted | unknown | failed`.

## Extension Architecture

- **background.ts** - Service worker handling network requests (OCSP, CRL, certificate fetch, PDF fetch) and delegating verification
- **content.ts** - Detects PDF links/embeds on pages, injects verify buttons, manages side panel (iframe) for results
- **popup/** - React components for the popup UI and verification result panel

Messages flow: content script -> background (via `chrome.runtime.sendMessage`) -> core verifier -> result back to content -> panel iframe.

## Conventions

- **UI strings**: Traditional Chinese (zh-TW) is the primary locale. All user-facing strings use `zh-TW.json` translations.
- **Immutability**: Create new objects, never mutate. See `mergeRevocationInfo()` pattern.
- **Small files**: Each module handles one concern (e.g., `digest-verifier.ts`, `chain-builder.ts`, `ocsp-client.ts`).
- **Path alias**: `@/` maps to `src/` (configured in tsconfig and vitest).
- **Error handling**: Always catch and wrap errors with descriptive Chinese messages.
- **No hardcoded secrets**: Root certificates loaded dynamically from `taiwan-roots.ts`.

## Key Dependencies

| Package | Purpose |
|---------|---------|
| `asn1js` | ASN.1 DER/BER encoding/decoding |
| `pkijs` | X.509 certificates, CMS/PKCS#7, OCSP, CRL |
| `pvutils` | Buffer/ArrayBuffer utility helpers for pkijs |
| `zustand` | Lightweight React state management |

## Testing

- Coverage threshold: 80% (lines, functions, branches, statements)
- Test environment: jsdom
- Setup file: `tests/setup.ts`
- Test pattern: `tests/**/*.{test,spec}.{ts,tsx}`
- Existing tests cover: byte-range, digest verification, i18n, trust manager, types, sample PDF verification
