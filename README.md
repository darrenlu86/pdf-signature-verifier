# PDF Signature Verifier

A browser extension that verifies digital signatures in PDF documents, with built-in support for Taiwan's PKI infrastructure (TWCA, GCA, MOICA root certificates).

## Features

- **Full PDF signature verification** -- parses PDF structure, extracts PKCS#7/CMS signatures, and validates every step of the chain
- **Taiwan PKI support** -- pre-loaded trust anchors for TWCA (commercial), GCA (government), and MOICA (citizen digital certificates)
- **Automatic PDF detection** -- injects "Verify Signature" buttons next to PDF links and embedded PDFs on any webpage
- **Built-in PDF viewer integration** -- floating verify button when viewing a PDF directly in the browser
- **Side panel results** -- verification results displayed in a slide-in panel without leaving the page
- **Comprehensive checks**:
  - Document integrity (message digest + cryptographic signature)
  - Certificate chain building and validation
  - Trust root verification
  - Certificate validity period (with LTV fallback for expired certificates)
  - Revocation checking (embedded OCSP/CRL, online OCSP, online CRL)
  - RFC 3161 timestamp verification
  - Long-Term Validation (LTV) completeness
- **Offline-capable** -- verifies embedded revocation data without requiring network access
- **Multi-language UI** -- Traditional Chinese (primary) and English
- **Cross-browser** -- Chrome (MV3) and Firefox support

## Installation

### From Source

1. Clone the repository:
   ```bash
   git clone https://github.com/darrenlu86/pdf-signature-verifier.git
   cd pdf-signature-verifier
   ```

2. Install dependencies:
   ```bash
   npm install
   ```

3. Build the extension:
   ```bash
   npm run build
   ```

4. Load in Chrome:
   - Navigate to `chrome://extensions/`
   - Enable "Developer mode"
   - Click "Load unpacked"
   - Select the `.output/chrome-mv3` directory

5. Load in Firefox:
   - Navigate to `about:debugging#/runtime/this-firefox`
   - Click "Load Temporary Add-on"
   - Select any file in the `.output/firefox-mv2` directory

## Development

### Prerequisites

- Node.js 18+
- npm

### Setup

```bash
npm install
npm run dev          # Start dev mode with hot reload (Chrome)
npm run dev:firefox  # Start dev mode (Firefox)
```

### Commands

| Command | Description |
|---------|-------------|
| `npm run dev` | Development mode with HMR (Chrome) |
| `npm run dev:firefox` | Development mode (Firefox) |
| `npm run build` | Production build (Chrome) |
| `npm run build:firefox` | Production build (Firefox) |
| `npm run build:all` | Build for both browsers |
| `npm run zip` | Build and package for Chrome Web Store |
| `npm run compile` | TypeScript type checking |
| `npm run test` | Run tests in watch mode |
| `npm run test:unit` | Run tests once |
| `npm run test:coverage` | Run tests with coverage report |
| `npm run test:e2e` | Run Playwright E2E tests |

### Testing

Tests use Vitest (unit/integration) and Playwright (E2E). Coverage threshold is 80%.

```bash
npm run test:unit       # Fast unit tests
npm run test:coverage   # With coverage report
npm run test:e2e        # End-to-end browser tests
```

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     Browser Extension                        │
├──────────────┬──────────────────────┬───────────────────────┤
│ Content      │   Background         │  Panel / Popup        │
│ Script       │   Service Worker     │  (React UI)           │
│              │                      │                       │
│ - Detect PDF │ - PDF fetch +        │ - DropZone            │
│   links      │   verify by URL     │ - SignatureList        │
│ - Inject     │ - Delegates to       │ - SignatureCard        │
│   buttons    │   core verifier      │ - CertificateChain    │
│ - Side panel │                      │ - VerificationDetails │
│   (iframe)   │                      │ - StatusBadge         │
│              │                      │                       │
└──────┬───────┴──────────┬───────────┴───────────────────────┘
       │                  │
       │    chrome.runtime.sendMessage
       │                  │
       ▼                  ▼
┌─────────────────────────────────────────────────────────────┐
│                    Core Verification Engine                   │
│                    (src/core/verifier.ts)                     │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌─────────┐  ┌──────────┐  ┌────────────┐  ┌───────────┐  │
│  │  PDF     │  │  Crypto  │  │Certificate │  │Revocation │  │
│  │  Parser  │  │  Engine  │  │  Chain     │  │  Checker  │  │
│  │         │  │          │  │           │  │           │  │
│  │- xref   │  │- PKCS#7  │  │- builder  │  │- embedded │  │
│  │- byte   │  │- digest  │  │- validator │  │- OCSP     │  │
│  │  range  │  │- sig     │  │- utils    │  │- CRL      │  │
│  │- extract│  │  verify  │  │           │  │           │  │
│  └────┬────┘  └────┬─────┘  └─────┬─────┘  └─────┬─────┘  │
│       │            │              │              │          │
│  ┌────┴────┐  ┌────┴─────┐  ┌─────┴─────┐                  │
│  │Timestamp│  │  Trust   │  │    LTV    │                  │
│  │Verifier │  │  Store   │  │  Checker  │                  │
│  │         │  │          │  │           │                  │
│  │- RFC    │  │- Taiwan  │  │- complete │                  │
│  │  3161   │  │  roots   │  │  -ness    │                  │
│  │- TST    │  │- manager │  │- expired  │                  │
│  │  verify │  │          │  │  cert LTV │                  │
│  └─────────┘  └──────────┘  └───────────┘                  │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

### Verification Pipeline

For each signature found in a PDF:

1. **Parse PDF** -- extract signature fields, byte ranges, and PKCS#7 data
2. **Validate byte range** -- ensure the signed region covers the document correctly
3. **Parse PKCS#7** -- decode the CMS SignedData structure (certificates, signer info, timestamps)
4. **Verify integrity** -- compute and compare message digest, then verify cryptographic signature
5. **Build certificate chain** -- from signer certificate through intermediates to root CA
6. **Check trust root** -- verify chain terminates at a known, trusted root certificate
7. **Verify timestamp** -- validate RFC 3161 embedded timestamp (imprint = hash of signature value)
8. **Check validity** -- ensure certificates were valid at signing time (LTV fallback for expired)
9. **Check revocation** -- embedded OCSP/CRL and online queries in parallel, auto-fallback
10. **Assess LTV** -- verify Long-Term Validation data is complete for archival trust

### Taiwan PKI Trust Roots

The extension includes trust anchors for Taiwan's national PKI:

| Root CA | Issuer | Purpose |
|---------|--------|---------|
| **TWCA** | Taiwan-CA Inc. | Commercial digital certificates |
| **GCA** | Government Root CA | Government PKI infrastructure |
| **MOICA** | Ministry of Interior | Citizen digital certificate (Natural Person Certificate) |

Root certificates are managed in `src/trust-store/taiwan-roots.ts` and loaded by `trust-manager.ts`.

## Tech Stack

- [WXT](https://wxt.dev/) -- Browser extension framework (Vite-based)
- [React](https://react.dev/) -- UI components
- [Tailwind CSS](https://tailwindcss.com/) -- Utility-first styling
- [PKI.js](https://pkijs.org/) -- X.509, CMS/PKCS#7, OCSP, TSP
- [ASN1.js](https://github.com/nicktomlin/nicktomlin.github.io) -- ASN.1 schema and parsing
- [Zustand](https://zustand.docs.pmnd.rs/) -- State management
- [Vitest](https://vitest.dev/) -- Unit and integration testing
- [Playwright](https://playwright.dev/) -- End-to-end testing

## License

MIT
