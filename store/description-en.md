# PDF Signature Verifier

Verify PDF digital signatures directly in your browser — no server uploads, no external services. Everything runs locally for maximum privacy.

## Features

- **Integrity Check** — Verify that the PDF has not been tampered with after signing (CMS/PKCS#7 digest + cryptographic signature)
- **Certificate Chain Validation** — Build and validate the full X.509 certificate chain from signer to root CA
- **Trust Verification** — Check if the signing certificate chains to a trusted root CA (supports global CAs and Taiwan PKI: TWCA, GCA, MOICA)
- **RFC 3161 Timestamp** — Verify embedded timestamps to prove when the document was signed
- **Certificate Validity** — Check that certificates were valid at signing time, with LTV fallback for expired certificates
- **Revocation Check** — Verify certificates have not been revoked via embedded or online OCSP and CRL
- **Long-Term Validation (LTV)** — Check if the signature contains enough embedded data for long-term verification
- **Detailed Report Export** — Export a comprehensive PDF verification report

## How It Works

1. Open any PDF file or click the verify button next to PDF links on web pages
2. The extension automatically detects and verifies all digital signatures
3. View detailed results including certificate chain, timestamp, and revocation status
4. Export a full verification report as PDF

## Privacy

All verification is performed locally in your browser. Your PDF files are never uploaded to any server.

## Supported Signatures

- CMS / PKCS#7 (adbe.pkcs7.detached, adbe.pkcs7.sha1)
- RSA, ECDSA, RSA-PSS signature algorithms
- SHA-256, SHA-384, SHA-512, SHA-1 hash algorithms
- PAdES (PDF Advanced Electronic Signatures)

## Languages

English and Traditional Chinese (繁體中文). Automatically detected from browser language, or manually switch in settings.
