import { describe, it, expect } from 'vitest'
import { readFileSync } from 'fs'
import { resolve } from 'path'
import { verifyPdfSignatures } from '@/core/verifier'

const SAMPLE_DIR = resolve(__dirname, '../../PDF_Sample')

/**
 * Audit P0–P3 reshaped what "trusted" means. With the curated Taiwan trust
 * store populated, signatures issued under TWCA/GRCA chains validate cleanly,
 * but two factors can still keep the overall status at `unknown`:
 *
 *   1. A second signature in the doc chains to a foreign CA (DigiCert /
 *      DocuSign) that is intentionally NOT in the Taiwan-only trust store.
 *   2. The embedded RFC 3161 timestamp's TSA signature fails Web Crypto
 *      verification (real-world TWCA TSP tokens hit this — a known
 *      limitation of the in-browser ASN.1 re-encoding path; the old code
 *      silently passed these as "valid", which the audit explicitly
 *      forbids).
 *
 * The tests below assert the parts that are deterministic: integrity,
 * chain, trust for Taiwan-rooted signatures, validity, and embedded
 * revocation should all PASS.
 */

function logVerification(label: string, result: Awaited<ReturnType<typeof verifyPdfSignatures>>) {
  console.log(`=== ${label} ===`)
  console.log('Overall status:', result.status)
  for (const sig of result.signatures) {
    console.log(`\nSignature #${sig.index}: ${sig.signerName} — ${sig.status}`)
    console.log('  Integrity:', sig.checks.integrity.passed ? 'PASS' : 'FAIL', '-', sig.checks.integrity.message)
    console.log('  Chain:', sig.checks.certificateChain.passed ? 'PASS' : 'FAIL', '-', sig.checks.certificateChain.message)
    console.log('  Trust:', sig.checks.trustRoot.passed ? 'PASS' : 'FAIL', '-', sig.checks.trustRoot.message, sig.checks.trustRoot.details)
    console.log('  Validity:', sig.checks.validity.passed ? 'PASS' : 'FAIL', '-', sig.checks.validity.message)
    if (sig.checks.timestamp) {
      console.log('  Timestamp:', sig.checks.timestamp.passed ? 'PASS' : 'FAIL', '-', sig.checks.timestamp.message)
    }
    console.log('  LTV:', sig.checks.ltv.passed ? 'PASS' : 'FAIL', '-', sig.checks.ltv.message)
    console.log('  Revocation:', sig.checks.revocation.passed ? 'PASS' : 'FAIL', '-', sig.checks.revocation.message)
  }
}

describe('Sample PDF Verification', () => {
  it('TWCA Docusign TSP sample: TWCA sig trusted, DocuSign sig untrusted (foreign CA)', async () => {
    const pdfPath = resolve(SAMPLE_DIR, '(TWCA 正式環境)Docusign TSP 簽章範例.pdf')
    const pdfData = readFileSync(pdfPath)
    const result = await verifyPdfSignatures(pdfData, 'TWCA_Docusign_TSP.pdf')

    logVerification('TWCA Docusign TSP', result)

    // Mixed-CA doc: overall status is whichever is worst.
    expect(['trusted', 'unknown']).toContain(result.status)

    // Per-signature assertions
    for (const sig of result.signatures) {
      if (sig.signerName.startsWith('DocTimeStamp')) continue
      // Document integrity must always pass — these are real signed PDFs.
      expect(sig.checks.integrity.passed).toBe(true)
      // Certificate chain must build (structurally).
      expect(sig.checks.certificateChain.passed).toBe(true)
      // Validity at signing time must hold.
      expect(sig.checks.validity.passed).toBe(true)
    }

    // The TWCA-rooted signature should now have Trust: PASS.
    // The DocuSign-rooted signature stays untrusted because DigiCert isn't
    // in our Taiwan trust store.
    const taiwanSig = result.signatures.find((s) => /HSMT|TWES/i.test(s.signerName))
    if (taiwanSig) {
      expect(taiwanSig.checks.trustRoot.passed).toBe(true)
    }
    const docusignSig = result.signatures.find((s) => /DocuSign/i.test(s.signerName))
    if (docusignSig) {
      expect(docusignSig.checks.trustRoot.passed).toBe(false)
    }
  })

  it('AATL sample: both signatures fully trusted (every check passes)', async () => {
    const pdfPath = resolve(SAMPLE_DIR, '範例文件(以工商憑證換發AATL憑證簽署).pdf')
    const pdfData = readFileSync(pdfPath)
    const result = await verifyPdfSignatures(pdfData, 'AATL_sample.pdf')

    logVerification('工商憑證 AATL', result)

    // Every gate passes for both signatures — overall is trusted.
    expect(result.status).toBe('trusted')

    for (const sig of result.signatures) {
      if (sig.signerName.startsWith('DocTimeStamp')) continue
      expect(sig.status).toBe('trusted')
      expect(sig.checks.integrity.passed).toBe(true)
      expect(sig.checks.certificateChain.passed).toBe(true)
      expect(sig.checks.validity.passed).toBe(true)
      expect(sig.checks.trustRoot.passed).toBe(true)
      expect(sig.checks.revocation.passed).toBe(true)
      // Timestamp must pass — embedded TWCA TSA signature now verifies.
      expect(sig.checks.timestamp?.passed).toBe(true)
      // LTV (B-LT or higher) must be reported.
      expect(sig.checks.ltv.passed).toBe(true)
      expect(sig.ltvLevel === 'B-LT' || sig.ltvLevel === 'B-LTA').toBe(true)
    }
  })
})
