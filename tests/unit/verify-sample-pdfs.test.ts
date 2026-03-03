import { describe, it, expect } from 'vitest'
import { readFileSync } from 'fs'
import { resolve } from 'path'
import { verifyPdfSignatures } from '@/core/verifier'

const SAMPLE_DIR = resolve(__dirname, '../../PDF_Sample')

describe('Sample PDF Verification', () => {
  it('should verify TWCA Docusign TSP sample', async () => {
    const pdfPath = resolve(SAMPLE_DIR, '(TWCA 正式環境)Docusign TSP 簽章範例.pdf')
    const pdfData = readFileSync(pdfPath)
    const result = await verifyPdfSignatures(pdfData, 'TWCA_Docusign_TSP.pdf')

    console.log('=== TWCA Docusign TSP ===')
    console.log('Overall status:', result.status)
    for (const sig of result.signatures) {
      console.log(`\nSignature #${sig.index}: ${sig.signerName} — ${sig.status}`)
      console.log('  Integrity:', sig.checks.integrity.passed ? 'PASS' : 'FAIL', '-', sig.checks.integrity.message)
      console.log('  Chain:', sig.checks.certificateChain.passed ? 'PASS' : 'FAIL', '-', sig.checks.certificateChain.message, sig.checks.certificateChain.details)
      console.log('  Trust:', sig.checks.trustRoot.passed ? 'PASS' : 'FAIL', '-', sig.checks.trustRoot.message, sig.checks.trustRoot.details)
      console.log('  Validity:', sig.checks.validity.passed ? 'PASS' : 'FAIL', '-', sig.checks.validity.message)
      if (sig.checks.timestamp) {
        console.log('  Timestamp:', sig.checks.timestamp.passed ? 'PASS' : 'FAIL', '-', sig.checks.timestamp.message, sig.checks.timestamp.details)
      }
      console.log('  Certs:')
      for (const cert of sig.certificateChain) {
        console.log(`    ${cert.isRoot ? '[ROOT]' : '      '} ${cert.subject}`)
      }
    }

    expect(result.status).toBe('trusted')
  })

  it('should verify 工商憑證 AATL sample', async () => {
    const pdfPath = resolve(SAMPLE_DIR, '範例文件(以工商憑證換發AATL憑證簽署).pdf')
    const pdfData = readFileSync(pdfPath)
    const result = await verifyPdfSignatures(pdfData, 'AATL_sample.pdf')

    console.log('=== 工商憑證 AATL ===')
    console.log('Overall status:', result.status)
    for (const sig of result.signatures) {
      console.log(`\nSignature #${sig.index}: ${sig.signerName} — ${sig.status}`)
      console.log('  Integrity:', sig.checks.integrity.passed ? 'PASS' : 'FAIL', '-', sig.checks.integrity.message)
      console.log('  Chain:', sig.checks.certificateChain.passed ? 'PASS' : 'FAIL', '-', sig.checks.certificateChain.message, sig.checks.certificateChain.details)
      console.log('  Trust:', sig.checks.trustRoot.passed ? 'PASS' : 'FAIL', '-', sig.checks.trustRoot.message, sig.checks.trustRoot.details)
      console.log('  Validity:', sig.checks.validity.passed ? 'PASS' : 'FAIL', '-', sig.checks.validity.message)
      if (sig.checks.timestamp) {
        console.log('  Timestamp:', sig.checks.timestamp.passed ? 'PASS' : 'FAIL', '-', sig.checks.timestamp.message, sig.checks.timestamp.details)
      }
      console.log('  Certs:')
      for (const cert of sig.certificateChain) {
        console.log(`    ${cert.isRoot ? '[ROOT]' : '      '} ${cert.subject}`)
      }
    }

    expect(result.status).toBe('trusted')
  })
})
