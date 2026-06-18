/**
 * PKI.js requires a CryptoEngine to be wired in before its built-in
 * `SignedData.verify()` will work. In browser / service-worker contexts the
 * library can usually auto-detect Web Crypto, but in MV3 service workers and
 * in test environments (vitest+jsdom, Node native) the detection is fragile
 * — calling .verify() then throws `"unable to create WebCrypto object"` or
 * similar, and verification silently falls through to a manual path.
 *
 * Call `ensurePkijsEngine()` at the entry point of any code path that uses
 * pkijs.SignedData.verify() or related methods.
 */

import * as pkijs from 'pkijs'

let initialized = false

export function ensurePkijsEngine(): void {
  if (initialized) return
  // crypto.subtle is available in modern browsers, service workers, and
  // Node.js ≥ 16 (via globalThis.crypto). If neither is available the
  // setEngine call will throw — we let that bubble up because the rest of
  // verification depends on Web Crypto anyway.
  const subtle = globalThis.crypto?.subtle
  if (!subtle) {
    initialized = true // don't retry — there's nothing to install
    return
  }
  pkijs.setEngine(
    'webcrypto',
    new pkijs.CryptoEngine({
      name: 'webcrypto',
      crypto: globalThis.crypto,
      subtle,
    })
  )
  initialized = true
}
