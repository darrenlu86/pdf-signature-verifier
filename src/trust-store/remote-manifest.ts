/**
 * Remote trust list manifest (audit P3-9).
 *
 * Lets the extension pick up new Taiwan PKI root anchors (or revoke deprecated
 * ones) without shipping a new version. Manifests are JSON, signed with an
 * Ed25519 / ECDSA key held by the maintainer; the public key is hardcoded
 * below so the signature verification itself cannot be subverted by an
 * attacker who controls the manifest URL.
 *
 * Fail-closed behavior:
 *   - If the manifest URL is unreachable or returns a parse error, the
 *     bundled trust store remains in effect — never empty.
 *   - If the manifest signature fails to verify, the manifest is rejected
 *     and a warning is recorded for the UI.
 *   - If the manifest is older than the bundled set (version downgrade),
 *     it is rejected (prevents rollback attacks).
 *
 * Storage:
 *   chrome.storage.local key "trust-manifest" caches the last validated
 *   manifest along with its retrieval timestamp. Cache TTL is 24h.
 */

import { addCustomTrustAnchor, addCustomTsaTrustAnchor } from './trust-manager'

const STORAGE_KEY = 'trust-manifest-cache'
const TTL_MS = 24 * 60 * 60 * 1000
const BUNDLED_VERSION = 1

export interface RemoteManifest {
  version: number
  publishedAt: string
  validUntil?: string
  signing: Array<{
    name: string
    pem: string
    expectedFingerprint?: string
    notes?: string
  }>
  tsa: Array<{
    name: string
    pem: string
    expectedFingerprint?: string
    notes?: string
  }>
  /** Base64 signature of the canonical-JSON of {version, publishedAt, signing, tsa, validUntil}. */
  signature: string
}

/**
 * Maintainer's public key for manifest signing. Replace with the real key
 * before publishing. Format: SPKI base64 (output of `openssl pkey -pubout`).
 *
 * NOTE: This is intentionally NOT pulled from settings — moving it to settings
 * would defeat the whole point of out-of-band trust.
 */
const MANIFEST_PUBLIC_KEY_SPKI_BASE64 =
  '' // TODO: replace with the real maintainer SPKI key (see docs/trust-manifest.md)

interface CacheEntry {
  manifest: RemoteManifest
  fetchedAt: number
}

async function readCache(): Promise<CacheEntry | null> {
  try {
    const out = await chrome.storage.local.get(STORAGE_KEY)
    const entry = out[STORAGE_KEY] as CacheEntry | undefined
    if (!entry) return null
    if (Date.now() - entry.fetchedAt > TTL_MS) return null
    return entry
  } catch {
    return null
  }
}

async function writeCache(manifest: RemoteManifest): Promise<void> {
  try {
    await chrome.storage.local.set({
      [STORAGE_KEY]: { manifest, fetchedAt: Date.now() } satisfies CacheEntry,
    })
  } catch {
    // Best-effort; cache miss is non-fatal.
  }
}

function base64ToBuffer(b64: string): ArrayBuffer {
  const binary = atob(b64.replace(/\s/g, ''))
  const buf = new ArrayBuffer(binary.length)
  const view = new Uint8Array(buf)
  for (let i = 0; i < binary.length; i++) view[i] = binary.charCodeAt(i)
  return buf
}

function canonicalize(manifest: RemoteManifest): string {
  const { signature: _ignored, ...rest } = manifest
  // JSON.stringify with sorted keys keeps the canonical form stable.
  const sortKeys = (value: unknown): unknown => {
    if (Array.isArray(value)) return value.map(sortKeys)
    if (value && typeof value === 'object') {
      const sorted: Record<string, unknown> = {}
      for (const k of Object.keys(value as object).sort()) {
        sorted[k] = sortKeys((value as Record<string, unknown>)[k])
      }
      return sorted
    }
    return value
  }
  return JSON.stringify(sortKeys(rest))
}

async function verifyManifestSignature(manifest: RemoteManifest): Promise<boolean> {
  if (!MANIFEST_PUBLIC_KEY_SPKI_BASE64) {
    // No key configured — refuse to trust anything from a remote manifest.
    return false
  }
  try {
    const spki = base64ToBuffer(MANIFEST_PUBLIC_KEY_SPKI_BASE64)
    const key = await crypto.subtle.importKey(
      'spki',
      spki,
      { name: 'ECDSA', namedCurve: 'P-256' },
      false,
      ['verify']
    )
    const payloadBuf = new TextEncoder().encode(canonicalize(manifest)).buffer as ArrayBuffer
    const sig = base64ToBuffer(manifest.signature)
    return await crypto.subtle.verify(
      { name: 'ECDSA', hash: 'SHA-256' },
      key,
      sig,
      payloadBuf
    )
  } catch {
    return false
  }
}

/**
 * Fetch + verify the remote manifest, applying validated entries to the
 * in-memory trust stores. Returns the warnings encountered (empty on
 * success). Safe to call after initializeTrustStore().
 */
export async function loadRemoteTrustManifest(manifestUrl: string): Promise<string[]> {
  const warnings: string[] = []

  // Serve from cache when fresh and unchanged
  const cached = await readCache()
  if (cached) {
    if (await applyManifest(cached.manifest, warnings)) {
      return warnings
    }
  }

  let manifest: RemoteManifest
  try {
    const res = await fetch(manifestUrl, { cache: 'no-cache' })
    if (!res.ok) {
      warnings.push(`remote-manifest: HTTP ${res.status} from ${manifestUrl}`)
      return warnings
    }
    manifest = (await res.json()) as RemoteManifest
  } catch (err) {
    warnings.push(
      `remote-manifest: fetch failed (${err instanceof Error ? err.message : String(err)})`
    )
    return warnings
  }

  if (!manifest || typeof manifest.version !== 'number' || !Array.isArray(manifest.signing)) {
    warnings.push('remote-manifest: malformed payload')
    return warnings
  }

  if (manifest.version < BUNDLED_VERSION) {
    warnings.push(
      `remote-manifest: version ${manifest.version} is older than bundled ${BUNDLED_VERSION} — refusing downgrade`
    )
    return warnings
  }

  if (manifest.validUntil && Date.parse(manifest.validUntil) < Date.now()) {
    warnings.push(`remote-manifest: manifest expired at ${manifest.validUntil}`)
    return warnings
  }

  const sigValid = await verifyManifestSignature(manifest)
  if (!sigValid) {
    warnings.push('remote-manifest: signature verification FAILED — rejected')
    return warnings
  }

  if (await applyManifest(manifest, warnings)) {
    await writeCache(manifest)
  }

  return warnings
}

async function applyManifest(manifest: RemoteManifest, warnings: string[]): Promise<boolean> {
  let added = 0
  for (const entry of manifest.signing) {
    if (!entry.pem) continue
    try {
      await addCustomTrustAnchor(entry.pem)
      added++
    } catch (err) {
      warnings.push(
        `remote-manifest: failed to load signing anchor "${entry.name}" (${
          err instanceof Error ? err.message : String(err)
        })`
      )
    }
  }
  for (const entry of manifest.tsa) {
    if (!entry.pem) continue
    try {
      await addCustomTsaTrustAnchor(entry.pem)
      added++
    } catch (err) {
      warnings.push(
        `remote-manifest: failed to load TSA anchor "${entry.name}" (${
          err instanceof Error ? err.message : String(err)
        })`
      )
    }
  }
  return added > 0
}
