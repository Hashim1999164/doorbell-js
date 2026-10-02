import { copyBytes, parseBase64, parseHex, toBase64, toHex } from './bytes.js'
import { matchAnyDigest } from './timing.js'

export async function hmacSha256(key: Uint8Array, data: Uint8Array): Promise<Uint8Array> {
  return hmac(key, data, 'SHA-256')
}

export async function hmacSha1(key: Uint8Array, data: Uint8Array): Promise<Uint8Array> {
  return hmac(key, data, 'SHA-1')
}

async function hmac(
  key: Uint8Array,
  data: Uint8Array,
  hash: 'SHA-256' | 'SHA-1',
): Promise<Uint8Array> {
  key = copyBytes(key)
  data = copyBytes(data)
  if (key.byteLength === 0) {
    throw new Error('HMAC key is empty')
  }

  try {
    const node = await import('node:crypto')
    const alg = hash === 'SHA-256' ? 'sha256' : 'sha1'
    return new Uint8Array(node.createHmac(alg, Buffer.from(key)).update(data).digest())
    /* v8 ignore start */
  } catch {
    return hmacSubtle(key, data, hash)
  }
  /* v8 ignore stop */
}

/**
 * WebCrypto path. Workers and browsers use globalThis.crypto.
 * Node 18 only exposes SubtleCrypto on crypto.webcrypto, not globalThis.
 */
export async function hmacSubtle(
  key: Uint8Array,
  data: Uint8Array,
  hash: 'SHA-256' | 'SHA-1' = 'SHA-256',
): Promise<Uint8Array> {
  const subtle = await resolveSubtle()
  /* v8 ignore next 3 */
  if (!subtle) {
    throw new Error('No HMAC implementation on this runtime')
  }
  const cryptoKey = await subtle.importKey(
    'raw',
    toArrayBuffer(key),
    { name: 'HMAC', hash },
    false,
    ['sign'],
  )
  const sig = await subtle.sign('HMAC', cryptoKey, toArrayBuffer(data))
  return new Uint8Array(sig)
}

async function resolveSubtle(): Promise<{
  importKey: (
    format: string,
    keyData: ArrayBuffer,
    algorithm: { name: string; hash: string },
    extractable: boolean,
    keyUsages: string[],
  ) => Promise<object>
  sign: (algorithm: string, key: object, data: ArrayBuffer) => Promise<ArrayBuffer>
} | undefined> {
  const fromGlobal = globalThis.crypto?.subtle
  if (fromGlobal) {
    return fromGlobal as {
      importKey: (
        format: string,
        keyData: ArrayBuffer,
        algorithm: { name: string; hash: string },
        extractable: boolean,
        keyUsages: string[],
      ) => Promise<object>
      sign: (algorithm: string, key: object, data: ArrayBuffer) => Promise<ArrayBuffer>
    }
  }
  try {
    const node = await import('node:crypto')
    const subtle = node.webcrypto?.subtle
    /* v8 ignore next */
    if (!subtle) return undefined
    return subtle as {
      importKey: (
        format: string,
        keyData: ArrayBuffer,
        algorithm: { name: string; hash: string },
        extractable: boolean,
        keyUsages: string[],
      ) => Promise<object>
      sign: (algorithm: string, key: object, data: ArrayBuffer) => Promise<ArrayBuffer>
    }
    /* v8 ignore next 3 */
  } catch {
    return undefined
  }
}

/** Fresh ArrayBuffer. WebCrypto rejects views over a SharedArrayBuffer or a pooled Buffer. */
function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  const out = new ArrayBuffer(bytes.byteLength)
  new Uint8Array(out).set(bytes)
  return out
}

export async function hmacSha256Hex(key: Uint8Array, data: Uint8Array): Promise<string> {
  return toHex(await hmacSha256(key, data))
}

export async function hmacSha256Base64(key: Uint8Array, data: Uint8Array): Promise<string> {
  return toBase64(await hmacSha256(key, data))
}

export async function matchHexMac(
  key: Uint8Array,
  data: Uint8Array,
  providedHex: string,
): Promise<boolean> {
  const expected = await hmacSha256(key, data)
  return matchAnyDigest([expected], [parseHex(providedHex)])
}

export async function matchBase64Mac(
  key: Uint8Array,
  data: Uint8Array,
  providedB64: string,
): Promise<boolean> {
  const expected = await hmacSha256(key, data)
  return matchAnyDigest([expected], [parseBase64(providedB64)])
}

export async function matchAnyHexMac(
  keys: Uint8Array[],
  data: Uint8Array,
  candidates: string[],
): Promise<boolean> {
  const expected = await Promise.all(keys.map((k) => hmacSha256(k, data)))
  const provided = (candidates.length > 0 ? candidates : ['']).map((c) => parseHex(c))
  return matchAnyDigest(expected, provided)
}

export async function matchAnyBase64Mac(
  keys: Uint8Array[],
  data: Uint8Array,
  candidates: string[],
): Promise<boolean> {
  const expected = await Promise.all(keys.map((k) => hmacSha256(k, data)))
  const provided = (candidates.length > 0 ? candidates : ['']).map((c) => parseBase64(c))
  return matchAnyDigest(expected, provided)
}

export function decodeHexMac(value: string): Uint8Array | null {
  return parseHex(value)
}

export { timingSafeEqual, timingSafeEqualHex, timingSafeEqualText } from './timing.js'
