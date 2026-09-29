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
  } catch {
    // workers / browsers
  }

  const subtle = globalThis.crypto?.subtle
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

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer
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
  const expected = await Promise.all(keys.map((key) => hmacSha256(key, data)))
  const provided = (candidates.length > 0 ? candidates : ['']).map((c) => parseHex(c))
  return matchAnyDigest(expected, provided)
}

export async function matchAnyBase64Mac(
  keys: Uint8Array[],
  data: Uint8Array,
  candidates: string[],
): Promise<boolean> {
  const expected = await Promise.all(keys.map((key) => hmacSha256(key, data)))
  const provided = (candidates.length > 0 ? candidates : ['']).map((c) => parseBase64(c))
  return matchAnyDigest(expected, provided)
}

export function decodeHexMac(value: string): Uint8Array | null {
  return parseHex(value)
}

export { timingSafeEqual, timingSafeEqualHex, timingSafeEqualText } from './timing.js'
