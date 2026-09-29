import { parseHex, toBase64, toHex } from './bytes.js'
import { timingSafeEqual, timingSafeEqualHex } from './timing.js'

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
  if (key.byteLength === 0) {
    throw new Error('HMAC key is empty')
  }
  const cryptoKey = await globalThis.crypto.subtle.importKey(
    'raw',
    toArrayBuffer(key),
    { name: 'HMAC', hash },
    false,
    ['sign'],
  )
  const sig = await globalThis.crypto.subtle.sign('HMAC', cryptoKey, toArrayBuffer(data))
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
  const expected = toHex(await hmacSha256(key, data))
  return timingSafeEqualHex(expected, providedHex)
}

export async function matchBase64Mac(
  key: Uint8Array,
  data: Uint8Array,
  providedB64: string,
): Promise<boolean> {
  const expected = await hmacSha256(key, data)
  const provided = parseBase64Strict(providedB64)
  if (!provided) {
    timingSafeEqual(expected, expected)
    return false
  }
  return timingSafeEqual(expected, provided)
}

function parseBase64Strict(value: string): Uint8Array | null {
  try {
    if (typeof Buffer !== 'undefined') {
      const buf = Buffer.from(value.trim(), 'base64')
      if (buf.byteLength === 0 && value.trim().length > 0) return null
      return new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength)
    }
    const bin = atob(value.trim())
    const out = new Uint8Array(bin.length)
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i)
    return out
  } catch {
    return null
  }
}

export async function matchAnyHexMac(
  keys: Uint8Array[],
  data: Uint8Array,
  candidates: string[],
): Promise<boolean> {
  let ok = false
  for (const key of keys) {
    const expected = toHex(await hmacSha256(key, data))
    for (const candidate of candidates) {
      if (timingSafeEqualHex(expected, candidate)) ok = true
    }
  }
  return ok
}

export function decodeHexMac(value: string): Uint8Array | null {
  return parseHex(value)
}

export { timingSafeEqual, timingSafeEqualHex }
