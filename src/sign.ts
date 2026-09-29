import { secretBytesUtf8, standardWebhookKey, utf8 } from './bytes.js'
import { hmacSha256, hmacSha256Hex } from './hmac.js'
import { toBase64 } from './bytes.js'
import { prefixRaw } from './wire.js'

export async function signStripe(
  payload: string | Uint8Array,
  secret: string,
  timestampSec: number,
): Promise<string> {
  const raw = typeof payload === 'string' ? utf8(payload) : payload
  const mac = await hmacSha256Hex(secretBytesUtf8(secret).key, prefixRaw(`${timestampSec}.`, raw))
  return `t=${timestampSec},v1=${mac}`
}

export async function signGitHub(payload: string | Uint8Array, secret: string): Promise<string> {
  const raw = typeof payload === 'string' ? utf8(payload) : payload
  const mac = await hmacSha256Hex(secretBytesUtf8(secret).key, raw)
  return `sha256=${mac}`
}

export async function signSlack(
  payload: string | Uint8Array,
  secret: string,
  timestampSec: number,
): Promise<string> {
  const raw = typeof payload === 'string' ? utf8(payload) : payload
  const mac = await hmacSha256Hex(secretBytesUtf8(secret).key, prefixRaw(`v0:${timestampSec}:`, raw))
  return `v0=${mac}`
}

export async function signShopify(payload: string | Uint8Array, secret: string): Promise<string> {
  const raw = typeof payload === 'string' ? utf8(payload) : payload
  const mac = await hmacSha256(secretBytesUtf8(secret).key, raw)
  return toBase64(mac)
}

export async function signLinear(payload: string | Uint8Array, secret: string): Promise<string> {
  const raw = typeof payload === 'string' ? utf8(payload) : payload
  return hmacSha256Hex(secretBytesUtf8(secret).key, raw)
}

export async function signPaddle(
  payload: string | Uint8Array,
  secret: string,
  timestampSec: number,
): Promise<string> {
  const raw = typeof payload === 'string' ? utf8(payload) : payload
  const mac = await hmacSha256Hex(secretBytesUtf8(secret).key, prefixRaw(`${timestampSec}:`, raw))
  return `ts=${timestampSec};h1=${mac}`
}

export async function signStandard(
  payload: string | Uint8Array,
  secret: string,
  id: string,
  timestampSec: number,
): Promise<string> {
  const raw = typeof payload === 'string' ? utf8(payload) : payload
  const key = standardWebhookKey(secret)
  const mac = await hmacSha256(key, prefixRaw(`${id}.${timestampSec}.`, raw))
  return `v1,${toBase64(mac)}`
}
