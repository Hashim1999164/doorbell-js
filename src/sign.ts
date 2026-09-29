import { secretBytesUtf8, standardWebhookKey, utf8 } from './bytes.js'
import { hmacSha256, hmacSha256Hex } from './hmac.js'
import { toBase64 } from './bytes.js'

export async function signStripe(
  payload: string,
  secret: string,
  timestampSec: number,
): Promise<string> {
  const mac = await hmacSha256Hex(secretBytesUtf8(secret).key, utf8(`${timestampSec}.${payload}`))
  return `t=${timestampSec},v1=${mac}`
}

export async function signGitHub(payload: string, secret: string): Promise<string> {
  const mac = await hmacSha256Hex(secretBytesUtf8(secret).key, utf8(payload))
  return `sha256=${mac}`
}

export async function signSlack(payload: string, secret: string, timestampSec: number): Promise<string> {
  const mac = await hmacSha256Hex(secretBytesUtf8(secret).key, utf8(`v0:${timestampSec}:${payload}`))
  return `v0=${mac}`
}

export async function signShopify(payload: string, secret: string): Promise<string> {
  const mac = await hmacSha256(secretBytesUtf8(secret).key, utf8(payload))
  return toBase64(mac)
}

export async function signLinear(payload: string, secret: string): Promise<string> {
  return hmacSha256Hex(secretBytesUtf8(secret).key, utf8(payload))
}

export async function signPaddle(
  payload: string,
  secret: string,
  timestampSec: number,
): Promise<string> {
  const mac = await hmacSha256Hex(secretBytesUtf8(secret).key, utf8(`${timestampSec}:${payload}`))
  return `ts=${timestampSec};h1=${mac}`
}

export async function signStandard(
  payload: string,
  secret: string,
  id: string,
  timestampSec: number,
): Promise<string> {
  const key = standardWebhookKey(secret)
  const mac = await hmacSha256(key, utf8(`${id}.${timestampSec}.${payload}`))
  return `v1,${toBase64(mac)}`
}
