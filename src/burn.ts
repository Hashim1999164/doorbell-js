import { hmacSha1, matchAnyBase64Mac, matchAnyHexMac, timingSafeEqual } from './hmac.js'

export async function burnHex(keys: Uint8Array[], data: Uint8Array): Promise<void> {
  if (keys.length === 0) return
  await matchAnyHexMac(keys, data, [''])
}

export async function burnB64(keys: Uint8Array[], data: Uint8Array): Promise<void> {
  if (keys.length === 0) return
  await matchAnyBase64Mac(keys, data, [''])
}

export async function burnSha1(keys: Uint8Array[], data: Uint8Array): Promise<void> {
  for (const key of keys) {
    const mac = await hmacSha1(key, data)
    timingSafeEqual(mac, mac)
  }
}
