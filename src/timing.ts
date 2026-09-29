import { parseHex, utf8 } from './bytes.js'

/**
 * Compare two byte strings without bailing on the first mismatch.
 * Length still leaks a little (we walk the longer one). HMAC outputs are fixed size,
 * so callers should compare digests, not the original header strings.
 */
export function timingSafeEqual(a: Uint8Array, b: Uint8Array): boolean {
  const len = Math.max(a.byteLength, b.byteLength, 1)
  let diff = a.byteLength ^ b.byteLength
  for (let i = 0; i < len; i++) {
    diff |= (a[i] ?? 0) ^ (b[i] ?? 0)
  }
  return diff === 0
}

export function timingSafeEqualHex(expectedHex: string, providedHex: string): boolean {
  const expected = parseHex(expectedHex)
  const provided = parseHex(providedHex)
  if (!expected || !provided) {
    timingSafeEqual(utf8(expectedHex), utf8(providedHex))
    return false
  }
  return timingSafeEqual(expected, provided)
}
