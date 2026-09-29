import { parseHex, utf8 } from './bytes.js'

/**
 * Compare two byte strings without bailing on the first mismatch.
 * HMAC outputs are fixed size. Compare those, not the header text.
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

export function timingSafeEqualText(a: string, b: string): boolean {
  return timingSafeEqual(utf8(a), utf8(b))
}

/**
 * Compare every expected digest with every provided digest.
 * Invalid / wrong-length candidates still get a dummy compare so we do not
 * return faster on "this is not even hex".
 */
export function matchAnyDigest(expected: Uint8Array[], provided: Array<Uint8Array | null>): boolean {
  const gotList = provided.length > 0 ? provided : [null]
  let ok = false
  for (const exp of expected) {
    const dummy = new Uint8Array(exp.byteLength)
    for (const got of gotList) {
      const right = got && got.byteLength === exp.byteLength ? got : dummy
      if (got && got.byteLength === exp.byteLength && timingSafeEqual(exp, right)) ok = true
      else timingSafeEqual(exp, right)
    }
  }
  return ok
}
