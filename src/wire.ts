import { concatBytes, utf8 } from './bytes.js'

/** HMAC is over prefix + raw bytes. Never decode the body and re-encode it. */
export function prefixRaw(prefix: string, raw: Uint8Array): Uint8Array {
  return concatBytes([utf8(prefix), raw])
}
