import { createHash } from 'node:crypto'

export function sha256(bytes: Uint8Array): Uint8Array {
  return new Uint8Array(createHash('sha256').update(bytes).digest())
}

/** Idempotency for providers that HMAC the body and leave the id header unsigned. */
export function bodyFingerprint(raw: Uint8Array): string {
  let hex = ''
  for (const byte of sha256(raw)) hex += byte.toString(16).padStart(2, '0')
  return hex.slice(0, 40)
}
