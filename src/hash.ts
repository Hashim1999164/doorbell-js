import { createHash } from 'node:crypto'

/** Idempotency for providers that HMAC the body and leave the id header unsigned. */
export function bodyFingerprint(raw: Uint8Array): string {
  return createHash('sha256').update(raw).digest('hex').slice(0, 40)
}
