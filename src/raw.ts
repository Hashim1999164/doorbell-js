import { asRawBody, copyBytes } from './bytes.js'

type RawCarrier = {
  rawBody?: unknown
  body?: unknown
}

/**
 * Drop this into express.json({ verify: preserveRawBody }).
 * json() still parses for the rest of the app. The webhook route can read the bytes.
 */
export function preserveRawBody(
  req: RawCarrier,
  _res: unknown,
  buf: Uint8Array,
): void {
  const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf as ArrayBuffer)
  req.rawBody = copyBytes(bytes)
}

/**
 * fastify.addContentTypeParser('application/json', { parseAs: 'buffer' }, captureFastifyBuffer)
 * doorbell.fastify then HMAC the copy, not Fastify's live buffer.
 */
export function captureFastifyBuffer(
  req: RawCarrier,
  body: Uint8Array,
  done: (err: Error | null, payload?: Uint8Array) => void,
): void {
  try {
    req.rawBody = asRawBody(body)
    done(null, body)
  } catch (err) {
    done(err instanceof Error ? err : new Error(String(err)))
  }
}

export function rawFromNodeRequest(req: RawCarrier): Uint8Array {
  if (req.rawBody != null) return asRawBody(req.rawBody)
  return asRawBody(req.body)
}
