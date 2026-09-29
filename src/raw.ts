import { asRawBody, concatBytes, copyBytes } from './bytes.js'
import { tooLargeError } from './errors.js'

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

/** Stop reading once the body is over the cap. Do not trust Content-Length. */
export async function readRequestBodyCapped(req: Request, maxBodyBytes: number): Promise<Uint8Array> {
  const reader = req.body?.getReader()
  if (!reader) return new Uint8Array()
  const chunks: Uint8Array[] = []
  let total = 0
  for (;;) {
    const { done, value } = await reader.read()
    if (done) break
    if (!value) continue
    total += value.byteLength
    if (maxBodyBytes > 0 && total > maxBodyBytes) {
      try {
        await reader.cancel()
      } catch {
        // already over the cap
      }
      throw tooLargeError(total, maxBodyBytes)
    }
    // Stream implementations may reuse the chunk buffer. Copy before the next read.
    chunks.push(copyBytes(value))
  }
  return concatBytes(chunks)
}
