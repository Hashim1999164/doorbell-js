import { asRawBody } from './bytes.js'

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
  req.rawBody = buf instanceof Uint8Array ? buf : new Uint8Array(buf as ArrayBuffer)
}

export function rawFromNodeRequest(req: RawCarrier): Uint8Array {
  if (req.rawBody != null) return asRawBody(req.rawBody)
  return asRawBody(req.body)
}
