import { assertFresh } from '../clock.js'
import { DoorbellError } from '../errors.js'
import { header } from '../headers.js'
import { matchAnyHexMac } from '../hmac.js'
import { parseJsonBody, stringField } from '../json.js'
import { prefixRaw } from '../wire.js'
import type { HeaderMap } from '../headers.js'
import type { Provider } from './types.js'

export function sniffPaddle(headers: HeaderMap): boolean {
  return Boolean(header(headers, 'paddle-signature'))
}

function parsePaddleHeader(value: string): { ts: string; h1: string[] } {
  const ts = []
  const h1 = []
  for (const part of value.split(';')) {
    const [k, v] = part.split('=')
    if (k?.trim() === 'ts' && v) ts.push(v.trim())
    if (k?.trim() === 'h1' && v) h1.push(v.trim())
  }
  return { ts: ts[0] ?? '', h1 }
}

export const paddle: Provider = {
  name: 'paddle',
  sniff: sniffPaddle,
  parse: parseJsonBody,
  eventId(_headers, payload) {
    return stringField(payload, 'event_id') ?? stringField(payload, 'notification_id') ?? 'paddle'
  },
  eventType(_headers, payload) {
    return stringField(payload, 'event_type') ?? 'paddle'
  },
  async verify(ctx) {
    const sig = header(ctx.headers, 'paddle-signature')
    if (!sig) {
      throw new DoorbellError('No Paddle-Signature header.', { code: 'missing_header' })
    }
    const parsed = parsePaddleHeader(sig)
    if (!parsed.ts || parsed.h1.length === 0) {
      throw new DoorbellError('Could not read ts and h1 from Paddle-Signature.', { code: 'bad_header' })
    }
    const timestamp = Number.parseInt(parsed.ts, 10)
    const freshness = assertFresh(timestamp, { toleranceSec: ctx.toleranceSec, now: ctx.now })
    if (freshness !== 'ok') {
      throw new DoorbellError('Paddle timestamp is outside the allowed window.', { code: 'replay' })
    }
    const signed = prefixRaw(`${parsed.ts}:`, ctx.raw)
    const ok = await matchAnyHexMac(ctx.secrets, signed, parsed.h1)
    if (!ok) {
      throw new DoorbellError('Paddle signature did not match.', { code: 'bad_signature' })
    }
    return { timestampSec: timestamp }
  },
}
