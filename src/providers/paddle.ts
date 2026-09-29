import { burnHex } from '../burn.js'
import { assertFresh, parseUnixSec } from '../clock.js'
import { DoorbellError } from '../errors.js'
import { capParts, header, sigHeader } from '../headers.js'
import { matchAnyHexMac } from '../hmac.js'
import { bodyFingerprint } from '../hash.js'
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
  for (const part of capParts(value.split(';'), 'Paddle')) {
    const eq = part.indexOf('=')
    if (eq === -1) continue
    const k = part.slice(0, eq).trim()
    const v = part.slice(eq + 1).trim()
    if (k === 'ts' && v) ts.push(v)
    if (k === 'h1' && v) h1.push(v)
  }
  capParts(h1, 'Paddle')
  return { ts: ts[0] ?? '', h1 }
}

export const paddle: Provider = {
  name: 'paddle',
  sniff: sniffPaddle,
  parse: parseJsonBody,
  eventId(_headers, payload, raw) {
    return stringField(payload, 'event_id') ?? stringField(payload, 'notification_id') ?? bodyFingerprint(raw)
  },
  eventType(_headers, payload) {
    return stringField(payload, 'event_type') ?? 'paddle'
  },
  async verify(ctx) {
    const sig = sigHeader(ctx.headers, 'paddle-signature', 'Paddle')
    if (!sig) {
      await burnHex(ctx.secrets, ctx.raw)
      throw new DoorbellError('No Paddle-Signature header.', { code: 'missing_header' })
    }
    const parsed = parsePaddleHeader(sig)
    if (!parsed.ts || parsed.h1.length === 0) {
      await burnHex(ctx.secrets, ctx.raw)
      throw new DoorbellError('Could not read ts and h1 from Paddle-Signature.', { code: 'bad_header' })
    }
    const signed = prefixRaw(`${parsed.ts}:`, ctx.raw)
    const ok = await matchAnyHexMac(ctx.secrets, signed, parsed.h1)
    if (!ok) {
      throw new DoorbellError('Paddle signature did not match.', { code: 'bad_signature' })
    }
    const timestamp = parseUnixSec(parsed.ts)
    if (timestamp == null) {
      throw new DoorbellError('Paddle timestamp is not a unix second.', { code: 'bad_header' })
    }
    const freshness = assertFresh(timestamp, {
      toleranceSec: ctx.toleranceSec,
      now: ctx.now,
      future: 'reject',
    })
    if (freshness !== 'ok') {
      throw new DoorbellError('Paddle timestamp is outside the allowed window.', { code: 'replay' })
    }
    return { timestampSec: timestamp }
  },
}
