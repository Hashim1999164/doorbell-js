import { burnHex } from '../burn.js'
import { assertFresh } from '../clock.js'
import { DoorbellError } from '../errors.js'
import { header, sigHeader } from '../headers.js'
import { matchAnyHexMac } from '../hmac.js'
import { bodyFingerprint } from '../hash.js'
import { parseJsonBody, stringField, unixField } from '../json.js'
import type { HeaderMap } from '../headers.js'
import type { Provider } from './types.js'

export function sniffLinear(headers: HeaderMap): boolean {
  return Boolean(header(headers, 'linear-signature'))
}

export const linear: Provider = {
  name: 'linear',
  sniff: sniffLinear,
  parse: parseJsonBody,
  eventId(_headers, payload, raw) {
    return stringField(payload, 'webhookId') ?? bodyFingerprint(raw)
  },
  eventType(_headers, payload) {
    const type = stringField(payload, 'type')
    const action = stringField(payload, 'action')
    if (type && action) return `${type}.${action}`
    return type ?? 'linear'
  },
  async verify(ctx) {
    const sig = sigHeader(ctx.headers, 'linear-signature', 'Linear')
    if (!sig) {
      await burnHex(ctx.secrets, ctx.raw)
      throw new DoorbellError('No Linear-Signature header.', { code: 'missing_header' })
    }
    const ok = await matchAnyHexMac(ctx.secrets, ctx.raw, [sig])
    if (!ok) {
      throw new DoorbellError('Linear signature did not match.', { code: 'bad_signature' })
    }
    let timestampSec: number | undefined
    try {
      timestampSec = unixField(parseJsonBody(ctx.raw), 'webhookTimestamp')
    } catch {
      timestampSec = undefined
    }
    if (timestampSec == null) {
      throw new DoorbellError('Linear body has no webhookTimestamp. That field is the replay clock.', {
        code: 'replay',
        hint: 'Linear signs the JSON. If webhookTimestamp is missing, a captured body can be posted forever.',
      })
    }
    const freshness = assertFresh(timestampSec, {
      toleranceSec: ctx.toleranceSec,
      now: ctx.now,
      future: 'reject',
    })
    if (freshness !== 'ok') {
      throw new DoorbellError('Linear webhookTimestamp is outside the allowed window.', {
        code: 'replay',
      })
    }
    return { timestampSec }
  },
}
