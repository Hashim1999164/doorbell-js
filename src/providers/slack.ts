import { assertFresh } from '../clock.js'
import { DoorbellError, secretHint } from '../errors.js'
import { header } from '../headers.js'
import { matchAnyHexMac } from '../hmac.js'
import { parseJsonBody, stringField } from '../json.js'
import { prefixRaw } from '../wire.js'
import type { HeaderMap } from '../headers.js'
import type { Provider } from './types.js'

export function sniffSlack(headers: HeaderMap): boolean {
  return Boolean(header(headers, 'x-slack-signature'))
}

export const slack: Provider = {
  name: 'slack',
  sniff: sniffSlack,
  parse: parseJsonBody,
  eventId(_headers, payload) {
    return (
      stringField(payload, 'event_id') ??
      stringField(payload, 'trigger_id') ??
      stringField(payload, 'challenge') ??
      'slack'
    )
  },
  eventType(_headers, payload) {
    return stringField(payload, 'type') ?? 'unknown'
  },
  async verify(ctx) {
    const sig = header(ctx.headers, 'x-slack-signature')
    const ts = header(ctx.headers, 'x-slack-request-timestamp')
    if (!sig || !ts) {
      throw new DoorbellError('Missing Slack signature headers.', {
        code: 'missing_header',
        hint: 'Need X-Slack-Signature and X-Slack-Request-Timestamp.',
      })
    }
    const timestamp = Number.parseInt(ts, 10)
    const freshness = assertFresh(timestamp, { toleranceSec: ctx.toleranceSec, now: ctx.now })
    if (freshness !== 'ok') {
      throw new DoorbellError('Slack timestamp is outside the allowed window.', {
        code: 'replay',
        hint: 'Slack asks for 5 minutes. Replay protection is the point.',
      })
    }
    const hex = sig.startsWith('v0=') ? sig.slice(3) : sig
    const signed = prefixRaw(`v0:${ts}:`, ctx.raw)
    const ok = await matchAnyHexMac(ctx.secrets, signed, [hex])
    if (!ok) {
      throw new DoorbellError('Slack signature did not match.', {
        code: 'bad_signature',
        hint: secretHint('slack'),
      })
    }
    return { timestampSec: timestamp }
  },
}
