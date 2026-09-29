import { burnHex } from '../burn.js'
import { assertFresh } from '../clock.js'
import { DoorbellError, secretHint } from '../errors.js'
import { header, sigHeader } from '../headers.js'
import { matchAnyHexMac } from '../hmac.js'
import { bodyFingerprint } from '../hash.js'
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
  eventId(_headers, payload, raw) {
    return (
      stringField(payload, 'event_id') ??
      stringField(payload, 'trigger_id') ??
      stringField(payload, 'challenge') ??
      bodyFingerprint(raw)
    )
  },
  eventType(_headers, payload) {
    return stringField(payload, 'type') ?? 'unknown'
  },
  async verify(ctx) {
    const sig = sigHeader(ctx.headers, 'x-slack-signature', 'Slack')
    const ts = sigHeader(ctx.headers, 'x-slack-request-timestamp', 'Slack')
    if (!sig || !ts) {
      await burnHex(ctx.secrets, ctx.raw)
      throw new DoorbellError('Missing Slack signature headers.', {
        code: 'missing_header',
        hint: 'Need X-Slack-Signature and X-Slack-Request-Timestamp.',
      })
    }
    const timestamp = Number.parseInt(ts, 10)
    const hex = sig.startsWith('v0=') ? sig.slice(3) : sig
    const signed = prefixRaw(`v0:${ts}:`, ctx.raw)
    const ok = await matchAnyHexMac(ctx.secrets, signed, [hex])
    if (!ok) {
      throw new DoorbellError('Slack signature did not match.', {
        code: 'bad_signature',
        hint: secretHint('slack'),
      })
    }
    const freshness = assertFresh(timestamp, {
      toleranceSec: ctx.toleranceSec,
      now: ctx.now,
      future: 'reject',
    })
    if (freshness !== 'ok') {
      throw new DoorbellError('Slack timestamp is outside the allowed window.', {
        code: 'replay',
        hint: 'Slack asks for 5 minutes either side. A timestamp from the future is how you stash a signed body and replay it later.',
      })
    }
    return { timestampSec: timestamp }
  },
}
