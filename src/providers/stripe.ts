import { fromUtf8, utf8 } from '../bytes.js'
import { assertFresh } from '../clock.js'
import { DoorbellError, secretHint } from '../errors.js'
import { header } from '../headers.js'
import { matchAnyHexMac } from '../hmac.js'
import type { HeaderMap } from '../headers.js'
import type { Provider, VerifyCtx } from './types.js'

function parseStripeHeader(value: string): { timestamp: number; signatures: string[] } {
  let timestamp = -1
  const signatures: string[] = []
  for (const part of value.split(',')) {
    const eq = part.indexOf('=')
    if (eq === -1) continue
    const k = part.slice(0, eq).trim()
    const v = part.slice(eq + 1).trim()
    if (k === 't') timestamp = Number.parseInt(v, 10)
    if (k === 'v1') signatures.push(v)
  }
  return { timestamp, signatures }
}

export function sniffStripe(headers: HeaderMap): boolean {
  return Boolean(header(headers, 'stripe-signature'))
}

export const stripe: Provider = {
  name: 'stripe',
  sniff: sniffStripe,
  parse(raw) {
    return jsonBody(raw)
  },
  eventId(_headers, payload) {
    if (payload && typeof payload === 'object' && 'id' in payload && typeof payload.id === 'string') {
      return payload.id
    }
    return fallbackId(rawHashKey(_headers, payload))
  },
  eventType(_headers, payload) {
    if (payload && typeof payload === 'object' && 'type' in payload && typeof payload.type === 'string') {
      return payload.type
    }
    return 'unknown'
  },
  async verify(ctx) {
    const sigHeader = header(ctx.headers, 'stripe-signature')
    if (!sigHeader) {
      throw new DoorbellError('No stripe-signature header.', {
        code: 'missing_header',
        hint: 'Stripe always sends Stripe-Signature. If you do not see it, a proxy stripped it.',
      })
    }
    const { timestamp, signatures } = parseStripeHeader(sigHeader)
    if (timestamp < 0 || signatures.length === 0) {
      throw new DoorbellError('Could not read timestamp and v1 signatures from Stripe-Signature.', {
        code: 'bad_header',
        hint: 'The header looks like t=123,v1=hex. If you pasted a test string, check commas.',
      })
    }
    const freshness = assertFresh(timestamp, { toleranceSec: ctx.toleranceSec, now: ctx.now })
    if (freshness === 'too_old' || freshness === 'too_new' || freshness === 'bad') {
      throw new DoorbellError(
        freshness === 'too_new'
          ? 'Stripe timestamp is in the future.'
          : 'Stripe timestamp is too old.',
        {
          code: 'replay',
          hint: 'Default window is 5 minutes. If your server clock is wrong, fix NTP. Do not disable this in production.',
        },
      )
    }
    const signed = utf8(`${timestamp}.${fromUtf8(ctx.raw)}`)
    const ok = await matchAnyHexMac(ctx.secrets, signed, signatures)
    if (!ok) {
      throw stripeMismatch(ctx)
    }
    return { timestampSec: timestamp }
  },
}

function stripeMismatch(ctx: VerifyCtx): DoorbellError {
  const looksParsed = ctx.raw.byteLength > 0 && false
  void looksParsed
  const whitespace = ctx.secretStrings.some((s) => s.trim() !== s || /\s/.test(s))
  return new DoorbellError('Stripe signature did not match.', {
    code: 'bad_signature',
    hint: [
      secretHint('stripe'),
      whitespace ? 'Your secret has whitespace in it. That is usually a leftover newline in .env.' : '',
      'Also: the body must be the exact bytes Stripe signed. JSON.stringify of a parsed object is not the same thing.',
    ]
      .filter(Boolean)
      .join('\n'),
  })
}

function jsonBody(raw: Uint8Array): unknown {
  const text = fromUtf8(raw)
  if (text.length === 0) return {}
  try {
    return JSON.parse(text) as unknown
  } catch (cause) {
    throw new DoorbellError('Body is not JSON.', { code: 'bad_json', cause })
  }
}

function fallbackId(seed: string): string {
  return `anon:${seed}`
}

function rawHashKey(_headers: HeaderMap, payload: unknown): string {
  if (payload && typeof payload === 'object') return JSON.stringify(payload).slice(0, 80)
  return 'none'
}
