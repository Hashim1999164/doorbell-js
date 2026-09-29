import { burnHex } from '../burn.js'
import { assertFresh } from '../clock.js'
import { DoorbellError, secretHint } from '../errors.js'
import { capParts, header, sigHeader } from '../headers.js'
import { matchAnyHexMac } from '../hmac.js'
import { parseJsonBody } from '../json.js'
import { prefixRaw } from '../wire.js'
import type { HeaderMap } from '../headers.js'
import type { Provider, VerifyCtx } from './types.js'

function parseStripeHeader(value: string): { timestamp: number; signatures: string[] } {
  let timestamp = -1
  const signatures: string[] = []
  for (const part of capParts(value.split(','), 'Stripe')) {
    const eq = part.indexOf('=')
    if (eq === -1) continue
    const k = part.slice(0, eq).trim()
    const v = part.slice(eq + 1).trim()
    if (k === 't') timestamp = Number.parseInt(v, 10)
    if (k === 'v1') signatures.push(v)
  }
  capParts(signatures, 'Stripe')
  return { timestamp, signatures }
}

export function sniffStripe(headers: HeaderMap): boolean {
  return Boolean(header(headers, 'stripe-signature'))
}

export const stripe: Provider = {
  name: 'stripe',
  sniff: sniffStripe,
  parse: parseJsonBody,
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
    const sigHeaderValue = sigHeader(ctx.headers, 'stripe-signature', 'Stripe')
    if (!sigHeaderValue) {
      await burnHex(ctx.secrets, ctx.raw)
      throw new DoorbellError('No stripe-signature header.', {
        code: 'missing_header',
        hint: 'Stripe always sends Stripe-Signature. If you do not see it, a proxy stripped it.',
      })
    }
    const { timestamp, signatures } = parseStripeHeader(sigHeaderValue)
    if (timestamp < 0 || signatures.length === 0) {
      await burnHex(ctx.secrets, ctx.raw)
      throw new DoorbellError('Could not read timestamp and v1 signatures from Stripe-Signature.', {
        code: 'bad_header',
        hint: 'The header looks like t=123,v1=hex. If you pasted a test string, check commas.',
      })
    }
    const signed = prefixRaw(`${timestamp}.`, ctx.raw)
    const ok = await matchAnyHexMac(ctx.secrets, signed, signatures)
    if (!ok) {
      throw stripeMismatch(ctx)
    }
    const freshness = assertFresh(timestamp, {
      toleranceSec: ctx.toleranceSec,
      now: ctx.now,
      future: 'allow',
    })
    if (freshness === 'too_old' || freshness === 'bad') {
      throw new DoorbellError('Stripe timestamp is too old.', {
        code: 'replay',
        hint: 'Default window is 5 minutes. Stripe-node only rejects old events, not future ones. If your server clock is wrong, fix NTP.',
      })
    }
    return { timestampSec: timestamp }
  },
}

function stripeMismatch(ctx: VerifyCtx): DoorbellError {
  const whitespace = ctx.secretStrings.some((s) => /\s/.test(s))
  return new DoorbellError('Stripe signature did not match.', {
    code: 'bad_signature',
    hint: [
      secretHint('stripe'),
      whitespace ? 'Your secret has whitespace in it. That is usually a leftover newline in .env.' : '',
      'The HMAC is over the raw bytes after t=timestamp. Decoding JSON and stringifying it again will not match.',
    ]
      .filter(Boolean)
      .join('\n'),
  })
}

function fallbackId(seed: string): string {
  return `anon:${seed}`
}

function rawHashKey(_headers: HeaderMap, payload: unknown): string {
  if (payload && typeof payload === 'object') return JSON.stringify(payload).slice(0, 80)
  return 'none'
}
