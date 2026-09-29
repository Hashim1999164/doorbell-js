import { standardWebhookKey } from '../bytes.js'
import { assertFresh } from '../clock.js'
import { DoorbellError, secretHint } from '../errors.js'
import { header } from '../headers.js'
import { matchAnyBase64Mac } from '../hmac.js'
import { parseJsonBody, stringField } from '../json.js'
import { prefixRaw } from '../wire.js'
import type { HeaderMap } from '../headers.js'
import type { Provider, ProviderName, VerifyCtx } from './types.js'

function makeStandard(name: ProviderName, idHeader: string, tsHeader: string, sigHeader: string): Provider {
  return {
    name,
    sniff(headers: HeaderMap) {
      return Boolean(header(headers, sigHeader) && header(headers, idHeader))
    },
    parse: parseJsonBody,
    eventId(headers) {
      return header(headers, idHeader) ?? name
    },
    eventType(_headers, payload) {
      return stringField(payload, 'type') ?? stringField(payload, 'event_type') ?? name
    },
    async verify(ctx: VerifyCtx) {
      const id = header(ctx.headers, idHeader)
      const ts = header(ctx.headers, tsHeader)
      const sig = header(ctx.headers, sigHeader)
      if (!id || !ts || !sig) {
        throw new DoorbellError(`Missing ${name} Standard Webhooks headers.`, {
          code: 'missing_header',
          hint: `Need ${idHeader}, ${tsHeader}, ${sigHeader}.`,
        })
      }
      const timestamp = Number.parseInt(ts, 10)
      const freshness = assertFresh(timestamp, { toleranceSec: ctx.toleranceSec, now: ctx.now })
      if (freshness !== 'ok') {
        throw new DoorbellError(`${name} timestamp is outside the allowed window.`, { code: 'replay' })
      }
      const toSign = prefixRaw(`${id}.${timestamp}.`, ctx.raw)
      const keys = ctx.secretStrings.map((s) => {
        try {
          return standardWebhookKey(s)
        } catch {
          throw new DoorbellError(`${name} secret is not a Standard Webhooks secret.`, {
            code: 'bad_secret',
            hint: secretHint(name),
          })
        }
      })
      const candidates = sig.split(/[,\s]+/).flatMap((part) => {
        const trimmed = part.trim()
        if (!trimmed) return []
        if (trimmed.startsWith('v1,')) return [trimmed.slice(3)]
        if (trimmed.startsWith('v1=')) return [trimmed.slice(3)]
        return [trimmed]
      })
      const ok = await matchAnyBase64Mac(keys, toSign, candidates)
      if (!ok) {
        throw new DoorbellError(`${name} signature did not match.`, {
          code: 'bad_signature',
          hint: secretHint(name),
        })
      }
      return { timestampSec: timestamp }
    },
  }
}

export const svix = makeStandard('svix', 'svix-id', 'svix-timestamp', 'svix-signature')
export const clerk = makeStandard('clerk', 'svix-id', 'svix-timestamp', 'svix-signature')
export const resend = makeStandard('resend', 'svix-id', 'svix-timestamp', 'svix-signature')
export const standard = makeStandard('svix', 'webhook-id', 'webhook-timestamp', 'webhook-signature')

export function sniffSvix(headers: HeaderMap): boolean {
  return Boolean(header(headers, 'svix-signature') || header(headers, 'webhook-signature'))
}
