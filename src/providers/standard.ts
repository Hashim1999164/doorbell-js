import { burnB64 } from '../burn.js'
import { standardWebhookKey } from '../bytes.js'
import { assertFresh, parseUnixSec } from '../clock.js'
import { DoorbellError, secretHint } from '../errors.js'
import { capParts, header, sigHeader } from '../headers.js'
import { matchAnyBase64Mac } from '../hmac.js'
import { parseJsonBody, stringField } from '../json.js'
import { prefixRaw } from '../wire.js'
import type { HeaderMap } from '../headers.js'
import type { Provider, ProviderName, VerifyCtx } from './types.js'

function makeStandard(name: ProviderName, idHeader: string, tsHeader: string, sigHeaderName: string): Provider {
  return {
    name,
    sniff(headers: HeaderMap) {
      return Boolean(header(headers, sigHeaderName) && header(headers, idHeader))
    },
    parse: parseJsonBody,
    eventId(headers) {
      return header(headers, idHeader) ?? name
    },
    eventType(_headers, payload) {
      return stringField(payload, 'type') ?? stringField(payload, 'event_type') ?? name
    },
    async verify(ctx: VerifyCtx) {
      const id = sigHeader(ctx.headers, idHeader, name)
      const ts = sigHeader(ctx.headers, tsHeader, name)
      const sig = sigHeader(ctx.headers, sigHeaderName, name)
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
      if (!id || !ts || !sig) {
        await burnB64(keys, ctx.raw)
        throw new DoorbellError(`Missing ${name} Standard Webhooks headers.`, {
          code: 'missing_header',
          hint: `Need ${idHeader}, ${tsHeader}, ${sigHeaderName}.`,
        })
      }
      const toSign = prefixRaw(`${id}.${ts.trim()}.`, ctx.raw)
      const candidates = capParts(v1Signatures(sig), name)
      const ok = await matchAnyBase64Mac(keys, toSign, candidates)
      if (!ok) {
        throw new DoorbellError(`${name} signature did not match.`, {
          code: 'bad_signature',
          hint: secretHint(name),
        })
      }
      const timestamp = parseUnixSec(ts)
      if (timestamp == null) {
        throw new DoorbellError(`${name} timestamp is not a unix second.`, { code: 'bad_header' })
      }
      const freshness = assertFresh(timestamp, {
        toleranceSec: ctx.toleranceSec,
        now: ctx.now,
        future: 'reject',
      })
      if (freshness !== 'ok') {
        throw new DoorbellError(`${name} timestamp is outside the allowed window.`, { code: 'replay' })
      }
      return { timestampSec: timestamp }
    },
  }
}

export const svix = makeStandard('svix', 'svix-id', 'svix-timestamp', 'svix-signature')
export const clerk = makeStandard('clerk', 'svix-id', 'svix-timestamp', 'svix-signature')
export const resend = makeStandard('resend', 'svix-id', 'svix-timestamp', 'svix-signature')
export const standard = makeStandard('svix', 'webhook-id', 'webhook-timestamp', 'webhook-signature')

/** Standard Webhooks is v1,<base64>. Ignore v0 and do not HMAC the leftover "v1" token. */
function v1Signatures(header: string): string[] {
  const parts = header.split(/[,\s]+/).map((p) => p.trim()).filter(Boolean)
  const out: string[] = []
  for (let i = 0; i < parts.length; i++) {
    const part = parts[i]
    if (!part) continue
    if (part === 'v1') {
      const next = parts[i + 1]
      if (next && !/^v\d+$/.test(next)) {
        out.push(next)
        i += 1
      }
      continue
    }
    if (part.startsWith('v1=')) {
      const rest = part.slice(3)
      if (rest) out.push(rest)
      continue
    }
    if (part.startsWith('v1,') && part.length > 3) out.push(part.slice(3))
  }
  return out
}

export function sniffSvix(headers: HeaderMap): boolean {
  return Boolean(header(headers, 'svix-signature') || header(headers, 'webhook-signature'))
}
