import { burnB64 } from '../burn.js'
import { assertFresh } from '../clock.js'
import { DoorbellError, secretHint } from '../errors.js'
import { header, sigHeader } from '../headers.js'
import { matchAnyBase64Mac } from '../hmac.js'
import { parseJsonBody } from '../json.js'
import type { HeaderMap } from '../headers.js'
import type { Provider } from './types.js'

export function sniffShopify(headers: HeaderMap): boolean {
  return Boolean(header(headers, 'x-shopify-hmac-sha256'))
}

export const shopify: Provider = {
  name: 'shopify',
  sniff: sniffShopify,
  parse: parseJsonBody,
  eventId(headers) {
    return header(headers, 'x-shopify-webhook-id') ?? header(headers, 'x-shopify-event-id') ?? 'shopify'
  },
  eventType(headers) {
    return header(headers, 'x-shopify-topic') ?? 'unknown'
  },
  async verify(ctx) {
    const hmac = sigHeader(ctx.headers, 'x-shopify-hmac-sha256', 'Shopify')
    if (!hmac) {
      await burnB64(ctx.secrets, ctx.raw)
      throw new DoorbellError('No X-Shopify-Hmac-Sha256 header.', { code: 'missing_header' })
    }
    const ok = await matchAnyBase64Mac(ctx.secrets, ctx.raw, [hmac])
    if (!ok) {
      throw new DoorbellError('Shopify signature did not match.', {
        code: 'bad_signature',
        hint: secretHint('shopify'),
      })
    }
    const triggered = sigHeader(ctx.headers, 'x-shopify-triggered-at', 'Shopify')
    if (triggered) {
      const ms = Date.parse(triggered)
      if (!Number.isFinite(ms)) {
        throw new DoorbellError('X-Shopify-Triggered-At is not a date.', { code: 'bad_header' })
      }
      const freshness = assertFresh(Math.floor(ms / 1000), {
        toleranceSec: ctx.toleranceSec,
        now: ctx.now,
        future: 'reject',
      })
      if (freshness !== 'ok') {
        throw new DoorbellError('Shopify triggered-at is outside the allowed window.', { code: 'replay' })
      }
    }
    return { timestampSec: undefined }
  },
}
