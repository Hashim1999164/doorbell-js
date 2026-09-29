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
      throw new DoorbellError('No X-Shopify-Hmac-Sha256 header.', { code: 'missing_header' })
    }
    const ok = await matchAnyBase64Mac(ctx.secrets, ctx.raw, [hmac])
    if (!ok) {
      throw new DoorbellError('Shopify signature did not match.', {
        code: 'bad_signature',
        hint: secretHint('shopify'),
      })
    }
    return { timestampSec: undefined }
  },
}

