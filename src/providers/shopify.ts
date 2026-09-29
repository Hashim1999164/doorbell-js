import { burnB64 } from '../burn.js'
import { DoorbellError, secretHint } from '../errors.js'
import { bodyFingerprint } from '../hash.js'
import { header, sigHeader } from '../headers.js'
import { matchAnyBase64Mac } from '../hmac.js'
import { hasOwn, parseJsonBody } from '../json.js'
import type { HeaderMap } from '../headers.js'
import type { Provider } from './types.js'

export function sniffShopify(headers: HeaderMap): boolean {
  return Boolean(header(headers, 'x-shopify-hmac-sha256'))
}

export const shopify: Provider = {
  name: 'shopify',
  sniff: sniffShopify,
  parse: parseJsonBody,
  eventId(_headers, _payload, raw) {
    return bodyFingerprint(raw)
  },
  eventType(_headers, payload) {
    // X-Shopify-Topic is not in the HMAC. Do not dispatch on[orders/paid] from that header.
    const family = shopifyFamilyForBody(payload)
    if (family) return family
    return 'shopify'
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
    const payload = parseJsonBody(ctx.raw)
    const topic = header(ctx.headers, 'x-shopify-topic') ?? ''
    if (!shopifyTopicMatchesBody(topic, payload)) {
      throw new DoorbellError('X-Shopify-Topic does not match the signed body.', {
        code: 'bad_header',
        hint: 'Shopify does not HMAC that header. If the signed JSON looks like an order, app/uninstalled will not run on[app/uninstalled].',
      })
    }
    return { timestampSec: undefined }
  },
}

export function shopifyTopicMatchesBody(topic: string, payload: unknown): boolean {
  const t = topic.trim().toLowerCase()
  if (!t) return false
  const family = shopifyFamilyForBody(payload)
  if (family === 'orders') return t.startsWith('orders/') || t.startsWith('checkouts/')
  if (family === 'products') return t.startsWith('products/')
  return true
}

function shopifyFamilyForBody(payload: unknown): 'orders' | 'products' | undefined {
  if (hasOwn(payload, 'line_items') || hasOwn(payload, 'order_number') || hasOwn(payload, 'checkout_id')) {
    return 'orders'
  }
  if (hasOwn(payload, 'variants') || hasOwn(payload, 'product_type')) return 'products'
  return undefined
}
