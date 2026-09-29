import { DoorbellError } from '../errors.js'
import { header } from '../headers.js'
import { matchAnyHexMac } from '../hmac.js'
import { parseJsonBody, stringField } from '../json.js'
import type { HeaderMap } from '../headers.js'
import type { Provider } from './types.js'

export function sniffLinear(headers: HeaderMap): boolean {
  return Boolean(header(headers, 'linear-signature'))
}

export const linear: Provider = {
  name: 'linear',
  sniff: sniffLinear,
  parse: parseJsonBody,
  eventId(_headers, payload) {
    const webhookId = stringField(payload, 'webhookTimestamp')
    const type = stringField(payload, 'type')
    const action = stringField(payload, 'action')
    return [type, action, webhookId].filter(Boolean).join(':') || 'linear'
  },
  eventType(_headers, payload) {
    const type = stringField(payload, 'type')
    const action = stringField(payload, 'action')
    if (type && action) return `${type}.${action}`
    return type ?? 'linear'
  },
  async verify(ctx) {
    const sig = header(ctx.headers, 'linear-signature')
    if (!sig) {
      throw new DoorbellError('No Linear-Signature header.', { code: 'missing_header' })
    }
    const ok = await matchAnyHexMac(ctx.secrets, ctx.raw, [sig])
    if (!ok) {
      throw new DoorbellError('Linear signature did not match.', { code: 'bad_signature' })
    }
    return { timestampSec: undefined }
  },
}
