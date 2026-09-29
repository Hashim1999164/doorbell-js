import { utf8 } from '../bytes.js'
import { DoorbellError, secretHint } from '../errors.js'
import { header } from '../headers.js'
import { hmacSha1, timingSafeEqual } from '../hmac.js'
import { parseBase64 } from '../bytes.js'
import type { HeaderMap } from '../headers.js'
import type { Provider } from './types.js'

export function sniffTwilio(headers: HeaderMap): boolean {
  return Boolean(header(headers, 'x-twilio-signature'))
}

function formParams(raw: Uint8Array): URLSearchParams {
  return new URLSearchParams(new TextDecoder().decode(raw))
}

function twilioBase(url: string, params: URLSearchParams): string {
  const keys = [...params.keys()].sort()
  let out = url
  for (const key of keys) {
    out += key + (params.get(key) ?? '')
  }
  return out
}

export const twilio: Provider = {
  name: 'twilio',
  sniff: sniffTwilio,
  parse(raw) {
    const params = formParams(raw)
    return Object.fromEntries(params.entries())
  },
  eventId(_headers, payload) {
    if (payload && typeof payload === 'object' && 'MessageSid' in payload && typeof payload.MessageSid === 'string') {
      return payload.MessageSid
    }
    if (payload && typeof payload === 'object' && 'CallSid' in payload && typeof payload.CallSid === 'string') {
      return payload.CallSid
    }
    return 'twilio'
  },
  eventType() {
    return 'twilio'
  },
  async verify(ctx) {
    const sig = header(ctx.headers, 'x-twilio-signature')
    if (!sig) {
      throw new DoorbellError('No X-Twilio-Signature header.', { code: 'missing_header' })
    }
    if (!ctx.url) {
      throw new DoorbellError('Twilio checks need the public URL Twilio called.', {
        code: 'missing_url',
        hint: secretHint('twilio'),
      })
    }
    const params = formParams(ctx.raw)
    const base = utf8(twilioBase(ctx.url, params))
    let ok = false
    for (const key of ctx.secrets) {
      const mac = await hmacSha1(key, base)
      const provided = parseBase64(sig)
      if (provided && timingSafeEqual(mac, provided)) ok = true
    }
    if (!ok) {
      throw new DoorbellError('Twilio signature did not match.', {
        code: 'bad_signature',
        hint: secretHint('twilio'),
      })
    }
    return { timestampSec: undefined }
  },
}
