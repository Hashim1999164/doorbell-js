import { utf8 } from '../bytes.js'
import { burnSha1 } from '../burn.js'
import { DoorbellError, secretHint } from '../errors.js'
import { header, sigHeader } from '../headers.js'
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

function urlVariants(url: string): string[] {
  const noSlash = url.replace(/\/+$/, '')
  const slash = `${noSlash}/`
  return [...new Set([url, noSlash, slash].filter((u) => u.length > 0))]
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
    const sig = sigHeader(ctx.headers, 'x-twilio-signature', 'Twilio')
    if (!sig) {
      await burnSha1(ctx.secrets, ctx.raw)
      throw new DoorbellError('No X-Twilio-Signature header.', { code: 'missing_header' })
    }
    if (!ctx.url) {
      await burnSha1(ctx.secrets, ctx.raw)
      throw new DoorbellError('Twilio checks need the public URL Twilio called.', {
        code: 'missing_url',
        hint: secretHint('twilio'),
      })
    }
    const params = formParams(ctx.raw)
    const provided = parseBase64(sig)
    let ok = false
    for (const url of urlVariants(ctx.url)) {
      const base = utf8(twilioBase(url, params))
      for (const key of ctx.secrets) {
        const mac = await hmacSha1(key, base)
        const dummy = new Uint8Array(mac.byteLength)
        const right = provided && provided.byteLength === mac.byteLength ? provided : dummy
        if (provided && provided.byteLength === mac.byteLength && timingSafeEqual(mac, right)) ok = true
        else timingSafeEqual(mac, right)
      }
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
