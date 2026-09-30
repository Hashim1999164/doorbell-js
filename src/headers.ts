import { DoorbellError } from './errors.js'

export type HeaderMap = Map<string, string>

const COMMA_JOIN = new Set([
  'stripe-signature',
  'svix-signature',
  'webhook-signature',
  'paddle-signature',
])

export function headerMap(
  input: Headers | Record<string, string | string[] | undefined> | HeaderMap,
): HeaderMap {
  if (input instanceof Map) return input
  const out: HeaderMap = new Map()
  if (typeof Headers !== 'undefined' && input instanceof Headers) {
    input.forEach((value, key) => {
      out.set(key.toLowerCase(), value)
    })
    return out
  }
  for (const [key, value] of Object.entries(input as Record<string, string | string[] | undefined>)) {
    if (value == null) continue
    const name = key.toLowerCase()
    if (Array.isArray(value)) {
      if (value.length === 0) continue
      out.set(name, COMMA_JOIN.has(name) ? value.join(',') : String(value[0]))
      continue
    }
    out.set(name, value)
  }
  return out
}

export function contentTypeAllowed(provider: string, headers: HeaderMap): boolean {
  const raw = header(headers, 'content-type')
  if (!raw) return true
  const ct = raw.split(';')[0]!.trim().toLowerCase()
  if (!ct) return true
  if (provider === 'twilio') {
    return (
      ct === 'application/x-www-form-urlencoded' ||
      ct === 'application/json' ||
      ct === 'application/octet-stream' ||
      ct === 'multipart/form-data' ||
      ct === 'text/plain'
    )
  }
  // Fetch sets text/plain on a string body. HMAC is the seal. text/html is a browser.
  return (
    ct === 'application/json' ||
    ct === 'application/octet-stream' ||
    ct === 'text/plain'
  )
}

export function header(headers: HeaderMap, name: string): string | undefined {
  return headers.get(name.toLowerCase())
}

export function headerRequired(headers: HeaderMap, name: string): string {
  const value = header(headers, name)
  if (!value) {
    throw new Error(`missing_header:${name.toLowerCase()}`)
  }
  return value
}

export function sigHeader(headers: HeaderMap, name: string, label: string): string | undefined {
  const value = header(headers, name)
  if (value) assertSigHeader(value, label)
  return value
}

const MAX_SIG_HEADER = 8192
const MAX_SIG_PARTS = 16

export function assertSigHeader(value: string, label: string): void {
  if (value.length > MAX_SIG_HEADER) {
    throw new DoorbellError(`${label} header is huge. Refusing to parse it.`, {
      code: 'header_too_large',
    })
  }
  for (let i = 0; i < value.length; i++) {
    const c = value.charCodeAt(i)
    if (c === 0 || c === 10 || c === 13) {
      throw new DoorbellError(`${label} header contains a newline. That is not a signature.`, {
        code: 'bad_header',
      })
    }
  }
}

export function capParts(parts: string[], label: string): string[] {
  if (parts.length > MAX_SIG_PARTS) {
    throw new DoorbellError(`${label} sent too many signatures.`, { code: 'bad_header' })
  }
  return parts
}

/** Unsigned headers are still RAM. A 1MB header block is not a webhook. */
export function assertHeaderBudget(headers: HeaderMap, maxBytes: number): void {
  if (maxBytes <= 0) return
  let n = 0
  for (const [k, v] of headers) {
    n += k.length + v.length
    if (n > maxBytes) {
      throw new DoorbellError('Request headers are huge.', {
        code: 'headers_too_large',
        hint: 'A webhook does not need a 1MB header block. Raise maxHeaderBytes if a proxy piles them on.',
      })
    }
  }
}
