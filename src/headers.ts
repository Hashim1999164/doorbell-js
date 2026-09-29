import { DoorbellError } from './errors.js'

export type HeaderMap = Map<string, string>

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
    const joined = Array.isArray(value) ? value.join(',') : value
    out.set(key.toLowerCase(), joined)
  }
  return out
}

export function header(headers: HeaderMap, name: string): string | undefined {
  return headers.get(name.toLowerCase()) ?? undefined
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
