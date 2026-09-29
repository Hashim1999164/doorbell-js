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
