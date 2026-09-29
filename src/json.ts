import { DoorbellError } from './errors.js'

export function parseJsonBody(raw: Uint8Array): unknown {
  if (raw.byteLength === 0) return {}
  let text: string
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(raw)
  } catch (cause) {
    throw new DoorbellError('Body is not valid UTF-8. Webhook JSON has to be.', {
      code: 'bad_utf8',
      cause,
    })
  }
  try {
    return JSON.parse(text) as unknown
  } catch (cause) {
    throw new DoorbellError('Body is not JSON.', { code: 'bad_json', cause })
  }
}

export function stringField(payload: unknown, key: string): string | undefined {
  if (payload && typeof payload === 'object' && key in payload) {
    const value = (payload as Record<string, unknown>)[key]
    if (typeof value === 'string' && value.length > 0) return value
  }
  return undefined
}

export function unixField(payload: unknown, key: string): number | undefined {
  if (!payload || typeof payload !== 'object' || !(key in payload)) return undefined
  const value = (payload as Record<string, unknown>)[key]
  let n: number | undefined
  if (typeof value === 'number' && Number.isFinite(value)) n = value
  else if (typeof value === 'string' && value.length > 0) {
    const parsed = Number(value)
    if (Number.isFinite(parsed)) n = parsed
  }
  if (n == null) return undefined
  return n > 1e11 ? Math.floor(n / 1000) : Math.floor(n)
}
