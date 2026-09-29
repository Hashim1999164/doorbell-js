import { fromUtf8 } from './bytes.js'
import { DoorbellError } from './errors.js'

export function parseJsonBody(raw: Uint8Array): unknown {
  const text = fromUtf8(raw)
  if (text.length === 0) return {}
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
