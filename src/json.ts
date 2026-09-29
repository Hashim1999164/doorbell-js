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
    return JSON.parse(text, jsonReviver) as unknown
  } catch (cause) {
    throw new DoorbellError('Body is not JSON.', { code: 'bad_json', cause })
  }
}

function jsonReviver(key: string, value: unknown): unknown {
  if (key === '__proto__' || key === 'prototype') return undefined
  if (key === 'constructor' && value !== null && typeof value === 'object') return undefined
  return value
}

export function hasOwn(payload: unknown, key: string): boolean {
  return Boolean(payload && typeof payload === 'object' && Object.prototype.hasOwnProperty.call(payload, key))
}

function own(payload: object, key: string): unknown {
  if (!Object.prototype.hasOwnProperty.call(payload, key)) return undefined
  return (payload as Record<string, unknown>)[key]
}

export function stringField(payload: unknown, key: string): string | undefined {
  if (!payload || typeof payload !== 'object') return undefined
  const value = own(payload, key)
  if (typeof value === 'string' && value.length > 0) return value
  return undefined
}

export function unixField(payload: unknown, key: string): number | undefined {
  if (!payload || typeof payload !== 'object') return undefined
  const value = own(payload, key)
  let n: number | undefined
  if (typeof value === 'number' && Number.isFinite(value)) n = value
  else if (typeof value === 'string' && value.length > 0) {
    const parsed = Number(value)
    if (Number.isFinite(parsed)) n = parsed
  }
  if (n == null) return undefined
  return n > 1e11 ? Math.floor(n / 1000) : Math.floor(n)
}
