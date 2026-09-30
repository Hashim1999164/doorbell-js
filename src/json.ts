import { DoorbellError } from './errors.js'
import { parseUnixSec } from './clock.js'

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
  /* v8 ignore next */
  if (text.charCodeAt(0) === 0xfeff) text = text.slice(1)
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
    // Digit unix seconds only. Number("1e12") is not a clock.
    const parsed = parseUnixSec(value)
    if (parsed != null) n = parsed
  }
  if (n == null) return undefined
  return n > 1e11 ? Math.floor(n / 1000) : Math.floor(n)
}

/** After HMAC. Stripe and GitHub send objects, not `"true"` or a JSON array. */
export function assertJsonObject(payload: unknown): void {
  if (payload === null || typeof payload !== 'object' || Array.isArray(payload)) {
    throw new DoorbellError('Webhook JSON must be an object.', {
      code: 'bad_json',
      hint: 'A signed body can still be a JSON string or array. That is not an event.',
    })
  }
}

/**
 * After HMAC. A signed GitHub push can still be a nest bomb that blows the stack
 * in your handler. Walk the parsed tree with a hard budget.
 */
export function assertJsonBudget(
  value: unknown,
  opts: { maxDepth: number; maxKeys: number; maxString?: number },
): void {
  let keys = 0
  const maxString = opts.maxString ?? 0
  const walk = (node: unknown, depth: number): void => {
    if (depth > opts.maxDepth) {
      throw new DoorbellError('JSON is nested too deep.', {
        code: 'json_too_deep',
        hint: 'A signed body can still be a nest bomb. Flatten it, or raise maxJsonDepth.',
      })
    }
    if (typeof node === 'string') {
      if (maxString > 0 && node.length > maxString) {
        throw new DoorbellError('JSON string is too long.', {
          code: 'json_string_too_long',
          hint: 'HMAC passed. A signed body can still put megabytes in one field. Raise maxJsonString if you want it.',
        })
      }
      return
    }
    if (!node || typeof node !== 'object') return
    if (Array.isArray(node)) {
      keys += node.length
      if (keys > opts.maxKeys) {
        throw new DoorbellError('JSON has too many keys.', { code: 'json_too_wide' })
      }
      for (const item of node) walk(item, depth + 1)
      return
    }
    const ks = Object.keys(node)
    keys += ks.length
    if (keys > opts.maxKeys) {
      throw new DoorbellError('JSON has too many keys.', { code: 'json_too_wide' })
    }
    for (const k of ks) walk((node as Record<string, unknown>)[k], depth + 1)
  }
  walk(value, 0)
}
