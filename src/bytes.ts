import { DoorbellError, parsedBodyError } from './errors.js'

const encoder = new TextEncoder()
const decoder = new TextDecoder()

export function utf8(text: string): Uint8Array {
  return encoder.encode(text)
}

export function fromUtf8(bytes: Uint8Array): string {
  return decoder.decode(bytes)
}

export function concatBytes(chunks: Uint8Array[]): Uint8Array {
  let total = 0
  for (const chunk of chunks) total += chunk.byteLength
  const out = new Uint8Array(total)
  let offset = 0
  for (const chunk of chunks) {
    out.set(chunk, offset)
    offset += chunk.byteLength
  }
  return out
}

export function copyBytes(input: Uint8Array): Uint8Array {
  const out = new Uint8Array(input.byteLength)
  out.set(input)
  return out
}

export function asRawBody(input: unknown): Uint8Array {
  if (input == null) {
    throw new DoorbellError('No webhook body.', {
      code: 'empty_body',
      hint: 'The request had nothing to sign. If this is Express, you are missing express.raw() on this route.',
    })
  }
  if (input instanceof Uint8Array) return copyBytes(input)
  if (typeof Buffer !== 'undefined' && Buffer.isBuffer(input)) {
    return copyBytes(new Uint8Array(input.buffer, input.byteOffset, input.byteLength))
  }
  if (typeof input === 'string') return utf8(input)
  throw parsedBodyError()
}

function nibble(code: number): number {
  if (code >= 48 && code <= 57) return code - 48
  const lower = code | 32
  if (lower >= 97 && lower <= 102) return lower - 87
  return 16
}

export function parseHex(hex: string): Uint8Array | null {
  const n = hex.length
  if (n === 0) return null
  let invalid = n & 1
  const out = new Uint8Array(n >> 1)
  for (let i = 0; i + 1 < n; i += 2) {
    const hi = nibble(hex.charCodeAt(i))
    const lo = nibble(hex.charCodeAt(i + 1))
    invalid |= hi > 15 ? 1 : 0
    invalid |= lo > 15 ? 1 : 0
    out[i >> 1] = ((hi & 15) << 4) | (lo & 15)
  }
  if (invalid) return null
  return out
}

export function toHex(bytes: Uint8Array): string {
  let out = ''
  for (const byte of bytes) out += byte.toString(16).padStart(2, '0')
  return out
}

export function parseBase64(value: string): Uint8Array | null {
  try {
    const compact = value.trim().replace(/\s+/g, '')
    if (compact.length === 0) return null
    const pad = compact.match(/=+$/)
    if (pad && pad[0].length > 2) return null
    const core = pad ? compact.slice(0, compact.length - pad[0].length) : compact
    if (core.length === 0 || !/^[A-Za-z0-9+/]+$/.test(core)) return null
    if (typeof Buffer !== 'undefined') {
      const buf = Buffer.from(compact, 'base64')
      if (buf.byteLength === 0) return null
      const bytes = copyBytes(new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength))
      const again = Buffer.from(bytes).toString('base64').replace(/=+$/, '')
      if (again !== core) return null
      return bytes
    }
    const bin = atob(compact)
    const out = new Uint8Array(bin.length)
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i)
    const again = toBase64(out).replace(/=+$/, '')
    if (again !== core) return null
    return out
  } catch {
    return null
  }
}

export function toBase64(bytes: Uint8Array): string {
  if (typeof Buffer !== 'undefined') {
    return Buffer.from(bytes).toString('base64')
  }
  let bin = ''
  for (const byte of bytes) bin += String.fromCharCode(byte)
  return btoa(bin)
}

export function secretBytesUtf8(secret: string): { key: Uint8Array; hadWhitespace: boolean } {
  const trimmed = secret.trim()
  return { key: utf8(trimmed), hadWhitespace: trimmed !== secret }
}

export function standardWebhookKey(secret: string): Uint8Array {
  const trimmed = secret.trim()
  const raw = trimmed.startsWith('whsec_') ? trimmed.slice('whsec_'.length) : trimmed
  const key = parseBase64(raw)
  if (!key || key.byteLength === 0) {
    throw new Error('bad_std_secret')
  }
  return key
}
