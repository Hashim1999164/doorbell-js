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

export function asRawBody(input: unknown): Uint8Array {
  if (input == null) {
    throw new DoorbellError('No webhook body.', {
      code: 'empty_body',
      hint: 'The request had nothing to sign. If this is Express, you are missing express.raw() on this route.',
    })
  }
  if (input instanceof Uint8Array) return input
  if (typeof Buffer !== 'undefined' && Buffer.isBuffer(input)) {
    return new Uint8Array(input.buffer, input.byteOffset, input.byteLength)
  }
  if (typeof input === 'string') return utf8(input)
  throw parsedBodyError()
}

export function parseHex(hex: string): Uint8Array | null {
  const clean = hex.trim().toLowerCase()
  if (clean.length === 0 || clean.length % 2 !== 0) return null
  const out = new Uint8Array(clean.length / 2)
  for (let i = 0; i < out.length; i++) {
    const pair = clean.slice(i * 2, i * 2 + 2)
    if (!/[0-9a-f]{2}/.test(pair)) return null
    out[i] = Number.parseInt(pair, 16)
  }
  return out
}

export function toHex(bytes: Uint8Array): string {
  let out = ''
  for (const byte of bytes) out += byte.toString(16).padStart(2, '0')
  return out
}

export function parseBase64(value: string): Uint8Array | null {
  try {
    const clean = value.trim()
    if (typeof Buffer !== 'undefined') {
      const buf = Buffer.from(clean, 'base64')
      if (buf.byteLength === 0 && clean.length > 0) return null
      return new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength)
    }
    const bin = atob(clean)
    const out = new Uint8Array(bin.length)
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i)
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
