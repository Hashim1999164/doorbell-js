import { describe, expect, it } from 'vitest'
import { parseBase64, parseHex, toHex, utf8 } from '../src/bytes.js'
import { parseUnixSec } from '../src/clock.js'
import { timingSafeEqual, timingSafeEqualHex, timingSafeEqualText } from '../src/timing.js'

describe('timingSafeEqual', () => {
  it('accepts equal bytes', () => {
    expect(timingSafeEqual(utf8('abcd'), utf8('abcd'))).toBe(true)
  })

  it('rejects a mismatch without caring where it is', () => {
    expect(timingSafeEqual(utf8('abcd'), utf8('abce'))).toBe(false)
    expect(timingSafeEqual(utf8('abcd'), utf8('abc'))).toBe(false)
  })

  it('compares hex via decoded bytes, not string ===', () => {
    expect(timingSafeEqualHex('0a0b', '0A0B')).toBe(true)
    expect(timingSafeEqualHex('0a0b', '0a0c')).toBe(false)
    expect(timingSafeEqualHex('zz', '0a')).toBe(false)
  })

  it('roundtrips hex', () => {
    const bytes = utf8('doorbell')
    expect(parseHex(toHex(bytes))).toEqual(bytes)
  })

  it('does not early return on the first bad nibble', () => {
    expect(parseHex('zz')).toBeNull()
    expect(parseHex('0a0')).toBeNull()
    expect(parseHex('0A0B')).toEqual(parseHex('0a0b'))
  })
})

describe('timingSafeEqualText', () => {
  it('matches Meta tokens without ===', () => {
    expect(timingSafeEqualText('my-token', 'my-token')).toBe(true)
    expect(timingSafeEqualText('my-token', 'nope')).toBe(false)
  })

  it('still rejects a short guess against a long token', () => {
    expect(timingSafeEqualText('ab', 'abcdefghijklmnop')).toBe(false)
  })
})

describe('parseBase64', () => {
  it('rejects junk that Node Buffer.from would still decode', () => {
    expect(parseBase64('SGVsbG8!')).toBeNull()
    expect(parseBase64('SGVsbG8=')).toEqual(utf8('Hello'))
  })
})

describe('parseUnixSec', () => {
  it('rejects leading zeros and trailing junk', () => {
    expect(parseUnixSec('1614556800')).toBe(1614556800)
    expect(parseUnixSec('01614556800')).toBeUndefined()
    expect(parseUnixSec('1614556800abc')).toBeUndefined()
  })
})
