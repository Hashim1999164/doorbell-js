import { describe, expect, it } from 'vitest'
import { parseHex, toHex, utf8 } from '../src/bytes.js'
import { timingSafeEqual, timingSafeEqualHex } from '../src/timing.js'

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
})
