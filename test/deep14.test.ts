import { describe, expect, it } from 'vitest'
import { doorbell, hmacSubtle, signStripe } from '../src/index.js'
import { hmacSha256 } from '../src/hmac.js'
import { utf8 } from '../src/bytes.js'
import { webcrypto } from 'node:crypto'

const NOW = () => 1_614_556_800_000
const TS = 1614556800

describe('1.14 crypto and browser headers', () => {
  it('uses node:crypto.webcrypto when globalThis.crypto.subtle is missing', async () => {
    const key = utf8('secretkeysecretkey')
    const data = utf8('body')
    const expected = await hmacSha256(key, data)
    const saved = globalThis.crypto
    Object.defineProperty(globalThis, 'crypto', {
      value: undefined,
      configurable: true,
      writable: true,
    })
    try {
      expect(globalThis.crypto?.subtle).toBeUndefined()
      const web = await hmacSubtle(key, data, 'SHA-256')
      expect(web).toEqual(expected)
      // Prove the Node webcrypto module itself still works
      expect(webcrypto.subtle).toBeTruthy()
    } finally {
      Object.defineProperty(globalThis, 'crypto', {
        value: saved,
        configurable: true,
        writable: true,
      })
    }
  })

  it('refuses Authorization and Sec-Fetch unless allowed', async () => {
    const payload = '{"id":"evt_auth","type":"ping"}'
    const secret = 'whsec_test_secret'
    const header = await signStripe(payload, secret, TS)
    const app = doorbell({ now: NOW, stripe: { secret, onAny: async () => {} } })
    const auth = await app(
      new Request('http://shop.test/webhooks/stripe', {
        method: 'POST',
        headers: { 'stripe-signature': header, authorization: 'Bearer x' },
        body: payload,
      }),
    )
    expect(auth.status).toBe(400)
    expect(await auth.text()).toMatch(/Authorization/)
    const sec = await app(
      new Request('http://shop.test/webhooks/stripe', {
        method: 'POST',
        headers: {
          'stripe-signature': header,
          'sec-fetch-site': 'cross-site',
          'sec-fetch-mode': 'cors',
        },
        body: payload,
      }),
    )
    expect(sec.status).toBe(400)
    expect(await sec.text()).toMatch(/Sec-Fetch/)
    const allowed = doorbell({
      now: NOW,
      allowAuthorization: true,
      allowSecFetch: true,
      stripe: { secret, onAny: async () => {} },
    })
    const ok = await allowed(
      new Request('http://shop.test/webhooks/stripe', {
        method: 'POST',
        headers: {
          'stripe-signature': header,
          authorization: 'Bearer x',
          'sec-fetch-dest': 'empty',
        },
        body: payload,
      }),
    )
    expect(ok.status).toBe(200)
  })

  it('returns 503 with Retry-After when maxInflight is full', async () => {
    const payload = '{"id":"evt_inf","type":"ping"}'
    const secret = 'whsec_test_secret'
    const header = await signStripe(payload, secret, TS)
    let release!: () => void
    const gate = new Promise<void>((r) => {
      release = r
    })
    const app = doorbell({
      now: NOW,
      maxInflight: 1,
      stripe: {
        secret,
        onAny: async () => {
          await gate
        },
      },
    })
    const first = app(
      new Request('http://shop.test/webhooks/stripe', {
        method: 'POST',
        headers: { 'stripe-signature': header },
        body: payload,
      }),
    )
    await new Promise((r) => setTimeout(r, 20))
    const payload2 = '{"id":"evt_inf2","type":"ping"}'
    const header2 = await signStripe(payload2, secret, TS)
    const second = await app(
      new Request('http://shop.test/webhooks/stripe', {
        method: 'POST',
        headers: { 'stripe-signature': header2 },
        body: payload2,
      }),
    )
    expect(second.status).toBe(503)
    expect(second.headers.get('retry-after')).toBe('2')
    release()
    expect((await first).status).toBe(200)
  })

  it('adds Retry-After on handler timeout', async () => {
    const payload = '{"id":"evt_to","type":"ping"}'
    const secret = 'whsec_test_secret'
    const header = await signStripe(payload, secret, TS)
    const app = doorbell({
      now: NOW,
      handlerTimeoutMs: 15,
      stripe: {
        secret,
        onAny: async () => {
          await new Promise((r) => setTimeout(r, 80))
        },
      },
    })
    const res = await app(
      new Request('http://shop.test/webhooks/stripe', {
        method: 'POST',
        headers: { 'stripe-signature': header },
        body: payload,
      }),
    )
    expect(res.status).toBe(500)
    expect(res.headers.get('retry-after')).toBe('5')
    expect(await res.text()).toMatch(/too long/)
  })

  it('refuses maxInflight below 1 at boot', () => {
    expect(() =>
      doorbell({
        maxInflight: 0,
        stripe: { secret: 'whsec_test_secret', onAny: async () => {} },
      }),
    ).toThrow(/maxInflight/)
  })

  it('adds Retry-After when the handler throws', async () => {
    const payload = '{"id":"evt_boom","type":"ping"}'
    const secret = 'whsec_test_secret'
    const header = await signStripe(payload, secret, TS)
    const app = doorbell({
      now: NOW,
      stripe: {
        secret,
        onAny: async () => {
          throw new Error('db down')
        },
      },
    })
    const res = await app(
      new Request('http://shop.test/webhooks/stripe', {
        method: 'POST',
        headers: { 'stripe-signature': header },
        body: payload,
      }),
    )
    expect(res.status).toBe(500)
    expect(res.headers.get('retry-after')).toBe('5')
  })

  it('stringifies a non-Error handler throw', async () => {
    const payload = '{"id":"evt_str","type":"ping"}'
    const secret = 'whsec_test_secret'
    const header = await signStripe(payload, secret, TS)
    const app = doorbell({
      now: NOW,
      stripe: {
        secret,
        onAny: async () => {
          throw 'plain string boom'
        },
      },
    })
    const res = await app(
      new Request('http://shop.test/webhooks/stripe', {
        method: 'POST',
        headers: { 'stripe-signature': header },
        body: payload,
      }),
    )
    expect(res.status).toBe(500)
    expect(await res.text()).toMatch(/plain string boom/)
  })
})
