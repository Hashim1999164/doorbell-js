import { describe, expect, it } from 'vitest'
import { doorbell, signStripe, signTwilio } from '../src/index.js'
import { assertFormBudget } from '../src/json.js'
import { lintSecret } from '../src/secrets.js'
import { utf8 } from '../src/bytes.js'
import { headerMap } from '../src/headers.js'

const NOW = () => 1_614_556_800_000
const TS = 1614556800

describe('1.13 intake', () => {
  it('refuses Transfer-Encoding chunked', async () => {
    const payload = '{"id":"evt_te","type":"ping"}'
    const secret = 'whsec_test_secret'
    const header = await signStripe(payload, secret, TS)
    const app = doorbell({ now: NOW, stripe: { secret, onAny: async () => {} } })
    const res = await app(
      new Request('http://shop.test/webhooks/stripe', {
        method: 'POST',
        headers: {
          'stripe-signature': header,
          'transfer-encoding': 'chunked',
        },
        body: payload,
      }),
    )
    expect(res.status).toBe(400)
    expect(await res.text()).toMatch(/Transfer-Encoding/)
  })

  it('allows Transfer-Encoding identity', async () => {
    const payload = '{"id":"evt_id","type":"ping"}'
    const secret = 'whsec_test_secret'
    const header = await signStripe(payload, secret, TS)
    const app = doorbell({ now: NOW, stripe: { secret, onAny: async () => {} } })
    const res = await app(
      new Request('http://shop.test/webhooks/stripe', {
        method: 'POST',
        headers: {
          'stripe-signature': header,
          'transfer-encoding': 'identity',
          'content-length': String(payload.length),
        },
        body: payload,
      }),
    )
    expect(res.status).toBe(200)
  })

  it('refuses Content-Length that does not match the body', async () => {
    const payload = '{"id":"evt_cl","type":"ping"}'
    const secret = 'whsec_test_secret'
    const header = await signStripe(payload, secret, TS)
    const app = doorbell({ now: NOW, stripe: { secret, onAny: async () => {} } })
    const res = await app.handle({
      method: 'POST',
      url: '/webhooks/stripe',
      headers: headerMap({
        'stripe-signature': header,
        'content-length': '999',
      }),
      raw: utf8(payload),
    })
    expect(res.status).toBe(400)
    expect(res.body).toMatch(/Content-Length does not match/)
  })

  it('refuses a non-digit Content-Length', async () => {
    const payload = '{"id":"evt_badcl","type":"ping"}'
    const secret = 'whsec_test_secret'
    const header = await signStripe(payload, secret, TS)
    const app = doorbell({ now: NOW, stripe: { secret, onAny: async () => {} } })
    const res = await app.handle({
      method: 'POST',
      url: '/webhooks/stripe',
      headers: headerMap({
        'stripe-signature': header,
        'content-length': '12abc',
      }),
      raw: utf8(payload),
    })
    expect(res.status).toBe(400)
    expect(res.body).toMatch(/digit length/)
  })

  it('refuses Cookie and Expect unless allowed', async () => {
    const payload = '{"id":"evt_ck","type":"ping"}'
    const secret = 'whsec_test_secret'
    const header = await signStripe(payload, secret, TS)
    const app = doorbell({ now: NOW, stripe: { secret, onAny: async () => {} } })
    const cookie = await app(
      new Request('http://shop.test/webhooks/stripe', {
        method: 'POST',
        headers: { 'stripe-signature': header, cookie: 'sid=1' },
        body: payload,
      }),
    )
    expect(cookie.status).toBe(400)
    expect(await cookie.text()).toMatch(/Cookie/)
    const expectHdr = await app(
      new Request('http://shop.test/webhooks/stripe', {
        method: 'POST',
        headers: { 'stripe-signature': header, expect: '100-continue' },
        body: payload,
      }),
    )
    expect(expectHdr.status).toBe(400)
    expect(await expectHdr.text()).toMatch(/Expect/)
    const allowed = doorbell({
      now: NOW,
      allowCookie: true,
      allowExpect: true,
      stripe: { secret, onAny: async () => {} },
    })
    const ok = await allowed(
      new Request('http://shop.test/webhooks/stripe', {
        method: 'POST',
        headers: {
          'stripe-signature': header,
          cookie: 'sid=1',
          expect: '100-continue',
        },
        body: payload,
      }),
    )
    expect(ok.status).toBe(200)
  })

  it('refuses a huge query string', async () => {
    const payload = '{"id":"evt_q","type":"ping"}'
    const secret = 'whsec_test_secret'
    const header = await signStripe(payload, secret, TS)
    const app = doorbell({
      now: NOW,
      maxQueryLength: 20,
      stripe: { secret, onAny: async () => {} },
    })
    const res = await app(
      new Request(`http://shop.test/webhooks/stripe?pad=${'a'.repeat(40)}`, {
        method: 'POST',
        headers: { 'stripe-signature': header },
        body: payload,
      }),
    )
    expect(res.status).toBe(400)
    expect(await res.text()).toMatch(/query string/)
    const withHash = await app.handle({
      method: 'POST',
      url: `/webhooks/stripe?pad=${'b'.repeat(40)}#frag`,
      headers: headerMap({ 'stripe-signature': header }),
      raw: utf8(payload),
    })
    expect(withHash.status).toBe(400)
    const unlimited = doorbell({
      now: NOW,
      maxQueryLength: 0,
      stripe: { secret, onAny: async () => {} },
    })
    const ok = await unlimited(
      new Request(`http://shop.test/webhooks/stripe?pad=${'c'.repeat(40)}`, {
        method: 'POST',
        headers: { 'stripe-signature': header },
        body: payload,
      }),
    )
    expect(ok.status).toBe(200)
  })

  it('treats empty Transfer-Encoding as fine', async () => {
    const payload = '{"id":"evt_te0","type":"ping"}'
    const secret = 'whsec_test_secret'
    const header = await signStripe(payload, secret, TS)
    const app = doorbell({ now: NOW, stripe: { secret, onAny: async () => {} } })
    const res = await app.handle({
      method: 'POST',
      url: '/webhooks/stripe',
      headers: headerMap({
        'stripe-signature': header,
        'transfer-encoding': '  , chunked',
      }),
      raw: utf8(payload),
    })
    // first part after split/trim is empty -> allowed, then HMAC runs
    expect(res.status).toBe(200)
  })

  it('sends Cache-Control no-store on replies', async () => {
    const payload = '{"id":"evt_cc","type":"ping"}'
    const secret = 'whsec_test_secret'
    const header = await signStripe(payload, secret, TS)
    const app = doorbell({ now: NOW, stripe: { secret, onAny: async () => {} } })
    const res = await app(
      new Request('http://shop.test/webhooks/stripe', {
        method: 'POST',
        headers: { 'stripe-signature': header },
        body: payload,
      }),
    )
    expect(res.headers.get('cache-control')).toBe('no-store')
    expect(res.headers.get('x-content-type-options')).toBe('nosniff')
  })

  it('freezes the verified event', async () => {
    const payload = '{"id":"evt_fr","type":"ping"}'
    const secret = 'whsec_test_secret'
    const header = await signStripe(payload, secret, TS)
    let frozen = false
    const app = doorbell({
      now: NOW,
      stripe: {
        secret,
        onAny: async (event) => {
          frozen = Object.isFrozen(event)
          expect(() => {
            ;(event as { id: string }).id = 'mutated'
          }).toThrow()
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
    expect(res.status).toBe(200)
    expect(frozen).toBe(true)
  })

  it('refuses non-ASCII secrets at boot', () => {
    expect(() => lintSecret('github', 'webhook—secret')).toThrow(/non-ASCII/)
    expect(() =>
      doorbell({
        handlerTimeoutMs: -1,
        stripe: { secret: 'whsec_test_secret', onAny: async () => {} },
      }),
    ).toThrow(/handlerTimeoutMs/)
    expect(() =>
      doorbell({
        idempotencyTtlMs: 999 * 24 * 60 * 60 * 1000,
        stripe: { secret: 'whsec_test_secret', onAny: async () => {} },
      }),
    ).toThrow(/idempotencyTtlMs/)
    expect(() =>
      doorbell({
        maxBodyBytes: -5,
        stripe: { secret: 'whsec_test_secret', onAny: async () => {} },
      }),
    ).toThrow(/maxBodyBytes/)
  })

  it('caps Twilio form field count after HMAC', async () => {
    const url = 'https://shop.test/webhooks/twilio'
    const parts: string[] = []
    for (let i = 0; i < 20; i++) parts.push(`k${i}=v`)
    const body = parts.join('&')
    const secret = 'twilio_auth_token'
    const sig = await signTwilio(url, body, secret)
    const app = doorbell({
      publicUrl: url,
      maxFormKeys: 8,
      twilio: { secret, onAny: async () => {} },
    })
    const res = await app(
      new Request(url, {
        method: 'POST',
        headers: {
          'x-twilio-signature': sig,
          'content-type': 'application/x-www-form-urlencoded',
        },
        body,
      }),
    )
    expect(res.status).toBe(400)
    expect(await res.text()).toMatch(/too many fields/)
  })

  it('caps Twilio form value length after HMAC', async () => {
    const url = 'https://shop.test/webhooks/twilio'
    const body = `MessageSid=SM1&Body=${'z'.repeat(50)}`
    const secret = 'twilio_auth_token'
    const sig = await signTwilio(url, body, secret)
    const app = doorbell({
      publicUrl: url,
      maxFormValueChars: 10,
      twilio: { secret, onAny: async () => {} },
    })
    const res = await app(
      new Request(url, {
        method: 'POST',
        headers: {
          'x-twilio-signature': sig,
          'content-type': 'application/x-www-form-urlencoded',
        },
        body,
      }),
    )
    expect(res.status).toBe(400)
    expect(await res.text()).toMatch(/too long/)
  })

  it('covers form budget helpers', () => {
    assertFormBudget(null, { maxKeys: 1, maxValueChars: 1 })
    assertFormBudget({ a: 'hi', b: ['x', 'y'] }, { maxKeys: 10, maxValueChars: 100 })
    expect(() => assertFormBudget({ a: 1, b: 2, c: 3 }, { maxKeys: 2, maxValueChars: 100 })).toThrow(
      /too many fields/,
    )
  })
})
