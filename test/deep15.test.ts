import { describe, expect, it } from 'vitest'
import { doorbell, signStripe } from '../src/index.js'
import { assertJsonBudget, deepFreeze, booleanField } from '../src/json.js'
import { utf8 } from '../src/bytes.js'
import { headerMap } from '../src/headers.js'

const NOW = () => 1_614_556_800_000
const TS = 1614556800

describe('1.15 intake', () => {
  it('refuses CORS preflight headers', async () => {
    const payload = '{"id":"evt_cors","type":"ping"}'
    const secret = 'whsec_test_secret'
    const header = await signStripe(payload, secret, TS)
    const app = doorbell({ now: NOW, stripe: { secret, onAny: async () => {} } })
    const res = await app(
      new Request('http://shop.test/webhooks/stripe', {
        method: 'POST',
        headers: {
          'stripe-signature': header,
          'access-control-request-method': 'POST',
        },
        body: payload,
      }),
    )
    expect(res.status).toBe(400)
    expect(await res.text()).toMatch(/CORS/)
    const allowed = doorbell({
      now: NOW,
      allowCorsProbe: true,
      stripe: { secret, onAny: async () => {} },
    })
    const ok = await allowed(
      new Request('http://shop.test/webhooks/stripe', {
        method: 'POST',
        headers: {
          'stripe-signature': header,
          'access-control-request-headers': 'content-type',
        },
        body: payload,
      }),
    )
    expect(ok.status).toBe(200)
  })

  it('refuses X-Requested-With unless allowed', async () => {
    const payload = '{"id":"evt_xhr","type":"ping"}'
    const secret = 'whsec_test_secret'
    const header = await signStripe(payload, secret, TS)
    const app = doorbell({ now: NOW, stripe: { secret, onAny: async () => {} } })
    const res = await app(
      new Request('http://shop.test/webhooks/stripe', {
        method: 'POST',
        headers: {
          'stripe-signature': header,
          'x-requested-with': 'XMLHttpRequest',
        },
        body: payload,
      }),
    )
    expect(res.status).toBe(400)
    expect(await res.text()).toMatch(/X-Requested-With/)
    const allowed = doorbell({
      now: NOW,
      allowXhr: true,
      stripe: { secret, onAny: async () => {} },
    })
    const ok = await allowed(
      new Request('http://shop.test/webhooks/stripe', {
        method: 'POST',
        headers: {
          'stripe-signature': header,
          'x-requested-with': 'XMLHttpRequest',
        },
        body: payload,
      }),
    )
    expect(ok.status).toBe(200)
  })

  it('refuses Trailer and trailers in Transfer-Encoding', async () => {
    const payload = '{"id":"evt_tr","type":"ping"}'
    const secret = 'whsec_test_secret'
    const header = await signStripe(payload, secret, TS)
    const app = doorbell({ now: NOW, stripe: { secret, onAny: async () => {} } })
    const trailer = await app.handle({
      method: 'POST',
      url: '/webhooks/stripe',
      headers: headerMap({
        'stripe-signature': header,
        trailer: 'X-Evil',
      }),
      raw: utf8(payload),
    })
    expect(trailer.status).toBe(400)
    expect(trailer.body).toMatch(/Trailer/)
    const te = await app.handle({
      method: 'POST',
      url: '/webhooks/stripe',
      headers: headerMap({
        'stripe-signature': header,
        'transfer-encoding': 'identity, trailers',
      }),
      raw: utf8(payload),
    })
    expect(te.status).toBe(400)
    expect(te.body).toMatch(/Transfer-Encoding/)
    const sneaky = await app.handle({
      method: 'POST',
      url: '/webhooks/stripe',
      headers: headerMap({
        'stripe-signature': header,
        'transfer-encoding': '  , chunked',
      }),
      raw: utf8(payload),
    })
    expect(sneaky.status).toBe(400)
  })

  it('refuses Infinity after HMAC', async () => {
    const payload = '{"id":"evt_inf","type":"ping","n":1e309}'
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
    expect(res.status).toBe(400)
    expect(await res.text()).toMatch(/Infinity/)
  })

  it('deep-freezes the payload and exposes Stripe livemode', async () => {
    const payload = '{"id":"evt_live","type":"ping","livemode":true,"data":{"object":{"id":"cs_1"}}}'
    const secret = 'whsec_test_secret'
    const header = await signStripe(payload, secret, TS)
    let livemode: boolean | undefined
    let frozen = false
    const app = doorbell({
      now: NOW,
      stripe: {
        secret,
        onAny: async (event) => {
          livemode = event.livemode
          frozen = Object.isFrozen(event.payload)
          const data = (event.payload as { data: { object: { id: string } } }).data
          expect(Object.isFrozen(data)).toBe(true)
          expect(() => {
            data.object.id = 'mutated'
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
    expect(livemode).toBe(true)
    expect(frozen).toBe(true)
  })

  it('leaves livemode undefined for non-Stripe and covers helpers', () => {
    expect(booleanField({ livemode: true }, 'livemode')).toBe(true)
    expect(booleanField({ livemode: 'yes' }, 'livemode')).toBeUndefined()
    expect(booleanField(null, 'livemode')).toBeUndefined()
    const obj = { a: { b: 1 }, c: [2, { d: 3 }] }
    deepFreeze(obj)
    expect(Object.isFrozen(obj)).toBe(true)
    expect(Object.isFrozen(obj.a)).toBe(true)
    expect(Object.isFrozen(obj.c)).toBe(true)
    expect(deepFreeze(null)).toBeNull()
    expect(deepFreeze(5)).toBe(5)
    deepFreeze(obj) // already frozen
    expect(() =>
      assertJsonBudget({ n: Number.POSITIVE_INFINITY }, { maxDepth: 4, maxKeys: 10 }),
    ).toThrow(/Infinity/)
    expect(() => assertJsonBudget({ n: Number.NaN }, { maxDepth: 4, maxKeys: 10 })).toThrow(/Infinity/)
    assertJsonBudget({ n: 1 }, { maxDepth: 4, maxKeys: 10 })
  })
})
