import { describe, expect, it } from 'vitest'
import { doorbell, signStripe } from '../src/index.js'
import { assertJsonBudget } from '../src/json.js'
import { sealBytes, utf8 } from '../src/bytes.js'
import { headerMap } from '../src/headers.js'

const NOW = () => 1_614_556_800_000
const TS = 1614556800

describe('1.16 intake', () => {
  it('refuses WebSocket upgrade headers', async () => {
    const payload = '{"id":"evt_ws","type":"ping"}'
    const secret = 'whsec_test_secret'
    const header = await signStripe(payload, secret, TS)
    const app = doorbell({ now: NOW, stripe: { secret, onAny: async () => {} } })
    const res = await app(
      new Request('http://shop.test/webhooks/stripe', {
        method: 'POST',
        headers: {
          'stripe-signature': header,
          upgrade: 'websocket',
          'sec-websocket-key': 'dGhlIHNhbXBsZSBub25jZQ==',
        },
        body: payload,
      }),
    )
    expect(res.status).toBe(400)
    expect(await res.text()).toMatch(/WebSocket|Upgrade/)
    const conn = await app.handle({
      method: 'POST',
      url: '/webhooks/stripe',
      headers: headerMap({
        'stripe-signature': header,
        connection: 'keep-alive, Upgrade',
      }),
      raw: utf8(payload),
    })
    expect(conn.status).toBe(400)
    expect(conn.body).toMatch(/Upgrade/)
    const allowed = doorbell({
      now: NOW,
      allowUpgrade: true,
      stripe: { secret, onAny: async () => {} },
    })
    const ok = await allowed(
      new Request('http://shop.test/webhooks/stripe', {
        method: 'POST',
        headers: {
          'stripe-signature': header,
          upgrade: 'websocket',
        },
        body: payload,
      }),
    )
    expect(ok.status).toBe(200)
  })

  it('refuses Accept that prefers HTML', async () => {
    const payload = '{"id":"evt_html","type":"ping"}'
    const secret = 'whsec_test_secret'
    const header = await signStripe(payload, secret, TS)
    const app = doorbell({ now: NOW, stripe: { secret, onAny: async () => {} } })
    const res = await app(
      new Request('http://shop.test/webhooks/stripe', {
        method: 'POST',
        headers: {
          'stripe-signature': header,
          accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        },
        body: payload,
      }),
    )
    expect(res.status).toBe(400)
    expect(await res.text()).toMatch(/Accept|HTML/)
    const star = await app(
      new Request('http://shop.test/webhooks/stripe', {
        method: 'POST',
        headers: {
          'stripe-signature': header,
          accept: '*/*',
        },
        body: payload,
      }),
    )
    expect(star.status).toBe(200)
    const allowed = doorbell({
      now: NOW,
      allowHtmlAccept: true,
      stripe: { secret, onAny: async () => {} },
    })
    const ok = await allowed(
      new Request('http://shop.test/webhooks/stripe', {
        method: 'POST',
        headers: {
          'stripe-signature': header,
          accept: 'text/html',
        },
        body: payload,
      }),
    )
    expect(ok.status).toBe(200)
  })

  it('refuses empty JSON bodies and still burns HMAC time', async () => {
    const secret = 'whsec_test_secret'
    const header = await signStripe('', secret, TS)
    const app = doorbell({ now: NOW, stripe: { secret, onAny: async () => {} } })
    const res = await app(
      new Request('http://shop.test/webhooks/stripe', {
        method: 'POST',
        headers: { 'stripe-signature': header },
        body: '',
      }),
    )
    expect(res.status).toBe(400)
    expect(await res.text()).toMatch(/empty/)
    const allowed = doorbell({
      now: NOW,
      allowEmptyBody: true,
      stripe: { secret, onAny: async () => {} },
    })
    const ok = await allowed(
      new Request('http://shop.test/webhooks/stripe', {
        method: 'POST',
        headers: { 'stripe-signature': header },
        body: '',
      }),
    )
    // empty body is not a JSON object after parse -> {}
    expect(ok.status).toBe(200)
  })

  it('seals event.raw so handlers cannot rewrite sealed bytes', async () => {
    const payload = '{"id":"evt_seal","type":"ping"}'
    const secret = 'whsec_test_secret'
    const header = await signStripe(payload, secret, TS)
    let threw = false
    const app = doorbell({
      now: NOW,
      stripe: {
        secret,
        onAny: async (event) => {
          expect(event.raw[0]).toBe(payload.charCodeAt(0))
          try {
            event.raw[0] = 0
          } catch {
            threw = true
          }
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
    expect(threw).toBe(true)
    const sealed = sealBytes(utf8('ab'))
    expect(sealed[0]).toBe(97)
    expect(() => {
      sealed[0] = 0
    }).toThrow(/sealed/)
  })

  it('caps JSON array length after HMAC', async () => {
    expect(() =>
      assertJsonBudget({ items: new Array(5).fill(1) }, { maxDepth: 4, maxKeys: 100, maxArray: 3 }),
    ).toThrow(/array/)
    assertJsonBudget({ items: [1, 2] }, { maxDepth: 4, maxKeys: 100, maxArray: 3 })
    const items = new Array(50_001).fill(0)
    const payload = JSON.stringify({ id: 'evt_arr', type: 'ping', items })
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
    expect(await res.text()).toMatch(/array/)
  })
})
