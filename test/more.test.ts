import { describe, expect, it } from 'vitest'
import { doorbell } from '../src/doorbell.js'
import { MemoryStore } from '../src/idempotency.js'
import { signGitHub, signLinear, signPaddle, signShopify, signStripe } from '../src/sign.js'

const NOW = () => 1_614_556_800_000

describe('shopify linear paddle', () => {
  it('verifies shopify base64 hmac', async () => {
    const payload = '{"id":1,"name":"Order"}'
    const secret = 'shopify_shared_secret'
    const hmac = await signShopify(payload, secret)
    let topic = ''
    const app = doorbell({
      shopify: {
        secret,
        onAny: async (event) => {
          topic = event.type
        },
      },
    })
    const res = await app(
      new Request('http://shop.test/webhooks/shopify', {
        method: 'POST',
        headers: {
          'x-shopify-hmac-sha256': hmac,
          'x-shopify-topic': 'orders/create',
          'x-shopify-webhook-id': 'wh_1',
        },
        body: payload,
      }),
    )
    expect(res.status).toBe(200)
    expect(topic).toBe('orders/create')
  })

  it('verifies linear hex hmac', async () => {
    const payload = '{"action":"create","type":"Issue"}'
    const secret = 'linear_webhook_secret'
    const sig = await signLinear(payload, secret)
    const app = doorbell({
      linear: { secret, onAny: async () => {} },
    })
    const res = await app(
      new Request('http://shop.test/webhooks/linear', {
        method: 'POST',
        headers: { 'linear-signature': sig },
        body: payload,
      }),
    )
    expect(res.status).toBe(200)
  })

  it('verifies paddle ts/h1', async () => {
    const payload = '{"event_type":"transaction.completed","event_id":"evt_1"}'
    const secret = 'paddle_endpoint_secret'
    const ts = 1614556800
    const sig = await signPaddle(payload, secret, ts)
    const app = doorbell({
      now: NOW,
      paddle: { secret, onAny: async () => {} },
    })
    const res = await app(
      new Request('http://shop.test/webhooks/paddle', {
        method: 'POST',
        headers: { 'paddle-signature': sig },
        body: payload,
      }),
    )
    expect(res.status).toBe(200)
  })
})

describe('detect', () => {
  it('picks stripe from headers when the path is generic', async () => {
    const payload = '{"id":"evt_x","type":"ping"}'
    const secret = 'whsec_x'
    const ts = 1614556800
    const header = await signStripe(payload, secret, ts)
    const app = doorbell({
      now: NOW,
      stripe: { secret, onAny: async () => {} },
      github: { secret: 'g', onAny: async () => {} },
    })
    const res = await app(
      new Request('http://shop.test/webhooks', {
        method: 'POST',
        headers: { 'stripe-signature': header },
        body: payload,
      }),
    )
    expect(res.status).toBe(200)
  })

  it('asks for a path when clerk and resend are both configured', async () => {
    const app = doorbell({
      clerk: { secret: 'whsec_Y2xhcms=', onAny: async () => {} },
      resend: { secret: 'whsec_cmVzZW5k', onAny: async () => {} },
    })
    const res = await app(
      new Request('http://shop.test/webhooks', {
        method: 'POST',
        headers: {
          'svix-id': 'msg_1',
          'svix-timestamp': '1614556800',
          'svix-signature': 'v1,xxxx',
        },
        body: '{}',
      }),
    )
    expect(res.status).toBe(400)
    expect(await res.text()).toContain('look the same')
  })
})

describe('meta handshake', () => {
  it('echoes hub.challenge when the token matches', async () => {
    const app = doorbell({
      meta: { secret: 'app_secret', verifyToken: 'my-token' },
    })
    const res = await app(
      new Request(
        'http://shop.test/webhooks/meta?hub.mode=subscribe&hub.verify_token=my-token&hub.challenge=CHALLENGE',
      ),
    )
    expect(res.status).toBe(200)
    expect(await res.text()).toBe('CHALLENGE')
  })

  it('rejects a bad verify token', async () => {
    const app = doorbell({
      meta: { secret: 'app_secret', verifyToken: 'my-token' },
    })
    const res = await app(
      new Request(
        'http://shop.test/webhooks/meta?hub.mode=subscribe&hub.verify_token=nope&hub.challenge=CHALLENGE',
      ),
    )
    expect(res.status).toBe(403)
  })
})

describe('linear clock', () => {
  it('rejects a signed Linear body with an old webhookTimestamp', async () => {
    const payload = '{"action":"create","type":"Issue","webhookTimestamp":1000}'
    const secret = 'linear_webhook_secret'
    const sig = await signLinear(payload, secret)
    const app = doorbell({
      now: NOW,
      linear: { secret, onAny: async () => {} },
    })
    const res = await app(
      new Request('http://shop.test/webhooks/linear', {
        method: 'POST',
        headers: { 'linear-signature': sig },
        body: payload,
      }),
    )
    expect(res.status).toBe(400)
    expect(await res.text()).toMatch(/webhookTimestamp|window/)
  })
})

describe('idempotency', () => {
  it('lets a failed handler run again', async () => {
    const store = new MemoryStore(NOW)
    let n = 0
    const payload = '{"zen":"x"}'
    const secret = 's'
    const sig = await signGitHub(payload, secret)
    const app = doorbell({
      store,
      github: {
        secret,
        on: {
          push: async () => {
            n += 1
            if (n === 1) throw new Error('nope')
          },
        },
      },
    })
    const req = () =>
      new Request('http://shop.test/webhooks/github', {
        method: 'POST',
        headers: {
          'x-github-event': 'push',
          'x-github-delivery': 'del-1',
          'x-hub-signature-256': sig,
        },
        body: payload,
      })
    expect((await app(req())).status).toBe(500)
    expect((await app(req())).status).toBe(200)
    expect(n).toBe(2)
  })
})

describe('unhandled events', () => {
  it('returns 200 so Stripe does not retry events you do not care about', async () => {
    const payload = '{"id":"evt_other","type":"customer.created"}'
    const secret = 'whsec_test_secret'
    const ts = 1614556800
    const header = await signStripe(payload, secret, ts)
    const app = doorbell({
      now: NOW,
      stripe: {
        secret,
        on: {
          'checkout.session.completed': async () => {},
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
    expect(await res.json()).toMatchObject({ ignored: 'customer.created' })
  })
})
