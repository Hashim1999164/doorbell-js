import { createHmac } from 'node:crypto'
import { describe, expect, it } from 'vitest'
import { doorbell } from '../src/doorbell.js'

describe('independent node crypto vectors', () => {
  it('matches Stripe the same way stripe-node does: utf8(secret) over t.body', async () => {
    const payload =
      '{"id":"evt_test","object":"event","type":"checkout.session.completed","data":{"object":{"id":"cs_test"}}}'
    const secret = 'whsec_test_secret'
    const ts = 1614556800
    const hex = createHmac('sha256', secret).update(`${ts}.${payload}`).digest('hex')
    expect(hex).toBe('c8ba94e6497b19a2985f92d1721221bb0e8d0a7e29f6bf0359b7a043d8330749')

    const app = doorbell({
      now: () => ts * 1000,
      stripe: { secret, onAny: async () => {} },
    })
    const res = await app(
      new Request('http://shop.test/webhooks/stripe', {
        method: 'POST',
        headers: { 'stripe-signature': `t=${ts},v1=${hex}` },
        body: payload,
      }),
    )
    expect(res.status).toBe(200)
  })

  it('does not accept JSON.stringify of a parsed object when Stripe signed the original spaces', async () => {
    const payload = '{ "id": "evt_space", "type": "ping" }'
    const secret = 'whsec_test_secret'
    const ts = 1614556800
    const hex = createHmac('sha256', secret).update(`${ts}.${payload}`).digest('hex')
    const app = doorbell({
      now: () => ts * 1000,
      stripe: { secret, onAny: async () => {} },
    })
    const rewritten = JSON.stringify(JSON.parse(payload))
    expect(rewritten).not.toBe(payload)
    const res = await app(
      new Request('http://shop.test/webhooks/stripe', {
        method: 'POST',
        headers: { 'stripe-signature': `t=${ts},v1=${hex}` },
        body: rewritten,
      }),
    )
    expect(res.status).toBe(400)
  })
})
