import { describe, expect, it } from 'vitest'
import { utf8 } from '../src/bytes.js'
import { doorbell } from '../src/doorbell.js'
import { headerMap } from '../src/headers.js'
import { MemoryStore } from '../src/idempotency.js'
import { parseJsonBody, stringField } from '../src/json.js'
import { signGitHub, signLinear, signPaddle, signShopify, signSlack, signStripe, signTwilio } from '../src/sign.js'

const NOW = () => 1_614_556_800_000

describe('shopify linear paddle', () => {
  it('verifies shopify base64 hmac', async () => {
    const payload = '{"id":1,"name":"Order","line_items":[]}'
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
    expect(topic).toBe('orders')
  })

  it('does not clock Shopify on X-Shopify-Triggered-At because that header is not signed', async () => {
    const payload = '{"id":1,"name":"Order","line_items":[]}'
    const secret = 'shopify_shared_secret'
    const hmac = await signShopify(payload, secret)
    const app = doorbell({
      now: NOW,
      shopify: { secret, onAny: async () => {} },
    })
    const res = await app(
      new Request('http://shop.test/webhooks/shopify', {
        method: 'POST',
        headers: {
          'x-shopify-hmac-sha256': hmac,
          'x-shopify-topic': 'orders/create',
          'x-shopify-triggered-at': '2000-01-01T00:00:00.000Z',
        },
        body: payload,
      }),
    )
    expect(res.status).toBe(200)
  })

  it('keys Shopify idempotency on the body, not the unsigned webhook-id header', async () => {
    const store = new MemoryStore(NOW)
    let n = 0
    const payload = '{"id":1,"name":"Order","line_items":[]}'
    const secret = 'shopify_shared_secret'
    const hmac = await signShopify(payload, secret)
    const app = doorbell({
      store,
      shopify: {
        secret,
        onAny: async () => {
          n += 1
        },
      },
    })
    const send = (id: string) =>
      app(
        new Request('http://shop.test/webhooks/shopify', {
          method: 'POST',
          headers: {
            'x-shopify-hmac-sha256': hmac,
            'x-shopify-topic': 'orders/create',
            'x-shopify-webhook-id': id,
          },
          body: payload,
        }),
      )
    expect((await send('wh_a')).status).toBe(200)
    const second = await send('wh_b')
    expect(second.status).toBe(200)
    expect(await second.json()).toMatchObject({ duplicate: true })
    expect(n).toBe(1)
  })

  it('refuses an order body labelled products/create', async () => {
    const payload = '{"id":1,"name":"Order","line_items":[]}'
    const secret = 'shopify_shared_secret'
    const hmac = await signShopify(payload, secret)
    let ran = false
    const app = doorbell({
      shopify: {
        secret,
        on: {
          'products/create': async () => {
            ran = true
          },
        },
      },
    })
    const res = await app(
      new Request('http://shop.test/webhooks/shopify', {
        method: 'POST',
        headers: {
          'x-shopify-hmac-sha256': hmac,
          'x-shopify-topic': 'products/create',
        },
        body: payload,
      }),
    )
    expect(res.status).toBe(400)
    expect(ran).toBe(false)
  })

  it('refuses an order body labelled app/uninstalled', async () => {
    const payload = '{"id":1,"name":"Order","line_items":[]}'
    const secret = 'shopify_shared_secret'
    const hmac = await signShopify(payload, secret)
    let ran = false
    const app = doorbell({
      shopify: {
        secret,
        on: {
          'app/uninstalled': async () => {
            ran = true
          },
        },
      },
    })
    const res = await app(
      new Request('http://shop.test/webhooks/shopify', {
        method: 'POST',
        headers: {
          'x-shopify-hmac-sha256': hmac,
          'x-shopify-topic': 'app/uninstalled',
        },
        body: payload,
      }),
    )
    expect(res.status).toBe(400)
    expect(ran).toBe(false)
  })

  it('does not run on[orders/paid] from the unsigned topic header', async () => {
    const payload = '{"id":1,"name":"Order","line_items":[]}'
    const secret = 'shopify_shared_secret'
    const hmac = await signShopify(payload, secret)
    let paid = false
    let orders = false
    const app = doorbell({
      shopify: {
        secret,
        on: {
          'orders/paid': async () => {
            paid = true
          },
          orders: async () => {
            orders = true
          },
        },
      },
    })
    const res = await app(
      new Request('http://shop.test/webhooks/shopify', {
        method: 'POST',
        headers: {
          'x-shopify-hmac-sha256': hmac,
          'x-shopify-topic': 'orders/paid',
        },
        body: payload,
      }),
    )
    expect(res.status).toBe(200)
    expect(paid).toBe(false)
    expect(orders).toBe(true)
  })

  it('does not run on[customers/data_request] from the unsigned topic', async () => {
    const payload = '{"id":"gid://shopify/AppInstallation/1"}'
    const secret = 'shopify_shared_secret'
    const hmac = await signShopify(payload, secret)
    let redact = false
    let shopifyType = false
    const app = doorbell({
      shopify: {
        secret,
        on: {
          'customers/data_request': async () => {
            redact = true
          },
          shopify: async () => {
            shopifyType = true
          },
        },
      },
    })
    const res = await app(
      new Request('http://shop.test/webhooks/shopify', {
        method: 'POST',
        headers: {
          'x-shopify-hmac-sha256': hmac,
          'x-shopify-topic': 'customers/data_request',
        },
        body: payload,
      }),
    )
    expect(res.status).toBe(200)
    expect(redact).toBe(false)
    expect(shopifyType).toBe(true)
  })

  it('runs on.shopify for bodies that are not orders or products', async () => {
    const payload = '{"id":"gid://shopify/AppInstallation/1"}'
    const secret = 'shopify_shared_secret'
    const hmac = await signShopify(payload, secret)
    let ran = false
    const app = doorbell({
      shopify: {
        secret,
        on: {
          shopify: async () => {
            ran = true
          },
        },
      },
    })
    const res = await app(
      new Request('http://shop.test/webhooks/shopify', {
        method: 'POST',
        headers: {
          'x-shopify-hmac-sha256': hmac,
          'x-shopify-topic': 'app/uninstalled',
        },
        body: payload,
      }),
    )
    expect(res.status).toBe(200)
    expect(ran).toBe(true)
  })

  it('verifies linear hex hmac', async () => {
    const payload = '{"action":"create","type":"Issue","webhookTimestamp":1614556800}'
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

  it('keeps duplicate Twilio form keys the HMAC saw', async () => {
    const url = 'https://shop.test/webhooks/twilio'
    const body = 'MessageSid=SM1&AddOns=a&AddOns=b'
    const secret = 'twilio_auth_token'
    const sig = await signTwilio(url, body, secret)
    let addons: unknown
    const app = doorbell({
      publicUrl: url,
      twilio: {
        secret,
        onAny: async (event) => {
          addons = (event.payload as { AddOns?: unknown }).AddOns
        },
      },
    })
    const res = await app(
      new Request(url, {
        method: 'POST',
        headers: { 'x-twilio-signature': sig, 'content-type': 'application/x-www-form-urlencoded' },
        body,
      }),
    )
    expect(res.status).toBe(200)
    expect(addons).toEqual(['a', 'b'])
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
    const payload = '{"ref":"refs/heads/main"}'
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

  it('does not collapse two Linear events that share type and action', async () => {
    const store = new MemoryStore(NOW)
    let n = 0
    const secret = 'linear_webhook_secret'
    const app = doorbell({
      now: NOW,
      store,
      linear: {
        secret,
        onAny: async () => {
          n += 1
        },
      },
    })
    const send = async (webhookId: string) => {
      const payload = `{"action":"create","type":"Issue","webhookId":"${webhookId}","webhookTimestamp":1614556800}`
      const sig = await signLinear(payload, secret)
      return app(
        new Request('http://shop.test/webhooks/linear', {
          method: 'POST',
          headers: { 'linear-signature': sig },
          body: payload,
        }),
      )
    }
    expect((await send('wh_a')).status).toBe(200)
    expect((await send('wh_b')).status).toBe(200)
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

describe('json intake', () => {
  it('drops __proto__ and constructor objects from parsed JSON', () => {
    const payload = parseJsonBody(
      utf8('{"type":"ok","__proto__":{"polluted":true},"constructor":{"prototype":{"polluted":true}}}'),
    )
    expect(Object.getPrototypeOf(payload as object)).toBe(Object.prototype)
    expect(({} as { polluted?: boolean }).polluted).toBeUndefined()
    expect(Object.prototype.hasOwnProperty.call(payload, '__proto__')).toBe(false)
    expect(Object.prototype.hasOwnProperty.call(payload, 'constructor')).toBe(false)
    expect(stringField(payload, 'type')).toBe('ok')
  })
})

describe('header arrays', () => {
  it('uses the first GitHub signature when Express gives an array, not a comma join', async () => {
    const payload = '{"ref":"refs/heads/main"}'
    const secret = 'not-a-token'
    const sig = await signGitHub(payload, secret)
    const app = doorbell({
      github: { secret, onAny: async () => {} },
    })
    const result = await app.handle({
      method: 'POST',
      url: 'http://shop.test/webhooks/github',
      headers: headerMap({
        'x-github-event': 'push',
        'x-hub-signature-256': [sig, 'sha256=deadbeef'],
      }),
      raw: utf8(payload),
    })
    expect(result.status).toBe(200)
  })
})

describe('1.9 signed fields and sniff', () => {
  it('refuses extra signature headers instead of picking the first sniff hit', async () => {
    const payload = '{"ref":"refs/heads/main"}'
    const secret = 'github_webhook_secret'
    const sig = await signGitHub(payload, secret)
    const app = doorbell({
      stripe: { secret: 'whsec_other', onAny: async () => {} },
      github: { secret, onAny: async () => {} },
    })
    const res = await app(
      new Request('http://shop.test/webhooks', {
        method: 'POST',
        headers: {
          'x-github-event': 'push',
          'x-hub-signature-256': sig,
          'stripe-signature': 't=1,v1=deadbeef',
        },
        body: payload,
      }),
    )
    expect(res.status).toBe(400)
    expect(await res.text()).toMatch(/more than one provider/)
  })

  it('still uses the path when extra signature headers are present', async () => {
    const payload = '{"ref":"refs/heads/main"}'
    const secret = 'github_webhook_secret'
    const sig = await signGitHub(payload, secret)
    let ran = false
    const app = doorbell({
      stripe: { secret: 'whsec_other', onAny: async () => {} },
      github: {
        secret,
        on: {
          push: async () => {
            ran = true
          },
        },
      },
    })
    const res = await app(
      new Request('http://shop.test/webhooks/github', {
        method: 'POST',
        headers: {
          'x-github-event': 'push',
          'x-hub-signature-256': sig,
          'stripe-signature': 't=1,v1=deadbeef',
        },
        body: payload,
      }),
    )
    expect(res.status).toBe(200)
    expect(ran).toBe(true)
  })

  it('runs Shopify customers/data_request from the signed JSON, not a spoofed topic', async () => {
    const payload = '{"shop_id":1,"shop_domain":"x.myshopify.com","orders_requested":[1],"customer":{"id":2}}'
    const secret = 'shopify_shared_secret'
    const hmac = await signShopify(payload, secret)
    let ran = false
    const app = doorbell({
      shopify: {
        secret,
        on: {
          'customers/data_request': async () => {
            ran = true
          },
        },
      },
    })
    const good = await app(
      new Request('http://shop.test/webhooks/shopify', {
        method: 'POST',
        headers: {
          'x-shopify-hmac-sha256': hmac,
          'x-shopify-topic': 'customers/data_request',
        },
        body: payload,
      }),
    )
    expect(good.status).toBe(200)
    expect(ran).toBe(true)
    ran = false
    const spoof = await app(
      new Request('http://shop.test/webhooks/shopify', {
        method: 'POST',
        headers: {
          'x-shopify-hmac-sha256': hmac,
          'x-shopify-topic': 'app/uninstalled',
        },
        body: payload,
      }),
    )
    expect(spoof.status).toBe(400)
    expect(ran).toBe(false)
  })

  it('rejects a signed Linear body with no webhookTimestamp', async () => {
    const payload = '{"action":"create","type":"Issue","webhookId":"wh_1"}'
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
    expect(await res.text()).toMatch(/webhookTimestamp/)
  })

  it('names Slack event_callback from the signed inner event type', async () => {
    const payload = '{"type":"event_callback","event_id":"Ev1","event":{"type":"message","text":"hi"}}'
    const secret = 'slack_signing_secret'
    const ts = 1614556800
    const sig = await signSlack(payload, secret, ts)
    let type = ''
    const app = doorbell({
      now: NOW,
      slack: {
        secret,
        on: {
          'event_callback.message': async (event) => {
            type = event.type
          },
        },
      },
    })
    const res = await app(
      new Request('http://shop.test/webhooks/slack', {
        method: 'POST',
        headers: {
          'x-slack-signature': sig,
          'x-slack-request-timestamp': String(ts),
        },
        body: payload,
      }),
    )
    expect(res.status).toBe(200)
    expect(type).toBe('event_callback.message')
  })

  it('takes Stripe Connect account from the signed JSON, not Stripe-Account', async () => {
    const payload = '{"id":"evt_connect","type":"ping","account":"acct_signed"}'
    const secret = 'whsec_test_secret'
    const ts = 1614556800
    const header = await signStripe(payload, secret, ts)
    let account: string | undefined
    const app = doorbell({
      now: NOW,
      stripe: {
        secret,
        onAny: async (event) => {
          account = event.account
        },
      },
    })
    const res = await app(
      new Request('http://shop.test/webhooks/stripe', {
        method: 'POST',
        headers: {
          'stripe-signature': header,
          'stripe-account': 'acct_spoofed',
        },
        body: payload,
      }),
    )
    expect(res.status).toBe(200)
    expect(account).toBe('acct_signed')
  })

  it('runs commit_comment from commit_id in the signed JSON', async () => {
    const payload = '{"action":"created","comment":{"id":1},"commit_id":"abc"}'
    const secret = 'github_webhook_secret'
    const sig = await signGitHub(payload, secret)
    let ran = false
    const app = doorbell({
      github: {
        secret,
        on: {
          'commit_comment.created': async () => {
            ran = true
          },
        },
      },
    })
    const res = await app(
      new Request('http://shop.test/webhooks/github', {
        method: 'POST',
        headers: {
          'x-github-event': 'commit_comment',
          'x-hub-signature-256': sig,
        },
        body: payload,
      }),
    )
    expect(res.status).toBe(200)
    expect(ran).toBe(true)
  })

  it('copies fetch chunks so a reused stream buffer cannot rewrite the body', async () => {
    const payload = '{"id":"evt_reuse","type":"ping"}'
    const secret = 'whsec_test_secret'
    const ts = 1614556800
    const header = await signStripe(payload, secret, ts)
    const encoded = new TextEncoder().encode(payload)
    const shared = new Uint8Array(encoded.byteLength)
    let step = 0
    const stream = new ReadableStream<Uint8Array>({
      pull(controller) {
        if (step === 0) {
          shared.set(encoded)
          controller.enqueue(shared)
          step = 1
          return
        }
        shared.fill(0)
        controller.close()
      },
    })
    const app = doorbell({
      now: NOW,
      stripe: { secret, onAny: async () => {} },
    })
    const res = await app(
      new Request('http://shop.test/webhooks/stripe', {
        method: 'POST',
        headers: { 'stripe-signature': header, 'content-type': 'application/json' },
        body: stream,
        duplex: 'half',
      } as RequestInit),
    )
    expect(res.status).toBe(200)
  })
})
