import { describe, expect, it } from 'vitest'
import { doorbell } from '../src/doorbell.js'
import { signGitHub, signSlack, signStandard, signStripe } from '../src/sign.js'

const NOW = () => 1_614_556_800_000

describe('stripe', () => {
  const payload =
    '{"id":"evt_test","object":"event","type":"checkout.session.completed","data":{"object":{"id":"cs_test"}}}'
  const secret = 'whsec_test_secret'
  const ts = 1614556800

  it('runs the handler when the seal matches', async () => {
    const seen: string[] = []
    const header = await signStripe(payload, secret, ts)
    const app = doorbell({
      now: NOW,
      stripe: {
        secret,
        on: {
          'checkout.session.completed': async (event) => {
            seen.push(event.id)
          },
        },
      },
    })
    const res = await app(
      new Request('http://shop.test/webhooks/stripe', {
        method: 'POST',
        headers: { 'stripe-signature': header, 'content-type': 'application/json' },
        body: payload,
      }),
    )
    expect(res.status).toBe(200)
    expect(seen).toEqual(['evt_test'])
    expect(await res.json()).toMatchObject({ ok: true, id: 'evt_test' })
  })

  it('rejects a parsed-looking object on the express path', async () => {
    const app = doorbell({
      now: NOW,
      stripe: { secret, onAny: async () => {} },
    })
    const res = { statusCode: 0, body: '', status(n: number) { this.statusCode = n; return this }, send(b: string) { this.body = b } }
    await app.express(
      {
        method: 'POST',
        url: '/webhooks/stripe',
        headers: { 'stripe-signature': 't=1,v1=abc' },
        body: JSON.parse(payload),
      },
      res,
    )
    expect(res.statusCode).toBe(400)
    expect(res.body).toContain('already parsed')
    expect(res.body).toContain('express.raw')
  })

  it('does not run twice for the same event id', async () => {
    let n = 0
    const header = await signStripe(payload, secret, ts)
    const app = doorbell({
      now: NOW,
      stripe: {
        secret,
        onAny: async () => {
          n += 1
        },
      },
    })
    const req = () =>
      new Request('http://shop.test/webhooks/stripe', {
        method: 'POST',
        headers: { 'stripe-signature': header },
        body: payload,
      })
    expect((await app(req())).status).toBe(200)
    const second = await app(req())
    expect(second.status).toBe(200)
    expect(await second.json()).toMatchObject({ duplicate: true })
    expect(n).toBe(1)
  })

  it('returns 500 if the handler throws so Stripe retries', async () => {
    const header = await signStripe(payload, secret, ts)
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
    expect(await res.text()).toContain('db down')
  })

  it('fails a wrong secret', async () => {
    const header = await signStripe(payload, secret, ts)
    const app = doorbell({
      now: NOW,
      stripe: { secret: 'whsec_other', onAny: async () => {} },
    })
    const res = await app(
      new Request('http://shop.test/webhooks/stripe', {
        method: 'POST',
        headers: { 'stripe-signature': header },
        body: payload,
      }),
    )
    expect(res.status).toBe(400)
    expect(await res.text()).toContain('did not match')
  })

  it('fails a wrong secret even when the timestamp is also old', async () => {
    const header = await signStripe(payload, secret, 1000)
    const app = doorbell({
      now: NOW,
      stripe: { secret: 'whsec_other', onAny: async () => {} },
    })
    const res = await app(
      new Request('http://shop.test/webhooks/stripe', {
        method: 'POST',
        headers: { 'stripe-signature': header },
        body: payload,
      }),
    )
    expect(res.status).toBe(400)
    const text = await res.text()
    expect(text).toContain('did not match')
    expect(text).not.toContain('too old')
  })

  it('fails a replayed old timestamp', async () => {
    const header = await signStripe(payload, secret, 1000)
    const app = doorbell({
      now: NOW,
      stripe: { secret, onAny: async () => {} },
    })
    const res = await app(
      new Request('http://shop.test/webhooks/stripe', {
        method: 'POST',
        headers: { 'stripe-signature': header },
        body: payload,
      }),
    )
    expect(res.status).toBe(400)
    expect(await res.text()).toContain('too old')
  })

  it('accepts a rotated secret', async () => {
    const header = await signStripe(payload, 'whsec_new', ts)
    const app = doorbell({
      now: NOW,
      stripe: { secret: ['whsec_old', 'whsec_new'], onAny: async () => {} },
    })
    const res = await app(
      new Request('http://shop.test/webhooks/stripe', {
        method: 'POST',
        headers: { 'stripe-signature': header },
        body: payload,
      }),
    )
    expect(res.status).toBe(200)
  })
})

describe('github', () => {
  it('accepts sha256 and answers ping without a handler', async () => {
    const payload = '{"zen":"Speak like a human."}'
    const secret = 'github_webhook_secret'
    const sig = await signGitHub(payload, secret)
    const app = doorbell({
      github: { secret },
    })
    const res = await app(
      new Request('http://shop.test/webhooks/github', {
        method: 'POST',
        headers: {
          'x-github-event': 'ping',
          'x-github-delivery': '123e4567-e89b-12d3-a456-426614174000',
          'x-hub-signature-256': sig,
        },
        body: payload,
      }),
    )
    expect(res.status).toBe(200)
    expect(await res.json()).toMatchObject({ ping: true })
  })

  it('refuses a ping body labelled issues because that header is unsigned', async () => {
    const payload = '{"zen":"Speak like a human."}'
    const secret = 'github_webhook_secret'
    const sig = await signGitHub(payload, secret)
    let ran = false
    const app = doorbell({
      github: {
        secret,
        on: {
          'issues.opened': async () => {
            ran = true
          },
        },
      },
    })
    const res = await app(
      new Request('http://shop.test/webhooks/github', {
        method: 'POST',
        headers: {
          'x-github-event': 'issues',
          'x-hub-signature-256': sig,
        },
        body: payload,
      }),
    )
    expect(res.status).toBe(400)
    expect(ran).toBe(false)
    expect(await res.text()).toContain('does not match')
  })

  it('refuses a signed push labelled as ping', async () => {
    const payload = '{"ref":"refs/heads/main"}'
    const secret = 'github_webhook_secret'
    const sig = await signGitHub(payload, secret)
    let ran = false
    const app = doorbell({
      github: {
        secret,
        onAny: async () => {
          ran = true
        },
      },
    })
    const res = await app(
      new Request('http://shop.test/webhooks/github', {
        method: 'POST',
        headers: {
          'x-github-event': 'ping',
          'x-hub-signature-256': sig,
        },
        body: payload,
      }),
    )
    expect(res.status).toBe(400)
    expect(ran).toBe(false)
  })

  it('runs issues.opened only when the signed body has an issue', async () => {
    const payload = '{"action":"opened","issue":{"id":1}}'
    const secret = 'github_webhook_secret'
    const sig = await signGitHub(payload, secret)
    let ran = false
    const app = doorbell({
      github: {
        secret,
        on: {
          'issues.opened': async () => {
            ran = true
          },
        },
      },
    })
    const res = await app(
      new Request('http://shop.test/webhooks/github', {
        method: 'POST',
        headers: {
          'x-github-event': 'issues',
          'x-hub-signature-256': sig,
        },
        body: payload,
      }),
    )
    expect(res.status).toBe(200)
    expect(ran).toBe(true)
  })

  it('refuses a push body labelled issues', async () => {
    const payload = '{"ref":"refs/heads/main"}'
    const secret = 'github_webhook_secret'
    const sig = await signGitHub(payload, secret)
    let ran = false
    const app = doorbell({
      github: {
        secret,
        on: {
          issues: async () => {
            ran = true
          },
        },
      },
    })
    const res = await app(
      new Request('http://shop.test/webhooks/github', {
        method: 'POST',
        headers: {
          'x-github-event': 'issues',
          'x-hub-signature-256': sig,
        },
        body: payload,
      }),
    )
    expect(res.status).toBe(400)
    expect(ran).toBe(false)
  })
})

describe('slack', () => {
  it('returns the challenge after the signature checks out', async () => {
    const payload = '{"type":"url_verification","challenge":"abc123"}'
    const secret = 'slack_signing_secret'
    const ts = 1614556800
    const sig = await signSlack(payload, secret, ts)
    const app = doorbell({
      now: NOW,
      slack: { secret },
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
    expect(await res.json()).toEqual({ challenge: 'abc123' })
  })
})

describe('standard webhooks / svix', () => {
  it('verifies a v1 signature', async () => {
    const payload = '{"type":"email.sent","data":{"id":"1"}}'
    const keyBytes = Buffer.from('secretkeysecretkeysecretke')
    const secret = `whsec_${keyBytes.toString('base64')}`
    const id = 'msg_p5jXN8AQM9LWM0D4loKWxJek'
    const ts = 1614556800
    const sig = await signStandard(payload, secret, id, ts)
    const app = doorbell({
      now: NOW,
      svix: {
        secret,
        on: {
          'email.sent': async (event) => {
            expect(event.id).toBe(id)
          },
        },
      },
    })
    const res = await app(
      new Request('http://shop.test/webhooks/svix', {
        method: 'POST',
        headers: {
          'svix-id': id,
          'svix-timestamp': String(ts),
          'svix-signature': sig,
        },
        body: payload,
      }),
    )
    expect(res.status).toBe(200)
  })
})
