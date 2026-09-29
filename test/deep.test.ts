import { createHmac } from 'node:crypto'
import { describe, expect, it } from 'vitest'
import { doorbell } from '../src/doorbell.js'
import { MemoryStore } from '../src/idempotency.js'
import { preserveRawBody } from '../src/raw.js'
import { signGitHub, signStripe } from '../src/sign.js'
import { prefixRaw } from '../src/wire.js'
import { fromUtf8, utf8 } from '../src/bytes.js'

const NOW = () => 1_614_556_800_000
const TS = 1614556800

describe('HMAC over raw bytes, not re-encoded text', () => {
  it('would disagree with a decode/re-encode of 0xff', () => {
    const raw = Uint8Array.from([0x31, 0xff, 0x32])
    const concat = prefixRaw(`${TS}.`, raw)
    const recoded = utf8(`${TS}.${fromUtf8(raw)}`)
    expect(Buffer.from(concat).equals(Buffer.from(recoded))).toBe(false)
  })

  it('verifies Stripe using the concatenated raw bytes', async () => {
    const raw = Uint8Array.from([0x31, 0xff, 0x32])
    const secret = 'whsec_test_secret'
    const header = await signStripe(raw, secret, TS)
    const expected = createHmac('sha256', secret)
      .update(Buffer.concat([Buffer.from(`${TS}.`), Buffer.from(raw)]))
      .digest('hex')
    expect(header).toContain(expected)

    const app = doorbell({
      now: NOW,
      stripe: { secret, onAny: async () => {} },
    })
    const res = await app.handle({
      method: 'POST',
      url: 'http://shop.test/webhooks/stripe',
      headers: new Map([['stripe-signature', header]]),
      raw,
    })
    // body is not JSON, so parse fails after verify
    expect(res.status).toBe(400)
    expect(res.body).toMatch(/UTF-8|JSON/)
  })

  it('still runs a JSON Stripe event after signing the raw buffer', async () => {
    const payload = '{"id":"evt_raw","type":"ping"}'
    const secret = 'whsec_test_secret'
    const header = await signStripe(Buffer.from(payload), secret, TS)
    const app = doorbell({
      now: NOW,
      stripe: { secret, onAny: async (event) => {
        expect(event.id).toBe('evt_raw')
        expect(event.signal.aborted).toBe(false)
      } },
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

describe('secret lint at boot', () => {
  it('refuses a Stripe API key', () => {
    expect(() =>
      doorbell({
        stripe: { secret: 'sk_live_not_a_webhook_secret', onAny: async () => {} },
      }),
    ).toThrow(/API key/)
  })

  it('refuses a GitHub PAT', () => {
    expect(() =>
      doorbell({
        github: { secret: 'ghp_abcdefghijklmnopqrstuvwxyz0123456789', onAny: async () => {} },
      }),
    ).toThrow(/GitHub token/)
  })
})

describe('limits', () => {
  it('rejects a body over maxBodyBytes before HMAC work', async () => {
    const payload = '{"id":"evt_big","type":"ping"}'
    const secret = 'whsec_test_secret'
    const header = await signStripe(payload, secret, TS)
    const app = doorbell({
      now: NOW,
      maxBodyBytes: 8,
      stripe: { secret, onAny: async () => {} },
    })
    const res = await app(
      new Request('http://shop.test/webhooks/stripe', {
        method: 'POST',
        headers: { 'stripe-signature': header },
        body: payload,
      }),
    )
    expect(res.status).toBe(413)
  })

  it('times out a stuck handler so the sender retries', async () => {
    const payload = '{"id":"evt_slow","type":"ping"}'
    const secret = 'whsec_test_secret'
    const header = await signStripe(payload, secret, TS)
    const app = doorbell({
      now: NOW,
      handlerTimeoutMs: 20,
      stripe: {
        secret,
        onAny: async () => {
          await new Promise((resolve) => setTimeout(resolve, 200))
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
    expect(await res.text()).toContain('too long')
  })
})

describe('express rawBody', () => {
  it('uses preserved bytes even if body was parsed', async () => {
    const payload = '{"id":"evt_keep","type":"ping"}'
    const secret = 'whsec_test_secret'
    const header = await signStripe(payload, secret, TS)
    const app = doorbell({
      now: NOW,
      stripe: { secret, onAny: async () => {} },
    })
    const req = {
      method: 'POST',
      url: '/webhooks/stripe',
      headers: { 'stripe-signature': header },
      body: JSON.parse(payload),
      rawBody: undefined as unknown,
    }
    preserveRawBody(req, null, Buffer.from(payload))
    const res = {
      statusCode: 0,
      body: '',
      status(n: number) {
        this.statusCode = n
        return this
      },
      send(b: string) {
        this.body = b
      },
    }
    await app.express(req, res)
    expect(res.statusCode).toBe(200)
  })
})

describe('concurrent deliveries', () => {
  it('only runs one handler when two copies arrive together', async () => {
    const store = new MemoryStore(NOW)
    let n = 0
    const payload = '{"zen":"x"}'
    const secret = 'not-a-token'
    const sig = await signGitHub(payload, secret)
    const app = doorbell({
      store,
      github: {
        secret,
        on: {
          push: async () => {
            n += 1
            await new Promise((r) => setTimeout(r, 30))
          },
        },
      },
    })
    const req = () =>
      new Request('http://shop.test/webhooks/github', {
        method: 'POST',
        headers: {
          'x-github-event': 'push',
          'x-github-delivery': 'del-same',
          'x-hub-signature-256': sig,
        },
        body: payload,
      })
    const [a, b] = await Promise.all([app(req()), app(req())])
    expect(a.status).toBe(200)
    expect(b.status).toBe(200)
    expect(n).toBe(1)
  })
})
