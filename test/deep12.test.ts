import { describe, expect, it } from 'vitest'
import { doorbell, MemoryStore, signStripe, signTwilio } from '../src/index.js'
import { assertHeaderBudget, headerMap } from '../src/headers.js'
import { assertJsonBudget } from '../src/json.js'
import { lintSecret } from '../src/secrets.js'
import { utf8 } from '../src/bytes.js'
import { bodyFingerprint } from '../src/hash.js'

const NOW = () => 1_614_556_800_000
const TS = 1614556800

function reply() {
  return {
    statusCode: 0,
    body: '',
    headers: {} as Record<string, string>,
    status(n: number) {
      this.statusCode = n
      return this
    },
    send(b: string) {
      this.body = b
    },
    setHeader(name: string, value: string) {
      this.headers[name] = value
    },
  }
}

describe('1.12 intake', () => {
  it('refuses Referer the same way it refuses Origin', async () => {
    const payload = '{"id":"evt_ref","type":"ping"}'
    const secret = 'whsec_test_secret'
    const header = await signStripe(payload, secret, TS)
    const app = doorbell({ now: NOW, stripe: { secret, onAny: async () => {} } })
    const blocked = await app(
      new Request('http://shop.test/webhooks/stripe', {
        method: 'POST',
        headers: { 'stripe-signature': header, referer: 'https://evil.test/' },
        body: payload,
      }),
    )
    expect(blocked.status).toBe(400)
    expect(await blocked.text()).toMatch(/Referer/)
    const allowed = doorbell({
      now: NOW,
      allowReferer: true,
      stripe: { secret, onAny: async () => {} },
    })
    const ok = await allowed(
      new Request('http://shop.test/webhooks/stripe', {
        method: 'POST',
        headers: { 'stripe-signature': header, referer: 'https://proxy.test/' },
        body: payload,
      }),
    )
    expect(ok.status).toBe(200)
  })

  it('refuses a huge unsigned header block', async () => {
    const payload = '{"id":"evt_hdr","type":"ping"}'
    const secret = 'whsec_test_secret'
    const header = await signStripe(payload, secret, TS)
    const app = doorbell({
      now: NOW,
      maxHeaderBytes: 80,
      stripe: { secret, onAny: async () => {} },
    })
    const res = await app(
      new Request('http://shop.test/webhooks/stripe', {
        method: 'POST',
        headers: { 'stripe-signature': header, 'x-padding': 'a'.repeat(200) },
        body: payload,
      }),
    )
    expect(res.status).toBe(400)
    expect(await res.text()).toMatch(/headers are huge/)
  })

  it('skips the header budget when maxHeaderBytes is 0', async () => {
    const payload = '{"id":"evt_h0","type":"ping"}'
    const secret = 'whsec_test_secret'
    const header = await signStripe(payload, secret, TS)
    const app = doorbell({
      now: NOW,
      maxHeaderBytes: 0,
      stripe: { secret, onAny: async () => {} },
    })
    const res = await app(
      new Request('http://shop.test/webhooks/stripe', {
        method: 'POST',
        headers: { 'stripe-signature': header, 'x-padding': 'b'.repeat(200) },
        body: payload,
      }),
    )
    expect(res.status).toBe(200)
    assertHeaderBudget(headerMap({ a: 'b' }), 0)
  })

  it('fingerprints event ids that are not store-safe', async () => {
    const payload = '{"id":"evt has spaces","type":"ping"}'
    const secret = 'whsec_test_secret'
    const header = await signStripe(payload, secret, TS)
    let id = ''
    const app = doorbell({
      now: NOW,
      stripe: {
        secret,
        onAny: async (event) => {
          id = event.id
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
    expect(id).toBe(bodyFingerprint(utf8(payload)))
    expect(await res.json()).toMatchObject({ id })
  })

  it('caps a huge event type and drops a dirty Stripe account', async () => {
    const type = 'a'.repeat(200)
    const payload = JSON.stringify({
      id: 'evt_type',
      type,
      account: 'acct_\nboom',
    })
    const secret = 'whsec_test_secret'
    const header = await signStripe(payload, secret, TS)
    let seen = ''
    let account: string | undefined = 'set'
    const app = doorbell({
      now: NOW,
      stripe: {
        secret,
        onAny: async (event) => {
          seen = event.type
          account = event.account
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
    expect(seen).toBe('unknown')
    expect(account).toBeUndefined()
  })

  it('turns a control character in event.type into unknown', async () => {
    const payload = '{"id":"evt_nl","type":"ping\\u0007"}'
    const secret = 'whsec_test_secret'
    const header = await signStripe(payload, secret, TS)
    let seen = ''
    const app = doorbell({
      now: NOW,
      stripe: {
        secret,
        onAny: async (event) => {
          seen = event.type
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
    expect(seen).toBe('unknown')
  })

  it('keeps a short Stripe Connect account id', async () => {
    const payload = '{"id":"evt_acct","type":"ping","account":"acct_123"}'
    const secret = 'whsec_test_secret'
    const header = await signStripe(payload, secret, TS)
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
        headers: { 'stripe-signature': header },
        body: payload,
      }),
    )
    expect(res.status).toBe(200)
    expect(account).toBe('acct_123')
  })

  it('drops an oversized Stripe account id', async () => {
    const payload = JSON.stringify({ id: 'evt_bigacct', type: 'ping', account: 'acct_' + 'x'.repeat(200) })
    const secret = 'whsec_test_secret'
    const header = await signStripe(payload, secret, TS)
    let account: string | undefined = 'set'
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
        headers: { 'stripe-signature': header },
        body: payload,
      }),
    )
    expect(res.status).toBe(200)
    expect(account).toBeUndefined()
  })

  it('refuses a huge JSON string after HMAC', async () => {
    const payload = JSON.stringify({ id: 'evt_str', type: 'ping', blob: 'z'.repeat(50) })
    const secret = 'whsec_test_secret'
    const header = await signStripe(payload, secret, TS)
    const app = doorbell({
      now: NOW,
      maxJsonString: 10,
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
    expect(await res.text()).toMatch(/string is too long/)
  })

  it('refuses a secret with a NUL at boot', () => {
    expect(() => lintSecret('github', 'goodsecret\0xx')).toThrow(/control character/)
    expect(() =>
      doorbell({ github: { secret: 'webhooksecret\nline', onAny: async () => {} } }),
    ).toThrow(/control character/)
  })
})

describe('1.12 Twilio URL and Express Host', () => {
  it('refuses http Twilio URLs that are not localhost', async () => {
    const url = 'http://shop.test/webhooks/twilio'
    const body = 'MessageSid=SM1'
    const secret = 'twilio_auth_token'
    const sig = await signTwilio(url, body, secret)
    const blocked = doorbell({
      publicUrl: url,
      twilio: { secret, onAny: async () => {} },
    })
    const res = await blocked(
      new Request('http://shop.test/webhooks/twilio', {
        method: 'POST',
        headers: { 'x-twilio-signature': sig, 'content-type': 'application/x-www-form-urlencoded' },
        body,
      }),
    )
    expect(res.status).toBe(400)
    expect(await res.text()).toMatch(/must be https/)
    const allowed = doorbell({
      publicUrl: url,
      allowInsecureTwilioUrl: true,
      twilio: { secret, onAny: async () => {} },
    })
    const ok = await allowed(
      new Request('http://shop.test/webhooks/twilio', {
        method: 'POST',
        headers: { 'x-twilio-signature': sig, 'content-type': 'application/x-www-form-urlencoded' },
        body,
      }),
    )
    expect(ok.status).toBe(200)
  })

  it('allows http Twilio on localhost', async () => {
    const url = 'http://localhost/webhooks/twilio'
    const body = 'MessageSid=SM2'
    const secret = 'twilio_auth_token'
    const sig = await signTwilio(url, body, secret)
    const app = doorbell({ twilio: { secret, onAny: async () => {} } })
    const res = await app(
      new Request(url, {
        method: 'POST',
        headers: { 'x-twilio-signature': sig, 'content-type': 'application/x-www-form-urlencoded' },
        body,
      }),
    )
    expect(res.status).toBe(200)
  })

  it('refuses a relative Twilio URL', async () => {
    const body = 'MessageSid=SM3'
    const secret = 'twilio_auth_token'
    const sig = await signTwilio('https://shop.test/webhooks/twilio', body, secret)
    const app = doorbell({
      publicUrl: '/webhooks/twilio',
      twilio: { secret, onAny: async () => {} },
    })
    const res = await app(
      new Request('http://shop.test/webhooks/twilio', {
        method: 'POST',
        headers: { 'x-twilio-signature': sig, 'content-type': 'application/x-www-form-urlencoded' },
        body,
      }),
    )
    expect(res.status).toBe(400)
    expect(await res.text()).toMatch(/absolute https/)
  })

  it('needs an absolute Twilio URL when publicUrl is missing', async () => {
    const body = 'MessageSid=SM4'
    const secret = 'twilio_auth_token'
    const app = doorbell({ twilio: { secret, onAny: async () => {} } })
    const res = await app.handle({
      method: 'POST',
      url: undefined,
      headers: headerMap({
        'x-twilio-signature': 'aaaa',
        'content-type': 'application/x-www-form-urlencoded',
      }),
      raw: utf8(body),
    })
    expect(res.status).toBe(400)
    expect(res.body).toMatch(/public URL/)
  })

  it('builds https from Host and ignores Express trust-proxy get(host)', async () => {
    const url = 'https://shop.test/webhooks/twilio'
    const body = 'MessageSid=SM5'
    const secret = 'twilio_auth_token'
    const sig = await signTwilio(url, body, secret)
    const app = doorbell({ twilio: { secret, onAny: async () => {} } })
    const res = reply()
    await app.express(
      {
        method: 'POST',
        url: '/webhooks/twilio',
        originalUrl: '/webhooks/twilio',
        protocol: 'http',
        headers: {
          host: 'shop.test',
          'x-forwarded-host': 'evil.test',
          'x-twilio-signature': sig,
          'content-type': 'application/x-www-form-urlencoded',
        },
        body: Buffer.from(body),
        get(name: string) {
          return name.toLowerCase() === 'host' ? 'evil.test' : undefined
        },
      },
      res,
    )
    expect(res.statusCode).toBe(200)
  })

  it('uses http for loopback Host on Express', async () => {
    const url = 'http://127.0.0.1:3000/webhooks/twilio'
    const body = 'MessageSid=SM6'
    const secret = 'twilio_auth_token'
    const sig = await signTwilio(url, body, secret)
    const app = doorbell({ twilio: { secret, onAny: async () => {} } })
    const res = reply()
    await app.express(
      {
        method: 'POST',
        originalUrl: '/webhooks/twilio',
        protocol: 'https',
        headers: {
          host: '127.0.0.1:3000',
          'x-twilio-signature': sig,
          'content-type': 'application/x-www-form-urlencoded',
        },
        body: Buffer.from(body),
      },
      res,
    )
    expect(res.statusCode).toBe(200)
  })

  it('uses http for [::1] Host on Express', async () => {
    const url = 'http://[::1]:3000/webhooks/twilio'
    const body = 'MessageSid=SM7'
    const secret = 'twilio_auth_token'
    const sig = await signTwilio(url, body, secret)
    const app = doorbell({ twilio: { secret, onAny: async () => {} } })
    const res = reply()
    await app.express(
      {
        method: 'POST',
        originalUrl: '/webhooks/twilio',
        headers: {
          host: '[::1]:3000',
          'x-twilio-signature': sig,
          'content-type': 'application/x-www-form-urlencoded',
        },
        body: Buffer.from(body),
      },
      res,
    )
    expect(res.statusCode).toBe(200)
  })

  it('does not treat a broken bracket Host as loopback', async () => {
    const payload = '{"id":"evt_br","type":"ping"}'
    const secret = 'whsec_test_secret'
    const header = await signStripe(payload, secret, TS)
    const app = doorbell({ now: NOW, stripe: { secret, onAny: async () => {} } })
    const res = reply()
    await app.express(
      {
        method: 'POST',
        originalUrl: '/webhooks/stripe',
        headers: { host: '[unclosed', 'stripe-signature': header },
        body: Buffer.from(payload),
      },
      res,
    )
    expect(res.statusCode).toBe(200)
  })

  it('drops a Host header that could rewrite the path', async () => {
    const payload = '{"id":"evt_slash","type":"ping"}'
    const secret = 'whsec_test_secret'
    const header = await signStripe(payload, secret, TS)
    const app = doorbell({ now: NOW, stripe: { secret, onAny: async () => {} } })
    const res = reply()
    await app.express(
      {
        method: 'POST',
        originalUrl: '/webhooks/stripe',
        headers: { host: 'evil.test/webhooks/github', 'stripe-signature': header },
        body: Buffer.from(payload),
      },
      res,
    )
    expect(res.statusCode).toBe(200)
    const crlf = reply()
    await app.express(
      {
        method: 'POST',
        originalUrl: '/webhooks/stripe',
        headers: { host: 'evil.test\nhost: x', 'stripe-signature': header },
        body: Buffer.from(payload),
      },
      crlf,
    )
    expect(crlf.statusCode).toBe(200)
  })
})

describe('1.12 store and json budget', () => {
  it('chains extra waiters when the same id is already inflight', async () => {
    const store = new MemoryStore(() => 1, 60_000, 10, 1)
    expect(await store.claim('same', { pin: true })).toBe('run')
    const first = store.claim('same')
    await new Promise((r) => setTimeout(r, 0))
    const extra = store.claim('same')
    await new Promise((r) => setTimeout(r, 0))
    const more = store.claim('same')
    await store.commit('same', 1000)
    expect(await first).toBe('duplicate')
    expect(await extra).toBe('duplicate')
    expect(await more).toBe('duplicate')
    const zero = new MemoryStore(() => 1, 60_000, 10, 0)
    expect(await zero.claim('n', { pin: true })).toBe('run')
    const waiting = zero.claim('n')
    await new Promise((r) => setTimeout(r, 0))
    await zero.commit('n', 1000)
    expect(await waiting).toBe('duplicate')
  })

  it('treats a nested JSON string over budget as too long', () => {
    expect(() =>
      assertJsonBudget({ a: { b: 'zzzzzz' } }, { maxDepth: 8, maxKeys: 10, maxString: 3 }),
    ).toThrow(/string is too long/)
    assertJsonBudget({ a: 'zzzzzz' }, { maxDepth: 8, maxKeys: 10, maxString: 0 })
  })
})
