import { describe, expect, it } from 'vitest'
import {
  asRawBody,
  parseBase64,
  parseHex,
  standardWebhookKey,
  toBase64,
  utf8,
} from '../src/bytes.js'
import { assertFresh, parseUnixSec } from '../src/clock.js'
import {
  doorbell,
  MemoryStore,
  captureFastifyBuffer,
  preserveRawBody,
  rawFromNodeRequest,
  signGitHub,
  signLinear,
  signPaddle,
  signShopify,
  signSlack,
  signStandard,
  signStripe,
  signTwilio,
} from '../src/index.js'
import { DoorbellError, missingSecretError, secretHint } from '../src/errors.js'
import { handshake } from '../src/handshake.js'
import { contentTypeAllowed, headerMap } from '../src/headers.js'
import { matchAnyDigest, timingSafeEqual, timingSafeEqualHex } from '../src/timing.js'
import { assertJsonObject, parseJsonBody, stringField, unixField } from '../src/json.js'
import { github, githubEventMatchesBody, meta } from '../src/providers/github.js'
import { linear } from '../src/providers/linear.js'
import { paddle } from '../src/providers/paddle.js'
import { shopify, shopifyTopicMatchesBody } from '../src/providers/shopify.js'
import { slack } from '../src/providers/slack.js'
import { clerk, resend, sniffSvix, standard, svix } from '../src/providers/standard.js'
import { stripe } from '../src/providers/stripe.js'
import { sniffTwilio, twilio } from '../src/providers/twilio.js'
import {
  pathHasDotSegments,
  providerFromPath,
  sniffHits,
  sniffProvider,
} from '../src/providers/index.js'
import { readRequestBodyCapped } from '../src/raw.js'
import { burnB64 } from '../src/burn.js'
import { hmacSha256, hmacSha256Hex, matchAnyBase64Mac, matchAnyHexMac } from '../src/hmac.js'
import { prefixRaw } from '../src/wire.js'

const NOW = () => 1_614_556_800_000
const TS = 1614556800

function ctx(
  providerSecrets: string[],
  extra: Partial<{
    raw: Uint8Array
    headers: Map<string, string>
    url: string | undefined
    now: () => number
    toleranceSec: number
  }> = {},
) {
  return {
    raw: extra.raw ?? utf8('{}'),
    headers: extra.headers ?? headerMap({}),
    secrets: providerSecrets.map((s) => utf8(s.trim())),
    secretStrings: providerSecrets,
    toleranceSec: extra.toleranceSec ?? 300,
    now: extra.now ?? NOW,
    url: extra.url,
  }
}

describe('intake hardening', () => {
  it('refuses x-http-method and x-method-override', async () => {
    const payload = '{"id":"evt_m","type":"ping"}'
    const secret = 'whsec_test_secret'
    const header = await signStripe(payload, secret, TS)
    const app = doorbell({ now: NOW, stripe: { secret, onAny: async () => {} } })
    for (const name of ['x-http-method', 'x-method-override'] as const) {
      const res = await app.handle({
        method: 'POST',
        url: '/webhooks/stripe',
        headers: headerMap({ 'stripe-signature': header, [name]: 'GET' }),
        raw: utf8(payload),
      })
      expect(res.status).toBe(400)
    }
    const open = doorbell({
      now: NOW,
      allowMethodOverride: true,
      stripe: { secret, onAny: async () => {} },
    })
    const ok = await open.handle({
      method: 'POST',
      url: '/webhooks/stripe',
      headers: headerMap({ 'stripe-signature': header, 'x-http-method-override': 'PUT' }),
      raw: utf8(payload),
    })
    expect(ok.status).toBe(200)
  })

  it('treats an empty method as POST', async () => {
    const payload = '{"id":"evt_em","type":"ping"}'
    const secret = 'whsec_test_secret'
    const header = await signStripe(payload, secret, TS)
    const app = doorbell({ now: NOW, stripe: { secret, onAny: async () => {} } })
    const res = await app.handle({
      method: '',
      url: '/webhooks/stripe',
      headers: headerMap({ 'stripe-signature': header }),
      raw: utf8(payload),
    })
    expect(res.status).toBe(200)
  })

  it('skips the body cap when maxBodyBytes is 0', async () => {
    const payload = '{"id":"evt_big","type":"ping"}'
    const secret = 'whsec_test_secret'
    const header = await signStripe(payload, secret, TS)
    const app = doorbell({
      now: NOW,
      maxBodyBytes: 0,
      stripe: { secret, onAny: async () => {} },
    })
    const res = await app.handle({
      method: 'POST',
      url: '/webhooks/stripe',
      headers: headerMap({ 'stripe-signature': header }),
      raw: utf8(payload),
    })
    expect(res.status).toBe(200)
  })

  it('runs with handlerTimeoutMs 0', async () => {
    const payload = '{"id":"evt_t0","type":"ping"}'
    const secret = 'whsec_test_secret'
    const header = await signStripe(payload, secret, TS)
    const app = doorbell({
      now: NOW,
      handlerTimeoutMs: 0,
      stripe: { secret, onAny: async () => {} },
    })
    expect(
      (
        await app.handle({
          method: 'POST',
          url: '/webhooks/stripe',
          headers: headerMap({ 'stripe-signature': header }),
          raw: utf8(payload),
        })
      ).status,
    ).toBe(200)
  })

  it('refuses a signed JSON string', async () => {
    const payload = '"hello"'
    const secret = 'whsec_test_secret'
    const header = await signStripe(payload, secret, TS)
    const app = doorbell({ now: NOW, stripe: { secret, onAny: async () => {} } })
    const res = await app.handle({
      method: 'POST',
      url: '/webhooks/stripe',
      headers: headerMap({ 'stripe-signature': header }),
      raw: utf8(payload),
    })
    expect(res.status).toBe(400)
    expect(res.body).toMatch(/must be an object/)
  })

  it('calls onError and uses a store without pin', async () => {
    const payload = '{"id":"evt_st","type":"ping"}'
    const secret = 'whsec_test_secret'
    const header = await signStripe(payload, secret, TS)
    const store = {
      async claim() {
        return 'run' as const
      },
      async commit() {},
      async drop() {},
    }
    const errors: string[] = []
    const app = doorbell({
      now: NOW,
      store,
      onError(err) {
        errors.push(err instanceof Error ? err.message : 'x')
      },
      stripe: {
        secret,
        onAny: async () => {
          throw new Error('handler boom')
        },
      },
    })
    const res = await app.handle({
      method: 'POST',
      url: '/webhooks/stripe',
      headers: headerMap({ 'stripe-signature': header }),
      raw: utf8(payload),
    })
    expect(res.status).toBe(500)
    expect(errors.length).toBe(1)
  })

  it('returns 500 when the store throws a plain Error', async () => {
    const payload = '{"id":"evt_se","type":"ping"}'
    const secret = 'whsec_test_secret'
    const header = await signStripe(payload, secret, TS)
    const app = doorbell({
      now: NOW,
      store: {
        async claim() {
          throw new Error('redis down')
        },
        async commit() {},
        async drop() {},
      },
      stripe: { secret, onAny: async () => {} },
    })
    const res = await app.handle({
      method: 'POST',
      url: '/webhooks/stripe',
      headers: headerMap({ 'stripe-signature': header }),
      raw: utf8(payload),
    })
    expect(res.status).toBe(500)
    expect(res.body).toMatch(/Handler failed/)
  })

  it('ignores events with no handler', async () => {
    const payload = '{"id":"evt_ig","type":"other"}'
    const secret = 'whsec_test_secret'
    const header = await signStripe(payload, secret, TS)
    const app = doorbell({
      now: NOW,
      stripe: { secret, on: { ping: async () => {} } },
    })
    const res = await app.handle({
      method: 'POST',
      url: '/webhooks/stripe',
      headers: headerMap({ 'stripe-signature': header }),
      raw: utf8(payload),
    })
    expect(res.status).toBe(200)
    expect(JSON.parse(res.body).ignored).toBe('other')
  })

  it('does not know who knocked without a path or headers', async () => {
    const app = doorbell({ now: NOW, stripe: { secret: 'whsec_test_secret', onAny: async () => {} } })
    const res = await app.handle({
      method: 'POST',
      url: '/webhooks',
      headers: headerMap({}),
      raw: utf8('{}'),
    })
    expect(res.status).toBe(400)
    expect(res.body).toMatch(/who knocked/)
  })

  it('says clerk and resend look the same', async () => {
    const app = doorbell({
      now: NOW,
      clerk: { secret: 'whsec_Y2xhcms=', onAny: async () => {} },
      resend: { secret: 'whsec_cmVzZW5k', onAny: async () => {} },
    })
    const res = await app.handle({
      method: 'POST',
      url: '/webhooks',
      headers: headerMap({
        'svix-id': '1',
        'svix-timestamp': String(TS),
        'svix-signature': 'v1,abcd',
      }),
      raw: utf8('{}'),
    })
    expect(res.status).toBe(400)
    expect(res.body).toMatch(/look the same/)
  })

  it('refuses a whitespace-only secret at boot', () => {
    expect(() =>
      doorbell({ stripe: { secret: '   ', onAny: async () => {} } }),
    ).toThrow(/No signing secret/)
    expect(() =>
      doorbell({ stripe: { secret: [], onAny: async () => {} } }),
    ).toThrow(/No signing secret/)
  })

  it('uses toleranceSec on the provider', async () => {
    const payload = '{"id":"evt_tol","type":"ping"}'
    const secret = 'whsec_test_secret'
    const header = await signStripe(payload, secret, TS)
    const app = doorbell({
      now: () => (TS + 10) * 1000,
      stripe: { secret, toleranceSec: 5, onAny: async () => {} },
    })
    const res = await app.handle({
      method: 'POST',
      url: '/webhooks/stripe',
      headers: headerMap({ 'stripe-signature': header }),
      raw: utf8(payload),
    })
    expect(res.status).toBe(400)
    expect(res.body).toMatch(/too old/)
  })
})

describe('adapters leftover', () => {
  it('builds an Express URL from host and path', async () => {
    const payload = '{"id":"evt_ex","type":"ping"}'
    const secret = 'whsec_test_secret'
    const header = await signStripe(payload, secret, TS)
    const app = doorbell({ now: NOW, stripe: { secret, onAny: async () => {} } })
    const reply = {
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
    await app.express(
      {
        method: 'POST',
        url: '/webhooks/stripe',
        originalUrl: '/webhooks/stripe',
        protocol: 'http',
        headers: { 'stripe-signature': header },
        body: Buffer.from(payload),
        get(name: string) {
          return name === 'host' ? 'shop.test' : undefined
        },
      },
      reply,
    )
    expect(reply.statusCode).toBe(200)
  })

  it('drops a dirty Host header so it cannot rewrite the URL', async () => {
    const payload = '{"id":"evt_host","type":"ping"}'
    const secret = 'whsec_test_secret'
    const header = await signStripe(payload, secret, TS)
    const app = doorbell({ now: NOW, stripe: { secret, onAny: async () => {} } })
    const reply = {
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
    await app.express(
      {
        method: 'POST',
        originalUrl: '/webhooks/stripe',
        headers: { 'stripe-signature': header },
        body: Buffer.from(payload),
        get() {
          return 'evil.test/webhooks/github'
        },
      },
      reply,
    )
    expect(reply.statusCode).toBe(200)
  })

  it('uses publicUrl string and function on Express', async () => {
    const payload = '{"id":"evt_pu","type":"ping"}'
    const secret = 'whsec_test_secret'
    const header = await signStripe(payload, secret, TS)
    const reply = () => ({
      statusCode: 0,
      body: '',
      status(n: number) {
        this.statusCode = n
        return this
      },
      send(b: string) {
        this.body = b
      },
    })
    const a = doorbell({
      now: NOW,
      publicUrl: 'https://edge.test/webhooks/stripe',
      stripe: { secret, onAny: async () => {} },
    })
    const ra = reply()
    await a.express(
      {
        method: 'POST',
        url: '/ignored',
        headers: { 'stripe-signature': header },
        body: Buffer.from(payload),
      },
      ra,
    )
    expect(ra.statusCode).toBe(200)
    const b = doorbell({
      now: NOW,
      publicUrl: ({ url }) => url ?? '/webhooks/stripe',
      stripe: { secret, onAny: async () => {} },
    })
    const rb = reply()
    await b.express(
      {
        method: 'POST',
        originalUrl: '/webhooks/stripe',
        headers: { 'stripe-signature': header },
        body: Buffer.from(payload),
      },
      rb,
    )
    expect(rb.statusCode).toBe(200)
  })

  it('throws on Express when next is missing', async () => {
    const app = doorbell({ stripe: { secret: 'whsec_test_secret', onAny: async () => {} } })
    await expect(
      app.express(
        {
          method: 'POST',
          url: '/webhooks/stripe',
          headers: {},
          body: Buffer.from('{}'),
        },
        {
          status() {
            throw new Error('no res')
          },
          send() {},
        },
      ),
    ).rejects.toThrow(/no res/)
  })

  it('answers Fastify when the body was already parsed', async () => {
    const app = doorbell({ stripe: { secret: 'whsec_test_secret', onAny: async () => {} } })
    const reply = {
      status: 0,
      body: '',
      code(n: number) {
        this.status = n
        return this
      },
      type() {
        return this
      },
      send(b: string) {
        this.body = b
      },
    }
    await app.fastify(
      {
        method: 'POST',
        url: '/webhooks/stripe',
        headers: {},
        body: { parsed: true },
      },
      reply,
    )
    expect(reply.status).toBe(400)
    expect(reply.body).toMatch(/already parsed/)
  })

  it('lets Fastify throw a non doorbell error', async () => {
    const app = doorbell({ stripe: { secret: 'whsec_test_secret', onAny: async () => {} } })
    await expect(
      app.fastify(
        {
          method: 'POST',
          url: '/webhooks/stripe',
          headers: {},
          get rawBody() {
            throw new Error('getter boom')
          },
        },
        {
          code() {
            return this
          },
          type() {
            return this
          },
          send() {},
        },
      ),
    ).rejects.toThrow(/getter boom/)
  })

  it('413s on fetch when the stream is over the cap', async () => {
    const app = doorbell({
      maxBodyBytes: 4,
      stripe: { secret: 'whsec_test_secret', onAny: async () => {} },
    })
    const res = await app(
      new Request('http://shop.test/webhooks/stripe', {
        method: 'POST',
        body: '0123456789',
      }),
    )
    expect(res.status).toBe(413)
  })

  it('rethrows a broken fetch reader', async () => {
    const app = doorbell({ stripe: { secret: 'whsec_test_secret', onAny: async () => {} } })
    await expect(
      app({
        method: 'POST',
        url: 'http://shop.test/webhooks/stripe',
        headers: new Headers(),
        body: {
          getReader() {
            throw new Error('reader boom')
          },
        },
      } as unknown as Request),
    ).rejects.toThrow(/reader boom/)
  })

  it('reads a stream that yields an empty chunk', async () => {
    const empty = await readRequestBodyCapped(
      {
        body: {
          getReader() {
            let i = 0
            return {
              async read() {
                i += 1
                if (i === 1) return { done: false, value: undefined }
                if (i === 2) return { done: false, value: utf8('ab') }
                return { done: true, value: undefined }
              },
              async cancel() {},
            }
          },
        },
      } as unknown as Request,
      100,
    )
    expect(empty).toEqual(utf8('ab'))
  })

  it('answers a Meta GET handshake through fetch', async () => {
    const app = doorbell({
      meta: { secret: 'meta_app_secret', verifyToken: 'tok', onAny: async () => {} },
    })
    const res = await app(
      new Request(
        'http://shop.test/webhooks/meta?hub.mode=subscribe&hub.verify_token=tok&hub.challenge=abc',
      ),
    )
    expect(res.status).toBe(200)
    expect(await res.text()).toBe('abc')
  })

  it('uses a string body on the node parser', () => {
    expect(rawFromNodeRequest({ body: '{"a":1}' })).toEqual(utf8('{"a":1}'))
    expect(() => asRawBody(null)).toThrow(/No webhook body/)
    expect(asRawBody('xy')).toEqual(utf8('xy'))
    const req: { rawBody?: unknown } = {}
    captureFastifyBuffer(req, utf8('ok'), () => undefined)
    expect(req.rawBody).toEqual(utf8('ok'))
  })
})

describe('github and meta families', () => {
  it('names known GitHub shapes from the signed JSON', () => {
    const h = headerMap({})
    expect(github.eventType(h, { zen: '' })).toBe('ping')
    expect(github.eventType(h, { workflow_run: {} })).toBe('workflow_run')
    expect(github.eventType(h, { workflow_job: {} })).toBe('workflow_job')
    expect(github.eventType(h, { check_run: {} })).toBe('check_run')
    expect(github.eventType(h, { check_suite: {} })).toBe('check_suite')
    expect(github.eventType(h, { release: {} })).toBe('release')
    expect(github.eventType(h, { forkee: {} })).toBe('fork')
    expect(github.eventType(h, { starred_at: 'x' })).toBe('star')
    expect(github.eventType(h, { pages: [] })).toBe('gollum')
    expect(github.eventType(h, { comment: {}, commit_id: 'c' })).toBe('commit_comment')
    expect(github.eventType(h, { discussion: {}, comment: {} })).toBe('discussion_comment')
    expect(github.eventType(h, { discussion: {} })).toBe('discussion')
    expect(github.eventType(h, { issue: {}, comment: {} })).toBe('issue_comment')
    expect(github.eventType(h, { issue: {}, action: 'opened' })).toBe('issues.opened')
    expect(github.eventType(h, { review: {}, pull_request: {} })).toBe('pull_request_review')
    expect(github.eventType(h, { comment: {}, pull_request: {} })).toBe('pull_request_review_comment')
    expect(github.eventType(h, { pull_request: {} })).toBe('pull_request')
    expect(github.eventType(h, { member: {}, team: {} })).toBe('membership')
    expect(github.eventType(h, { member: {} })).toBe('member')
    expect(github.eventType(h, { ref_type: 'branch', master_branch: 'main' })).toBe('create')
    expect(github.eventType(h, { ref_type: 'branch' })).toBe('delete')
    expect(github.eventType(h, { ref: 'refs/heads/main' })).toBe('push')
    expect(github.eventType(h, { commits: [] })).toBe('push')
    expect(github.eventType(h, { weird: true })).toBe('github')
    expect(githubEventMatchesBody('', { ref: 'x' })).toBe(false)
    expect(githubEventMatchesBody('push', { mystery: true })).toBe(true)
    expect(github.eventId(h, {}, utf8('x'))).toHaveLength(40)
    expect(meta.eventType(h, { object: 'page' })).toBe('page')
    expect(meta.eventType(h, {})).toBe('meta')
  })

  it('runs those GitHub families through HMAC', async () => {
    const secret = 'github_webhook_secret'
    const app = doorbell({ now: NOW, github: { secret, onAny: async () => {} } })
    const bodies: Array<[unknown, string]> = [
      [{ workflow_run: {} }, 'workflow_run'],
      [{ workflow_job: {} }, 'workflow_job'],
      [{ check_run: {} }, 'check_run'],
      [{ check_suite: {} }, 'check_suite'],
      [{ release: {} }, 'release'],
      [{ forkee: {} }, 'fork'],
      [{ starred_at: 't' }, 'star'],
      [{ discussion: {}, comment: {} }, 'discussion_comment'],
      [{ issue: {}, comment: {} }, 'issue_comment'],
      [{ review: {}, pull_request: {} }, 'pull_request_review'],
      [{ comment: {}, pull_request: {} }, 'pull_request_review_comment'],
      [{ pull_request: {} }, 'pull_request'],
      [{ member: {}, team: {} }, 'membership'],
      [{ member: {} }, 'member'],
      [{ ref_type: 'tag', master_branch: 'main' }, 'create'],
    ]
    for (const [body, event] of bodies) {
      const payload = JSON.stringify(body)
      const sig = await signGitHub(payload, secret)
      const res = await app.handle({
        method: 'POST',
        url: '/webhooks/github',
        headers: headerMap({ 'x-hub-signature-256': sig, 'x-github-event': event }),
        raw: utf8(payload),
      })
      expect(res.status, event).toBe(200)
    }
  })

  it('covers GitHub and Meta verify failures', async () => {
    const secret = 'github_webhook_secret'
    await expect(github.verify(ctx([secret]))).rejects.toThrow(/No X-Hub-Signature-256/)
    await expect(
      github.verify(
        ctx([secret], { headers: headerMap({ 'x-hub-signature-256': 'sha1=abcd' }) }),
      ),
    ).rejects.toThrow(/sha256/)
    const payload = '{"ref":"refs/heads/main"}'
    const sig = await signGitHub(payload, secret)
    await expect(
      github.verify(
        ctx([secret], {
          raw: utf8(payload),
          headers: headerMap({ 'x-hub-signature-256': sig.slice(0, 10) + 'ff' }),
        }),
      ),
    ).rejects.toThrow(/did not match/)
    await expect(meta.verify(ctx(['meta_app_secret']))).rejects.toThrow(/No X-Hub-Signature-256/)
    await expect(
      meta.verify(ctx(['meta_app_secret'], { headers: headerMap({ 'x-hub-signature-256': 'deadbeef' }) })),
    ).rejects.toThrow(/sha256/)
    const metaBody = '{"object":"user"}'
    const metaSig = await signGitHub(metaBody, 'meta_app_secret')
    await expect(
      meta.verify(
        ctx(['meta_app_secret'], {
          raw: utf8(metaBody),
          headers: headerMap({ 'x-hub-signature-256': metaSig.replace(/[0-9a-f]{8}$/i, 'ffffffff') }),
        }),
      ),
    ).rejects.toThrow(/did not match/)
  })

  it('sniffs Meta from sha256 without a GitHub event header', () => {
    expect(sniffProvider(headerMap({ 'x-hub-signature-256': 'sha256=ab' }), new Set(['meta']))).toBe(
      'meta',
    )
    expect(
      sniffHits(headerMap({ 'x-hub-signature-256': 'sha256=ab', 'x-github-event': 'push' }), new Set(['meta']))
        .length,
    ).toBe(0)
    expect(sniffHits(headerMap({ 'x-github-delivery': '1' }), new Set(['github'])).includes('github')).toBe(
      true,
    )
  })
})

describe('other providers verify edges', () => {
  it('covers Stripe header parse failures', async () => {
    await expect(stripe.verify(ctx(['whsec_test_secret']))).rejects.toThrow(/No stripe-signature/)
    await expect(
      stripe.verify(
        ctx(['whsec_test_secret'], { headers: headerMap({ 'stripe-signature': 'nope' }) }),
      ),
    ).rejects.toThrow(/Could not read/)
    const payload = '{"id":"evt_x","type":"ping"}'
    const header = await signStripe(payload, 'whsec_test_secret', TS)
    await expect(
      stripe.verify(
        ctx(['whsec_test_secret'], {
          raw: utf8(payload),
          headers: headerMap({ 'stripe-signature': header.replace('v1=', 'v1=00') }),
        }),
      ),
    ).rejects.toThrow(/did not match/)
    expect(stripe.eventId(headerMap({}), {}, utf8('z'))).toHaveLength(40)
    expect(stripe.eventType(headerMap({}), {})).toBe('unknown')
  })

  it('covers Slack header and clock failures', async () => {
    await expect(slack.verify(ctx(['slack_signing_secret']))).rejects.toThrow(/Missing Slack/)
    const payload = '{"type":"event_callback","event":{}}'
    const badTs = 'not-a-time'
    const sig =
      'v0=' +
      (await hmacSha256Hex(utf8('slack_signing_secret'), prefixRaw(`v0:${badTs}:`, utf8(payload))))
    await expect(
      slack.verify(
        ctx(['slack_signing_secret'], {
          raw: utf8(payload),
          headers: headerMap({
            'x-slack-signature': sig,
            'x-slack-request-timestamp': badTs,
          }),
        }),
      ),
    ).rejects.toThrow(/unix second/)
    await expect(
      slack.verify(
        ctx(['slack_signing_secret'], {
          raw: utf8(payload),
          headers: headerMap({
            'x-slack-signature': 'v0=00',
            'x-slack-request-timestamp': String(TS),
          }),
        }),
      ),
    ).rejects.toThrow(/did not match/)
    const oldSig = await signSlack(payload, 'slack_signing_secret', TS - 10_000)
    await expect(
      slack.verify(
        ctx(['slack_signing_secret'], {
          raw: utf8(payload),
          headers: headerMap({
            'x-slack-signature': oldSig,
            'x-slack-request-timestamp': String(TS - 10_000),
          }),
        }),
      ),
    ).rejects.toThrow(/window/)
    expect(slack.eventType(headerMap({}), { type: 'event_callback', event: {} })).toBe('event_callback')
    expect(slack.eventType(headerMap({}), {})).toBe('unknown')
    expect(slack.eventId(headerMap({}), { trigger_id: 'tr' }, utf8('x'))).toBe('tr')
  })

  it('covers Shopify hmac failures and families', async () => {
    await expect(shopify.verify(ctx(['shopify_shared_secret']))).rejects.toThrow(/No X-Shopify/)
    const payload = '{"id":1}'
    const hmac = await signShopify(payload, 'shopify_shared_secret')
    await expect(
      shopify.verify(
        ctx(['shopify_shared_secret'], {
          raw: utf8(payload),
          headers: headerMap({ 'x-shopify-hmac-sha256': hmac.slice(0, 4) }),
        }),
      ),
    ).rejects.toThrow(/did not match/)
    expect(shopifyTopicMatchesBody('', {})).toBe(false)
    expect(shopifyTopicMatchesBody('orders/paid', { line_items: [] })).toBe(true)
    expect(shopifyTopicMatchesBody('checkouts/create', { checkout_id: 1 })).toBe(true)
    expect(shopifyTopicMatchesBody('products/update', { variants: [] })).toBe(true)
    expect(shopifyTopicMatchesBody('customers/redact', { orders_to_redact: [] })).toBe(true)
    expect(shopify.eventType(headerMap({}), { line_items: [] })).toBe('orders')
    expect(shopify.eventType(headerMap({}), { variants: [] })).toBe('products')
    expect(shopify.eventType(headerMap({}), { orders_to_redact: [1] })).toBe('customers/redact')
    expect(shopify.sniff(headerMap({ 'x-shopify-hmac-sha256': 'x' }))).toBe(true)
  })

  it('covers Linear hmac and parse failures', async () => {
    await expect(linear.verify(ctx(['linear_webhook_secret']))).rejects.toThrow(/No Linear/)
    const payload = '{"action":"create","type":"Issue","webhookTimestamp":1614556800}'
    const sig = await signLinear(payload, 'linear_webhook_secret')
    await expect(
      linear.verify(
        ctx(['linear_webhook_secret'], {
          raw: utf8(payload),
          headers: headerMap({ 'linear-signature': 'aa' }),
        }),
      ),
    ).rejects.toThrow(/did not match/)
    await expect(
      linear.verify(
        ctx(['linear_webhook_secret'], {
          raw: utf8('not-json'),
          headers: headerMap({ 'linear-signature': await signLinear('not-json', 'linear_webhook_secret') }),
        }),
      ),
    ).rejects.toThrow(/webhookTimestamp/)
    expect(linear.eventType(headerMap({}), { type: 'Issue' })).toBe('Issue')
    expect(linear.eventType(headerMap({}), {})).toBe('linear')
    expect(linear.sniff(headerMap({ 'linear-signature': 'x' }))).toBe(true)
    expect(sig.length).toBe(64)
  })

  it('covers Paddle header and clock failures', async () => {
    await expect(paddle.verify(ctx(['paddle_secret_key']))).rejects.toThrow(/No Paddle/)
    await expect(
      paddle.verify(ctx(['paddle_secret_key'], { headers: headerMap({ 'paddle-signature': 'nope' }) })),
    ).rejects.toThrow(/Could not read/)
    const payload = '{"event_type":"x"}'
    const sig = await signPaddle(payload, 'paddle_secret_key', TS)
    await expect(
      paddle.verify(
        ctx(['paddle_secret_key'], {
          raw: utf8(payload),
          headers: headerMap({ 'paddle-signature': sig.replace('h1=', 'h1=00') }),
        }),
      ),
    ).rejects.toThrow(/did not match/)
    await expect(
      paddle.verify(
        ctx(['paddle_secret_key'], {
          raw: utf8(payload),
          headers: headerMap({ 'paddle-signature': `ts=notime;h1=${sig.split('h1=')[1]}` }),
        }),
      ),
    ).rejects.toThrow(/unix second|did not match/)
    const future = await signPaddle(payload, 'paddle_secret_key', TS + 10_000)
    await expect(
      paddle.verify(
        ctx(['paddle_secret_key'], {
          raw: utf8(payload),
          headers: headerMap({ 'paddle-signature': future }),
        }),
      ),
    ).rejects.toThrow(/window/)
    expect(paddle.eventType(headerMap({}), {})).toBe('paddle')
    expect(paddle.eventId(headerMap({}), {}, utf8('p'))).toHaveLength(40)
    expect(paddle.sniff(headerMap({ 'paddle-signature': 'x' }))).toBe(true)
  })

  it('covers Twilio verify failures', async () => {
    await expect(twilio.verify(ctx(['twilio_auth_token']))).rejects.toThrow(/No X-Twilio/)
    await expect(
      twilio.verify(
        ctx(['twilio_auth_token'], { headers: headerMap({ 'x-twilio-signature': 'aaaa' }) }),
      ),
    ).rejects.toThrow(/public URL/)
    const body = 'MessageSid=SM1'
    const sig = await signTwilio('https://shop.test/hooks', body, 'twilio_auth_token')
    await expect(
      twilio.verify(
        ctx(['twilio_auth_token'], {
          raw: utf8(body),
          url: 'https://shop.test/hooks',
          headers: headerMap({ 'x-twilio-signature': 'xxxx' }),
        }),
      ),
    ).rejects.toThrow(/did not match/)
    expect(twilio.eventType(headerMap({}), {})).toBe('twilio')
    expect(sniffTwilio(headerMap({ 'x-twilio-signature': 'x' }))).toBe(true)
    expect(sig.length).toBeGreaterThan(10)
  })

  it('covers Standard Webhooks failures and resend', async () => {
    await expect(svix.verify(ctx(['whsec_Y2xhcms=']))).rejects.toThrow(/Missing/)
    await expect(
      clerk.verify(
        ctx(['not_b64!!'], {
          headers: headerMap({
            'svix-id': '1',
            'svix-timestamp': String(TS),
            'svix-signature': 'v1,abcd',
          }),
        }),
      ),
    ).rejects.toThrow(/Standard Webhooks secret/)
    const payload = '{"type":"email.sent"}'
    const keyBytes = Buffer.from('secretkeysecretkeysecretke')
    const secret = `whsec_${keyBytes.toString('base64')}`
    const id = 'msg_1'
    const sig = await signStandard(payload, secret, id, TS)
    await expect(
      svix.verify(
        ctx([secret], {
          raw: utf8(payload),
          headers: headerMap({
            'svix-id': id,
            'svix-timestamp': String(TS),
            'svix-signature': 'v1,AAAA',
          }),
        }),
      ),
    ).rejects.toThrow(/did not match/)
    await expect(
      svix.verify(
        ctx([secret], {
          raw: utf8(payload),
          headers: headerMap({
            'svix-id': id,
            'svix-timestamp': 'notime',
            'svix-signature': sig,
          }),
        }),
      ),
    ).rejects.toThrow(/unix second|did not match/)
    const future = await signStandard(payload, secret, id, TS + 10_000)
    await expect(
      svix.verify(
        ctx([secret], {
          raw: utf8(payload),
          headers: headerMap({
            'svix-id': id,
            'svix-timestamp': String(TS + 10_000),
            'svix-signature': future,
          }),
        }),
      ),
    ).rejects.toThrow(/window/)
    const app = doorbell({ now: NOW, resend: { secret, onAny: async () => {} } })
    const res = await app.handle({
      method: 'POST',
      url: '/webhooks/resend',
      headers: headerMap({
        'svix-id': id,
        'svix-timestamp': String(TS),
        'svix-signature': sig,
      }),
      raw: utf8(payload),
    })
    expect(res.status).toBe(200)
    expect(standard.eventType(headerMap({}), { event_type: 'x.y' })).toBe('x.y')
    expect(standard.eventId(headerMap({}), {}, utf8('x'))).toBe('svix')
    expect(sniffSvix(headerMap({ 'webhook-signature': 'v1,x' }))).toBe(true)
    expect(resend.sniff(headerMap({ 'svix-id': '1', 'svix-signature': 'v1,x' }))).toBe(true)
  })
})

describe('bytes clocks json headers store', () => {
  it('covers remaining byte helpers', () => {
    expect(parseHex('gg')).toBeNull()
    expect(parseHex('abc')).toBeNull()
    expect(parseBase64('A')).toBeNull()
    expect(parseBase64('==')).toBeNull()
    expect(parseBase64('SGVsbG8')).toEqual(utf8('Hello'))
    expect(toBase64(utf8('Hi'))).toBe(Buffer.from('Hi').toString('base64'))
    expect(standardWebhookKey(Buffer.from('secretkeysecretkeysecretke').toString('base64')).byteLength).toBeGreaterThan(0)
    expect(parseUnixSec('01')).toBeUndefined()
    expect(parseUnixSec('abc')).toBeUndefined()
    expect(parseUnixSec('')).toBeUndefined()
    expect(assertFresh(TS - 400, { toleranceSec: 300, now: NOW, future: 'allow' })).toBe('too_old')
    expect(timingSafeEqual(new Uint8Array([1]), new Uint8Array([1, 2]))).toBe(false)
    expect(timingSafeEqualHex('zz', '00')).toBe(false)
    expect(matchAnyDigest([utf8('aa')], [])).toBe(false)
    expect(() => assertJsonObject(null)).toThrow(/object/)
    expect(() => assertJsonObject([1])).toThrow(/object/)
    expect(parseJsonBody(utf8('\uFEFF{"a":1}'))).toEqual({ a: 1 })
    expect(parseJsonBody(utf8('{"constructor":null}'))).toEqual({ constructor: null })
    expect(unixField({ n: Number.NaN }, 'n')).toBeUndefined()
    expect(unixField({ n: '' }, 'n')).toBeUndefined()
    expect(stringField({ a: 1 }, 'a')).toBeUndefined()
    expect(contentTypeAllowed('stripe', headerMap({ 'content-type': 'application/octet-stream' }))).toBe(
      true,
    )
    expect(contentTypeAllowed('stripe', headerMap({ 'content-type': '; charset=utf-8' }))).toBe(true)
    expect(contentTypeAllowed('stripe', headerMap({ 'content-type': 'text/plain' }))).toBe(true)
    expect(contentTypeAllowed('twilio', headerMap({ 'content-type': 'application/json' }))).toBe(true)
    expect(contentTypeAllowed('twilio', headerMap({ 'content-type': 'multipart/form-data' }))).toBe(true)
    expect(contentTypeAllowed('twilio', headerMap({ 'content-type': 'application/octet-stream' }))).toBe(
      true,
    )
    expect(contentTypeAllowed('twilio', headerMap({ 'content-type': 'text/plain' }))).toBe(true)
    expect(contentTypeAllowed('twilio', headerMap({ 'content-type': 'text/html' }))).toBe(false)
    expect(pathHasDotSegments('/webhooks/./stripe')).toBe(true)
    expect(pathHasDotSegments('/webhooks/%2e')).toBe(true)
    expect(pathHasDotSegments('/webhooks/%E0%A4')).toBe(false)
    expect(providerFromPath('/webhooks/nope', new Set(['stripe']))).toBeUndefined()
    expect(secretHint('stripe')).toMatch(/whsec_/)
    expect(secretHint('shopify')).toMatch(/Shopify/)
    expect(secretHint('twilio')).toMatch(/Auth Token/)
    expect(secretHint('meta')).toMatch(/App Secret/)
    expect(secretHint('linear')).toMatch(/signing secret/)
    expect(missingSecretError('github').message).toMatch(/github/)
  })

  it('covers MemoryStore wait, steal, and pinned eviction', async () => {
    const clock = { t: 1000 }
    const store = new MemoryStore(() => clock.t, 50, 2)
    expect(await store.claim('k', { pin: true })).toBe('run')
    const waiting = store.claim('k')
    await store.commit('k', 5000)
    expect(await waiting).toBe('duplicate')
    const steal = new MemoryStore(() => clock.t, 10, 10)
    expect(await steal.claim('x')).toBe('run')
    clock.t = 2000
    expect(await steal.claim('x')).toBe('run')
    const pinStore = new MemoryStore(() => 1, 60_000, 1)
    expect(await pinStore.claim('a', { pin: true })).toBe('run')
    expect(await pinStore.claim('b', { pin: true })).toBe('run')
    const waitDrop = new MemoryStore(() => 1, 60_000, 10)
    expect(await waitDrop.claim('z', { pin: true })).toBe('run')
    const pending = waitDrop.claim('z')
    await waitDrop.drop('z')
    expect(await pending).toBe('run')
    const unlimited = new MemoryStore(() => 1, 60_000, 0)
    expect(await unlimited.claim('n')).toBe('run')
    await burnB64([utf8('secretkeysecretkey')], utf8('x'))
  })

  it('covers handshake missing query bits', () => {
    expect(handshake('GET', undefined, new Map(), new Uint8Array(), { metaVerifyToken: 't' })).toBeUndefined()
    const noToken = handshake(
      'GET',
      'http://x/?hub.mode=subscribe',
      new Map(),
      new Uint8Array(),
      { metaVerifyToken: 't' },
    )
    expect(noToken?.status).toBe(403)
  })

  it('signs Uint8Array payloads', async () => {
    const raw = utf8('{"a":1}')
    expect(await signGitHub(raw, 'github_webhook_secret')).toMatch(/^sha256=/)
    expect(await signSlack(raw, 'slack_signing_secret', TS)).toMatch(/^v0=/)
    expect(await signShopify(raw, 'shopify_shared_secret')).toMatch(/^[A-Za-z0-9+/=]+$/)
    expect(await signLinear(raw, 'linear_webhook_secret')).toHaveLength(64)
    expect(await signPaddle(raw, 'paddle_secret_key', TS)).toMatch(/^ts=/)
    const keyBytes = Buffer.from('secretkeysecretkeysecretke')
    expect(
      await signStandard(raw, `whsec_${keyBytes.toString('base64')}`, 'id', TS),
    ).toMatch(/^v1,/)
    expect(await signStripe(raw, 'whsec_test_secret', TS)).toMatch(/^t=/)
    expect(await signTwilio('https://x.test/h', 'a=1', 'twilio_auth_token')).toMatch(/^[A-Za-z0-9+/=]+$/)
  })

  it('preserves a Buffer through preserveRawBody', () => {
    const req: { rawBody?: unknown } = {}
    preserveRawBody(req, null, Buffer.from('abc'))
    expect(rawFromNodeRequest(req)).toEqual(utf8('abc'))
    expect(asRawBody(Buffer.from('abc'))).toEqual(utf8('abc'))
    expect(asRawBody(new Uint8Array([97, 98, 99]))).toEqual(utf8('abc'))
  })
})

describe('last branches', () => {
  it('413s on handle when the raw buffer is already over the cap', async () => {
    const app = doorbell({
      maxBodyBytes: 4,
      stripe: { secret: 'whsec_test_secret', onAny: async () => {} },
    })
    const res = await app.handle({
      method: 'POST',
      url: '/webhooks/stripe',
      headers: headerMap({}),
      raw: utf8('0123456789'),
    })
    expect(res.status).toBe(413)
  })

  it('passes a rawBody getter throw to Express next', async () => {
    const app = doorbell({ stripe: { secret: 'whsec_test_secret', onAny: async () => {} } })
    let caught: unknown
    await app.express(
      {
        method: 'POST',
        url: '/webhooks/stripe',
        headers: {},
        get rawBody() {
          throw new Error('getter boom')
        },
        body: undefined,
      },
      {
        status() {
          return this
        },
        send() {},
      },
      (err) => {
        caught = err
      },
    )
    expect(caught).toBeInstanceOf(Error)
  })

  it('matches empty HMAC candidate lists', async () => {
    const key = utf8('secretkeysecretkey')
    expect(await matchAnyHexMac([key], utf8('x'), [])).toBe(false)
    expect(await matchAnyBase64Mac([key], utf8('x'), [])).toBe(false)
  })

  it('uses GitHub HMAC without an event header as an empty name', async () => {
    const secret = 'github_webhook_secret'
    const payload = '{"ref":"refs/heads/main"}'
    const sig = await signGitHub(payload, secret)
    await expect(
      github.verify(
        ctx([secret], {
          raw: utf8(payload),
          headers: headerMap({ 'x-hub-signature-256': sig }),
        }),
      ),
    ).rejects.toThrow(/does not match/)
  })

  it('uses Shopify HMAC without a topic header as an empty topic', async () => {
    const secret = 'shopify_shared_secret'
    const payload = '{"line_items":[]}'
    const hmac = await signShopify(payload, secret)
    await expect(
      shopify.verify(
        ctx([secret], {
          raw: utf8(payload),
          headers: headerMap({ 'x-shopify-hmac-sha256': hmac }),
        }),
      ),
    ).rejects.toThrow(/does not match/)
  })

  it('accepts Slack hex without a v0= prefix', async () => {
    const payload = '{"type":"event_callback","event":{"type":"message"}}'
    const hex = await hmacSha256Hex(
      utf8('slack_signing_secret'),
      prefixRaw(`v0:${TS}:`, utf8(payload)),
    )
    await slack.verify(
      ctx(['slack_signing_secret'], {
        raw: utf8(payload),
        headers: headerMap({
          'x-slack-signature': hex,
          'x-slack-request-timestamp': String(TS),
        }),
      }),
    )
  })

  it('rejects a Paddle timestamp that is not unix after HMAC', async () => {
    const payload = '{"event_type":"x"}'
    const mac = await hmacSha256Hex(utf8('paddle_secret_key'), prefixRaw('notime:', utf8(payload)))
    await expect(
      paddle.verify(
        ctx(['paddle_secret_key'], {
          raw: utf8(payload),
          headers: headerMap({ 'paddle-signature': `ts=notime;h1=${mac}` }),
        }),
      ),
    ).rejects.toThrow(/unix second/)
  })

  it('rejects a Standard Webhooks timestamp that is not unix after HMAC', async () => {
    const payload = '{"type":"email.sent"}'
    const keyBytes = Buffer.from('secretkeysecretkeysecretke')
    const secret = `whsec_${keyBytes.toString('base64')}`
    const id = 'msg_ts'
    const mac = await hmacSha256(standardWebhookKey(secret), prefixRaw(`${id}.notime.`, utf8(payload)))
    await expect(
      svix.verify(
        ctx([secret], {
          raw: utf8(payload),
          headers: headerMap({
            'svix-id': id,
            'svix-timestamp': 'notime',
            'svix-signature': `v1,${toBase64(mac)}`,
          }),
        }),
      ),
    ).rejects.toThrow(/unix second/)
  })

  it('mentions whitespace when a Stripe secret has a leftover newline', async () => {
    const payload = '{"id":"evt_ws","type":"ping"}'
    const header = await signStripe(payload, 'whsec_test_secret', TS)
    try {
      await stripe.verify({
        raw: utf8(payload),
        headers: headerMap({ 'stripe-signature': header }),
        secrets: [utf8('whsec_wrong_secret')],
        secretStrings: ['whsec_test_secret\n'],
        toleranceSec: 300,
        now: NOW,
        url: undefined,
      })
      expect.fail('should throw')
    } catch (err) {
      expect(err).toBeInstanceOf(DoorbellError)
      expect((err as DoorbellError).toText()).toMatch(/whitespace/)
    }
  })

  it('fingerprints Twilio when CallSid and MessageSid are missing', async () => {
    const url = 'https://shop.test/webhooks/twilio'
    const body = 'Digits=1'
    const secret = 'twilio_auth_token'
    const sig = await signTwilio(url, body, secret)
    let id = ''
    const app = doorbell({
      publicUrl: url,
      twilio: {
        secret,
        onAny: async (event) => {
          id = event.id
        },
      },
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
    expect(res.status).toBe(200)
    expect(id).toHaveLength(40)
  })

  it('strips a BOM given as raw UTF-8 bytes', () => {
    expect(parseJsonBody(Uint8Array.from([0xef, 0xbb, 0xbf, 0x7b, 0x7d]))).toEqual({})
  })

  it('rejects non-canonical base64', () => {
    expect(parseBase64('YR')).toBeNull()
    expect(parseBase64('YR', 'web')).toBeNull()
  })

  it('falls Standard Webhooks type back to the provider name', () => {
    expect(standard.eventType(headerMap({}), {})).toBe('svix')
  })

  it('handles a missing url and missing Express method', async () => {
    const payload = '{"id":"evt_nu","type":"ping"}'
    const secret = 'whsec_test_secret'
    const header = await signStripe(payload, secret, TS)
    const seen: unknown[] = []
    const app = doorbell({
      now: NOW,
      onError: (err) => seen.push(err),
      stripe: { secret, onAny: async () => {} },
    })
    const res = await app.handle({
      method: 'POST',
      url: undefined,
      headers: headerMap({ 'stripe-signature': header }),
      raw: utf8(payload),
    })
    expect(res.status).toBe(200)
    const reply = {
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
    await app.express(
      {
        url: '/webhooks/stripe',
        headers: { 'stripe-signature': header },
        body: Buffer.from(payload),
        get() {
          return 'shop.test'
        },
      },
      reply,
    )
    expect(reply.statusCode).toBe(200)
    expect(reply.headers['content-type']).toMatch(/json/)
    const fast = {
      status: 0,
      body: '',
      code(n: number) {
        this.status = n
        return this
      },
      type() {
        return this
      },
      send(b: string) {
        this.body = b
      },
    }
    await app.fastify(
      {
        url: '/webhooks/stripe',
        headers: { 'stripe-signature': header },
        body: Buffer.from(payload),
      },
      fast,
    )
    expect(fast.status).toBe(200)
    const pub = doorbell({
      now: NOW,
      publicUrl: ({ url }) => url ?? '/webhooks/stripe',
      stripe: { secret, onAny: async () => {} },
    })
    const rp = {
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
    await pub.express(
      {
        method: 'POST',
        url: '/webhooks/stripe',
        headers: { 'stripe-signature': header },
        body: Buffer.from(payload),
      },
      rp,
    )
    expect(rp.statusCode).toBe(200)
    const miss = await app.handle({
      method: 'POST',
      url: '/webhooks/stripe',
      headers: headerMap({}),
      raw: utf8(payload),
    })
    expect(miss.status).toBe(400)
    expect(seen.length).toBeGreaterThan(0)
  })

  it('times out with onError and throws a string from the handler', async () => {
    const payload = '{"id":"evt_to","type":"ping"}'
    const secret = 'whsec_test_secret'
    const header = await signStripe(payload, secret, TS)
    const seen: unknown[] = []
    const slow = doorbell({
      now: NOW,
      handlerTimeoutMs: 15,
      onError: (err) => seen.push(err),
      stripe: {
        secret,
        onAny: async () => {
          await new Promise((r) => setTimeout(r, 80))
        },
      },
    })
    const timed = await slow.handle({
      method: 'POST',
      url: '/webhooks/stripe',
      headers: headerMap({ 'stripe-signature': header }),
      raw: utf8(payload),
    })
    expect(timed.status).toBe(500)
    expect(seen.length).toBe(1)
    const boom = doorbell({
      now: NOW,
      onError: (err) => seen.push(err),
      stripe: {
        secret,
        onAny: async () => {
          throw 'string boom'
        },
      },
    })
    const thrown = await boom.handle({
      method: 'POST',
      url: '/webhooks/stripe',
      headers: headerMap({ 'stripe-signature': header }),
      raw: utf8(payload),
    })
    expect(thrown.status).toBe(500)
    expect(thrown.body).toMatch(/string boom/)
  })

  it('calls onError when the store throws', async () => {
    const payload = '{"id":"evt_oe","type":"ping"}'
    const secret = 'whsec_test_secret'
    const header = await signStripe(payload, secret, TS)
    const seen: unknown[] = []
    const app = doorbell({
      now: NOW,
      onError: (err) => seen.push(err),
      store: {
        async claim() {
          throw new Error('redis down')
        },
        async commit() {},
        async drop() {},
      },
      stripe: { secret, onAny: async () => {} },
    })
    const res = await app.handle({
      method: 'POST',
      url: '/webhooks/stripe',
      headers: headerMap({ 'stripe-signature': header }),
      raw: utf8(payload),
    })
    expect(res.status).toBe(500)
    expect(seen.length).toBe(1)
  })

  it('refuses a missing secret field at boot', () => {
    expect(() =>
      doorbell({ stripe: { onAny: async () => {} } as never }),
    ).toThrow(/No signing secret/)
  })

  it('commits and drops missing store keys and wakes waiters on gc and evict', async () => {
    const clock = { t: 1000 }
    const store = new MemoryStore(() => clock.t, 10, 10)
    await store.commit('missing', 1000)
    await store.drop('missing')
    await store.claim('x')
    const waiting = store.claim('x')
    clock.t = 2000
    await store.claim('y')
    await waiting
    const evict = new MemoryStore(() => 1, 60_000, 2)
    await evict.claim('a')
    const pending = evict.claim('a')
    await evict.claim('b', { pin: true })
    await evict.claim('c')
    await pending
    const fresh = new MemoryStore(() => 1, 60_000, 10)
    await fresh.drop('never-existed')
  })

  it('sets a header on the Express parsed-body error', async () => {
    const app = doorbell({ stripe: { secret: 'whsec_test_secret', onAny: async () => {} } })
    const reply = {
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
    await app.express(
      {
        method: 'POST',
        url: '/webhooks/stripe',
        headers: { 'stripe-signature': 't=1,v1=abc' },
        body: { parsed: true },
      },
      reply,
    )
    expect(reply.statusCode).toBe(400)
    expect(reply.headers['content-type']).toMatch(/text\/plain/)
  })
})

