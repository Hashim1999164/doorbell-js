import { describe, expect, it } from 'vitest'
import {
  concatBytes,
  copyBytes,
  fromUtf8,
  parseBase64,
  parseHex,
  secretBytesUtf8,
  standardWebhookKey,
  toBase64,
  utf8,
} from '../src/bytes.js'
import { assertFresh, parseUnixSec, unixSeconds } from '../src/clock.js'
import {
  doorbell,
  DoorbellError,
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
import { burnB64, burnHex, burnSha1 } from '../src/burn.js'
import { missingSecretError, parsedBodyError, secretHint, tooLargeError } from '../src/errors.js'
import { handshake } from '../src/handshake.js'
import {
  assertSigHeader,
  capParts,
  contentTypeAllowed,
  headerMap,
  headerRequired,
  sigHeader,
} from '../src/headers.js'
import { bodyFingerprint, sha256 } from '../src/hash.js'
import {
  decodeHexMac,
  hmacSha1,
  hmacSha256,
  hmacSha256Base64,
  hmacSha256Hex,
  hmacSubtle,
  matchBase64Mac,
  matchHexMac,
} from '../src/hmac.js'
import { assertJsonBudget, hasOwn, parseJsonBody, stringField, unixField } from '../src/json.js'
import { pathHasDotSegments, providerFromPath, sniffHits, sniffProvider } from '../src/providers/index.js'
import { readRequestBodyCapped } from '../src/raw.js'
import { lintSecret } from '../src/secrets.js'
import { prefixRaw } from '../src/wire.js'

const NOW = () => 1_614_556_800_000
const TS = 1614556800

describe('pathOnly and methods', () => {
  it('does not sniff when pathOnly is on', async () => {
    const payload = '{"id":"evt_path","type":"ping"}'
    const secret = 'whsec_test_secret'
    const header = await signStripe(payload, secret, TS)
    const app = doorbell({
      now: NOW,
      pathOnly: true,
      stripe: { secret, onAny: async () => {} },
    })
    const sniffed = await app(
      new Request('http://shop.test/webhooks', {
        method: 'POST',
        headers: { 'stripe-signature': header },
        body: payload,
      }),
    )
    expect(sniffed.status).toBe(400)
    expect(await sniffed.text()).toMatch(/pathOnly/)
    const named = await app(
      new Request('http://shop.test/webhooks/stripe', {
        method: 'POST',
        headers: { 'stripe-signature': header },
        body: payload,
      }),
    )
    expect(named.status).toBe(200)
  })

  it('rejects PUT unless allowPut is on', async () => {
    const payload = '{"id":"evt_put","type":"ping"}'
    const secret = 'whsec_test_secret'
    const header = await signStripe(payload, secret, TS)
    const closed = doorbell({ now: NOW, stripe: { secret, onAny: async () => {} } })
    const denied = await closed(
      new Request('http://shop.test/webhooks/stripe', {
        method: 'PUT',
        headers: { 'stripe-signature': header },
        body: payload,
      }),
    )
    expect(denied.status).toBe(405)
    const open = doorbell({ now: NOW, allowPut: true, stripe: { secret, onAny: async () => {} } })
    const ok = await open(
      new Request('http://shop.test/webhooks/stripe', {
        method: 'PUT',
        headers: { 'stripe-signature': header },
        body: payload,
      }),
    )
    expect(ok.status).toBe(200)
  })

  it('rejects a browser Content-Type', async () => {
    const payload = '{"id":"evt_html","type":"ping"}'
    const secret = 'whsec_test_secret'
    const header = await signStripe(payload, secret, TS)
    const app = doorbell({ now: NOW, stripe: { secret, onAny: async () => {} } })
    const res = await app(
      new Request('http://shop.test/webhooks/stripe', {
        method: 'POST',
        headers: { 'stripe-signature': header, 'content-type': 'text/html' },
        body: payload,
      }),
    )
    expect(res.status).toBe(400)
    expect(await res.text()).toMatch(/Content-Type/)
  })

  it('refuses gzip because HMAC would be over the wrong bytes', async () => {
    const payload = '{"id":"evt_gz","type":"ping"}'
    const secret = 'whsec_test_secret'
    const header = await signStripe(payload, secret, TS)
    const app = doorbell({ now: NOW, stripe: { secret, onAny: async () => {} } })
    const res = await app(
      new Request('http://shop.test/webhooks/stripe', {
        method: 'POST',
        headers: {
          'stripe-signature': header,
          'content-encoding': 'gzip',
        },
        body: payload,
      }),
    )
    expect(res.status).toBe(400)
    expect(await res.text()).toMatch(/Compressed/)
  })

  it('allows identity Content-Encoding', async () => {
    const payload = '{"id":"evt_id","type":"ping"}'
    const secret = 'whsec_test_secret'
    const header = await signStripe(payload, secret, TS)
    const app = doorbell({ now: NOW, stripe: { secret, onAny: async () => {} } })
    const res = await app(
      new Request('http://shop.test/webhooks/stripe', {
        method: 'POST',
        headers: {
          'stripe-signature': header,
          'content-encoding': 'identity',
        },
        body: payload,
      }),
    )
    expect(res.status).toBe(200)
  })

  it('refuses Origin so a browser form never reaches HMAC', async () => {
    const payload = '{"id":"evt_or","type":"ping"}'
    const secret = 'whsec_test_secret'
    const header = await signStripe(payload, secret, TS)
    const app = doorbell({ now: NOW, stripe: { secret, onAny: async () => {} } })
    const res = await app(
      new Request('http://shop.test/webhooks/stripe', {
        method: 'POST',
        headers: {
          'stripe-signature': header,
          origin: 'https://evil.test',
        },
        body: payload,
      }),
    )
    expect(res.status).toBe(400)
    expect(await res.text()).toMatch(/Origin/)
    const open = doorbell({
      now: NOW,
      allowOrigin: true,
      stripe: { secret, onAny: async () => {} },
    })
    const ok = await open(
      new Request('http://shop.test/webhooks/stripe', {
        method: 'POST',
        headers: {
          'stripe-signature': header,
          origin: 'https://evil.test',
        },
        body: payload,
      }),
    )
    expect(ok.status).toBe(200)
  })

  it('refuses method override headers', async () => {
    const payload = '{"id":"evt_mo","type":"ping"}'
    const secret = 'whsec_test_secret'
    const header = await signStripe(payload, secret, TS)
    const app = doorbell({ now: NOW, stripe: { secret, onAny: async () => {} } })
    const res = await app(
      new Request('http://shop.test/webhooks/stripe', {
        method: 'POST',
        headers: {
          'stripe-signature': header,
          'x-http-method-override': 'GET',
        },
        body: payload,
      }),
    )
    expect(res.status).toBe(400)
    expect(await res.text()).toMatch(/override/)
  })

  it('refuses a huge URL', async () => {
    const payload = '{"id":"evt_url","type":"ping"}'
    const secret = 'whsec_test_secret'
    const header = await signStripe(payload, secret, TS)
    const app = doorbell({
      now: NOW,
      maxUrlLength: 20,
      stripe: { secret, onAny: async () => {} },
    })
    const res = await app.handle({
      method: 'POST',
      url: 'http://shop.test/webhooks/stripe',
      headers: headerMap({ 'stripe-signature': header }),
      raw: utf8(payload),
    })
    expect(res.status).toBe(400)
    expect(res.body).toMatch(/URL is huge/)
  })

  it('refuses a signed JSON array', async () => {
    const payload = '[{"id":"evt_arr"}]'
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
    expect(await res.text()).toMatch(/must be an object/)
  })
})

describe('json budget and BOM', () => {
  it('parses a UTF-8 BOM after HMAC of the raw bytes', async () => {
    const json = '{"id":"evt_bom","type":"ping"}'
    const raw = concatBytes([utf8('\uFEFF'), utf8(json)])
    const secret = 'whsec_test_secret'
    const header = await signStripe(raw, secret, TS)
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
    const res = await app.handle({
      method: 'POST',
      url: 'http://shop.test/webhooks/stripe',
      headers: headerMap({ 'stripe-signature': header }),
      raw,
    })
    expect(res.status).toBe(200)
    expect(id).toBe('evt_bom')
  })

  it('refuses a nest bomb after HMAC', async () => {
    let nested = '{"id":"evt_deep","type":"ping","n":1}'
    for (let i = 0; i < 12; i++) nested = `{"n":${nested}}`
    const secret = 'whsec_test_secret'
    const header = await signStripe(nested, secret, TS)
    const app = doorbell({
      now: NOW,
      maxJsonDepth: 4,
      stripe: { secret, onAny: async () => {} },
    })
    const res = await app(
      new Request('http://shop.test/webhooks/stripe', {
        method: 'POST',
        headers: { 'stripe-signature': header },
        body: nested,
      }),
    )
    expect(res.status).toBe(400)
    expect(await res.text()).toMatch(/nested too deep/)
  })

  it('refuses a wide JSON object after HMAC', async () => {
    const keys = Array.from({ length: 30 }, (_, i) => `"k${i}":1`).join(',')
    const payload = `{"id":"evt_wide","type":"ping",${keys}}`
    const secret = 'whsec_test_secret'
    const header = await signStripe(payload, secret, TS)
    const app = doorbell({
      now: NOW,
      maxJsonKeys: 8,
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
    expect(await res.text()).toMatch(/too many keys/)
  })

  it('fingerprints an oversized event id so the store cannot be keyed on a 10k string', async () => {
    const big = 'e'.repeat(300)
    const payload = `{"id":"${big}","type":"ping"}`
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
    expect(id.length).toBe(40)
    expect(id).toBe(bodyFingerprint(utf8(payload)))
  })
})

describe('boot lint', () => {
  it('refuses an empty config', () => {
    expect(() => doorbell({})).toThrow(/at least one provider/)
  })

  it('refuses a one character GitHub secret', () => {
    expect(() => doorbell({ github: { secret: 'x', onAny: async () => {} } })).toThrow(/too short/)
  })

  it('refuses a pile of rotation secrets', () => {
    const secrets = Array.from({ length: 9 }, (_, i) => `whsec_rot_${i}`)
    expect(() => doorbell({ stripe: { secret: secrets, onAny: async () => {} } })).toThrow(/Too many/)
  })

  it('refuses a Slack bot token', () => {
    expect(() =>
      doorbell({ slack: { secret: 'xoxb-123456789012-abcdefgh', onAny: async () => {} } }),
    ).toThrow(/Slack token/)
  })

  it('refuses a Stripe key stuffed into Clerk', () => {
    expect(() =>
      doorbell({ clerk: { secret: 'sk_test_not_svix', onAny: async () => {} } }),
    ).toThrow(/Standard Webhooks/)
  })
})

describe('adapters', () => {
  it('runs hono off the raw Request', async () => {
    const payload = '{"id":"evt_hono","type":"ping"}'
    const secret = 'whsec_test_secret'
    const header = await signStripe(payload, secret, TS)
    const app = doorbell({ now: NOW, stripe: { secret, onAny: async () => {} } })
    const res = await app.hono({
      req: {
        raw: new Request('http://shop.test/webhooks/stripe', {
          method: 'POST',
          headers: { 'stripe-signature': header },
          body: payload,
        }),
      },
    })
    expect(res.status).toBe(200)
  })

  it('runs fastify off rawBody', async () => {
    const payload = '{"id":"evt_fast","type":"ping"}'
    const secret = 'whsec_test_secret'
    const header = await signStripe(payload, secret, TS)
    const app = doorbell({ now: NOW, stripe: { secret, onAny: async () => {} } })
    const req = {
      method: 'POST',
      url: '/webhooks/stripe',
      headers: { 'stripe-signature': header },
      body: JSON.parse(payload),
      rawBody: undefined as unknown,
    }
    preserveRawBody(req, null, Buffer.from(payload))
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
    await app.fastify(req, reply)
    expect(reply.status).toBe(200)
  })

  it('passes unexpected express errors to next', async () => {
    const payload = '{"id":"evt_next","type":"ping"}'
    const secret = 'whsec_test_secret'
    const header = await signStripe(payload, secret, TS)
    const app = doorbell({ now: NOW, stripe: { secret, onAny: async () => {} } })
    let caught: unknown
    await app.express(
      {
        method: 'POST',
        url: '/webhooks/stripe',
        headers: { 'stripe-signature': header },
        body: Buffer.from(payload),
      },
      {
        status() {
          throw new Error('res boom')
        },
        send() {},
      },
      (err) => {
        caught = err
      },
    )
    expect(caught).toBeInstanceOf(Error)
  })
})

describe('crypto and bytes', () => {
  it('matches node HMAC on the WebCrypto path', async () => {
    const key = utf8('secretkeysecretkey')
    const data = utf8('body')
    const node = await hmacSha256(key, data)
    const web = await hmacSubtle(key, data, 'SHA-256')
    expect(web).toEqual(node)
    expect(await hmacSha1(key, data)).toHaveLength(20)
    expect((await hmacSha256Hex(key, data)).length).toBe(64)
    expect((await hmacSha256Base64(key, data)).length).toBeGreaterThan(20)
  })

  it('throws on an empty HMAC key', async () => {
    await expect(hmacSha256(new Uint8Array(), utf8('x'))).rejects.toThrow(/empty/)
  })

  it('roundtrips web base64', () => {
    const bytes = utf8('Hello')
    expect(parseBase64(toBase64(bytes, 'web'), 'web')).toEqual(bytes)
    expect(parseBase64('SGVsbG8=', 'web')).toEqual(bytes)
    expect(parseBase64('', 'web')).toBeNull()
    expect(parseBase64('====', 'web')).toBeNull()
    expect(parseBase64('SGVsbG8!', 'web')).toBeNull()
  })

  it('compares hex and base64 MACs', async () => {
    const key = utf8('secretkeysecretkey')
    const data = utf8('body')
    const hex = await hmacSha256Hex(key, data)
    const b64 = await hmacSha256Base64(key, data)
    expect(await matchHexMac(key, data, hex)).toBe(true)
    expect(await matchHexMac(key, data, '00')).toBe(false)
    expect(await matchBase64Mac(key, data, b64)).toBe(true)
    expect(decodeHexMac(hex)?.byteLength).toBe(32)
    expect(copyBytes(data)).toEqual(data)
    expect(fromUtf8(data)).toBe('body')
    expect(concatBytes([utf8('a'), utf8('b')])).toEqual(utf8('ab'))
    expect(secretBytesUtf8('  abc  ').hadWhitespace).toBe(true)
  })
})

describe('internals', () => {
  it('covers handshake edges', () => {
    expect(handshake('POST', '/x', new Map(), new Uint8Array(), { metaVerifyToken: 't' })).toBeUndefined()
    expect(
      handshake('GET', 'http://[', new Map(), new Uint8Array(), { metaVerifyToken: 't' })?.status,
    ).toBeUndefined()
    const long = handshake(
      'GET',
      `http://x/?hub.mode=subscribe&hub.verify_token=t&hub.challenge=${'c'.repeat(3000)}`,
      new Map(),
      new Uint8Array(),
      { metaVerifyToken: 't' },
    )
    expect(long?.status).toBe(400)
    const missing = handshake(
      'GET',
      'http://x/?hub.mode=subscribe&hub.verify_token=t&hub.challenge=c',
      new Map(),
      new Uint8Array(),
      { metaVerifyToken: undefined },
    )
    expect(missing?.status).toBe(403)
  })

  it('covers header maps and caps', () => {
    expect(headerMap(new Map([['a', 'b']])).get('a')).toBe('b')
    expect(headerMap({ skip: undefined, empty: [], 'stripe-signature': ['t=1', 'v1=x'] }).get('stripe-signature')).toBe(
      't=1,v1=x',
    )
    expect(headerMap(new Headers({ 'X-Test': '1' })).get('x-test')).toBe('1')
    expect(headerRequired(headerMap({ x: 'y' }), 'x')).toBe('y')
    expect(() => headerRequired(headerMap({}), 'x')).toThrow(/missing_header/)
    expect(contentTypeAllowed('stripe', headerMap({}))).toBe(true)
    expect(contentTypeAllowed('stripe', headerMap({ 'content-type': 'application/json; charset=utf-8' }))).toBe(true)
    expect(contentTypeAllowed('twilio', headerMap({ 'content-type': 'application/x-www-form-urlencoded' }))).toBe(true)
    expect(() => assertSigHeader('a'.repeat(9000), 'Stripe')).toThrow(/huge/)
    expect(() => assertSigHeader('ab\ncd', 'Stripe')).toThrow(/newline/)
    expect(() => capParts(Array.from({ length: 20 }, () => 'x'), 'Stripe')).toThrow(/too many/)
    expect(sigHeader(headerMap({}), 'stripe-signature', 'Stripe')).toBeUndefined()
  })

  it('covers path helpers', () => {
    const allowed = new Set(['stripe', 'github'] as const)
    expect(providerFromPath(undefined, allowed)).toBeUndefined()
    expect(providerFromPath('http://[', allowed)).toBeUndefined()
    expect(providerFromPath('/webhooks/stripe', allowed)).toBe('stripe')
    expect(pathHasDotSegments('/webhooks/github/../stripe')).toBe(true)
    expect(pathHasDotSegments('/webhooks/stripe?x=1')).toBe(false)
    expect(pathHasDotSegments('/%')).toBe(false)
    expect(sniffProvider(headerMap({ 'stripe-signature': 't=1,v1=x' }), new Set(['stripe']))).toBe('stripe')
    expect(sniffProvider(headerMap({ 'stripe-signature': 't=1,v1=x', 'x-slack-signature': 'v0=x' }), new Set(['stripe', 'slack']))).toBeUndefined()
    expect(sniffHits(headerMap({ 'webhook-id': '1', 'webhook-signature': 'v1,x' }), new Set(['svix'])).includes('svix')).toBe(
      true,
    )
  })

  it('covers json helpers and clocks', () => {
    expect(parseJsonBody(new Uint8Array())).toEqual({})
    expect(hasOwn(null, 'a')).toBe(false)
    expect(stringField('x', 'a')).toBeUndefined()
    expect(stringField({ a: '' }, 'a')).toBeUndefined()
    expect(unixField({ n: 1614556800000 }, 'n')).toBe(1614556800)
    expect(unixField({ n: '1614556800' }, 'n')).toBe(1614556800)
    expect(unixField({ n: '1e12' }, 'n')).toBeUndefined()
    expect(unixField(null, 'n')).toBeUndefined()
    expect(() => parseJsonBody(utf8('not-json'))).toThrow(/not JSON/)
    expect(() => parseJsonBody(Uint8Array.from([0xff]))).toThrow(/UTF-8/)
    assertJsonBudget('x', { maxDepth: 1, maxKeys: 1 })
    expect(() => assertJsonBudget([[[[1]]]], { maxDepth: 2, maxKeys: 10 })).toThrow(/nested/)
    expect(() => assertJsonBudget([1, 2, 3, 4], { maxDepth: 8, maxKeys: 2 })).toThrow(/too many keys/)
    expect(parseUnixSec('1614556800')).toBe(1614556800)
    expect(unixSeconds(NOW)).toBe(TS)
    expect(unixSeconds()).toBeGreaterThan(1_700_000_000)
    expect(assertFresh(0, { toleranceSec: 300, now: NOW, future: 'allow' })).toBe('bad')
    expect(assertFresh(TS + 400, { toleranceSec: 300, now: NOW, future: 'reject' })).toBe('too_new')
    expect(assertFresh(TS, { toleranceSec: 300, now: NOW, future: 'allow' })).toBe('ok')
  })

  it('covers store eviction and pin on a missing key', async () => {
    const store = new MemoryStore(NOW, 60_000, 2)
    expect(await store.claim('a', { pin: true })).toBe('run')
    await store.commit('a', 1000)
    expect(await store.claim('b')).toBe('run')
    await store.commit('b', 1000)
    expect(await store.claim('c')).toBe('run')
    await store.pin('missing')
    const zeroHold = new MemoryStore(NOW, 0, 10)
    expect(await zeroHold.claim('z')).toBe('run')
  })

  it('covers burns, errors, and secrets', async () => {
    await burnHex([], utf8('x'))
    await burnB64([], utf8('x'))
    await burnSha1([utf8('secretkey')], utf8('x'))
    expect(new DoorbellError('plain', { code: 'x' }).toText()).toBe('plain')
    expect(tooLargeError(9, 1).status).toBe(413)
    expect(parsedBodyError().code).toBe('parsed_body')
    expect(missingSecretError('linear').status).toBe(500)
    expect(secretHint('linear')).toMatch(/signing secret/)
    expect(secretHint('paddle')).toMatch(/signing secret/)
    lintSecret('github', '   ')
    expect(() => lintSecret('stripe', 'pk_test_abc')).toThrow(/API key/)
    expect(() => lintSecret('stripe', 'rk_test_abc')).toThrow(/API key/)
    expect(() => lintSecret('stripe', 'not_a_whsec_secret')).toThrow(/whsec_/)
    expect(() => standardWebhookKey('!!!')).toThrow(/bad_std_secret/)
    expect(sha256(utf8('a')).byteLength).toBe(32)
    expect(prefixRaw('t.', utf8('x')).byteLength).toBe(3)
  })

  it('covers raw helpers', async () => {
    const req: { rawBody?: unknown; body?: unknown } = {}
    preserveRawBody(req, null, new Uint8Array([1, 2]).buffer)
    expect(rawFromNodeRequest(req).byteLength).toBe(2)
    let doneErr: Error | null = null
    captureFastifyBuffer(req, utf8('{"a":1}'), (err) => {
      doneErr = err
    })
    expect(doneErr).toBeNull()
    captureFastifyBuffer(req, { parsed: true } as unknown as Uint8Array, (err) => {
      doneErr = err
    })
    expect(doneErr).toBeInstanceOf(Error)
    const empty = await readRequestBodyCapped({ body: null } as Request, 10)
    expect(empty.byteLength).toBe(0)
  })
})

describe('providers leftover paths', () => {
  it('accepts Standard Webhooks v1= form', async () => {
    const payload = '{"type":"email.sent"}'
    const keyBytes = Buffer.from('secretkeysecretkeysecretke')
    const secret = `whsec_${keyBytes.toString('base64')}`
    const id = 'msg_eq'
    const sig = await signStandard(payload, secret, id, TS)
    const b64 = sig.slice(3)
    const app = doorbell({ now: NOW, svix: { secret, onAny: async () => {} } })
    const res = await app(
      new Request('http://shop.test/webhooks/svix', {
        method: 'POST',
        headers: {
          'svix-id': id,
          'svix-timestamp': String(TS),
          'svix-signature': `v1=${b64}`,
        },
        body: payload,
      }),
    )
    expect(res.status).toBe(200)
  })

  it('runs clerk when the path names it', async () => {
    const payload = '{"type":"user.created"}'
    const keyBytes = Buffer.from('secretkeysecretkeysecretke')
    const secret = `whsec_${keyBytes.toString('base64')}`
    const id = 'msg_clerk'
    const sig = await signStandard(payload, secret, id, TS)
    const app = doorbell({ now: NOW, clerk: { secret, onAny: async () => {} } })
    const res = await app(
      new Request('http://shop.test/webhooks/clerk', {
        method: 'POST',
        headers: {
          'svix-id': id,
          'svix-timestamp': String(TS),
          'svix-signature': sig,
        },
        body: payload,
      }),
    )
    expect(res.status).toBe(200)
  })

  it('keys Twilio on CallSid and publicUrl string', async () => {
    const url = 'https://shop.test/webhooks/twilio/'
    const body = 'CallSid=CA1'
    const secret = 'twilio_auth_token'
    const sig = await signTwilio(url.replace(/\/$/, ''), body, secret)
    let id = ''
    const app = doorbell({
      publicUrl: url.replace(/\/$/, ''),
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
    expect(id).toBe('CA1')
  })

  it('runs Shopify products from the signed JSON', async () => {
    const payload = '{"id":1,"product_type":"shirt"}'
    const secret = 'shopify_shared_secret'
    const hmac = await signShopify(payload, secret)
    let type = ''
    const app = doorbell({
      shopify: {
        secret,
        on: {
          products: async (event) => {
            type = event.type
          },
        },
      },
    })
    const res = await app(
      new Request('http://shop.test/webhooks/shopify', {
        method: 'POST',
        headers: {
          'x-shopify-hmac-sha256': hmac,
          'x-shopify-topic': 'products/update',
        },
        body: payload,
      }),
    )
    expect(res.status).toBe(200)
    expect(type).toBe('products')
  })

  it('uses Paddle notification_id when event_id is missing', async () => {
    const payload = '{"event_type":"transaction.completed","notification_id":"ntf_1"}'
    const secret = 'paddle_secret_key'
    const sig = await signPaddle(payload, secret, TS)
    let id = ''
    const app = doorbell({
      now: NOW,
      paddle: {
        secret,
        onAny: async (event) => {
          id = event.id
        },
      },
    })
    const res = await app(
      new Request('http://shop.test/webhooks/paddle', {
        method: 'POST',
        headers: { 'paddle-signature': sig },
        body: payload,
      }),
    )
    expect(res.status).toBe(200)
    expect(id).toBe('ntf_1')
  })

  it('returns 404 on GET that is not a Meta handshake', async () => {
    const app = doorbell({ stripe: { secret: 'whsec_test_secret', onAny: async () => {} } })
    const res = await app(new Request('http://shop.test/webhooks/stripe'))
    expect(res.status).toBe(404)
  })

  it('returns 500 when unhandled is error', async () => {
    const payload = '{"id":"evt_no","type":"other"}'
    const secret = 'whsec_test_secret'
    const header = await signStripe(payload, secret, TS)
    const app = doorbell({
      now: NOW,
      unhandled: 'error',
      stripe: { secret, on: { ping: async () => {} } },
    })
    const res = await app(
      new Request('http://shop.test/webhooks/stripe', {
        method: 'POST',
        headers: { 'stripe-signature': header },
        body: payload,
      }),
    )
    expect(res.status).toBe(500)
  })

  it('uses publicUrl as a function for Twilio', async () => {
    const url = 'https://edge.test/webhooks/twilio'
    const body = 'MessageSid=SM9'
    const secret = 'twilio_auth_token'
    const sig = await signTwilio(url, body, secret)
    const app = doorbell({
      publicUrl: () => url,
      twilio: { secret, onAny: async () => {} },
    })
    const res = await app(
      new Request('http://localhost/webhooks/twilio', {
        method: 'POST',
        headers: { 'x-twilio-signature': sig, 'content-type': 'application/x-www-form-urlencoded' },
        body,
      }),
    )
    expect(res.status).toBe(200)
  })

  it('answers Slack url_verification with an empty challenge', async () => {
    const payload = '{"type":"url_verification"}'
    const secret = 'slack_signing_secret'
    const sig = await signSlack(payload, secret, TS)
    const app = doorbell({ now: NOW, slack: { secret } })
    const res = await app(
      new Request('http://shop.test/webhooks/slack', {
        method: 'POST',
        headers: {
          'x-slack-signature': sig,
          'x-slack-request-timestamp': String(TS),
        },
        body: payload,
      }),
    )
    expect(res.status).toBe(200)
    expect(await res.json()).toEqual({ challenge: '' })
  })

  it('rejects Linear scientific notation timestamps', async () => {
    const payload = '{"action":"create","type":"Issue","webhookId":"wh_1","webhookTimestamp":"1e12"}'
    const secret = 'linear_webhook_secret'
    const sig = await signLinear(payload, secret)
    const app = doorbell({ now: NOW, linear: { secret, onAny: async () => {} } })
    const res = await app(
      new Request('http://shop.test/webhooks/linear', {
        method: 'POST',
        headers: { 'linear-signature': sig },
        body: payload,
      }),
    )
    expect(res.status).toBe(400)
  })
})
