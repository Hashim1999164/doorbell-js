import { copyBytes, secretBytesUtf8 } from './bytes.js'
import { DoorbellError, missingSecretError, secretHint, tooLargeError } from './errors.js'
import { handshake } from './handshake.js'
import { assertHeaderBudget, contentTypeAllowed, header, headerMap } from './headers.js'
import { bodyFingerprint } from './hash.js'
import { MemoryStore, type IdempotencyStore } from './idempotency.js'
import { assertJsonBudget, assertJsonObject, hasOwn, stringField } from './json.js'
import { pathHasDotSegments, providerFromPath, providers, sniffHits } from './providers/index.js'
import { rawFromNodeRequest, readRequestBodyCapped } from './raw.js'
import { lintSecret } from './secrets.js'
import type { ProviderName, VerifiedEvent } from './providers/types.js'
import type { HeaderMap } from './headers.js'

export type WebhookHandler = (event: VerifiedEvent) => unknown | Promise<unknown>

export type ProviderConfig = {
  secret: string | string[]
  on?: Record<string, WebhookHandler>
  onAny?: WebhookHandler
  toleranceSec?: number
  verifyToken?: string
}

export type DoorbellConfig = {
  stripe?: ProviderConfig
  github?: ProviderConfig
  slack?: ProviderConfig
  shopify?: ProviderConfig
  svix?: ProviderConfig
  clerk?: ProviderConfig
  resend?: ProviderConfig
  linear?: ProviderConfig
  paddle?: ProviderConfig
  meta?: ProviderConfig
  twilio?: ProviderConfig
  toleranceSec?: number
  now?: () => number
  store?: IdempotencyStore
  unhandled?: 'ignore' | 'error'
  idempotencyTtlMs?: number
  publicUrl?: string | ((info: { url: string | undefined; headers: HeaderMap }) => string)
  onError?: (err: unknown, event: VerifiedEvent | undefined) => void
  maxBodyBytes?: number
  handlerTimeoutMs?: number
  /**
   * Do not sniff signature headers. The path must name the provider.
   * Unsigned headers cannot pick who knocked.
   */
  pathOnly?: boolean
  /** PUT is off. Stripe and GitHub POST. */
  allowPut?: boolean
  maxJsonDepth?: number
  maxJsonKeys?: number
  /** After HMAC. One signed field can still be megabytes of string. */
  maxJsonString?: number
  maxSecrets?: number
  maxStoreSlots?: number
  /** Concurrent retries of one inflight id share this many waiter slots. Extra callers chain. */
  maxStoreWaiters?: number
  maxUrlLength?: number
  maxHeaderBytes?: number
  /**
   * Browsers send Origin. Stripe does not. Refuse it so a form on another site
   * cannot even reach HMAC.
   */
  allowOrigin?: boolean
  /** Browsers send Referer. Stripe does not. Same idea as Origin. */
  allowReferer?: boolean
  /** POST with X-HTTP-Method-Override: GET would skip HMAC and hit Meta handshake. */
  allowMethodOverride?: boolean
  /**
   * Twilio HMAC includes the public URL. http is only for localhost.
   * Production needs https, or set publicUrl to the https URL Twilio called.
   */
  allowInsecureTwilioUrl?: boolean
}

export type NormalizedRequest = {
  method: string
  url: string | undefined
  headers: HeaderMap
  raw: Uint8Array
}

export type NormalizedResponse = {
  status: number
  body: string
  headers: Record<string, string>
}

export type ExpressReq = {
  method?: string
  url?: string
  originalUrl?: string
  protocol?: string
  headers: Record<string, string | string[] | undefined>
  body: unknown
  rawBody?: unknown
  get?: (name: string) => string | undefined
}

export type ExpressRes = {
  status: (code: number) => ExpressRes
  send: (body: string) => unknown
  setHeader?: (name: string, value: string) => void
}

export type FastifyReq = {
  method?: string
  url?: string
  headers: Record<string, string | string[] | undefined>
  body: unknown
  rawBody?: unknown
}

export type FastifyReply = {
  code: (status: number) => FastifyReply
  type: (contentType: string) => FastifyReply
  send: (body: string) => unknown
}

export type HonoContext = {
  req: { raw: Request }
}

export type Doorbell = {
  (req: Request): Promise<Response>
  express: (req: ExpressReq, res: ExpressRes, next?: (err?: unknown) => void) => Promise<void>
  fastify: (req: FastifyReq, reply: FastifyReply) => Promise<void>
  hono: (c: HonoContext) => Promise<Response>
  handle: (req: NormalizedRequest) => Promise<NormalizedResponse>
}

const NAMES: ProviderName[] = [
  'stripe',
  'github',
  'slack',
  'shopify',
  'svix',
  'clerk',
  'resend',
  'linear',
  'paddle',
  'meta',
  'twilio',
]

export function doorbell(config: DoorbellConfig): Doorbell {
  const allowed = new Set<ProviderName>()
  for (const name of NAMES) {
    if (config[name]) allowed.add(name)
  }
  if (allowed.size === 0) {
    throw new DoorbellError('doorbell() needs at least one provider.', { code: 'empty_config', status: 500 })
  }
  const maxSecrets = config.maxSecrets ?? 8
  for (const name of allowed) {
    const secrets = asSecretList(config[name]?.secret)
    if (secrets.length === 0) throw missingSecretError(name)
    if (secrets.length > maxSecrets) {
      throw new DoorbellError('Too many signing secrets for one provider.', {
        code: 'too_many_secrets',
        status: 500,
        hint: 'Rotation wants two keys, not a pile. Raise maxSecrets if you really need more.',
      })
    }
    for (const secret of secrets) lintSecret(name, secret)
  }

  const handlerTimeoutMs = config.handlerTimeoutMs
  const inflightHoldMs = Math.max(
    60_000,
    (handlerTimeoutMs && handlerTimeoutMs > 0 ? handlerTimeoutMs : 0) + 60_000,
  )
  const store =
    config.store ??
    new MemoryStore(
      config.now ?? Date.now,
      inflightHoldMs,
      config.maxStoreSlots ?? 50_000,
      config.maxStoreWaiters ?? 64,
    )
  const ttl = config.idempotencyTtlMs ?? 24 * 60 * 60 * 1000
  const unhandled = config.unhandled ?? 'ignore'
  const maxBodyBytes = config.maxBodyBytes ?? 5_000_000

  const handle = async (req: NormalizedRequest): Promise<NormalizedResponse> => {
    const method = (req.method || 'POST').toUpperCase()
    const headers = req.headers

    if (maxBodyBytes > 0 && req.raw.byteLength > maxBodyBytes) {
      throw tooLargeError(req.raw.byteLength, maxBodyBytes)
    }
    const raw = copyBytes(req.raw)

    if (method === 'GET') {
      const metaCfg = config.meta
      const hs = handshake(method, req.url, headers, raw, {
        metaVerifyToken: metaCfg?.verifyToken,
      })
      if (hs) return hs
      return text(404, 'Nothing to do on GET unless this is a Meta hub.challenge handshake.')
    }

    if (method !== 'POST') {
      if (!(method === 'PUT' && config.allowPut)) {
        return text(405, 'Use POST.')
      }
    }

    if ((req.url?.length ?? 0) > (config.maxUrlLength ?? 4096)) {
      throw new DoorbellError('Webhook URL is huge.', {
        code: 'bad_url',
        hint: 'Express originalUrl should be a path, not a 100KB string.',
      })
    }

    assertHeaderBudget(headers, config.maxHeaderBytes ?? 32_768)

    const encoding = header(headers, 'content-encoding')
    if (encoding) {
      const enc = encoding.split(',')[0]!.trim().toLowerCase()
      if (enc && enc !== 'identity') {
        throw new DoorbellError('Compressed webhook bodies are refused.', {
          code: 'bad_encoding',
          hint: 'HMAC is over the bytes we read. gzip of the JSON is not the JSON Stripe signed.',
        })
      }
    }

    if (!config.allowOrigin && header(headers, 'origin')) {
      throw new DoorbellError('Origin header on a webhook. Browsers send that. Stripe does not.', {
        code: 'browser_origin',
        hint: 'A page on another origin can POST here. HMAC still has to match, but this route should not look like a browser form. Set allowOrigin if a proxy adds Origin.',
      })
    }

    if (!config.allowReferer && header(headers, 'referer')) {
      throw new DoorbellError('Referer header on a webhook. Browsers send that. Stripe does not.', {
        code: 'browser_referer',
        hint: 'Same as Origin. Set allowReferer if a proxy adds it.',
      })
    }

    if (
      !config.allowMethodOverride &&
      (header(headers, 'x-http-method-override') ||
        header(headers, 'x-http-method') ||
        header(headers, 'x-method-override'))
    ) {
      throw new DoorbellError('Method override headers are refused.', {
        code: 'method_override',
        hint: 'POST with X-HTTP-Method-Override: GET would skip HMAC and hit the Meta handshake.',
      })
    }

    if (req.url && pathHasDotSegments(req.url)) {
      throw new DoorbellError('Webhook path contains . or .. . Refusing to pick a provider from it.', {
        code: 'bad_path',
        hint: 'Put the provider in a plain path segment: /webhooks/stripe. Dot segments change which handler runs.',
      })
    }

    let name = providerFromPath(req.url, allowed)
    if (!name) {
      if (config.pathOnly) {
        throw new DoorbellError('Could not tell who knocked.', {
          code: 'unknown_provider',
          hint: 'pathOnly is on. Put the provider in the URL (/webhooks/stripe). Signature headers are not a name.',
        })
      }
      const hits = sniffHits(headers, allowed)
      if (hits.length === 1) {
        name = hits[0]
      } else if (hits.length > 1) {
        const svixFamily = hits.filter((n) => n === 'svix' || n === 'clerk' || n === 'resend')
        const svixOnly = svixFamily.length === hits.length
        throw new DoorbellError(
          svixOnly
            ? 'Clerk, Resend, and Svix look the same on the wire.'
            : 'Those headers match more than one provider.',
          {
            code: 'ambiguous_provider',
            hint: svixOnly
              ? 'Put the provider in the path: /webhooks/clerk or /webhooks/resend.'
              : `Saw ${hits.join(', ')}. Put the name in the URL (/webhooks/${hits[0]}). Extra signature headers from a proxy will not pick a winner.`,
          },
        )
      }
    }
    if (!name) {
      throw new DoorbellError('Could not tell who knocked.', {
        code: 'unknown_provider',
        hint: `Configured: ${[...allowed].join(', ')}. Put the name in the URL (/webhooks/stripe) or send the usual signature headers.`,
      })
    }

    const cfg = config[name]
    /* v8 ignore start */
    if (!cfg) {
      throw new DoorbellError(`Got a ${name} hook but that provider is not configured.`, {
        code: 'unconfigured',
      })
    }
    /* v8 ignore stop */

    if (!contentTypeAllowed(name, headers)) {
      throw new DoorbellError('Content-Type is not a webhook type.', {
        code: 'bad_content_type',
        hint: 'JSON providers want application/json. Twilio wants form-urlencoded. A browser navigating here sends text/html.',
      })
    }

    const secrets = asSecretList(cfg.secret)
    const provider = providers[name]
    const toleranceSec = cfg.toleranceSec ?? config.toleranceSec ?? 300
    const now = config.now ?? Date.now
    const url = resolveUrl(config.publicUrl, req)
    if (name === 'twilio') assertTwilioPublicUrl(url, config.allowInsecureTwilioUrl)

    const verified = await provider.verify({
      raw,
      headers,
      secrets: secrets.map((s) => copyBytes(secretBytesUtf8(s).key)),
      secretStrings: secrets,
      toleranceSec,
      now,
      url,
    })

    const payload = provider.parse(raw)
    if (name !== 'twilio') assertJsonObject(payload)
    assertJsonBudget(payload, {
      maxDepth: config.maxJsonDepth ?? 40,
      maxKeys: config.maxJsonKeys ?? 20_000,
      maxString: config.maxJsonString ?? 1_000_000,
    })
    const ac = new AbortController()
    const event: VerifiedEvent = {
      provider: name,
      id: capEventId(provider.eventId(headers, payload, raw), raw),
      type: capEventType(provider.eventType(headers, payload)),
      payload,
      raw,
      timestampSec: verified.timestampSec,
      signal: ac.signal,
      // Stripe-Account is not in the HMAC. Connect account id lives on the signed JSON.
      account: capAccount(name === 'stripe' ? stringField(payload, 'account') : undefined),
    }

    // GitHub ping is the signed zen field, even if it is empty. That header is not in the HMAC.
    if (name === 'github' && hasOwn(payload, 'zen')) {
      return json(200, { ok: true, ping: true })
    }

    if (name === 'slack' && stringField(payload, 'type') === 'url_verification') {
      return json(200, { challenge: stringField(payload, 'challenge') ?? '' })
    }

    const fn = pickHandler(cfg, event.type)
    if (!fn) {
      if (unhandled === 'error') {
        throw new DoorbellError(`No handler for ${name} ${event.type}.`, {
          code: 'unhandled',
          status: 500,
        })
      }
      return json(200, { ok: true, ignored: event.type })
    }

    const key = `${name}:${event.id}`
    const claim = await store.claim(key, { pin: true })
    if (claim === 'duplicate') {
      return json(200, { ok: true, duplicate: true, id: event.id })
    }
    await store.pin?.(key)

    const work = Promise.resolve(fn(event)).then(() => undefined)
    try {
      await awaitHandler(work, handlerTimeoutMs)
      await store.commit(key, ttl)
      return json(200, { ok: true, id: event.id, type: event.type })
    } catch (err) {
      if (err instanceof DoorbellError && err.code === 'timeout') {
        // Do not abort. Abort turns a handler that already wrote the DB into a throw,
        // which drops inflight and lets Stripe retry fulfill again.
        void work.then(
          () => store.commit(key, ttl).catch(() => undefined),
          () => store.drop(key).catch(() => undefined),
        )
        config.onError?.(err, event)
        return text(err.status, err.toText())
      }
      ac.abort()
      await store.drop(key)
      config.onError?.(err, event)
      const wrapped = new DoorbellError('Handler threw. Told the sender to retry.', {
        code: 'handler',
        status: 500,
        cause: err,
        hint: err instanceof Error ? err.message : String(err),
      })
      return text(wrapped.status, wrapped.toText())
    }
  }

  const guarded = async (req: NormalizedRequest): Promise<NormalizedResponse> => {
    try {
      return await handle(req)
    } catch (err) {
      if (err instanceof DoorbellError) {
        config.onError?.(err, undefined)
        return text(err.status, err.toText())
      }
      config.onError?.(err, undefined)
      return text(500, 'Handler failed.')
    }
  }

  const fetchHandler = async (req: Request): Promise<Response> => {
    let raw: Uint8Array
    try {
      raw = await readRequestBodyCapped(req, maxBodyBytes)
    } catch (err) {
      if (err instanceof DoorbellError) {
        return new Response(err.toText(), {
          status: err.status,
          headers: { 'content-type': 'text/plain; charset=utf-8' },
        })
      }
      throw err
    }
    const result = await guarded({
      method: req.method,
      url: req.url,
      headers: headerMap(req.headers),
      raw,
    })
    return new Response(result.body, { status: result.status, headers: result.headers })
  }

  const express = async (req: ExpressReq, res: ExpressRes, next?: (err?: unknown) => void) => {
    try {
      let raw: Uint8Array
      try {
        raw = rawFromNodeRequest(req)
      } catch (err) {
        if (err instanceof DoorbellError) {
          res.setHeader?.('content-type', 'text/plain; charset=utf-8')
          res.status(err.status).send(err.toText())
          return
        }
        throw err
      }
      const result = await guarded({
        method: req.method ?? 'POST',
        url: expressUrl(req, config),
        headers: headerMap(req.headers),
        raw,
      })
      res.setHeader?.('content-type', result.headers['content-type']!)
      res.status(result.status).send(result.body)
    } catch (err) {
      if (next) next(err)
      else throw err
    }
  }

  const fastify = async (req: FastifyReq, reply: FastifyReply) => {
    let raw: Uint8Array
    try {
      raw = rawFromNodeRequest(req)
    } catch (err) {
      if (err instanceof DoorbellError) {
        reply.code(err.status).type('text/plain; charset=utf-8').send(err.toText())
        return
      }
      throw err
    }
    const result = await guarded({
      method: req.method ?? 'POST',
      url: req.url,
      headers: headerMap(req.headers),
      raw,
    })
    reply.code(result.status).type(result.headers['content-type']!).send(result.body)
  }

  const hono = async (c: HonoContext) => fetchHandler(c.req.raw)

  const doorbellFn = Object.assign(fetchHandler, { express, fastify, hono, handle: guarded })
  return doorbellFn
}

function asSecretList(secret: string | string[] | undefined): string[] {
  if (secret == null) return []
  const list = Array.isArray(secret) ? secret : [secret]
  return list.map((s) => s.trim()).filter((s) => s.length > 0)
}

function capEventId(id: string, raw: Uint8Array): string {
  if (id.length === 0 || id.length > 256 || /[^a-zA-Z0-9._:-]/.test(id)) {
    return bodyFingerprint(raw)
  }
  return id
}

function capEventType(type: string): string {
  if (type.length === 0 || type.length > 128 || /[\x00-\x1f\x7f]/.test(type)) return 'unknown'
  return type
}

function capAccount(account: string | undefined): string | undefined {
  if (!account) return undefined
  if (account.length > 128 || /[\x00-\x1f\x7f]/.test(account)) return undefined
  return account
}

function assertTwilioPublicUrl(url: string | undefined, allowInsecure: boolean | undefined): void {
  if (!url) {
    throw new DoorbellError('Twilio checks need the public URL Twilio called.', {
      code: 'missing_url',
      hint: secretHint('twilio'),
    })
  }
  let parsed: URL
  try {
    parsed = new URL(url)
  } catch {
    throw new DoorbellError('Twilio public URL must be absolute https.', {
      code: 'missing_url',
      hint: secretHint('twilio'),
    })
  }
  if (parsed.protocol === 'https:') return
  const hostname = parsed.hostname.replace(/^\[|\]$/g, '')
  const local = hostname === 'localhost' || hostname === '127.0.0.1' || hostname === '::1'
  if (parsed.protocol === 'http:' && (allowInsecure || local)) return
  throw new DoorbellError('Twilio public URL must be https.', {
    code: 'insecure_url',
    hint: 'Twilio signs the URL it called. http is only for localhost. Set publicUrl to the https URL, or allowInsecureTwilioUrl for a local tunnel.',
  })
}

function pickHandler(cfg: ProviderConfig, type: string): WebhookHandler | undefined {
  if (cfg.on?.[type]) return cfg.on[type]
  if (cfg.onAny) return cfg.onAny
  return undefined
}

async function awaitHandler(work: Promise<void>, timeoutMs: number | undefined): Promise<void> {
  if (timeoutMs == null || timeoutMs <= 0) {
    await work
    return
  }
  let timer: ReturnType<typeof setTimeout> | undefined
  try {
    await Promise.race([
      work,
      new Promise<never>((_, reject) => {
        timer = setTimeout(() => {
          reject(
            new DoorbellError('Handler ran too long.', {
              code: 'timeout',
              status: 500,
              hint: 'Stripe retries 5xx. Keep this short, or push the slow work onto a queue and return.',
            }),
          )
        }, timeoutMs)
      }),
    ])
  } finally {
    if (timer) clearTimeout(timer)
  }
}

function text(status: number, body: string): NormalizedResponse {
  return { status, body, headers: { 'content-type': 'text/plain; charset=utf-8' } }
}

function json(status: number, body: unknown): NormalizedResponse {
  return {
    status,
    body: JSON.stringify(body),
    headers: { 'content-type': 'application/json; charset=utf-8' },
  }
}

function resolveUrl(
  publicUrl: DoorbellConfig['publicUrl'],
  req: NormalizedRequest,
): string | undefined {
  if (typeof publicUrl === 'function') return publicUrl({ url: req.url, headers: req.headers })
  if (typeof publicUrl === 'string') return publicUrl
  return req.url
}

function expressUrl(req: ExpressReq, config: DoorbellConfig): string | undefined {
  if (typeof config.publicUrl === 'string') return config.publicUrl
  if (typeof config.publicUrl === 'function') {
    return config.publicUrl({ url: req.originalUrl ?? req.url, headers: headerMap(req.headers) })
  }
  const headers = headerMap(req.headers)
  const host = header(headers, 'host')
  const path = req.originalUrl ?? req.url
  // Express req.get('host') follows trust proxy / X-Forwarded-Host. Do not.
  if (host && /[\r\n\x00/]/.test(host)) return path
  if (host && path) {
    const proto = hostIsLocal(host) ? 'http' : 'https'
    return `${proto}://${host}${path}`
  }
  return path
}

function hostIsLocal(host: string): boolean {
  let name = host.toLowerCase()
  if (name.startsWith('[')) {
    const end = name.indexOf(']')
    name = end === -1 ? name : name.slice(1, end)
  } else {
    name = name.split(':')[0]!
  }
  return name === 'localhost' || name === '127.0.0.1' || name === '::1'
}
