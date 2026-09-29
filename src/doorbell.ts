import { copyBytes, secretBytesUtf8 } from './bytes.js'
import { DoorbellError, missingSecretError } from './errors.js'
import { handshake } from './handshake.js'
import { headerMap } from './headers.js'
import { MemoryStore, type IdempotencyStore } from './idempotency.js'
import { stringField } from './json.js'
import { providerFromPath, providers, sniffProvider } from './providers/index.js'
import { rawFromNodeRequest } from './raw.js'
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
  for (const name of allowed) {
    const secrets = asSecretList(config[name]?.secret)
    if (secrets.length === 0) throw missingSecretError(name)
    for (const secret of secrets) lintSecret(name, secret)
  }

  const store = config.store ?? new MemoryStore(config.now ?? Date.now)
  const ttl = config.idempotencyTtlMs ?? 24 * 60 * 60 * 1000
  const unhandled = config.unhandled ?? 'ignore'
  const maxBodyBytes = config.maxBodyBytes ?? 5_000_000
  const handlerTimeoutMs = config.handlerTimeoutMs

  const handle = async (req: NormalizedRequest): Promise<NormalizedResponse> => {
    const method = (req.method || 'POST').toUpperCase()
    const headers = req.headers
    const raw = copyBytes(req.raw)

    if (method === 'GET') {
      const metaCfg = config.meta
      const hs = handshake(method, req.url, headers, raw, {
        metaVerifyToken: metaCfg?.verifyToken,
      })
      if (hs) return hs
      return text(404, 'Nothing to do on GET unless this is a Meta hub.challenge handshake.')
    }

    if (method !== 'POST' && method !== 'PUT') {
      return text(405, 'Use POST.')
    }

    if (maxBodyBytes > 0 && raw.byteLength > maxBodyBytes) {
      throw new DoorbellError(`Body is ${raw.byteLength} bytes. Limit is ${maxBodyBytes}.`, {
        code: 'too_large',
        status: 413,
        hint: 'Raise maxBodyBytes if you really take huge GitHub push payloads. HMAC on a 50MB body is how people melt a box.',
      })
    }

    let name = providerFromPath(req.url, allowed) ?? sniffProvider(headers, allowed)
    if (!name) {
      const svixConfigured = [...allowed].filter((n) => n === 'svix' || n === 'clerk' || n === 'resend')
      if (svixConfigured.length > 1 && (headers.get('svix-signature') || headers.get('webhook-signature'))) {
        throw new DoorbellError(
          'Clerk, Resend, and Svix look the same on the wire.',
          {
            code: 'ambiguous_provider',
            hint: 'Put the provider in the path: /webhooks/clerk or /webhooks/resend.',
          },
        )
      }
      throw new DoorbellError('Could not tell who knocked.', {
        code: 'unknown_provider',
        hint: `Configured: ${[...allowed].join(', ')}. Put the name in the URL (/webhooks/stripe) or send the usual signature headers.`,
      })
    }

    const cfg = config[name]
    if (!cfg) {
      throw new DoorbellError(`Got a ${name} hook but that provider is not configured.`, {
        code: 'unconfigured',
      })
    }

    const secrets = asSecretList(cfg.secret)
    const provider = providers[name]
    const toleranceSec = cfg.toleranceSec ?? config.toleranceSec ?? 300
    const now = config.now ?? Date.now
    const url = resolveUrl(config.publicUrl, req)

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
    const ac = new AbortController()
    const event: VerifiedEvent = {
      provider: name,
      id: provider.eventId(headers, payload, raw),
      type: provider.eventType(headers, payload),
      payload,
      raw,
      timestampSec: verified.timestampSec,
      signal: ac.signal,
    }

    if (name === 'github' && (headers.get('x-github-event') ?? '').toLowerCase() === 'ping') {
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
    const claim = await store.claim(key)
    if (claim === 'duplicate') {
      return json(200, { ok: true, duplicate: true, id: event.id })
    }

    try {
      await runHandler(fn, event, handlerTimeoutMs, ac)
      await store.commit(key, ttl)
      return json(200, { ok: true, id: event.id, type: event.type })
    } catch (err) {
      ac.abort()
      await store.drop(key)
      config.onError?.(err, event)
      if (err instanceof DoorbellError && err.code === 'timeout') throw err
      throw new DoorbellError('Handler threw. Told the sender to retry.', {
        code: 'handler',
        status: 500,
        cause: err,
        hint: err instanceof Error ? err.message : String(err),
      })
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
    const raw = copyBytes(new Uint8Array(await req.arrayBuffer()))
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
      res.setHeader?.('content-type', result.headers['content-type'] ?? 'text/plain; charset=utf-8')
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
    reply.code(result.status).type(result.headers['content-type'] ?? 'text/plain; charset=utf-8').send(result.body)
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

function pickHandler(cfg: ProviderConfig, type: string): WebhookHandler | undefined {
  if (cfg.on?.[type]) return cfg.on[type]
  if (cfg.onAny) return cfg.onAny
  return undefined
}

async function runHandler(
  fn: WebhookHandler,
  event: VerifiedEvent,
  timeoutMs: number | undefined,
  ac: AbortController,
): Promise<void> {
  const work = Promise.resolve(fn(event))
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
          ac.abort()
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
  const host = req.get?.('host')
  const path = req.originalUrl ?? req.url
  if (host && path) return `${req.protocol ?? 'https'}://${host}${path}`
  return path
}
