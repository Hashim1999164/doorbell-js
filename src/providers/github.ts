import { burnHex } from '../burn.js'
import { DoorbellError, secretHint } from '../errors.js'
import { bodyFingerprint } from '../hash.js'
import { header, sigHeader } from '../headers.js'
import { matchAnyHexMac } from '../hmac.js'
import { hasOwn, parseJsonBody, stringField } from '../json.js'
import type { HeaderMap } from '../headers.js'
import type { Provider } from './types.js'

export function sniffGitHub(headers: HeaderMap): boolean {
  return Boolean(header(headers, 'x-github-event') || header(headers, 'x-github-delivery'))
}

function signatureHex(headerValue: string): string | undefined {
  const value = headerValue.trim()
  if (value.startsWith('sha256=')) return value.slice('sha256='.length)
  if (value.startsWith('sha1=')) return undefined
  return value
}

export const github: Provider = {
  name: 'github',
  sniff: sniffGitHub,
  parse: parseJsonBody,
  eventId(_headers, _payload, raw) {
    return bodyFingerprint(raw)
  },
  eventType(headers, payload) {
    // X-GitHub-Event is not in the HMAC. Prefer onAny and read the payload.
    const event = header(headers, 'x-github-event') ?? 'unknown'
    const action = stringField(payload, 'action')
    return action ? `${event}.${action}` : event
  },
  async verify(ctx) {
    const sig = sigHeader(ctx.headers, 'x-hub-signature-256', 'GitHub')
    if (!sig) {
      await burnHex(ctx.secrets, ctx.raw)
      throw new DoorbellError('No X-Hub-Signature-256 header.', {
        code: 'missing_header',
        hint: 'GitHub only sends this if you set a secret on the webhook. Empty secret means anyone can POST here.',
      })
    }
    const hex = signatureHex(sig)
    if (!hex) {
      await burnHex(ctx.secrets, ctx.raw)
      throw new DoorbellError('GitHub signature was sha1. That scheme is dead. Use sha256.', {
        code: 'bad_header',
      })
    }
    const ok = await matchAnyHexMac(ctx.secrets, ctx.raw, [hex])
    if (!ok) {
      throw new DoorbellError('GitHub signature did not match.', {
        code: 'bad_signature',
        hint: [
          secretHint('github'),
          'The HMAC is over the raw body. If this is Express, you want express.raw(), not express.json().',
        ].join('\n'),
      })
    }
    const payload = parseJsonBody(ctx.raw)
    const eventName = header(ctx.headers, 'x-github-event') ?? ''
    if (!githubEventMatchesBody(eventName, payload)) {
      throw new DoorbellError('X-GitHub-Event does not match the signed body.', {
        code: 'bad_header',
        hint: 'GitHub does not HMAC that header. If the signed JSON looks like a push, gollum will not run on[gollum].',
      })
    }
    return { timestampSec: undefined }
  },
}

/** Infer from the signed JSON, then require the unsigned event name to match that family. */
export function githubEventMatchesBody(eventName: string, payload: unknown): boolean {
  const event = eventName.trim().toLowerCase()
  if (!event) return false
  const allowed = githubEventsForBody(payload)
  if (!allowed) return true
  return allowed.includes(event)
}

function githubEventsForBody(payload: unknown): string[] | undefined {
  if (hasOwn(payload, 'zen')) return ['ping']
  if (hasOwn(payload, 'workflow_run')) return ['workflow_run']
  if (hasOwn(payload, 'workflow_job')) return ['workflow_job']
  if (hasOwn(payload, 'check_run')) return ['check_run']
  if (hasOwn(payload, 'check_suite')) return ['check_suite']
  if (hasOwn(payload, 'release')) return ['release']
  if (hasOwn(payload, 'forkee')) return ['fork']
  if (hasOwn(payload, 'starred_at')) return ['star']
  if (hasOwn(payload, 'issue') && hasOwn(payload, 'comment')) return ['issue_comment']
  if (hasOwn(payload, 'issue')) return ['issues']
  if (hasOwn(payload, 'review') && hasOwn(payload, 'pull_request')) return ['pull_request_review']
  if (hasOwn(payload, 'comment') && hasOwn(payload, 'pull_request')) return ['pull_request_review_comment']
  if (hasOwn(payload, 'pull_request')) return ['pull_request']
  if (hasOwn(payload, 'ref_type')) return ['create', 'delete']
  if (hasOwn(payload, 'ref') || hasOwn(payload, 'commits')) return ['push']
  return undefined
}

export function sniffMeta(headers: HeaderMap): boolean {
  if (header(headers, 'x-github-event')) return false
  return Boolean(header(headers, 'x-hub-signature-256') && header(headers, 'x-hub-signature'))
}

export const meta: Provider = {
  name: 'meta',
  sniff: sniffMeta,
  parse: parseJsonBody,
  eventId(_headers, _payload, raw) {
    return bodyFingerprint(raw)
  },
  eventType(_headers, payload) {
    return stringField(payload, 'object') ?? 'meta'
  },
  async verify(ctx) {
    const sig = sigHeader(ctx.headers, 'x-hub-signature-256', 'Meta')
    if (!sig) {
      await burnHex(ctx.secrets, ctx.raw)
      throw new DoorbellError('No X-Hub-Signature-256 header from Meta.', {
        code: 'missing_header',
        hint: secretHint('meta'),
      })
    }
    const hex = signatureHex(sig)
    if (!hex) {
      await burnHex(ctx.secrets, ctx.raw)
      throw new DoorbellError('Meta signature missing sha256= prefix.', { code: 'bad_header' })
    }
    const ok = await matchAnyHexMac(ctx.secrets, ctx.raw, [hex])
    if (!ok) {
      throw new DoorbellError('Meta signature did not match.', {
        code: 'bad_signature',
        hint: secretHint('meta'),
      })
    }
    return { timestampSec: undefined }
  },
}
