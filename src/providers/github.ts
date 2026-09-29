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
        hint: 'GitHub does not HMAC that header. A captured push labelled issues will not run on[issues].',
      })
    }
    return { timestampSec: undefined }
  },
}

/** Known GitHub events have a body shape. Unknown events stay fail-open after HMAC. */
export function githubEventMatchesBody(eventName: string, payload: unknown): boolean {
  const event = eventName.trim().toLowerCase()
  if (!event) return false
  switch (event) {
    case 'ping':
      return hasOwn(payload, 'zen')
    case 'push':
      return hasOwn(payload, 'ref') || hasOwn(payload, 'commits')
    case 'issues':
      return hasOwn(payload, 'issue') && !hasOwn(payload, 'comment')
    case 'issue_comment':
      return hasOwn(payload, 'issue') && hasOwn(payload, 'comment')
    case 'pull_request':
      return hasOwn(payload, 'pull_request') && !hasOwn(payload, 'review')
    case 'pull_request_review':
      return hasOwn(payload, 'review') && hasOwn(payload, 'pull_request')
    case 'pull_request_review_comment':
      return hasOwn(payload, 'comment') && hasOwn(payload, 'pull_request')
    case 'release':
      return hasOwn(payload, 'release')
    case 'workflow_run':
      return hasOwn(payload, 'workflow_run')
    case 'workflow_job':
      return hasOwn(payload, 'workflow_job')
    case 'check_run':
      return hasOwn(payload, 'check_run')
    case 'check_suite':
      return hasOwn(payload, 'check_suite')
    case 'create':
    case 'delete':
      return hasOwn(payload, 'ref_type')
    case 'fork':
      return hasOwn(payload, 'forkee')
    case 'star':
      return hasOwn(payload, 'starred_at')
    default:
      return true
  }
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
