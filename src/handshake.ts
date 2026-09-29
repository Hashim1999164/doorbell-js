import { timingSafeEqualText } from './timing.js'
import type { HeaderMap } from './headers.js'

export type Handshake = { status: number; body: string; headers: Record<string, string> }

const MAX_CHALLENGE = 2048

export function handshake(
  method: string,
  url: string | undefined,
  _headers: HeaderMap,
  _raw: Uint8Array,
  opts: { metaVerifyToken: string | undefined },
): Handshake | undefined {
  if (method !== 'GET') return undefined

  let search = ''
  try {
    search = new URL(url ?? '', 'http://doorbell.local').search
  } catch {
    search = ''
  }
  const params = new URLSearchParams(search.startsWith('?') ? search.slice(1) : search)
  if (params.get('hub.mode') !== 'subscribe') return undefined

  const token = params.get('hub.verify_token') ?? ''
  const challenge = params.get('hub.challenge') ?? ''
  if (!opts.metaVerifyToken) {
    return {
      status: 403,
      body: 'Meta GET handshake needs meta.verifyToken on the doorbell config.',
      headers: { 'content-type': 'text/plain; charset=utf-8' },
    }
  }
  if (challenge.length > MAX_CHALLENGE) {
    return {
      status: 400,
      body: 'hub.challenge is too long.',
      headers: { 'content-type': 'text/plain; charset=utf-8' },
    }
  }
  if (!timingSafeEqualText(token, opts.metaVerifyToken)) {
    return {
      status: 403,
      body: 'hub.verify_token did not match.',
      headers: { 'content-type': 'text/plain; charset=utf-8' },
    }
  }
  return {
    status: 200,
    body: challenge,
    headers: { 'content-type': 'text/plain; charset=utf-8' },
  }
}
