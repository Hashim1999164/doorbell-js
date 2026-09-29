import { header } from './headers.js'
import { parseJsonBody, stringField } from './json.js'
import type { HeaderMap } from './headers.js'

export type Handshake = { status: number; body: string; headers: Record<string, string> }

export function handshake(
  method: string,
  url: string | undefined,
  headers: HeaderMap,
  raw: Uint8Array,
  opts: { metaVerifyToken: string | undefined },
): Handshake | undefined {
  if (method === 'GET') {
    let search = ''
    try {
      search = new URL(url ?? '', 'http://doorbell.local').search
    } catch {
      search = ''
    }
    const params = new URLSearchParams(search.startsWith('?') ? search.slice(1) : search)
    if (params.get('hub.mode') === 'subscribe') {
      const token = params.get('hub.verify_token')
      const challenge = params.get('hub.challenge') ?? ''
      if (!opts.metaVerifyToken) {
        return {
          status: 403,
          body: 'Meta GET handshake needs meta.verifyToken on the doorbell config.',
          headers: { 'content-type': 'text/plain; charset=utf-8' },
        }
      }
      if (token !== opts.metaVerifyToken) {
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
    return undefined
  }

  if (method !== 'POST' && method !== 'PUT') return undefined
  if (!header(headers, 'x-slack-signature')) return undefined
  let payload: unknown
  try {
    payload = parseJsonBody(raw)
  } catch {
    return undefined
  }
  if (stringField(payload, 'type') === 'url_verification') {
    const challenge = stringField(payload, 'challenge') ?? ''
    return {
      status: 200,
      body: JSON.stringify({ challenge }),
      headers: { 'content-type': 'application/json' },
    }
  }
  return undefined
}
