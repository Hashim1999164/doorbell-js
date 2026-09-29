import { github, meta } from './github.js'
import { linear } from './linear.js'
import { paddle } from './paddle.js'
import { shopify } from './shopify.js'
import { slack } from './slack.js'
import { clerk, resend, standard, svix } from './standard.js'
import { stripe } from './stripe.js'
import { twilio } from './twilio.js'
import type { HeaderMap } from '../headers.js'
import type { Provider, ProviderName } from './types.js'

export const providers: Record<ProviderName, Provider> = {
  stripe,
  github,
  slack,
  shopify,
  svix,
  clerk,
  resend,
  linear,
  paddle,
  meta,
  twilio,
}

const uniqueSniffOrder: ProviderName[] = [
  'stripe',
  'github',
  'slack',
  'shopify',
  'linear',
  'paddle',
  'twilio',
  'meta',
  'svix',
  'clerk',
  'resend',
]

export function sniffHits(headers: HeaderMap, allowed: Set<ProviderName>): ProviderName[] {
  const hits: ProviderName[] = []
  for (const name of uniqueSniffOrder) {
    if (!allowed.has(name)) continue
    if (providers[name].sniff(headers)) hits.push(name)
  }
  // Standard Webhooks branded vs unbranded
  if (allowed.has('svix') && standard.sniff(headers) && !hits.includes('svix')) {
    hits.push('svix')
  }
  return [...new Set(hits)]
}

export function sniffProvider(headers: HeaderMap, allowed: Set<ProviderName>): ProviderName | undefined {
  const unique = sniffHits(headers, allowed)
  if (unique.length === 1) return unique[0]
  // GitHub sends both hub signature headers. Meta sniff already skips x-github-event,
  // but a delivery id plus both signatures still looks like Meta too.
  if (unique.length === 2 && unique.includes('github') && unique.includes('meta')) return 'github'
  return undefined
}

/** Raw path, before URL resolution. `..` must not switch /webhooks/github into /webhooks/stripe. */
export function pathHasDotSegments(url: string): boolean {
  let path = url.trim()
  const host = path.match(/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\/[^/?#]*/)
  if (host) path = path.slice(host[0].length)
  const cut = path.search(/[?#]/)
  if (cut !== -1) path = path.slice(0, cut)
  for (const part of path.split('/')) {
    if (!part) continue
    let decoded = part
    for (let i = 0; i < 4; i++) {
      try {
        const next = decodeURIComponent(decoded.replace(/\+/g, '%20'))
        if (next === decoded) break
        decoded = next
      } catch {
        break
      }
    }
    if (decoded === '.' || decoded === '..') return true
  }
  return false
}

export function providerFromPath(url: string | undefined, allowed: Set<ProviderName>): ProviderName | undefined {
  if (!url) return undefined
  let path = url
  try {
    path = new URL(url, 'http://doorbell.local').pathname
  } catch {
    path = url
  }
  const parts = path.split('/').filter(Boolean)
  const last = parts[parts.length - 1]
  if (last && allowed.has(last as ProviderName)) return last as ProviderName
  return undefined
}

export type { Provider, ProviderName, VerifiedEvent, VerifyCtx } from './types.js'
