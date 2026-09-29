import type { Clock } from '../clock.js'
import type { HeaderMap } from '../headers.js'

export type ProviderName =
  | 'stripe'
  | 'github'
  | 'slack'
  | 'shopify'
  | 'svix'
  | 'clerk'
  | 'resend'
  | 'linear'
  | 'paddle'
  | 'meta'
  | 'twilio'

export type VerifiedEvent = {
  provider: ProviderName
  id: string
  type: string
  payload: unknown
  raw: Uint8Array
  timestampSec: number | undefined
}

export type VerifyCtx = {
  raw: Uint8Array
  headers: HeaderMap
  secrets: Uint8Array[]
  secretStrings: string[]
  toleranceSec: number
  now: Clock
  url: string | undefined
}

export type Provider = {
  name: ProviderName
  sniff(headers: HeaderMap): boolean
  eventId(headers: HeaderMap, payload: unknown, raw: Uint8Array): string
  eventType(headers: HeaderMap, payload: unknown): string
  parse(raw: Uint8Array): unknown
  verify(ctx: VerifyCtx): Promise<{ timestampSec: number | undefined }>
}
