export type Clock = () => number

export function unixSeconds(now: Clock = Date.now): number {
  return Math.floor(now() / 1000)
}

/** Unix seconds as a digit string. Leading zeros and junk after the number do not count. */
export function parseUnixSec(value: string): number | undefined {
  const trimmed = value.trim()
  if (!/^[0-9]{1,12}$/.test(trimmed)) return undefined
  const n = Number.parseInt(trimmed, 10)
  if (!Number.isFinite(n) || String(n) !== trimmed) return undefined
  return n
}

/**
 * Stripe-node only rejects events older than the window.
 * Slack and Standard Webhooks reject both too old and too new.
 */
export function assertFresh(
  timestampSec: number,
  opts: { toleranceSec: number; now: Clock; future: 'allow' | 'reject' },
): 'ok' | 'too_old' | 'too_new' | 'bad' {
  if (!Number.isFinite(timestampSec) || timestampSec <= 0) return 'bad'
  const nowSec = unixSeconds(opts.now)
  const age = nowSec - timestampSec
  if (age > opts.toleranceSec) return 'too_old'
  if (opts.future === 'reject' && timestampSec > nowSec + opts.toleranceSec) return 'too_new'
  return 'ok'
}
