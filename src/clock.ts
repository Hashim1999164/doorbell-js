export type Clock = () => number

export function unixSeconds(now: Clock = Date.now): number {
  return Math.floor(now() / 1000)
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
