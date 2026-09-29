export type Clock = () => number

export function unixSeconds(now: Clock = Date.now): number {
  return Math.floor(now() / 1000)
}

export function assertFresh(
  timestampSec: number,
  opts: { toleranceSec: number; now: Clock; skewBothWays?: boolean },
): 'ok' | 'too_old' | 'too_new' | 'bad' {
  if (!Number.isFinite(timestampSec) || timestampSec <= 0) return 'bad'
  const nowSec = unixSeconds(opts.now)
  const age = nowSec - timestampSec
  if (age > opts.toleranceSec) return 'too_old'
  if ((opts.skewBothWays ?? true) && timestampSec > nowSec + opts.toleranceSec) return 'too_new'
  return 'ok'
}
