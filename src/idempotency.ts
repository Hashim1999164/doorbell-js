export type IdempotencyStore = {
  /**
   * Try to take this event. Return 'run' if the handler should run,
   * 'duplicate' if it already succeeded.
   * Concurrent deliveries of the same id wait on the first one.
   */
  claim(key: string, opts?: { pin?: boolean }): Promise<'run' | 'duplicate'>
  commit(key: string, ttlMs: number): Promise<void>
  drop(key: string): Promise<void>
  /**
   * Keep this inflight slot alive until commit or drop.
   * A timed out handler that is still writing must not lose the slot to gc.
   */
  pin?(key: string): Promise<void>
}

type Slot = {
  state: 'inflight' | 'done'
  waiters: Array<() => void>
  expiresAt: number
  pinned: boolean
}

export class MemoryStore implements IdempotencyStore {
  private readonly slots = new Map<string, Slot>()

  constructor(
    private readonly now: () => number = Date.now,
    private readonly inflightMs: number = 60_000,
  ) {}

  async claim(key: string, opts?: { pin?: boolean }): Promise<'run' | 'duplicate'> {
    this.gc()
    for (;;) {
      const existing = this.slots.get(key)
      if (existing?.state === 'done' && existing.expiresAt > this.now()) return 'duplicate'
      if (existing?.state === 'inflight') {
        if (!existing.pinned && existing.expiresAt <= this.now()) {
          this.slots.delete(key)
          for (const w of existing.waiters) w()
          continue
        }
        await new Promise<void>((resolve) => {
          existing.waiters.push(resolve)
        })
        continue
      }
      const hold = this.inflightMs > 0 ? this.inflightMs : 60_000
      this.slots.set(key, {
        state: 'inflight',
        waiters: [],
        expiresAt: this.now() + hold,
        pinned: Boolean(opts?.pin),
      })
      return 'run'
    }
  }

  async pin(key: string): Promise<void> {
    const slot = this.slots.get(key)
    if (slot?.state === 'inflight') slot.pinned = true
  }

  async commit(key: string, ttlMs: number): Promise<void> {
    const slot = this.slots.get(key)
    const waiters = slot?.waiters ?? []
    this.slots.set(key, { state: 'done', waiters: [], expiresAt: this.now() + ttlMs, pinned: false })
    for (const w of waiters) w()
  }

  async drop(key: string): Promise<void> {
    const slot = this.slots.get(key)
    this.slots.delete(key)
    for (const w of slot?.waiters ?? []) w()
  }

  private gc() {
    const now = this.now()
    for (const [key, slot] of this.slots) {
      if (slot.pinned) continue
      if (slot.expiresAt <= now) {
        for (const w of slot.waiters) w()
        this.slots.delete(key)
      }
    }
  }
}
