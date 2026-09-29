export type IdempotencyStore = {
  /**
   * Try to take this event. Return 'run' if the handler should run,
   * 'duplicate' if it already succeeded.
   * Concurrent deliveries of the same id wait on the first one.
   */
  claim(key: string): Promise<'run' | 'duplicate'>
  commit(key: string, ttlMs: number): Promise<void>
  drop(key: string): Promise<void>
}

type Slot = {
  state: 'inflight' | 'done'
  waiters: Array<() => void>
  expiresAt: number
}

export class MemoryStore implements IdempotencyStore {
  private readonly slots = new Map<string, Slot>()

  constructor(
    private readonly now: () => number = Date.now,
    private readonly inflightMs: number = 60_000,
  ) {}

  async claim(key: string): Promise<'run' | 'duplicate'> {
    this.gc()
    for (;;) {
      const existing = this.slots.get(key)
      if (existing?.state === 'done' && existing.expiresAt > this.now()) return 'duplicate'
      if (existing?.state === 'inflight') {
        if (existing.expiresAt <= this.now()) {
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
      this.slots.set(key, { state: 'inflight', waiters: [], expiresAt: this.now() + hold })
      return 'run'
    }
  }

  async commit(key: string, ttlMs: number): Promise<void> {
    const slot = this.slots.get(key)
    const waiters = slot?.waiters ?? []
    this.slots.set(key, { state: 'done', waiters: [], expiresAt: this.now() + ttlMs })
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
      if (slot.expiresAt <= now) {
        for (const w of slot.waiters) w()
        this.slots.delete(key)
      }
    }
  }
}
