import type { AuthEmailEvent, EmailSender } from "@aoothjs/auth"

interface CaptureWaiter {
  filter: (event: AuthEmailEvent) => boolean
  resolve: (event: AuthEmailEvent) => void
  timer: ReturnType<typeof setTimeout>
}

/**
 * Test-only EmailSender. Captures every event into an in-memory queue and
 * exposes async helpers (`next`) so test code can deterministically wait for
 * a workflow-triggered email without racing the outlet's `await`.
 */
export class CaptureEmailSender implements EmailSender {
  readonly events: AuthEmailEvent[] = []
  private readonly waiters: CaptureWaiter[] = []

  send(event: AuthEmailEvent): Promise<void> {
    this.events.push(event)
    for (let i = this.waiters.length - 1; i >= 0; i--) {
      const w = this.waiters[i]
      if (w.filter(event)) {
        clearTimeout(w.timer)
        this.waiters.splice(i, 1)
        w.resolve(event)
      }
    }
    return Promise.resolve()
  }

  drain(): AuthEmailEvent[] {
    return this.events.splice(0, this.events.length)
  }

  reset(): void {
    this.events.length = 0
    for (const w of this.waiters) clearTimeout(w.timer)
    this.waiters.length = 0
  }

  next(
    filter: (event: AuthEmailEvent) => boolean = () => true,
    timeoutMs = 1000,
  ): Promise<AuthEmailEvent> {
    const existing = this.events.find(filter)
    if (existing) return Promise.resolve(existing)
    return new Promise<AuthEmailEvent>((resolve, reject) => {
      const timer = setTimeout(() => {
        const idx = this.waiters.findIndex((w) => w.timer === timer)
        if (idx >= 0) this.waiters.splice(idx, 1)
        reject(
          new Error(
            `CaptureEmailSender.next() timed out after ${timeoutMs}ms; events captured so far: ${JSON.stringify(this.events)}`,
          ),
        )
      }, timeoutMs)
      this.waiters.push({ filter, resolve, timer })
    })
  }
}
