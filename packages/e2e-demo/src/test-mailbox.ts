import type { AuthEmailEvent, AuthSmsEvent } from "@aooth/auth";
import { Public } from "@aooth/auth-moost";
import { Delete, Get, Post } from "@moostjs/event-http";
import { Controller } from "moost";

export interface TestMailboxDeps {
  /** Live reference to the captured-email buffer (mutated in place). */
  emails: AuthEmailEvent[];
  /** Live reference to the captured-SMS buffer (mutated in place). */
  sms: AuthSmsEvent[];
  /**
   * Truncates every app DB table and re-runs the demo seed. Returns the
   * number of seeded users so Playwright specs can assert the reset
   * actually re-populated fixtures (vs. silently failing).
   */
  reseed: () => Promise<number>;
}

/**
 * Factory returns a `@Controller('__test')` class that exposes the captured
 * mailboxes + a reset endpoint to Playwright specs. Mounted ONLY when
 * `process.env.DEMO_MODE === 'test'`. Closure-over-controller pattern mirrors
 * `makeHandoverWorkflow` in `src/workflows/handover.workflow.ts` and the
 * `make<Resource>Controller` factories in `src/controllers/` — the live
 * mailbox refs and the reseed closure are captured by ctor-less methods.
 */
export function createTestMailboxController(
  deps: TestMailboxDeps,
): new (...args: never[]) => unknown {
  const { emails, sms, reseed } = deps;

  // `@Public()` bypasses the global auth guard — these endpoints are the
  // entry point used BY tests, before any login has happened.
  @Controller("__test")
  @Public()
  class TestMailboxController {
    @Get("emails")
    listEmails(): AuthEmailEvent[] {
      return emails;
    }

    @Get("sms")
    listSms(): AuthSmsEvent[] {
      return sms;
    }

    @Delete("mailbox")
    clearMailbox(): { ok: true } {
      emails.length = 0;
      sms.length = 0;
      return { ok: true };
    }

    @Post("reset")
    async reset(): Promise<{ ok: true; seeded: number }> {
      emails.length = 0;
      sms.length = 0;
      const seeded = await reseed();
      return { ok: true, seeded };
    }
  }

  return TestMailboxController;
}
