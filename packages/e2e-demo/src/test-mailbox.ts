import type { AuthEmailEvent, AuthSmsEvent } from "@aooth/auth";
import { type AuditEvent, AuthGuarded, Public, UserId } from "@aooth/auth-moost";
import type { UserService } from "@aooth/user";
import { Delete, Get, Post } from "@moostjs/event-http";
import { Controller, Param } from "moost";

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
  /**
   * Look-up handle for `GET /__test/totp-secret/:username`. Playwright specs
   * need the TOTP secret to compute a current code for users like `t1_grace`
   * / `t1_multi_mfa` — secrets are randomized each seed cycle so they can't
   * be hard-coded in test code.
   */
  userService: UserService;
  /**
   * Plaintext backup-code buffer keyed by username — backup codes are
   * randomized per seed and only known at generation time (the stored form is
   * hashed), so the seed pushes the plaintext into this map and the
   * `/__test/backup-codes/:username` endpoint reads it.
   */
  backupCodes: Map<string, string[]>;
  /**
   * Captured `RecoveryWorkflow.audit(event)` payloads. The demo's recovery
   * subclass pushes here; `/__test/audit` returns the array; `__test/reset`
   * clears it via `length = 0`.
   */
  auditEvents: AuditEvent[];
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
  const { emails, sms, reseed, userService, backupCodes, auditEvents } = deps;

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
      auditEvents.length = 0;
      const seeded = await reseed();
      return { ok: true, seeded };
    }

    /**
     * Returns the live captured-audit buffer (populated by
     * `DemoRecoveryWorkflow.audit()`). Cleared on `POST /__test/reset` and on
     * boot-time `reseed()`.
     */
    @Get("audit")
    listAudit(): AuditEvent[] {
      return auditEvents;
    }

    /**
     * Auth-guarded probe so Playwright specs can prove that a previously
     * issued access token has been invalidated by a password reset
     * (WF-RECOVERY old-token rejection). Returns the resolved `userId` from
     * the guard — `useAuth()` throws HTTP 401 when the token is missing /
     * expired / revoked. Uses method-level `@AuthGuarded()` to override the
     * class-level `@Public()`.
     */
    @AuthGuarded()
    @Get("whoami")
    whoami(@UserId() userId: string): { userId: string } {
      return { userId };
    }

    /**
     * Surfaces the TOTP secret seeded for `:username`. Used by Playwright
     * specs that exercise the TOTP branch — seed-time secrets rotate per
     * boot so specs can't hard-code. Returns 404 if user lacks a confirmed
     * TOTP method.
     */
    @Get("totp-secret/:username")
    async totpSecret(@Param("username") username: string): Promise<{ secret: string }> {
      const user = await userService.getUser(username);
      const method = user.mfa.methods.find((m) => m.name === "totp" && m.confirmed);
      if (!method) throw new Error(`No confirmed TOTP method for ${username}`);
      return { secret: method.value };
    }

    /**
     * Returns the plaintext backup codes generated for `:username` at seed
     * time. Stored codes are hashed (one-way), so the seed pushes the
     * plaintext list into a globalThis-anchored map; this endpoint reads it.
     */
    @Get("backup-codes/:username")
    backupCodesFor(@Param("username") username: string): { codes: string[] } {
      return { codes: backupCodes.get(username) ?? [] };
    }
  }

  return TestMailboxController;
}
