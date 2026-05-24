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

    /**
     * Read a user record (mfa.methods + account flags) for Playwright specs
     * that need to assert post-flow store state — e.g. the MFA-enrolment
     * coverage tests pin "skip leaves no unconfirmed method" and
     * "useDifferentMethod cleanup removes the row". Read-only; auth-bypassed
     * since the whole controller is `@Public()` in test mode only.
     */
    @Get("user/:username")
    async readUser(@Param("username") username: string): Promise<{
      username: string;
      mfa: {
        methods: Array<{ name: string; confirmed: boolean; value: string }>;
        defaultMethod: string;
      };
      account: { active: boolean; locked: boolean; pendingInvitation?: boolean };
    }> {
      const user = await userService.getUser(username);
      return {
        username: user.username,
        mfa: {
          methods: user.mfa.methods.map((m) => ({
            name: m.name,
            confirmed: m.confirmed,
            value: m.value,
          })),
          defaultMethod: user.mfa.defaultMethod,
        },
        account: {
          active: user.account.active,
          locked: user.account.locked,
          ...(user.account.pendingInvitation !== undefined && {
            pendingInvitation: user.account.pendingInvitation,
          }),
        },
      };
    }

    /**
     * Clear every MFA method on `:username` so an existing seeded user can
     * stand in as a freshly-unenrolled account for the MFA-enrolment
     * Playwright coverage. Avoids polluting `seed.ts` with a one-off
     * `t1_enroll_target` seed user — re-runs reset each test via the existing
     * `__test/reset` hook and selectively zap MFA in the test body. Returns
     * the post-clear method count (always 0 on success) so the caller can
     * assert.
     */
    @Post("reset-mfa/:username")
    async resetMfa(@Param("username") username: string): Promise<{ ok: true; methods: number }> {
      const user = await userService.getUser(username);
      // Iterate names rather than calling a bulk-clear (no such helper today).
      // Snapshot first because `removeMfaMethod` re-reads + filters per call.
      const names = user.mfa.methods.map((m) => m.name);
      for (const name of names) {
        await userService.removeMfaMethod(username, name);
      }
      const after = await userService.getUser(username);
      return { ok: true, methods: after.mfa.methods.length };
    }

    /**
     * Flip the globalThis flag that drives
     * `DemoInviteWorkflow.duplicateCheck()` into the `'allow'` branch for
     * WF-INVITE-018. Reset to `false` by `__test/reset` (via `reseed()`).
     */
    @Post("allow-duplicate-invites")
    allowDuplicateInvites(): { ok: true } {
      /* eslint-disable no-underscore-dangle -- intentional `__`-prefix marks internal globalThis slot */
      (
        globalThis as { __aoothE2eAllowDuplicateInvites?: boolean }
      ).__aoothE2eAllowDuplicateInvites = true;
      /* eslint-enable no-underscore-dangle */
      return { ok: true };
    }
  }

  return TestMailboxController;
}
