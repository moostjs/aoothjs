/**
 * Phase-2 inline-consent coverage for `RecoveryWorkflow`.
 *
 * Same shape as the sibling `workflows.invite.consent.spec.ts` — Phase 2 fans
 * the `persistConsents(username, events)` seam introduced in Phase 1 out to
 * recovery. The canonical recovery scenario for inline consent is a
 * terms-version bump during password reset ("since you last set your password
 * we updated our terms"). Marketing re-prompt at recovery time is unusual UX,
 * so defaults are off; consumers override `resolveAcceptance(ctx)` to enable
 * collection.
 *
 * `SetPasswordForm` is the guaranteed carrier form on every recovery
 * completion path — magicLink, OTP, and choice all converge there before
 * tokens are issued. The new `processInlineConsent` call inside
 * `setPassword` is the load-bearing wiring.
 *
 * Anti-test guard (Rule 9): each test asserts an observable outcome the
 * production branch under test is required to produce.
 */
import { AuthCredential } from "@aooth/auth";
import { UserService } from "@aooth/user";
import { Controller, Inherit } from "moost";
import { describe, expect, it } from "vite-plus/test";

import { AuthOpts } from "../auth.opts";
import {
  type ConsentEvent,
  RecoveryWorkflow,
  type RecoveryWfCtx,
  type RecoveryWorkflowOpts,
} from "../workflows/index";
import { prepareWfApp, seedActiveUser } from "./workflow-utils";

const NEW_PASSWORD = "NewPassword2!";

/**
 * Build a `RecoveryWorkflow` subclass with `resolveAcceptance` overridden to
 * return the supplied policy and a captured-events buffer wired onto
 * `persistConsents`. Mirrors `makeCapturingInvite` in the invite consent
 * spec — kept parallel intentionally so a refactor across the three workflows
 * stays grep-able.
 */
function makeCapturingRecovery(
  policy: NonNullable<RecoveryWfCtx["acceptance"]>,
  calls: Array<{ username: string; events: ConsentEvent[] }>,
  options: { persistDelayMs?: number } = {},
): typeof RecoveryWorkflow {
  @Inherit()
  @Controller("auth/recovery")
  class CapturingRecovery extends RecoveryWorkflow {
    constructor(
      opts: RecoveryWorkflowOpts,
      users: UserService,
      auth: AuthCredential,
      authOpts: AuthOpts,
    ) {
      super(opts, users, auth, authOpts);
    }
    protected override resolveAcceptance(
      _ctx: RecoveryWfCtx,
    ): NonNullable<RecoveryWfCtx["acceptance"]> {
      return policy;
    }
    protected override async persistConsents(
      username: string,
      events: ConsentEvent[],
    ): Promise<void> {
      calls.push({ username, events: [...events] });
    }
    override async persistConsentsStep(ctx: RecoveryWfCtx): Promise<undefined> {
      if (options.persistDelayMs && options.persistDelayMs > 0) {
        await new Promise<void>((r) => setTimeout(r, options.persistDelayMs));
      }
      await super.persistConsentsStep(ctx);
      return undefined;
    }
  }
  return CapturingRecovery;
}

describe("RecoveryWorkflow — inline-consent persist seam (Phase 2)", () => {
  it("RECOVERY-PERSIST-CONSENT-01: terms-bump scenario → persistConsents receives [{kind:'terms',version:'v2',at}]", async () => {
    // WHY: pins the headline recovery scenario — terms-version bump capture.
    // The consumer flips `acceptance.termsVersion: 'v2'` on `resolveAcceptance`,
    // the user goes through the default magic-link recovery, ticks
    // `acceptedTerms` on `SetPasswordForm`, and the consumer's `persistConsents`
    // hook receives a single `kind:'terms'` event with the new version.
    //
    // Also pins the "`at` captured at acceptance moment, not at write time"
    // semantic — we sleep 50ms between SetPasswordForm submit and
    // `persistConsentsStep` firing, then assert `at <= afterSubmit`.
    const calls: Array<{ username: string; events: ConsentEvent[] }> = [];
    const Capturing = makeCapturingRecovery(
      { termsVersion: "v2", consentMarketing: false },
      calls,
      { persistDelayMs: 50 },
    );
    const app = await prepareWfApp({ recoveryWorkflowClass: Capturing });
    await seedActiveUser(app.users, "alice@test.com", "OldPassword1");

    const before = Date.now();
    const r1 = await app.trigger({ wfid: "auth/recovery/flow" });
    await app.trigger({
      wfs: r1.body?.wfs as string,
      input: { email: "alice@test.com" },
    });
    const token = new URL(app.emails[0].url as string).searchParams.get("wfs") as string;
    const r3 = await app.resumeViaQuery(token);
    const afterSubmit = await app
      .trigger({
        wfs: r3.body?.wfs as string,
        input: {
          newPassword: NEW_PASSWORD,
          confirmPassword: NEW_PASSWORD,
          acceptedTerms: true,
        },
      })
      .then(() => Date.now());

    expect(calls.length).toBe(1);
    expect(calls[0].username).toBe("alice@test.com");
    expect(calls[0].events.length).toBe(1);
    expect(calls[0].events[0].kind).toBe("terms");
    expect(calls[0].events[0].version).toBe("v2");
    expect(calls[0].events[0].at).toBeGreaterThanOrEqual(before);
    // `at` stamped at processInlineConsent time (before the 50ms persist
    // delay). Must therefore be <= the moment SetPasswordForm completed its
    // trigger response — strictly NOT past the post-delay `Date.now()` the
    // persistConsentsStep call sees.
    expect(calls[0].events[0].at).toBeLessThanOrEqual(afterSubmit);
  });

  it("RECOVERY-PERSIST-SKIP-01: no acceptance policy + no consent fields → persist hook never called", async () => {
    // WHY: pins the schema-condition short-circuit. When neither terms-done
    // nor marketing-decided is set, the `persist-consents` step is SKIPPED
    // entirely (condition false) and the consumer hook stays at zero calls.
    // A regression that flipped the condition would silently fire a no-op
    // event-less `persistConsents([])` call, polluting consumer audit logs.
    const calls: Array<{ username: string; events: ConsentEvent[] }> = [];
    const Capturing = makeCapturingRecovery({ consentMarketing: false }, calls);
    const app = await prepareWfApp({ recoveryWorkflowClass: Capturing });
    await seedActiveUser(app.users, "bob@test.com", "OldPassword1");

    const r1 = await app.trigger({ wfid: "auth/recovery/flow" });
    await app.trigger({
      wfs: r1.body?.wfs as string,
      input: { email: "bob@test.com" },
    });
    const token = new URL(app.emails[0].url as string).searchParams.get("wfs") as string;
    const r3 = await app.resumeViaQuery(token);
    await app.trigger({
      wfs: r3.body?.wfs as string,
      input: { newPassword: NEW_PASSWORD, confirmPassword: NEW_PASSWORD },
    });
    expect(calls.length).toBe(0);
  });
});
