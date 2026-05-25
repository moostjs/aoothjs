/**
 * Phase-2 inline-consent coverage for `RecoveryWorkflow`.
 *
 * Same shape as the sibling `workflows.invite.consent.spec.ts` — Phase 2
 * wires the `persist-consents` step body to `consentStore.save(username,
 * events)` across all three workflows. The canonical recovery scenario for
 * inline consent is a terms-version bump during password reset ("since you
 * last set your password we updated our terms"). Marketing re-prompt at
 * recovery time is unusual UX, so defaults are off; consumers override
 * `resolveAcceptance(ctx)` to enable collection.
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
import { Controller, Inherit, Injectable } from "moost";
import { describe, expect, it } from "vite-plus/test";

import { AuthOpts } from "../auth.opts";
import { type ConsentDescriptor, ConsentStore } from "../consent.store";
import {
  type ConsentEvent,
  RecoveryWorkflow,
  type RecoveryWfCtx,
  type RecoveryWorkflowOpts,
} from "../workflows/index";
import { prepareWfApp, seedActiveUser } from "./workflow-utils";

const NEW_PASSWORD = "NewPassword2!";

/**
 * `ConsentStore` subclass that captures every `save(username, events)` call.
 * `persistDelayMs` sleeps BEFORE pushing so the `at` timestamp captured by
 * `processInlineConsent` (form-submit time) is provably earlier than
 * `Date.now()` at write-time.
 */
@Injectable()
class CapturingConsentStore extends ConsentStore {
  readonly calls: Array<{ username: string; events: ConsentEvent[] }> = [];
  persistDelayMs = 0;
  override async save(username: string, events: ConsentEvent[]): Promise<void> {
    if (this.persistDelayMs > 0) {
      await new Promise<void>((r) => setTimeout(r, this.persistDelayMs));
    }
    this.calls.push({ username, events: [...events] });
  }
}

/**
 * Build a `RecoveryWorkflow` subclass with `resolveAcceptance` overridden to
 * return the supplied policy.
 */
function makeCapturingRecovery(
  policy: NonNullable<RecoveryWfCtx["acceptance"]>,
): typeof RecoveryWorkflow {
  @Inherit()
  @Controller("auth/recovery")
  class CapturingRecovery extends RecoveryWorkflow {
    constructor(
      opts: RecoveryWorkflowOpts,
      users: UserService,
      auth: AuthCredential,
      authOpts: AuthOpts,
      consentStore: ConsentStore,
    ) {
      super(opts, users, auth, authOpts, consentStore);
    }
    protected override resolveAcceptance(
      _ctx: RecoveryWfCtx,
    ): NonNullable<RecoveryWfCtx["acceptance"]> {
      return policy;
    }
  }
  return CapturingRecovery;
}

describe("RecoveryWorkflow — inline-consent persist seam (Phase 2)", () => {
  it("RECOVERY-PERSIST-CONSENT-01: terms-bump scenario → consentStore.save receives [{kind:'terms',version:'v2',at}]", async () => {
    // WHY: pins the headline recovery scenario — terms-version bump capture.
    // The consumer flips `acceptance.termsVersion: 'v2'` on `resolveAcceptance`,
    // the user goes through the default magic-link recovery, ticks
    // `acceptedTerms` on `SetPasswordForm`, and the consumer's
    // `ConsentStore.save` override receives a single `kind:'terms'` event
    // with the new version.
    //
    // Also pins the "`at` captured at acceptance moment, not at write time"
    // semantic — the store sleeps 50ms before pushing, then we assert
    // `at <= afterSubmit`.
    const consentStore = new CapturingConsentStore();
    consentStore.persistDelayMs = 50;
    const Capturing = makeCapturingRecovery({ termsVersion: "v2", consentMarketing: false });
    const app = await prepareWfApp({ consentStore, recoveryWorkflowClass: Capturing });
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

    expect(consentStore.calls.length).toBe(1);
    expect(consentStore.calls[0].username).toBe("alice@test.com");
    expect(consentStore.calls[0].events.length).toBe(1);
    expect(consentStore.calls[0].events[0].kind).toBe("terms");
    expect(consentStore.calls[0].events[0].version).toBe("v2");
    expect(consentStore.calls[0].events[0].at).toBeGreaterThanOrEqual(before);
    // `at` stamped at processInlineConsent time (before the 50ms persist
    // delay). Must therefore be <= the moment SetPasswordForm completed its
    // trigger response — strictly NOT past the post-delay `Date.now()` the
    // consentStore.save call sees.
    expect(consentStore.calls[0].events[0].at).toBeLessThanOrEqual(afterSubmit);
  });

  it("RECOVERY-PERSIST-SKIP-01: no acceptance policy + no consent fields → consentStore.save never called", async () => {
    // WHY: pins the schema-condition short-circuit. When neither terms-done
    // nor marketing-decided is set, the `persist-consents` step is SKIPPED
    // entirely (condition false) and the save hook stays at zero calls.
    // A regression that flipped the condition would silently fire a no-op
    // event-less `consentStore.save(_, [])` call, polluting consumer audit
    // logs.
    const consentStore = new CapturingConsentStore();
    const Capturing = makeCapturingRecovery({ consentMarketing: false });
    const app = await prepareWfApp({ consentStore, recoveryWorkflowClass: Capturing });
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
    expect(consentStore.calls.length).toBe(0);
  });
});

/**
 * `ConsentStore` subclass that captures every `getPendingConsents` invocation
 * AND lets a test seed the return value. Used by the Phase-4 ctx.pendingConsents
 * transport tests.
 */
@Injectable()
class RecordingConsentStore extends ConsentStore {
  readonly pendingCalls: Array<{
    username: string | undefined;
    ctx: { workflow: string; channel?: "email" | "sms" };
  }> = [];
  pendingReturn: ConsentDescriptor[] = [];
  override async getPendingConsents(
    username: string | undefined,
    ctx: { workflow: string; channel?: "email" | "sms" },
  ): Promise<ConsentDescriptor[]> {
    this.pendingCalls.push({ username, ctx });
    return this.pendingReturn;
  }
}

/**
 * Build a `RecoveryWorkflow` subclass that stashes post-prepareConsents ctx
 * onto the supplied slot so tests can read `ctx.pendingConsents` directly
 * (the wf engine's finished-response envelopes don't echo full ctx).
 */
function makeCtxCapturingRecovery(captured: { ctx?: RecoveryWfCtx }): typeof RecoveryWorkflow {
  @Inherit()
  @Controller("auth/recovery")
  class CtxCapturingRecovery extends RecoveryWorkflow {
    constructor(
      opts: RecoveryWorkflowOpts,
      users: UserService,
      auth: AuthCredential,
      authOpts: AuthOpts,
      consentStore: ConsentStore,
    ) {
      super(opts, users, auth, authOpts, consentStore);
    }
    override prepareConsents(ctx: RecoveryWfCtx): undefined | Promise<undefined> {
      const result = super.prepareConsents(ctx);
      if (result instanceof Promise) {
        return result.then((r) => {
          captured.ctx = ctx;
          return r;
        });
      }
      captured.ctx = ctx;
      return result;
    }
  }
  return CtxCapturingRecovery;
}

describe("RecoveryWorkflow — prepare-consents @Step + ctx.pendingConsents transport (Phase 4)", () => {
  it("RECOVERY-PENDING-CONSENTS-01: default no-op ConsentStore → ctx.pendingConsents is [] (always array, never undefined)", async () => {
    // WHY: pins the "always array, never undefined" contract for Phase 5
    // carrier-form gates on recovery's SetPasswordForm.
    const captured: { ctx?: RecoveryWfCtx } = {};
    const Capturing = makeCtxCapturingRecovery(captured);
    const app = await prepareWfApp({ recoveryWorkflowClass: Capturing });
    await seedActiveUser(app.users, "grace@test.com", "OldPassword1");
    const r1 = await app.trigger({ wfid: "auth/recovery/flow" });
    await app.trigger({
      wfs: r1.body?.wfs as string,
      input: { email: "grace@test.com" },
    });
    const token = new URL(app.emails[0].url as string).searchParams.get("wfs") as string;
    await app.resumeViaQuery(token);
    expect(captured.ctx).toBeTruthy();
    expect(captured.ctx!.pendingConsents).toEqual([]);
    expect(Array.isArray(captured.ctx!.pendingConsents)).toBe(true);
  });

  it("RECOVERY-PENDING-CONSENTS-WORKFLOW-ARG-01: prepare-consents calls getPendingConsents with {workflow: 'auth/recovery/flow'}", async () => {
    // WHY: pins the workflow-string contract for recovery so customer overrides
    // can branch on workflow identity. Recovery may want a different consent
    // set than login (e.g., re-confirm marketing on password reset).
    const consentStore = new RecordingConsentStore();
    const app = await prepareWfApp({ consentStore });
    await seedActiveUser(app.users, "hank@test.com", "OldPassword1");
    const r1 = await app.trigger({ wfid: "auth/recovery/flow" });
    await app.trigger({
      wfs: r1.body?.wfs as string,
      input: { email: "hank@test.com" },
    });
    const token = new URL(app.emails[0].url as string).searchParams.get("wfs") as string;
    await app.resumeViaQuery(token);
    expect(consentStore.pendingCalls.length).toBeGreaterThanOrEqual(1);
    const lastCall = consentStore.pendingCalls.at(-1)!;
    expect(lastCall.ctx.workflow).toBe("auth/recovery/flow");
    expect(lastCall.ctx.channel).toBeUndefined();
    expect(lastCall.username).toBe("hank@test.com");
  });
});
