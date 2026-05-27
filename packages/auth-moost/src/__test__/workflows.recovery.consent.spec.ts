/**
 * Phase-5 inline-consent coverage for `RecoveryWorkflow`.
 *
 * Same shape as the sibling `workflows.invite.consent.spec.ts` — Phase 5
 * replaces the static `acceptedTerms`/`marketingOptIn` carrier-form pair
 * with a single dynamic `consents: string[]` field. The canonical recovery
 * scenario for inline consent is a customer-defined consent set (terms
 * version bump, jurisdiction prompt, ...) captured at password reset time.
 *
 * `SetPasswordForm` is the guaranteed carrier form on every recovery
 * completion path — magicLink, OTP, and choice all converge there before
 * tokens are issued. The new `processInlineConsent` call inside
 * `setPassword` validates `consents` against the server-owned
 * `ctx.consents?.pending` whitelist.
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
 * `ConsentStore` subclass that captures every `save(username, events)` call
 * AND lets a test seed pending descriptors via `pendingResponse`.
 * `persistDelayMs` sleeps BEFORE pushing so the `at` timestamp captured by
 * `processInlineConsent` (form-submit time) is provably earlier than
 * `Date.now()` at write-time.
 */
@Injectable()
class CapturingConsentStore extends ConsentStore {
  readonly calls: Array<{ username: string; events: ConsentEvent[] }> = [];
  persistDelayMs = 0;
  pendingResponse: ConsentDescriptor[] = [];
  override async save(username: string, events: ConsentEvent[]): Promise<void> {
    if (this.persistDelayMs > 0) {
      await new Promise<void>((r) => setTimeout(r, this.persistDelayMs));
    }
    this.calls.push({ username, events: [...events] });
  }
  override async getPendingConsents(
    _username: string | undefined,
    _ctx: { workflow: string; channel?: "email" | "sms" },
  ): Promise<ConsentDescriptor[]> {
    return this.pendingResponse;
  }
}

describe("RecoveryWorkflow — inline-consent persist seam (Phase 5)", () => {
  it("RECOVERY-PERSIST-CONSENT-01: terms-bump scenario → consentStore.save receives [{id:'terms',accepted:true,version:'v2',at}]", async () => {
    // WHY: pins the headline recovery scenario — terms-version bump capture
    // via the dynamic-consent shape. The customer seeds
    // `getPendingConsents` to return a required terms descriptor with the
    // new version, the user goes through the default magic-link recovery,
    // submits `consents: ['terms']` on `SetPasswordForm`, and the consumer's
    // `ConsentStore.save` override receives a single event with the
    // server-authoritative version stamped from the descriptor.
    //
    // Also pins the "`at` captured at acceptance moment, not at write time"
    // semantic — the store sleeps 50ms before pushing, then we assert
    // `at <= afterSubmit`.
    const consentStore = new CapturingConsentStore();
    consentStore.persistDelayMs = 50;
    consentStore.pendingResponse = [
      { id: "terms", text: "Accept Terms", required: "must accept", version: "v2" },
    ];
    const app = await prepareWfApp({ consentStore });
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
          consents: ["terms"],
        },
      })
      .then(() => Date.now());

    expect(consentStore.calls.length).toBe(1);
    expect(consentStore.calls[0].username).toBe("alice@test.com");
    expect(consentStore.calls[0].events.length).toBe(1);
    expect(consentStore.calls[0].events[0].id).toBe("terms");
    expect(consentStore.calls[0].events[0].accepted).toBe(true);
    expect(consentStore.calls[0].events[0].version).toBe("v2");
    expect(consentStore.calls[0].events[0].at).toBeGreaterThanOrEqual(before);
    // `at` stamped at processInlineConsent time (before the 50ms persist
    // delay). Must therefore be <= the moment SetPasswordForm completed its
    // trigger response — strictly NOT past the post-delay `Date.now()` the
    // consentStore.save call sees.
    expect(consentStore.calls[0].events[0].at).toBeLessThanOrEqual(afterSubmit);
  });

  it("RECOVERY-PERSIST-SKIP-01: empty pendingConsents → consentStore.save NEVER called", async () => {
    // WHY: pins the "no pending consents, no audit row" invariant.
    // When `getPendingConsents` returns `[]`, the schema's
    // `consentsDecidedAt` gate stays false and the persist step is
    // SKIPPED entirely. A regression that flipped the condition would
    // silently fire a no-op event-less `consentStore.save(_, [])` call,
    // polluting consumer audit logs.
    const consentStore = new CapturingConsentStore();
    consentStore.pendingResponse = [];
    const app = await prepareWfApp({ consentStore });
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
 * AND lets a test seed the return value. Used by the Phase-4 ctx.consents?.pending
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
 * onto the supplied slot so tests can read `ctx.consents?.pending` directly
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

describe("RecoveryWorkflow — prepare-consents @Step + ctx.consents.pending transport (Phase 4)", () => {
  it("RECOVERY-PENDING-CONSENTS-01: default no-op ConsentStore → ctx.consents.pending is [] (always array, never undefined)", async () => {
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
    expect(captured.ctx!.consents?.pending).toEqual([]);
    expect(Array.isArray(captured.ctx!.consents?.pending)).toBe(true);
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
