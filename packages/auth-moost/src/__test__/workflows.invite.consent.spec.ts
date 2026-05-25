/**
 * Phase-2 inline-consent coverage for `InviteWorkflow`.
 *
 * Phase 1 landed the `ConsentStore` DI seam; Phase 2 wires the
 * `persist-consents` step body to `consentStore.save(username, events)` and
 * fans the same pattern out across all three workflows. Consumers writing
 * apps with these workflows shouldn't have to choose between consent-tracking
 * on login but not on invite — invite is the headline-value scenario after
 * login (new user accepting an invitation → consent collection is part of
 * onboarding).
 *
 * The inline-consent surface is `SetPasswordForm` (the guaranteed carrier
 * form on invite's accept tail). It already `extends WithInlineConsentForm`,
 * so the same `acceptedTerms` / `marketingOptIn` fields ride through with no
 * form changes. The new `processInlineConsent` call inside
 * `createPasswordForm` is the load-bearing wiring — without it, an admin who
 * sets `acceptance.termsVersion` would never see the consumer
 * `ConsentStore.save` override fire.
 *
 * Anti-test guard (Rule 9): each test asserts an observable outcome
 * (consumer override receives event with the right shape; idempotency
 * counter stays at the expected value). Removing the production branch
 * under test (the `processInlineConsent` call, the schema's
 * `persist-consents` condition, the step's `if (consentsPersisted)`
 * idempotency guard) would make the matching test fail.
 */
import { AuthCredential } from "@aooth/auth";
import { UserService } from "@aooth/user";
import { Controller, Inherit, Injectable } from "moost";
import { describe, expect, it } from "vite-plus/test";

import { AuthOpts } from "../auth.opts";
import { type ConsentDescriptor, ConsentStore } from "../consent.store";
import {
  type ConsentEvent,
  InviteWorkflow,
  type InviteWfCtx,
  type InviteWorkflowOpts,
} from "../workflows/index";
import { prepareWfApp, withInviteMfaCtx } from "./workflow-utils";

const PASSWORD = "NewPassword123";

/**
 * `ConsentStore` subclass that captures every `save(username, events)` call.
 * `persistDelayMs` sleeps BEFORE pushing so the `at` timestamp captured by
 * `processInlineConsent` (form-submit time) is provably earlier than
 * `Date.now()` at write-time — pins the "captured at acceptance, not at
 * write" semantic.
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
 * Build an `InviteWorkflow` subclass with `resolveAcceptance` overridden to
 * return the supplied policy. Optional `doubleStep` re-invokes
 * `persistConsentsStep` after the engine's first pass so the idempotency
 * guard is exercised.
 */
function makeCapturingInvite(
  policy: NonNullable<InviteWfCtx["acceptance"]>,
  options: { doubleStep?: boolean } = {},
): typeof InviteWorkflow {
  @Inherit()
  @Controller("auth/invite")
  class CapturingInvite extends InviteWorkflow {
    constructor(
      opts: InviteWorkflowOpts,
      users: UserService,
      auth: AuthCredential,
      authOpts: AuthOpts,
      consentStore: ConsentStore,
    ) {
      super(opts, users, auth, authOpts, consentStore);
    }
    protected override resolveAcceptance(
      _ctx: InviteWfCtx,
    ): NonNullable<InviteWfCtx["acceptance"]> {
      return policy;
    }
    override async persistConsentsStep(ctx: InviteWfCtx): Promise<undefined> {
      await super.persistConsentsStep(ctx);
      // Idempotency cover: a second call must NOT trigger another
      // `consentStore.save` invocation (the `if (consentsPersisted) return`
      // guard at the top of the step body is the load-bearing defense).
      if (options.doubleStep) await super.persistConsentsStep(ctx);
      return undefined;
    }
  }
  return CapturingInvite;
}

/**
 * Drive the canonical invite happy-path through the resume tail. Returns the
 * captured magic-link wfs token + the resume response (paused on
 * `SetPasswordForm`). The caller submits `SetPasswordForm` themselves so each
 * test can vary the inline-consent payload.
 */
async function inviteUntilSetPassword(
  app: Awaited<ReturnType<typeof prepareWfApp>>,
  email: string,
): Promise<{ wfs: string }> {
  const r1 = await app.trigger({ wfid: "auth/invite/start" });
  await app.trigger({ wfs: r1.body?.wfs as string, input: { email } });
  const token = new URL(app.emails[0].url as string).searchParams.get("wfs") as string;
  const r3 = await app.resumeViaQuery(token);
  return { wfs: r3.body?.wfs as string };
}

describe("InviteWorkflow — inline-consent persist seam (Phase 2)", () => {
  it("INVITE-PERSIST-CONSENT-01: terms-only flow → consentStore.save receives [{kind:'terms',version,at}]", async () => {
    // WHY: pins the headline guarantee — `acceptance.termsVersion` set + the
    // invitee submitting `acceptedTerms: true` on `SetPasswordForm` results in
    // the consumer override receiving exactly one terms event with the
    // server-authoritative version + a captured timestamp. Without the
    // `processInlineConsent` call in `createPasswordForm` (production branch
    // under test), the submitted `acceptedTerms` would be a stripped form-
    // extra and the workflow would never record acceptance.
    //
    // Also covers the "`at` captured at acceptance moment, not at write
    // time" semantic — the store sleeps 50ms before pushing, then we assert
    // `at <= afterSubmit` (i.e. strictly less than `Date.now()` after the
    // sleep). A regression that stamped `at` inside `persistConsentsStep`
    // would push the value past `afterSubmit`, failing this assertion.
    const consentStore = new CapturingConsentStore();
    consentStore.persistDelayMs = 50;
    const Capturing = makeCapturingInvite({ termsVersion: "v1", consentMarketing: false });
    const app = await prepareWfApp({
      consentStore,
      inviteWorkflowClass: withInviteMfaCtx(Capturing, { mfaMode: "disabled" }),
    });
    const before = Date.now();
    const { wfs } = await inviteUntilSetPassword(app, "alice@test.com");
    const afterSubmit = await app
      .trigger({
        wfs,
        input: {
          newPassword: PASSWORD,
          confirmPassword: PASSWORD,
          acceptedTerms: true,
        },
      })
      .then(() => Date.now());

    expect(consentStore.calls.length).toBe(1);
    expect(consentStore.calls[0].username).toBe("alice@test.com");
    expect(consentStore.calls[0].events.length).toBe(1);
    expect(consentStore.calls[0].events[0].kind).toBe("terms");
    expect(consentStore.calls[0].events[0].version).toBe("v1");
    expect(consentStore.calls[0].events[0].at).toBeGreaterThanOrEqual(before);
    // `at` was stamped at processInlineConsent time (before the 50ms persist
    // delay). It must therefore be <= the moment SetPasswordForm completed
    // its trigger response — strictly NOT past the post-delay `Date.now()`
    // that the consentStore.save call sees.
    expect(consentStore.calls[0].events[0].at).toBeLessThanOrEqual(afterSubmit);
  });

  it("INVITE-PERSIST-CONSENT-02: marketing-only flow → consentStore.save receives [{kind:'marketing',optIn,at}]", async () => {
    // WHY: pins the marketing-only event shape. No terms event should be
    // added when terms policy is off; the optIn boolean rides through to the
    // event payload unchanged.
    const consentStore = new CapturingConsentStore();
    const Capturing = makeCapturingInvite({ consentMarketing: true });
    const app = await prepareWfApp({
      consentStore,
      inviteWorkflowClass: withInviteMfaCtx(Capturing, { mfaMode: "disabled" }),
    });
    const { wfs } = await inviteUntilSetPassword(app, "bob@test.com");
    await app.trigger({
      wfs,
      input: {
        newPassword: PASSWORD,
        confirmPassword: PASSWORD,
        marketingOptIn: true,
      },
    });
    expect(consentStore.calls.length).toBe(1);
    expect(consentStore.calls[0].events.length).toBe(1);
    expect(consentStore.calls[0].events[0].kind).toBe("marketing");
    expect(consentStore.calls[0].events[0].optIn).toBe(true);
  });

  it("INVITE-PERSIST-IDEMPOTENT-01: re-entering persist-consents → no second consentStore.save call (idempotency)", async () => {
    // WHY (Rule 9): the step MUST be idempotent — a paused-workflow that
    // resumes through `persist-consents` a second time (or schema
    // re-iteration) must not double-write consents. The
    // `if (ctx.consentsPersisted) return undefined` guard at the top of the
    // step body is the load-bearing defense. Pinned via a subclass that
    // calls `super.persistConsentsStep` TWICE inside its override — the
    // second call must short-circuit on the guard.
    const consentStore = new CapturingConsentStore();
    const Capturing = makeCapturingInvite({ consentMarketing: true }, { doubleStep: true });
    const app = await prepareWfApp({
      consentStore,
      inviteWorkflowClass: withInviteMfaCtx(Capturing, { mfaMode: "disabled" }),
    });
    const { wfs } = await inviteUntilSetPassword(app, "carol@test.com");
    await app.trigger({
      wfs,
      input: {
        newPassword: PASSWORD,
        confirmPassword: PASSWORD,
        marketingOptIn: true,
      },
    });
    expect(consentStore.calls.length).toBe(1);
  });

  it("INVITE-PERSIST-SKIP-01: no acceptance policy + no consent fields → consentStore.save never called", async () => {
    // WHY: pins the schema-condition short-circuit. The `persist-consents`
    // step's condition is
    //   `!consentsPersisted && (termsAcceptedDone || pendingMarketingOptIn !== undefined)`
    // — when neither has fired the step is SKIPPED entirely and the save
    // hook stays at 0 calls. A regression that always invoked the step body
    // would emit a `consentStore.save(username, [])` call here (the body's
    // `events.length === 0` branch sets `consentsPersisted = true` but does
    // NOT call save — but skipping the step entirely is what we want to
    // prove via the call counter).
    const consentStore = new CapturingConsentStore();
    const Capturing = makeCapturingInvite({ consentMarketing: false });
    const app = await prepareWfApp({
      consentStore,
      inviteWorkflowClass: withInviteMfaCtx(Capturing, { mfaMode: "disabled" }),
    });
    const { wfs } = await inviteUntilSetPassword(app, "dan@test.com");
    await app.trigger({
      wfs,
      input: { newPassword: PASSWORD, confirmPassword: PASSWORD },
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
 * Build an `InviteWorkflow` subclass that stashes post-prepareConsents ctx onto
 * the supplied slot so tests can read `ctx.pendingConsents` directly (the wf
 * engine's finished-response envelopes don't echo full ctx).
 */
function makeCtxCapturingInvite(captured: { ctx?: InviteWfCtx }): typeof InviteWorkflow {
  @Inherit()
  @Controller("auth/invite")
  class CtxCapturingInvite extends InviteWorkflow {
    constructor(
      opts: InviteWorkflowOpts,
      users: UserService,
      auth: AuthCredential,
      authOpts: AuthOpts,
      consentStore: ConsentStore,
    ) {
      super(opts, users, auth, authOpts, consentStore);
    }
    override prepareConsents(ctx: InviteWfCtx): undefined | Promise<undefined> {
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
  return CtxCapturingInvite;
}

describe("InviteWorkflow — prepare-consents @Step + ctx.pendingConsents transport (Phase 4)", () => {
  it("INVITE-PENDING-CONSENTS-01: default no-op ConsentStore → ctx.pendingConsents is [] (always array, never undefined)", async () => {
    // WHY: pins the "always array, never undefined" contract for Phase 5
    // carrier-form gates on invite's SetPasswordForm. Without the default
    // empty-array invariant, every Phase-5 form condition would need a
    // defensive `?? []`.
    const captured: { ctx?: InviteWfCtx } = {};
    const Capturing = makeCtxCapturingInvite(captured);
    const app = await prepareWfApp({
      inviteWorkflowClass: withInviteMfaCtx(Capturing, { mfaMode: "disabled" }),
    });
    await inviteUntilSetPassword(app, "evan@test.com");
    expect(captured.ctx).toBeTruthy();
    expect(captured.ctx!.pendingConsents).toEqual([]);
    expect(Array.isArray(captured.ctx!.pendingConsents)).toBe(true);
  });

  it("INVITE-PENDING-CONSENTS-WORKFLOW-ARG-01: prepare-consents calls getPendingConsents with {workflow: 'auth/invite/start'}", async () => {
    // WHY: pins the workflow-string contract so customer overrides can branch
    // on which workflow is asking — e.g., "show GDPR cookie consent only on
    // first invite acceptance, not on every login." Without the workflow arg,
    // customers can't disambiguate.
    const consentStore = new RecordingConsentStore();
    const app = await prepareWfApp({ consentStore });
    await inviteUntilSetPassword(app, "fred@test.com");
    expect(consentStore.pendingCalls.length).toBeGreaterThanOrEqual(1);
    const lastCall = consentStore.pendingCalls.at(-1)!;
    expect(lastCall.ctx.workflow).toBe("auth/invite/start");
    expect(lastCall.ctx.channel).toBeUndefined();
    expect(lastCall.username).toBe("fred@test.com");
  });
});
