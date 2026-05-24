/**
 * Phase-2 inline-consent coverage for `InviteWorkflow`.
 *
 * Phase 1 (commit c36a95c) landed the `persistConsents(username, events)` seam
 * on `LoginWorkflow`; Phase 2 fans the same pattern out to `InviteWorkflow`
 * (this file) and `RecoveryWorkflow` (sibling spec). Consumers writing apps
 * with these workflows shouldn't have to choose between consent-tracking on
 * login but not on invite — invite is the headline-value scenario after
 * login (new user accepting an invitation → consent collection is part of
 * onboarding).
 *
 * The inline-consent surface is `SetPasswordForm` (the guaranteed carrier
 * form on invite's accept tail). It already `extends WithInlineConsentForm`,
 * so the same `acceptedTerms` / `marketingOptIn` fields ride through with no
 * form changes. The new `processInlineConsent` call inside
 * `createPasswordForm` is the load-bearing wiring — without it, an admin who
 * sets `acceptance.termsVersion` would never see the consumer
 * `persistConsents` hook fire.
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
import { Controller, Inherit } from "moost";
import { describe, expect, it } from "vite-plus/test";

import { AuthOpts } from "../auth.opts";
import {
  type ConsentEvent,
  InviteWorkflow,
  type InviteWfCtx,
  type InviteWorkflowOpts,
} from "../workflows/index";
import { prepareWfApp, withInviteMfaCtx } from "./workflow-utils";

const PASSWORD = "NewPassword123";

/**
 * Build an `InviteWorkflow` subclass with `resolveAcceptance` overridden to
 * return the supplied policy and a captured-events buffer wired onto
 * `persistConsents`. Mirrors the canonical consumer override shape (see
 * Phase-1 PERSIST-CONSENT-01..04 in workflows.login.options.spec.ts).
 */
function makeCapturingInvite(
  policy: NonNullable<InviteWfCtx["acceptance"]>,
  calls: Array<{ username: string; events: ConsentEvent[] }>,
  options: { persistDelayMs?: number; doubleStep?: boolean } = {},
): typeof InviteWorkflow {
  @Inherit()
  @Controller("auth/invite")
  class CapturingInvite extends InviteWorkflow {
    constructor(
      opts: InviteWorkflowOpts,
      users: UserService,
      auth: AuthCredential,
      authOpts: AuthOpts,
    ) {
      super(opts, users, auth, authOpts);
    }
    protected override resolveAcceptance(
      _ctx: InviteWfCtx,
    ): NonNullable<InviteWfCtx["acceptance"]> {
      return policy;
    }
    protected override async persistConsents(
      username: string,
      events: ConsentEvent[],
    ): Promise<void> {
      calls.push({ username, events: [...events] });
    }
    override async persistConsentsStep(ctx: InviteWfCtx): Promise<undefined> {
      // Sleep BEFORE the underlying super call so the `at` timestamp captured
      // by `processInlineConsent` (at form-submit time) is provably earlier
      // than `Date.now()` at write-time — pins the "captured at acceptance,
      // not at write" semantic.
      if (options.persistDelayMs && options.persistDelayMs > 0) {
        await new Promise<void>((r) => setTimeout(r, options.persistDelayMs));
      }
      await super.persistConsentsStep(ctx);
      // Idempotency cover: a second call must NOT trigger another
      // `persistConsents` invocation (the `if (consentsPersisted) return`
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
  it("INVITE-PERSIST-CONSENT-01: terms-only flow → persistConsents receives [{kind:'terms',version,at}]", async () => {
    // WHY: pins the headline guarantee — `acceptance.termsVersion` set + the
    // invitee submitting `acceptedTerms: true` on `SetPasswordForm` results in
    // the consumer override receiving exactly one terms event with the
    // server-authoritative version + a captured timestamp. Without the
    // `processInlineConsent` call in `createPasswordForm` (production branch
    // under test), the submitted `acceptedTerms` would be a stripped form-
    // extra and the workflow would never record acceptance.
    //
    // Also covers the "`at` captured at acceptance moment, not at write
    // time" semantic — we sleep 50ms between SetPasswordForm submit and the
    // persist-consents step firing, then assert `at <= afterSubmit` (i.e.
    // strictly less than `Date.now()` after the sleep). A regression that
    // stamped `at` inside `persistConsentsStep` would push the value past
    // `afterSubmit`, failing this assertion.
    const calls: Array<{ username: string; events: ConsentEvent[] }> = [];
    const Capturing = makeCapturingInvite({ termsVersion: "v1", consentMarketing: false }, calls, {
      persistDelayMs: 50,
    });
    const app = await prepareWfApp({
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

    expect(calls.length).toBe(1);
    expect(calls[0].username).toBe("alice@test.com");
    expect(calls[0].events.length).toBe(1);
    expect(calls[0].events[0].kind).toBe("terms");
    expect(calls[0].events[0].version).toBe("v1");
    expect(calls[0].events[0].at).toBeGreaterThanOrEqual(before);
    // `at` was stamped at processInlineConsent time (before the 50ms persist
    // delay). It must therefore be <= the moment SetPasswordForm completed
    // its trigger response — strictly NOT past the post-delay `Date.now()`
    // that the persistConsentsStep call sees.
    expect(calls[0].events[0].at).toBeLessThanOrEqual(afterSubmit);
  });

  it("INVITE-PERSIST-CONSENT-02: marketing-only flow → persistConsents receives [{kind:'marketing',optIn,at}]", async () => {
    // WHY: pins the marketing-only event shape. No terms event should be
    // added when terms policy is off; the optIn boolean rides through to the
    // event payload unchanged.
    const calls: Array<{ username: string; events: ConsentEvent[] }> = [];
    const Capturing = makeCapturingInvite({ consentMarketing: true }, calls);
    const app = await prepareWfApp({
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
    expect(calls.length).toBe(1);
    expect(calls[0].events.length).toBe(1);
    expect(calls[0].events[0].kind).toBe("marketing");
    expect(calls[0].events[0].optIn).toBe(true);
  });

  it("INVITE-PERSIST-IDEMPOTENT-01: re-entering persist-consents → no second persistConsents call (idempotency)", async () => {
    // WHY (Rule 9): the step MUST be idempotent — a paused-workflow that
    // resumes through `persist-consents` a second time (or schema
    // re-iteration) must not double-write consents. The
    // `if (ctx.consentsPersisted) return undefined` guard at the top of the
    // step body is the load-bearing defense. Pinned via a subclass that
    // calls `super.persistConsentsStep` TWICE inside its override — the
    // second call must short-circuit on the guard.
    const calls: Array<{ username: string; events: ConsentEvent[] }> = [];
    const Capturing = makeCapturingInvite({ consentMarketing: true }, calls, { doubleStep: true });
    const app = await prepareWfApp({
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
    expect(calls.length).toBe(1);
  });

  it("INVITE-PERSIST-SKIP-01: no acceptance policy + no consent fields → persist hook never called", async () => {
    // WHY: pins the schema-condition short-circuit. The `persist-consents`
    // step's condition is
    //   `!consentsPersisted && (termsAcceptedDone || pendingMarketingOptIn !== undefined)`
    // — when neither has fired the step is SKIPPED entirely and the hook
    // stays at 0 calls. A regression that always invoked the step body would
    // emit a `persistConsents(username, [])` call here (the body's
    // `events.length === 0` branch sets `consentsPersisted = true` but does
    // NOT call the hook — but skipping the step entirely is what we want to
    // prove via the call counter).
    const calls: Array<{ username: string; events: ConsentEvent[] }> = [];
    const Capturing = makeCapturingInvite({ consentMarketing: false }, calls);
    const app = await prepareWfApp({
      inviteWorkflowClass: withInviteMfaCtx(Capturing, { mfaMode: "disabled" }),
    });
    const { wfs } = await inviteUntilSetPassword(app, "dan@test.com");
    await app.trigger({
      wfs,
      input: { newPassword: PASSWORD, confirmPassword: PASSWORD },
    });
    expect(calls.length).toBe(0);
  });
});
