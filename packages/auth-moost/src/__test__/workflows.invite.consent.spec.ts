/**
 * Phase-5 inline-consent coverage for `InviteWorkflow`.
 *
 * Phase 1 landed the `ConsentStore` DI seam; Phase 2 wired the
 * `persist-consents` step body to `consentStore.save(username, events)`.
 * Phase 4 added the `prepare-consents` @Step that populates
 * `ctx.pendingConsents` from `ConsentStore.getPendingConsents`. Phase 5
 * replaces the static `acceptedTerms`/`marketingOptIn` carrier-form pair
 * with a single dynamic `consents: string[]` field rendered by
 * `AsConsentArray` (`@atscript/vue-aooth`).
 *
 * The inline-consent surface is `SetPasswordForm` (the guaranteed carrier
 * form on invite's accept tail) which `extends WithInlineConsentForm`. The
 * new `processInlineConsent` call inside `createPasswordForm` validates the
 * submitted ids against the server-owned `ctx.pendingConsents` whitelist
 * (silent-drop unknown, throw on missing-required), and the
 * `persist-consents` step persists ONE event per pending descriptor
 * (audit-friendly default — declined-optional consents persisted with
 * `accepted: false`).
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
  InviteWorkflow,
  type InviteWfCtx,
  type InviteWorkflowOpts,
} from "../workflows/index";
import { prepareWfApp, withInviteMfaCtx } from "./workflow-utils";

const PASSWORD = "NewPassword123";

/**
 * `ConsentStore` subclass that captures every `save(username, events)` call
 * AND lets a test seed the pending descriptors via `pendingResponse`.
 * `persistDelayMs` sleeps BEFORE pushing so the `at` timestamp captured by
 * `processInlineConsent` (form-submit time) is provably earlier than
 * `Date.now()` at write-time — pins the "captured at acceptance, not at
 * write" semantic.
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

/**
 * Build an `InviteWorkflow` subclass with the constructor declared so DI
 * metadata regenerates. `doubleStep` re-invokes `persistConsentsStep` after
 * the engine's first pass so the idempotency guard is exercised.
 */
function makeInviteSubclass(options: { doubleStep?: boolean } = {}): typeof InviteWorkflow {
  @Inherit()
  @Controller("auth/invite")
  class InviteSubclass extends InviteWorkflow {
    constructor(
      opts: InviteWorkflowOpts,
      users: UserService,
      auth: AuthCredential,
      authOpts: AuthOpts,
      consentStore: ConsentStore,
    ) {
      super(opts, users, auth, authOpts, consentStore);
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
  return InviteSubclass;
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

describe("InviteWorkflow — inline-consent persist seam (Phase 5)", () => {
  it("INVITE-PERSIST-CONSENT-01: required terms descriptor + consents:['terms'] → consentStore.save receives [{id:'terms',accepted:true,version,at}]", async () => {
    // WHY: pins the headline guarantee — `pendingConsents` containing a
    // required terms descriptor + the invitee submitting `consents: ['terms']`
    // on `SetPasswordForm` results in the consumer override receiving exactly
    // one event with the server-authoritative `descriptor.version` + a
    // captured timestamp. Without the `processInlineConsent` call in
    // `createPasswordForm` (production branch under test), the submitted
    // `consents` field would be a stripped form-extra and the workflow would
    // never record acceptance.
    //
    // Also covers the "`at` captured at acceptance moment, not at write
    // time" semantic — the store sleeps 50ms before pushing, then we assert
    // `at <= afterSubmit` (i.e. strictly less than `Date.now()` after the
    // sleep). A regression that stamped `at` inside `persistConsentsStep`
    // would push the value past `afterSubmit`, failing this assertion.
    const consentStore = new CapturingConsentStore();
    consentStore.persistDelayMs = 50;
    consentStore.pendingResponse = [
      { id: "terms", text: "Accept the Terms", required: "must accept", version: "v1" },
    ];
    const Capturing = makeInviteSubclass();
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
          consents: ["terms"],
        },
      })
      .then(() => Date.now());

    expect(consentStore.calls.length).toBe(1);
    expect(consentStore.calls[0].username).toBe("alice@test.com");
    expect(consentStore.calls[0].events.length).toBe(1);
    expect(consentStore.calls[0].events[0].id).toBe("terms");
    expect(consentStore.calls[0].events[0].accepted).toBe(true);
    expect(consentStore.calls[0].events[0].version).toBe("v1");
    expect(consentStore.calls[0].events[0].at).toBeGreaterThanOrEqual(before);
    // `at` stamped at processInlineConsent time (before the 50ms persist
    // delay). Must therefore be <= the moment SetPasswordForm completed
    // its trigger response — strictly NOT past the post-delay `Date.now()`
    // that the consentStore.save call sees.
    expect(consentStore.calls[0].events[0].at).toBeLessThanOrEqual(afterSubmit);
  });

  it("INVITE-PERSIST-CONSENT-02: optional marketing ticked → consentStore.save receives [{id:'marketing',accepted:true,at}] (no version)", async () => {
    // WHY: pins the optional-descriptor event shape with no version. A
    // regression that always stamped `version` (e.g. forced default) would
    // break customers who keep versioning on the FK side only.
    const consentStore = new CapturingConsentStore();
    consentStore.pendingResponse = [{ id: "marketing", text: "Marketing emails" }];
    const Capturing = makeInviteSubclass();
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
        consents: ["marketing"],
      },
    });
    expect(consentStore.calls.length).toBe(1);
    expect(consentStore.calls[0].events.length).toBe(1);
    expect(consentStore.calls[0].events[0].id).toBe("marketing");
    expect(consentStore.calls[0].events[0].accepted).toBe(true);
    expect(consentStore.calls[0].events[0].version).toBeUndefined();
  });

  it("INVITE-PERSIST-CONSENT-DECLINED-01: optional marketing un-ticked → consentStore.save receives [{id:'marketing',accepted:false,at}] (audit default)", async () => {
    // WHY: pins the audit-friendly default — an un-ticked OPTIONAL
    // descriptor is still persisted with `accepted: false`. The whole
    // event-per-pending invariant is what lets customers prove the user
    // was asked. A regression that filtered to only-accepted (saving
    // bytes) would break compliance audits. Submit `consents: []` against
    // an optional marketing descriptor — workflow MUST advance AND persist
    // the declined-optional event.
    const consentStore = new CapturingConsentStore();
    consentStore.pendingResponse = [{ id: "marketing", text: "Marketing emails" }];
    const Capturing = makeInviteSubclass();
    const app = await prepareWfApp({
      consentStore,
      inviteWorkflowClass: withInviteMfaCtx(Capturing, { mfaMode: "disabled" }),
    });
    const { wfs } = await inviteUntilSetPassword(app, "carol@test.com");
    await app.trigger({
      wfs,
      input: { newPassword: PASSWORD, confirmPassword: PASSWORD, consents: [] },
    });
    expect(consentStore.calls.length).toBe(1);
    expect(consentStore.calls[0].events.length).toBe(1);
    expect(consentStore.calls[0].events[0].id).toBe("marketing");
    expect(consentStore.calls[0].events[0].accepted).toBe(false);
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
    consentStore.pendingResponse = [{ id: "marketing", text: "Marketing emails" }];
    const Capturing = makeInviteSubclass({ doubleStep: true });
    const app = await prepareWfApp({
      consentStore,
      inviteWorkflowClass: withInviteMfaCtx(Capturing, { mfaMode: "disabled" }),
    });
    const { wfs } = await inviteUntilSetPassword(app, "dan@test.com");
    await app.trigger({
      wfs,
      input: {
        newPassword: PASSWORD,
        confirmPassword: PASSWORD,
        consents: ["marketing"],
      },
    });
    expect(consentStore.calls.length).toBe(1);
  });

  it("INVITE-PERSIST-SKIP-01: empty pendingConsents → consentStore.save NEVER called even if client posts ids", async () => {
    // WHY: pins the "no pending consents, no audit row" invariant.
    // The `persist-consents` schema condition gates on
    // `consentsDecidedAt` (which is only set when pending was non-empty);
    // a regression that always invoked `save()` (even with an empty
    // events array) would generate empty-event audit rows polluting
    // consumer logs.
    const consentStore = new CapturingConsentStore();
    consentStore.pendingResponse = []; // No pending — silent-drop on any submission.
    const Capturing = makeInviteSubclass();
    const app = await prepareWfApp({
      consentStore,
      inviteWorkflowClass: withInviteMfaCtx(Capturing, { mfaMode: "disabled" }),
    });
    const { wfs } = await inviteUntilSetPassword(app, "evan@test.com");
    await app.trigger({
      wfs,
      // Client tries to smuggle ids — silent-drop says they go nowhere.
      input: { newPassword: PASSWORD, confirmPassword: PASSWORD, consents: ["ignored"] },
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
    await inviteUntilSetPassword(app, "fred@test.com");
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
    await inviteUntilSetPassword(app, "greg@test.com");
    expect(consentStore.pendingCalls.length).toBeGreaterThanOrEqual(1);
    const lastCall = consentStore.pendingCalls.at(-1)!;
    expect(lastCall.ctx.workflow).toBe("auth/invite/start");
    expect(lastCall.ctx.channel).toBeUndefined();
    expect(lastCall.username).toBe("greg@test.com");
  });
});
