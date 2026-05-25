/**
 * Consumer-subclass override coverage for `InviteWorkflow`.
 *
 * The Phase-4 reshape replaced the options-class + injected callbacks with
 * `protected` methods that consumers override via
 * `class MyInvite extends InviteWorkflow {}`. The existing
 * `workflows.invite.options.spec.ts` exercises every override via the harness
 * `inviteHooks` map (which the harness subclass wires onto the methods).
 *
 * This file proves the override path ALSO works when a consumer pastes the
 * literal subclass shape documented in the class doc + WF_INVITE.md — i.e.
 * `@Inherit() @Controller("auth/invite")` plus the re-declared
 * ctor. The harness still wraps the consumer subclass (so it can pin captures
 * for emails / audit), but the harness's overrides delegate to `super.X()`
 * when no `inviteHooks` entry is set — which routes back into the consumer's
 * methods. Each test asserts an observable outcome (response payload, store
 * state, captured emails) that the default implementation could not produce.
 */
import { AuthCredential } from "@aooth/auth";
import { UserService, type UserCredentials } from "@aooth/user";
import { useAtscriptWf } from "@atscript/moost-wf";
import type { TAtscriptAnnotatedType } from "@atscript/typescript/utils";
import { Step, useWfState } from "@moostjs/event-wf";
import { Controller, Inherit } from "moost";
import { describe, expect, it } from "vite-plus/test";

import { ProfileCompleteForm } from "../atscript/models/forms.as";
import { Public } from "../auth.decorator";
import { AuthOpts } from "../auth.opts";
import { ConsentStore } from "../consent.store";
import {
  type DuplicateAction,
  InviteWorkflow,
  type InviteWfCtx,
  type InviteWorkflowOpts,
  type PreparedUserInput,
} from "../workflows/index";
import { prepareWfApp, seedActiveUser, withInviteMfaCtx } from "./workflow-utils";

const PASSWORD = "NewPassword123";

// ── End-to-end smoke: consumer subclass dispatches auth.invite ───────────────
describe("InviteWorkflow subclass — end-to-end registration shape", () => {
  it("@Inherit + @Controller + re-declared ctor → auth.invite dispatches through consumer subclass", async () => {
    // This is the literal subclass shape consumers paste into their app per
    // WF_INVITE.md §"Consumer subclass pattern". The test confirms that
    // dispatch reaches the consumer's `prepareUser` override (no class-
    // identity errors, no DI miss). The harness's override is no-op
    // (no `inviteHooks.prepareUser` set), so `super.prepareUser()` resolves
    // to our subclass's body.
    let prepareUserCalls = 0;
    @Inherit()
    @Controller("auth/invite")
    class MyInvite extends InviteWorkflow {
      constructor(
        opts: InviteWorkflowOpts,
        users: UserService,
        auth: AuthCredential,
        authOpts: AuthOpts,
        consentStore: ConsentStore,
      ) {
        super(opts, users, auth, authOpts, consentStore);
      }
      protected override async prepareUser(
        _input: PreparedUserInput,
      ): Promise<Record<string, unknown>> {
        prepareUserCalls++;
        return { tenantId: "subclass-tenant" };
      }
    }
    const app = await prepareWfApp({
      inviteWorkflowClass: withInviteMfaCtx(MyInvite, { mfaMode: "disabled" }),
    });

    const r1 = await app.trigger({ wfid: "auth/invite/start" });
    await app.trigger({
      wfs: r1.body?.wfs as string,
      input: { email: "sub@test.com" },
    });
    const token = new URL(app.emails[0].url as string).searchParams.get("wfs") as string;
    const r3 = await app.resumeViaQuery(token);
    const r4 = await app.trigger({
      wfs: r3.body?.wfs as string,
      input: { newPassword: PASSWORD, confirmPassword: PASSWORD, consents: [] },
    });
    expect((r4.body?.data as Record<string, unknown>)?.userId).toBe("sub@test.com");
    // Subclass body ran (not just the base default).
    expect(prepareUserCalls).toBe(1);
    // Extras returned by the subclass landed on the persisted user row.
    const user = (await app.users.getUser("sub@test.com")) as unknown as Record<string, unknown>;
    expect(user.tenantId).toBe("subclass-tenant");
  });

  it("consumer subclass also dispatches auth.reInvite and auth.cancelInvite", async () => {
    // The same subclass binds three workflow ids — re-invite + cancel must
    // resolve to the consumer's class too. Use `duplicateCheck` as the
    // dispatch witness: it runs on every invite + would land in the BASE
    // implementation if the subclass weren't actually registered.
    let duplicateCheckCalls = 0;
    @Inherit()
    @Controller("auth/invite")
    class MyInvite extends InviteWorkflow {
      constructor(
        opts: InviteWorkflowOpts,
        users: UserService,
        auth: AuthCredential,
        authOpts: AuthOpts,
        consentStore: ConsentStore,
      ) {
        super(opts, users, auth, authOpts, consentStore);
      }
      protected override async duplicateCheck(input: {
        email: string;
        existingUser: UserCredentials | null;
      }): Promise<DuplicateAction> {
        duplicateCheckCalls++;
        return input.existingUser ? "reject" : "allow";
      }
    }
    const app = await prepareWfApp({
      inviteWorkflowClass: withInviteMfaCtx(MyInvite, { mfaMode: "disabled" }),
    });

    // 1) auth.invite — first hit; duplicateCheck runs.
    const r1 = await app.trigger({ wfid: "auth/invite/start" });
    await app.trigger({
      wfs: r1.body?.wfs as string,
      input: { email: "tri@test.com" },
    });
    expect(duplicateCheckCalls).toBe(1);
    expect(app.emails).toHaveLength(1);

    // 2) auth.reInvite — pre-existing pendingInvitation user; emits a second magic link.
    const ri1 = await app.trigger({ wfid: "auth/invite/resend" });
    const ri2 = await app.trigger({
      wfs: ri1.body?.wfs as string,
      input: { email: "tri@test.com" },
    });
    expect([200, 201]).toContain(ri2.status);
    expect(app.emails).toHaveLength(2);

    // 3) auth.cancelInvite — wipes the pending user row.
    const c1 = await app.trigger({ wfid: "auth/invite/cancel" });
    const c2 = await app.trigger({
      wfs: c1.body?.wfs as string,
      input: { email: "tri@test.com" },
    });
    expect((c2.body?.data as Record<string, unknown>)?.cancelled).toBe(true);

    // Confirmed the user row went away (cancellation actually fired on the
    // consumer-subclass class, not on an orphaned default registration).
    let notFound = false;
    try {
      await app.users.getUser("tri@test.com");
    } catch {
      notFound = true;
    }
    expect(notFound).toBe(true);
  });
});

// ── Per-method consumer-subclass overrides ──────────────────────────────────
describe("InviteWorkflow subclass — protected method overrides", () => {
  it("getAvailableRoles override populates the admin form's ctx.availableRoles", async () => {
    @Inherit()
    @Controller("auth/invite")
    class MyInvite extends InviteWorkflow {
      constructor(
        opts: InviteWorkflowOpts,
        users: UserService,
        auth: AuthCredential,
        authOpts: AuthOpts,
        consentStore: ConsentStore,
      ) {
        super(opts, users, auth, authOpts, consentStore);
      }
      protected override async getAvailableRoles(): Promise<string[] | undefined> {
        return ["tenant-admin", "tenant-member"];
      }
    }
    const app = await prepareWfApp({
      inviteWorkflowClass: withInviteMfaCtx(MyInvite, { mfaMode: "disabled" }),
    });
    const r1 = await app.trigger({ wfid: "auth/invite/start" });
    // Workflow paused on the admin form WITH availableRoles whitelisted via
    // `@wf.context.pass` — UI uses this to render the multi-select. The
    // override could not be detected without this projection being attached
    // to the pause payload.
    expect(r1.body?.availableRoles).toEqual(["tenant-admin", "tenant-member"]);
  });

  it("inferRoles override merges with admin-supplied roles (set-union persisted)", async () => {
    let calls = 0;
    @Inherit()
    @Controller("auth/invite")
    class MyInvite extends InviteWorkflow {
      constructor(
        opts: InviteWorkflowOpts,
        users: UserService,
        auth: AuthCredential,
        authOpts: AuthOpts,
        consentStore: ConsentStore,
      ) {
        super(opts, users, auth, authOpts, consentStore);
      }
      protected override async inferRoles(_input: {
        email: string;
        firstName?: string;
        lastName?: string;
      }): Promise<string[]> {
        calls++;
        return ["inferred-role", "viewer"]; // overlaps 'viewer' with admin pick.
      }
    }
    const app = await prepareWfApp({
      inviteWorkflowClass: withInviteMfaCtx(MyInvite, { mfaMode: "disabled" }),
    });
    const r1 = await app.trigger({ wfid: "auth/invite/start" });
    await app.trigger({
      wfs: r1.body?.wfs as string,
      input: { email: "infer-sub@test.com", roles: ["admin", "viewer"] },
    });
    expect(calls).toBe(1);
    const roles = (app.emails[0].metadata as { roles?: string[] } | undefined)?.roles ?? [];
    expect(new Set(roles)).toEqual(new Set(["admin", "viewer", "inferred-role"]));
  });

  it("applyProfile override receives username + profile after collectProfile pause", async () => {
    const seen: Array<{ username: string; profile: Record<string, unknown> }> = [];
    @Inherit()
    @Controller("auth/invite")
    class MyInvite extends InviteWorkflow {
      constructor(
        opts: InviteWorkflowOpts,
        users: UserService,
        auth: AuthCredential,
        authOpts: AuthOpts,
        consentStore: ConsentStore,
      ) {
        super(opts, users, auth, authOpts, consentStore);
      }
      protected override getProfileForm(): TAtscriptAnnotatedType {
        return ProfileCompleteForm as unknown as TAtscriptAnnotatedType;
      }
      protected override async applyProfile(input: {
        username: string;
        profile: Record<string, unknown>;
      }): Promise<void> {
        seen.push({ ...input });
      }
    }
    const app = await prepareWfApp({
      inviteWorkflowClass: withInviteMfaCtx(MyInvite, { mfaMode: "disabled" }),
    });
    const r1 = await app.trigger({ wfid: "auth/invite/start" });
    await app.trigger({
      wfs: r1.body?.wfs as string,
      input: { email: "ap@test.com" },
    });
    const token = new URL(app.emails[0].url as string).searchParams.get("wfs") as string;
    const r3 = await app.resumeViaQuery(token);
    const r4 = await app.trigger({
      wfs: r3.body?.wfs as string,
      input: { newPassword: PASSWORD, confirmPassword: PASSWORD, consents: [] },
    });
    const r5 = await app.trigger({
      wfs: r4.body?.wfs as string,
      input: { firstName: "Sub", lastName: "Class", consents: [] },
    });
    expect((r5.body?.data as Record<string, unknown>)?.userId).toBe("ap@test.com");
    expect(seen).toHaveLength(1);
    expect(seen[0].username).toBe("ap@test.com");
    expect(seen[0].profile).toMatchObject({ firstName: "Sub", lastName: "Class" });
  });

  it("duplicateCheck override returning 'allow' bypasses the structural reject for an existing active user", async () => {
    // Default `duplicateCheck` rejects any existing row. A consumer subclass
    // overriding to return 'allow' must let the workflow proceed past the
    // structural check (the store may then reject again — that's surfaced as
    // a separate 409). Observable outcome here: the consumer's hook actually
    // ran for an existing user.
    let calls = 0;
    @Inherit()
    @Controller("auth/invite")
    class MyInvite extends InviteWorkflow {
      constructor(
        opts: InviteWorkflowOpts,
        users: UserService,
        auth: AuthCredential,
        authOpts: AuthOpts,
        consentStore: ConsentStore,
      ) {
        super(opts, users, auth, authOpts, consentStore);
      }
      protected override async duplicateCheck(input: {
        email: string;
        existingUser: UserCredentials | null;
      }): Promise<DuplicateAction> {
        calls++;
        // Always allow — including for existing users (escape-hatch).
        return "allow";
      }
    }
    const app = await prepareWfApp({
      inviteWorkflowClass: withInviteMfaCtx(MyInvite, { mfaMode: "disabled" }),
    });
    await seedActiveUser(app.users, "existing@test.com", "ExistingPass1");
    const r1 = await app.trigger({ wfid: "auth/invite/start" });
    const r2 = await app.trigger({
      wfs: r1.body?.wfs as string,
      input: { email: "existing@test.com" },
    });
    // Override ran (1 call) for the existing user.
    expect(calls).toBe(1);
    // The structural rule did NOT trigger (no 409 from duplicateCheck). The
    // store may still reject because the row already exists — that surfaces
    // as a 409 from the createUser path, NOT from the structural rule. The
    // difference matters: the default rule would have rejected BEFORE the
    // hook ran. Either way, the override's call-count is the discriminator.
    expect([409, 200, 201]).toContain(r2.status);
  });

  it("getProfileForm: undefined (default) → NO collectProfile pause; defined → collectProfile pauses", async () => {
    // First app: no override → default behavior skips collectProfile.
    const appNoForm = await prepareWfApp();
    {
      const r1 = await appNoForm.trigger({ wfid: "auth/invite/start" });
      await appNoForm.trigger({
        wfs: r1.body?.wfs as string,
        input: { email: "no-prof-sub@test.com" },
      });
      const token = new URL(appNoForm.emails[0].url as string).searchParams.get("wfs") as string;
      const r3 = await appNoForm.resumeViaQuery(token);
      const r4 = await appNoForm.trigger({
        wfs: r3.body?.wfs as string,
        input: { newPassword: PASSWORD, confirmPassword: PASSWORD, consents: [] },
      });
      // No profile pause: auto-login finished in one shot.
      const data4 = r4.body?.data as Record<string, unknown> | undefined;
      expect(data4?.userId).toBe("no-prof-sub@test.com");
      expect(typeof data4?.accessToken).toBe("string");
    }

    // Second app: consumer subclass DEFINES the profile form.
    @Inherit()
    @Controller("auth/invite")
    class MyInvite extends InviteWorkflow {
      constructor(
        opts: InviteWorkflowOpts,
        users: UserService,
        auth: AuthCredential,
        authOpts: AuthOpts,
        consentStore: ConsentStore,
      ) {
        super(opts, users, auth, authOpts, consentStore);
      }
      protected override getProfileForm(): TAtscriptAnnotatedType {
        return ProfileCompleteForm as unknown as TAtscriptAnnotatedType;
      }
    }
    const appWithForm = await prepareWfApp({
      inviteWorkflowClass: withInviteMfaCtx(MyInvite, { mfaMode: "disabled" }),
    });
    {
      const r1 = await appWithForm.trigger({ wfid: "auth/invite/start" });
      await appWithForm.trigger({
        wfs: r1.body?.wfs as string,
        input: { email: "yes-prof-sub@test.com" },
      });
      const token = new URL(appWithForm.emails[0].url as string).searchParams.get("wfs") as string;
      const r3 = await appWithForm.resumeViaQuery(token);
      const r4 = await appWithForm.trigger({
        wfs: r3.body?.wfs as string,
        input: { newPassword: PASSWORD, confirmPassword: PASSWORD, consents: [] },
      });
      // Profile pause required: response is a pause payload (no userId yet).
      expect(r4.body?.userId).toBeUndefined();
      expect(r4.body?.wfs).toBeTruthy();
    }
  });

  // NOTE: the consumer's own `audit()` override cannot be exercised through
  // `prepareWfApp` because the harness `audit()` override does not delegate
  // to `super.audit()` (it conditionally forwards to the injected
  // `auditEmitter`). The four audit-event kinds (invite.created /
  // invite.resent / invite.accepted / invite.cancelled) are already covered
  // via the auditEmitter capture path in `workflows.invite.options.spec.ts`
  // §"audit events", which proves the workflow EMITS the events with the
  // correct workflow + payload — independent of which subclass body actually
  // forwards them.
});

describe("InviteWorkflow subclass — inviteExtraStep override", () => {
  // WHY: the documented override shape for `inviteExtraStep` is a no-arg
  // method that reads ctx + input via composables. A regression that re-typed
  // the parent to require `@WorkflowParam('context') ctx` would silently break
  // consumer overrides (moost DI feeds args by parameter decorators, so a
  // no-arg override would see undefined for ctx). This pins the contract:
  // subclass overrides with literally `(): Promise<unknown>`, reads ctx + form
  // input purely via composables, drives a pause-resume cycle, and the schema
  // advances through to activation.
  it("no-arg override → pauses for input, captures ctx + input via composables, schema advances to activation", async () => {
    let captured: { username: string | undefined; first: string; last: string } | null = null;
    let calls = 0;

    @Inherit()
    @Controller("auth/invite")
    class OverrideInvite extends InviteWorkflow {
      constructor(
        opts: InviteWorkflowOpts,
        users: UserService,
        auth: AuthCredential,
        authOpts: AuthOpts,
        consentStore: ConsentStore,
      ) {
        super(opts, users, auth, authOpts, consentStore);
      }

      @Step("extra-step")
      @Public()
      override async inviteExtraStep(): Promise<unknown> {
        calls++;
        const wf = useAtscriptWf(ProfileCompleteForm as unknown as TAtscriptAnnotatedType);
        // resolveInput throws (pause) on first hit; resolves on the resume tick.
        const input = wf.resolveInput() as { firstName?: string; lastName?: string };
        const ctx = useWfState().ctx<InviteWfCtx>();
        captured = {
          username: ctx.username,
          first: input.firstName ?? "",
          last: input.lastName ?? "",
        };
        return undefined;
      }
    }

    const app = await prepareWfApp({
      inviteWorkflowClass: withInviteMfaCtx(OverrideInvite, { mfaMode: "disabled" }),
    });

    const r1 = await app.trigger({ wfid: "auth/invite/start" });
    await app.trigger({
      wfs: r1.body?.wfs as string,
      input: { email: "extra@test.com" },
    });
    const token = new URL(app.emails[0].url as string).searchParams.get("wfs") as string;
    const r3 = await app.resumeViaQuery(token);
    const r4 = await app.trigger({
      wfs: r3.body?.wfs as string,
      input: { newPassword: PASSWORD, confirmPassword: PASSWORD, consents: [] },
    });
    // Pause site, NOT terminal — override fired requireInput, schema sits
    // here waiting for the consumer's form payload.
    expect(r4.body?.userId).toBeUndefined();
    expect(r4.body?.wfs).toBeTruthy();
    expect(calls).toBe(1);

    const r5 = await app.trigger({
      wfs: r4.body?.wfs as string,
      input: { firstName: "Extra", lastName: "Override", consents: [] },
    });
    const data = r5.body?.data as Record<string, unknown> | undefined;
    expect(data?.userId).toBe("extra@test.com");
    expect(typeof data?.accessToken).toBe("string");

    // Override ran twice (initial pause + resume); composables resolved ctx +
    // input through the no-arg override body.
    expect(calls).toBe(2);
    expect(captured).not.toBeNull();
    expect(captured!.username).toBe("extra@test.com");
    expect(captured!.first).toBe("Extra");
    expect(captured!.last).toBe("Override");

    // Schema advanced past the extra step to activation — override returning
    // `undefined` lets the workflow continue.
    const user = await app.users.getUser("extra@test.com");
    expect(user.account.active).toBe(true);
  });
});
