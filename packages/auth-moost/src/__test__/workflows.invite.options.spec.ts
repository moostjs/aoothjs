/**
 * Per-option behaviour tests for `InviteWorkflow` (auth/invite/start) — the
 * post-simplification surface (admin form → email outlet → magic-link resume →
 * accept tail). Pre-simplification reInvite / cancel workflows + send-mode
 * picker + audit-emission tests are gone.
 *
 * Anti-test guard (Rule 9): every test asserts observable output (response
 * payloads, captured emails, user-store state). No step-count / step-name
 * assertions.
 *
 * Tests configure InviteWorkflow via the nested-pojo `inviteOpts`
 * (infrastructure: forms) + the `invitePolicy` knob (resolveXxx policy groups:
 * adminForm, accept, mfa) + the harness's `inviteHooks` map (`protected`
 * method overrides).
 */
import { ppHasMinLength, UserStoreMemory } from "@aooth/user";
import type { UserCredentials } from "@aooth/user";
import type { InviteWfCtx } from "@aooth/auth-moost";
import { describe, expect, it } from "vite-plus/test";

import { InviteForm, ProfileCompleteForm } from "../atscript/models/forms.as";
import { prepareWfApp, seedActiveUser } from "./workflow-utils";

/**
 * Default-merged `accept` policy — saves each test from spelling out the full
 * shape just to flip one flag. Mirrors `InviteWorkflow.resolveAccept`
 * defaults, with `showConfirmation: false` swapped in to match the harness
 * default (most tests assert the auto-login response shape directly,
 * pre-dating the confirmation pause).
 */
function acceptPolicy(
  partial: Partial<NonNullable<InviteWfCtx["accept"]>> = {},
): NonNullable<InviteWfCtx["accept"]> {
  return {
    alreadyAcceptedRedirectUrl: "/login",
    freshLoginRequired: false,
    loginUrl: "/login",
    showConfirmation: false,
    confirmationMessage: "Your account has been created.",
    ...partial,
  };
}

/**
 * Simulates atscript-db's strict-schema persistence: rejects any property on
 * the create payload that isn't in `allowedColumns`. Mirrors the real
 * `UsersStoreAtscriptDb` behaviour where the row-type validator throws
 * `"<prop>: Unexpected property"` for fields the consumer's `.as` model does
 * not declare. Reproduces the InviteWorkflow contract bug at unit-test scope
 * without pulling in a real DB.
 */
class StrictSchemaUserStore extends UserStoreMemory {
  constructor(private readonly allowedColumns: Set<string>) {
    super();
  }
  override async create(data: UserCredentials & object): Promise<void> {
    const rec = data as unknown as Record<string, unknown>;
    for (const key of Object.keys(rec)) {
      if (!this.allowedColumns.has(key)) {
        throw new Error(`${key}: Unexpected property`);
      }
    }
    await super.create(data);
  }
}

/** Columns mirroring `AoothArbacUserCredentials` (base + `roles`). */
const BASE_USER_COLUMNS = new Set([
  "username",
  "password",
  "passwordHistory",
  "account",
  "id",
  "roles",
  "mfa",
  "recovery",
  "trustedDevices",
  "createdAt",
  "updatedAt",
  "version",
]);

const PASSWORD = "NewPassword123";

/**
 * Drive the canonical happy-path: admin opens `auth.invite`, submits invite
 * form, captures the email, resumes via magic link, submits password. Returns
 * the final response.
 */
async function driveDefaultInviteAccept(
  app: Awaited<ReturnType<typeof prepareWfApp>>,
  email: string,
): Promise<{ status: number; body: Record<string, unknown> | null }> {
  const r1 = await app.trigger({ wfid: "auth/invite/start" });
  await app.trigger({ wfs: r1.body?.wfs as string, input: { email, roles: [] } });
  const token = new URL(app.emails[0].url as string).searchParams.get("wfs") as string;
  const r3 = await app.resumeViaQuery(token);
  const r4 = await app.trigger({
    wfs: r3.body?.wfs as string,
    input: { newPassword: PASSWORD, confirmPassword: PASSWORD, consents: [] },
  });
  return { status: r4.status, body: r4.body };
}

describe("InviteWorkflow — default flow end-to-end", () => {
  it("admin invite → magic link → accept → auto-login (back-compat default)", async () => {
    // This mirrors workflows.invite.spec.ts "happy path" but also asserts the
    // `pendingInvitation` flag round-trips through UsersStoreMemory: TRUE
    // after pre-create, FALSE after accept.
    const app = await prepareWfApp();
    const r1 = await app.trigger({ wfid: "auth/invite/start" });
    await app.trigger({
      wfs: r1.body?.wfs as string,
      input: { email: "alice@test.com", roles: [] },
    });

    // After preCreateUser: user row exists with pendingInvitation === true.
    const pre = await app.users.getUser("alice@test.com");
    expect(pre.account?.pendingInvitation).toBe(true);

    const token = new URL(app.emails[0].url as string).searchParams.get("wfs") as string;
    const r3 = await app.resumeViaQuery(token);
    const r4 = await app.trigger({
      wfs: r3.body?.wfs as string,
      input: { newPassword: PASSWORD, confirmPassword: PASSWORD, consents: [] },
    });

    const data4 = r4.body?.data as Record<string, unknown> | undefined;
    expect(data4?.userId).toBe("alice@test.com");
    expect(typeof data4?.accessToken).toBe("string");

    // pendingInvitation cleared on accept; user activated.
    const post = await app.users.getUser("alice@test.com");
    expect(post.account?.pendingInvitation).toBe(false);
    expect(post.account?.active).toBe(true);
  });

  it("invite for an existing pendingInvitation user → 409 uses 'pending' wording", async () => {
    // Belt-and-braces: confirms the pendingInvitation flag survives a
    // round-trip and influences the structural duplicate check.
    const app = await prepareWfApp();
    const r1 = await app.trigger({ wfid: "auth/invite/start" });
    await app.trigger({
      wfs: r1.body?.wfs as string,
      input: { email: "twice2@test.com", roles: [] },
    });
    const r2 = await app.trigger({ wfid: "auth/invite/start" });
    const r2b = await app.trigger({
      wfs: r2.body?.wfs as string,
      input: { email: "twice2@test.com", roles: [] },
    });
    // WHY: structural duplicate now routes through `wf.requireInput` so the
    // admin can correct the email inline without losing the wf token; the
    // "pending invitation" wording must surface on the per-field `email` error.
    expect(r2b.status).toBe(201);
    const errors = r2b.body?.errors as Record<string, string> | undefined;
    expect(errors?.email).toMatch(/reInvite|pending/i);
  });
});

describe("InviteWorkflow — getProfileForm + applyProfile", () => {
  it("getProfileForm + custom applyProfile override fires with raw profile + username", async () => {
    const seen: Array<{ username: string; profile: Record<string, unknown> }> = [];
    const app = await prepareWfApp({
      inviteHooks: {
        getProfileForm: () => ProfileCompleteForm,
        applyProfile: async ({ username, profile }) => {
          seen.push({ username, profile });
        },
      },
    });

    const r1 = await app.trigger({ wfid: "auth/invite/start" });
    await app.trigger({
      wfs: r1.body?.wfs as string,
      input: { email: "pp@test.com", roles: [] },
    });
    const token = new URL(app.emails[0].url as string).searchParams.get("wfs") as string;
    const r3 = await app.resumeViaQuery(token);
    const r4 = await app.trigger({
      wfs: r3.body?.wfs as string,
      input: { newPassword: PASSWORD, confirmPassword: PASSWORD, consents: [] },
    });
    // After password set, workflow pauses at collectProfile form.
    expect(JSON.stringify(r4.body)).toMatch(/firstName|lastName|ProfileCompleteForm/);
    const r5 = await app.trigger({
      wfs: r4.body?.wfs as string,
      input: { firstName: "Pat", lastName: "Patel", consents: [] },
    });
    // Now finished with auto-login.
    expect((r5.body?.data as Record<string, unknown>)?.userId).toBe("pp@test.com");

    expect(seen).toHaveLength(1);
    expect(seen[0].username).toBe("pp@test.com");
    expect(seen[0].profile).toMatchObject({ firstName: "Pat", lastName: "Patel" });
  });

  it("getProfileForm WITHOUT applyProfile override → default deep-merge fallback writes via UserService.update", async () => {
    const app = await prepareWfApp({
      inviteHooks: {
        getProfileForm: () => ProfileCompleteForm,
        // no applyProfile — default deep-merge runs.
      },
    });

    const r1 = await app.trigger({ wfid: "auth/invite/start" });
    await app.trigger({
      wfs: r1.body?.wfs as string,
      input: { email: "dm@test.com", roles: [] },
    });
    const token = new URL(app.emails[0].url as string).searchParams.get("wfs") as string;
    const r3 = await app.resumeViaQuery(token);
    const r4 = await app.trigger({
      wfs: r3.body?.wfs as string,
      input: { newPassword: PASSWORD, confirmPassword: PASSWORD, consents: [] },
    });
    await app.trigger({
      wfs: r4.body?.wfs as string,
      input: { firstName: "Default", lastName: "Merge", consents: [] },
    });

    const user = (await app.users.getUser("dm@test.com")) as unknown as Record<string, unknown>;
    expect(user.firstName).toBe("Default");
    expect(user.lastName).toBe("Merge");
  });

  it("no getProfileForm override → no profile pause; password-set advances straight to auto-login", async () => {
    const app = await prepareWfApp();
    const r = await driveDefaultInviteAccept(app, "noprof@test.com");
    expect((r.body?.data as Record<string, unknown>)?.userId).toBe("noprof@test.com");
  });
});

describe("InviteWorkflow — getAvailableRoles + inferRoles", () => {
  it("getAvailableRoles populates ctx.availableRoles on the InviteForm pause", async () => {
    const app = await prepareWfApp({
      inviteHooks: {
        getAvailableRoles: async () => ["admin", "viewer"],
      },
    });
    const r1 = await app.trigger({ wfid: "auth/invite/start" });
    // Admin form returned; availableRoles whitelisted via `@wf.context.pass`.
    expect(r1.body?.availableRoles).toEqual(["admin", "viewer"]);
  });

  it("getAvailableRoles whitelist rejects admin-submitted role outside the list", async () => {
    // Server-side guard against the admin submitting a role that the consumer
    // hook did not surface — without this, a tampered form payload could
    // assign arbitrary roles.
    const app = await prepareWfApp({
      inviteHooks: {
        getAvailableRoles: async () => ["admin", "viewer"],
      },
    });
    const r1 = await app.trigger({ wfid: "auth/invite/start" });
    const r2 = await app.trigger({
      wfs: r1.body?.wfs as string,
      input: { email: "bad-role@test.com", roles: ["admin", "superuser"] },
    });
    // Workflow re-pauses on the invite form with a `roles` field error.
    expect(r2.body?.errors).toMatchObject({ roles: "Invalid role" });
    // No invite email was sent — the workflow did not advance past the form.
    expect(app.emails).toHaveLength(0);
  });

  it("inferRoles merges with admin-supplied roles (set-union)", async () => {
    const calls: Array<Record<string, unknown>> = [];
    const app = await prepareWfApp({
      inviteHooks: {
        inferRoles: async (input) => {
          calls.push({ ...input });
          return ["auto-role", "viewer"]; // 'viewer' overlaps with admin pick
        },
      },
    });
    const r1 = await app.trigger({ wfid: "auth/invite/start" });
    await app.trigger({
      wfs: r1.body?.wfs as string,
      input: { email: "infer@test.com", roles: ["viewer", "admin"] },
    });
    expect(calls).toHaveLength(1);
    expect(calls[0]).toMatchObject({ email: "infer@test.com" });
    // The combined roles are persisted onto the user record + carried in the email metadata.
    expect(app.emails[0].metadata).toBeDefined();
    const roles = (app.emails[0].metadata as { roles: string[] }).roles;
    expect(new Set(roles)).toEqual(new Set(["viewer", "admin", "auto-role"]));
  });
});

describe("InviteWorkflow — idempotent magic-link click", () => {
  it("second click after a successful accept → redirect / 4xx (single-use token)", async () => {
    const app = await prepareWfApp({
      invitePolicy: { accept: acceptPolicy({ alreadyAcceptedRedirectUrl: "/already-in" }) },
    });
    const r1 = await app.trigger({ wfid: "auth/invite/start" });
    await app.trigger({
      wfs: r1.body?.wfs as string,
      input: { email: "idem@test.com", roles: [] },
    });
    const token = new URL(app.emails[0].url as string).searchParams.get("wfs") as string;
    // First click → finishes accept.
    const r3 = await app.resumeViaQuery(token);
    const r4 = await app.trigger({
      wfs: r3.body?.wfs as string,
      input: { newPassword: PASSWORD, confirmPassword: PASSWORD, consents: [] },
    });
    expect((r4.body?.data as Record<string, unknown>)?.userId).toBe("idem@test.com");

    // Second click (replay): single-use tokens reject after consumption with
    // 410 Gone — the configured `alreadyAcceptedRedirectUrl` branch would
    // fire only on a parallel second link issued before accept. Either
    // short-circuit proves the user is NOT taken back into the password form.
    const replay = await app.resumeViaQuery(token);
    expect(replay.status).toBeGreaterThanOrEqual(400);
    expect(replay.status).toBeLessThan(500);
  });
});

describe("InviteWorkflow — accept.freshLoginRequired", () => {
  it("freshLoginRequired=true skips auto-login (redirect to loginUrl)", async () => {
    const app = await prepareWfApp({
      invitePolicy: {
        accept: acceptPolicy({ freshLoginRequired: true, loginUrl: "/sign-in" }),
      },
    });
    const r = await driveDefaultInviteAccept(app, "fresh@test.com");
    // Envelope: immediate redirect via finishWf({ next: immediate }), no auto-login data.
    const end = (r.body as Record<string, unknown>)?.next as
      | { trigger?: string; action?: { type?: string; target?: string; reason?: string } }
      | undefined;
    expect(end?.trigger).toBe("immediate");
    expect(end?.action?.type).toBe("redirect");
    expect(end?.action?.target).toBe("/sign-in");
    expect(end?.action?.reason).toBe("fresh-login-required");
    expect((r.body?.data as Record<string, unknown>)?.accessToken).toBeUndefined();
  });
});

describe("InviteWorkflow — duplicate-invite structural rule", () => {
  it("invite for an email that already has pendingInvitation=true → re-renders InviteForm with reInvite hint", async () => {
    // WHY: structural duplicate previously threw HttpError(409) — token-eating
    // throw broke retry. Fix routes through `wf.requireInput` so the admin can
    // correct the email inline; the "reInvite" hint must surface on the
    // per-field `email` error.
    const app = await prepareWfApp();
    // First invite: pre-creates the user with pendingInvitation: true.
    const r1 = await app.trigger({ wfid: "auth/invite/start" });
    await app.trigger({
      wfs: r1.body?.wfs as string,
      input: { email: "dup@test.com", roles: [] },
    });
    // Second invite for same email → form re-render with the reInvite hint.
    const r2 = await app.trigger({ wfid: "auth/invite/start" });
    const r2b = await app.trigger({
      wfs: r2.body?.wfs as string,
      input: { email: "dup@test.com", roles: [] },
    });
    expect(r2b.status).toBe(201);
    const errors = r2b.body?.errors as Record<string, string> | undefined;
    expect(errors?.email).toMatch(/reInvite/i);
  });

  it("invite for an email that exists with pendingInvitation=false → re-renders InviteForm with 'already exists'", async () => {
    // WHY: same regression class. Surfaces on per-field `email` error so the
    // admin retries without losing the wf token.
    const app = await prepareWfApp();
    await seedActiveUser(app.users, "live@test.com", "ExistingPass1");
    const r1 = await app.trigger({ wfid: "auth/invite/start" });
    const r2 = await app.trigger({
      wfs: r1.body?.wfs as string,
      input: { email: "live@test.com", roles: [] },
    });
    expect(r2.status).toBe(201);
    const errors = r2.body?.errors as Record<string, string> | undefined;
    expect(errors?.email).toMatch(/already exists/i);
  });

  it("duplicateCheck override returning 'allow' bypasses the structural rule (multi-tenant escape hatch)", async () => {
    // The escape hatch lets multi-tenant apps permit re-using an email across
    // tenants. When the override returns 'allow' the workflow does NOT
    // short-circuit on the structural duplicate check.
    const seen: Array<{ email: string; hadExisting: boolean }> = [];
    const app = await prepareWfApp({
      inviteHooks: {
        duplicateCheck: async ({ email, existingUser }) => {
          seen.push({ email, hadExisting: existingUser !== null });
          return "allow" as const;
        },
      },
    });
    const r1 = await app.trigger({ wfid: "auth/invite/start" });
    const r2 = await app.trigger({
      wfs: r1.body?.wfs as string,
      input: { email: "fresh@test.com", roles: [] },
    });
    // Override was invoked + workflow advanced past the duplicate check
    // (pauses at the email outlet or 200/201-style finish state, NOT 409).
    expect(seen).toEqual([{ email: "fresh@test.com", hadExisting: false }]);
    expect([200, 201]).toContain(r2.status);
    // And the email was actually sent (the workflow continued through
    // preCreateUser + sendInviteEmail).
    expect(app.emails).toHaveLength(1);
    expect(app.emails[0].recipient).toBe("fresh@test.com");
  });
});

describe("InviteWorkflow — admin form roles wiring", () => {
  it("getAvailableRoles + admin-submitted role outside whitelist → 400-equivalent inline form error (NOT 500)", async () => {
    // The whitelist enforcement must surface as an inline form error before
    // the workflow reaches `preCreateUser`. This existed already; the
    // regression guard pairs it with the strict-schema store to make sure
    // the "Invalid role" path stays the friendly inline path rather than
    // tripping a downstream 500.
    const app = await prepareWfApp({
      userStore: new StrictSchemaUserStore(BASE_USER_COLUMNS),
      inviteHooks: { getAvailableRoles: async () => ["admin", "viewer"] },
    });
    const r1 = await app.trigger({ wfid: "auth/invite/start" });
    const r2 = await app.trigger({
      wfs: r1.body?.wfs as string,
      input: { email: "bad@x.com", roles: ["admin", "superuser"] },
    });
    expect(r2.status).toBeLessThan(500);
    expect(r2.body?.errors).toMatchObject({ roles: "Invalid role" });
    expect(app.emails).toHaveLength(0);
  });
});

// ─── WfFinished envelope migration (UI-MIGRATION.md §invite.workflow.ts) ───
describe("InviteWorkflow — WfFinished envelope shape", () => {
  it("password-form cancel alt-action → abortWf envelope with reason='cancel'", async () => {
    const app = await prepareWfApp();
    const r1 = await app.trigger({ wfid: "auth/invite/start" });
    await app.trigger({
      wfs: r1.body?.wfs as string,
      input: { email: "abort@test.com", roles: [] },
    });
    const token = new URL(app.emails[0].url as string).searchParams.get("wfs") as string;
    const r3 = await app.resumeViaQuery(token);
    // Submit the password form with the cancel alt-action.
    const r4 = await app.trigger({
      wfs: r3.body?.wfs as string,
      input: { action: "cancel" },
    });
    const body = r4.body as Record<string, unknown>;
    expect(body.finished).toBe(true);
    expect(body.aborted).toBe(true);
    expect(body.reason).toBe("cancel");
    // User record NOT deleted — pending invitation flag stays true so admin
    // can reInvite later (documented contract).
    const u = await app.users.getUser("abort@test.com");
    expect(u.account?.pendingInvitation).toBe(true);
  });

  it("freshLoginRequired → finishWf({ next: immediate redirect }) envelope with reason='fresh-login-required'", async () => {
    const app = await prepareWfApp({
      invitePolicy: {
        accept: acceptPolicy({ freshLoginRequired: true, loginUrl: "/post-accept" }),
      },
    });
    const r = await driveDefaultInviteAccept(app, "fl@test.com");
    expect(r.status).toBeLessThan(400);
    const body = r.body as Record<string, unknown>;
    expect(body.finished).toBe(true);
    const end = body.next as
      | { trigger: string; action: { target: string; reason?: string } }
      | undefined;
    expect(end?.trigger).toBe("immediate");
    expect(end?.action?.target).toBe("/post-accept");
    expect(end?.action?.reason).toBe("fresh-login-required");
  });

  it("auto-login terminal still carries cookies (raw WfFinished envelope path)", async () => {
    // The cookies-bearing finish stays on the raw `useWfFinished` path because
    // helpers don't expose `cookies`. Envelope shape: { finished: true, data }.
    const app = await prepareWfApp();
    const r1 = await app.trigger({ wfid: "auth/invite/start" });
    await app.trigger({
      wfs: r1.body?.wfs as string,
      input: { email: "cookie@test.com", roles: [] },
    });
    const token = new URL(app.emails[0].url as string).searchParams.get("wfs") as string;
    const r3 = await app.resumeViaQuery(token);
    const r4 = await app.trigger({
      wfs: r3.body?.wfs as string,
      input: { newPassword: PASSWORD, confirmPassword: PASSWORD, consents: [] },
    });
    const body = r4.body as Record<string, unknown>;
    expect(body.finished).toBe(true);
    const data = body.data as Record<string, unknown> | undefined;
    expect(data?.userId).toBe("cookie@test.com");
    expect(typeof data?.accessToken).toBe("string");
    // Auth cookies still set despite the new envelope.
    expect(r4.setCookies.length).toBeGreaterThan(0);
  });
});

// ─── Multiselect (atscript-ui 0.1.64) — InviteForm.roles serialization ───
describe("InviteForm.roles multiselect metadata", () => {
  it("InviteForm.roles serializes with multiselect options metadata (atscript-ui 0.1.64 multiselect support)", async () => {
    // The upstream atscript-ui 0.1.64 bump renders `string[]` + `@ui.form.type
    // 'select'` + `@ui.form.fn.options` as a multiselect. The form schema
    // itself was already correct; this test pins the metadata that drives the
    // rendering so a future schema regression surfaces here.
    // biome-ignore lint/suspicious/noExplicitAny: navigating atscript runtime metadata
    const props = (InviteForm as any).type?.props as Map<string, any>;
    const roles = props.get("roles");
    expect(roles).toBeDefined();
    expect(roles.optional).toBe(true);
    // Underlying type is an array (multi-value carrier).
    expect(roles.type?.kind).toBe("array");
    // The combo that 0.1.64 reads to render a multiselect:
    //   ui.form.type === 'select' + ui.form.fn.options callback + array carrier.
    expect(roles.metadata.get("ui.form.type")).toBe("select");
    const optionsAnnotation = roles.metadata.get("ui.form.fn.options");
    expect(optionsAnnotation).toBeDefined();
    // Annotation is a callback string referring to the role-options resolver
    // (consumes ctx.availableRoles populated by `invitePrepareAvailableRoles`).
    expect(String(optionsAnnotation)).toMatch(/availableRoles/);
  });
});

describe("InviteWorkflow — password.policies surfaces on SetPasswordForm pause", () => {
  it("WF-INVITE-PWPOLICY — password.policies reaches client on SetPasswordForm pause", async () => {
    // Guards two regressions at once:
    //   1. `@wf.context.pass 'password'` on SetPasswordForm — without
    //      it `extractPassContext` strips the key before the inputRequired
    //      envelope leaves the engine.
    //   2. `invitePreparePasswordRules` seeding `ctx.password.policies` so the
    //      next step's `inviteCreatePasswordForm` ships the rules to the client.
    const app = await prepareWfApp({
      userConfig: { password: { policies: [ppHasMinLength(8)] } },
    });
    const r1 = await app.trigger({ wfid: "auth/invite/start" });
    await app.trigger({
      wfs: r1.body?.wfs as string,
      input: { email: "alice@test.com", roles: [] },
    });
    const token = new URL(app.emails[0].url as string).searchParams.get("wfs") as string;
    const r3 = await app.resumeViaQuery(token);

    // The `password` group is shipped as a nested object — whitelisted ctx
    // keys merged alongside the form schema.
    const body = r3.body as { id?: string; password?: { policies?: unknown } };
    expect(body.id).toBe("SetPasswordForm");
    const policies = body.password?.policies as unknown[] | undefined;
    expect(policies).toEqual(app.users.getTransferablePolicies());
    expect(Array.isArray(policies)).toBe(true);
    expect(policies?.length ?? 0).toBeGreaterThan(0);
  });
});
