/**
 * Per-option behaviour tests for `InviteWorkflow` (auth.invite + auth.reInvite
 * + auth.cancelInvite) — covers every actionable item from WF_INVITE.md §"Tasks".
 *
 * Anti-test guard (Rule 9): every test asserts observable output (response
 * payloads, captured emails, audit events, user-store state). No step-count /
 * step-name assertions. Each test would fail if the production branch under
 * test were removed.
 *
 * Phase 4 reshape: tests configure InviteWorkflow via the nested-pojo
 * `inviteOpts` (infrastructure: forms, TTLs, pincode length) + the
 * `invitePolicy` knob (resolveXxx policy groups: adminForm, send, accept,
 * cancellation, audit, mfa) + the harness's `inviteHooks` map (`protected`
 * method overrides). Pre-reshape options-class + rate-limit are gone.
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
  await app.trigger({ wfs: r1.body?.wfs as string, input: { email } });
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
      input: { email: "alice@test.com" },
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
      input: { email: "twice2@test.com" },
    });
    const r2 = await app.trigger({ wfid: "auth/invite/start" });
    const r2b = await app.trigger({
      wfs: r2.body?.wfs as string,
      input: { email: "twice2@test.com" },
    });
    // WHY: structural duplicate now routes through `wf.requireInput` so the
    // admin can correct the email inline without losing the wf token; the
    // "pending invitation" wording must surface on the per-field `email` error.
    expect(r2b.status).toBe(201);
    const errors = r2b.body?.errors as Record<string, string> | undefined;
    expect(errors?.email).toMatch(/reInvite|pending/i);
  });
});

describe("InviteWorkflow — send.mode shareableLink", () => {
  it("shareableLink: admin form completes; magic-link URL returned in trigger response (no email sent)", async () => {
    // shareableLink mode uses the dedicated `shareableLink` outlet — the URL
    // is surfaced in the admin's HTTP response body, no email envelope.
    const app = await prepareWfApp({
      invitePolicy: {
        send: { mode: "shareableLink" },
      },
    });

    const r1 = await app.trigger({ wfid: "auth/invite/start" });
    const r2 = await app.trigger({
      wfs: r1.body?.wfs as string,
      input: { email: "share@test.com" },
    });

    expect(app.emails).toHaveLength(0);
    const url = r2.body?.url as string | undefined;
    expect(url, "shareableLink outlet returns a magic-link url in the trigger body").toBeTruthy();
    const token = new URL(url as string).searchParams.get("wfs") as string;
    const r3 = await app.resumeViaQuery(token);
    expect(r3.body?.wfs).toBeTruthy();
  });
});

describe("InviteWorkflow — send.mode choice", () => {
  it("choice: admin picks 'shareableLink' at runtime → URL surfaced in trigger response (no email)", async () => {
    const app = await prepareWfApp({
      invitePolicy: { send: { mode: "choice" } },
    });
    const r1 = await app.trigger({ wfid: "auth/invite/start" });
    // First pause: send-mode picker (InviteSendModeForm).
    expect(JSON.stringify(r1.body)).toMatch(/InviteSendModeForm|mode/);
    const r2 = await app.trigger({
      wfs: r1.body?.wfs as string,
      input: { mode: "shareableLink" },
    });
    // Second pause: invite form (InviteForm).
    expect(JSON.stringify(r2.body)).toMatch(/InviteForm|email/);
    const r3 = await app.trigger({
      wfs: r2.body?.wfs as string,
      input: { email: "choice@test.com" },
    });
    expect(app.emails).toHaveLength(0);
    const url = r3.body?.url as string | undefined;
    expect(url).toBeTruthy();
    const token = new URL(url as string).searchParams.get("wfs") as string;
    const r4 = await app.resumeViaQuery(token);
    expect(r4.body?.wfs).toBeTruthy();
  });

  it("choice: admin picks 'email' → email sent normally", async () => {
    const app = await prepareWfApp({
      invitePolicy: { send: { mode: "choice" } },
    });
    const r1 = await app.trigger({ wfid: "auth/invite/start" });
    const r2 = await app.trigger({
      wfs: r1.body?.wfs as string,
      input: { mode: "email" },
    });
    await app.trigger({
      wfs: r2.body?.wfs as string,
      input: { email: "choice2@test.com" },
    });
    expect(app.emails).toHaveLength(1);
    expect(app.emails[0].kind).toBe("invite.magicLink");
    expect(app.emails[0].recipient).toBe("choice2@test.com");
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
    await app.trigger({ wfs: r1.body?.wfs as string, input: { email: "pp@test.com" } });
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
    await app.trigger({ wfs: r1.body?.wfs as string, input: { email: "dm@test.com" } });
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

describe("InviteWorkflow — re-invite", () => {
  it("re-invite happy path: original link works, then re-invite issues new magic link", async () => {
    const app = await prepareWfApp();
    const r1 = await app.trigger({ wfid: "auth/invite/start" });
    await app.trigger({
      wfs: r1.body?.wfs as string,
      input: { email: "redo@test.com" },
    });
    expect(app.emails).toHaveLength(1);
    // Admin re-invites — second magic link captured.
    const ri1 = await app.trigger({ wfid: "auth/invite/resend" });
    await app.trigger({
      wfs: ri1.body?.wfs as string,
      input: { email: "redo@test.com" },
    });
    expect(app.emails).toHaveLength(2);
    expect(app.emails[1].kind).toBe("invite.magicLink");
    expect(app.emails[1].recipient).toBe("redo@test.com");

    // The fresh magic-link token resumes through accept successfully.
    const token = new URL(app.emails[1].url as string).searchParams.get("wfs") as string;
    const r3 = await app.resumeViaQuery(token);
    const r4 = await app.trigger({
      wfs: r3.body?.wfs as string,
      input: { newPassword: PASSWORD, confirmPassword: PASSWORD, consents: [] },
    });
    expect((r4.body?.data as Record<string, unknown>)?.userId).toBe("redo@test.com");
  });

  it("re-invite refuses on already-accepted user → 409", async () => {
    const app = await prepareWfApp();
    // Complete a full invite + accept first.
    await driveDefaultInviteAccept(app, "done@test.com");
    // Now try to re-invite.
    const ri1 = await app.trigger({ wfid: "auth/invite/resend" });
    const ri2 = await app.trigger({
      wfs: ri1.body?.wfs as string,
      input: { email: "done@test.com" },
    });
    // WHY: previously HttpError(409) — token-eating throw made retry impossible.
    // Fix surfaces the "already accepted" message as a per-field `email` error
    // so the admin can correct the address in the same workflow run.
    expect(ri2.status).toBe(201);
    const errors = ri2.body?.errors as Record<string, string> | undefined;
    expect(errors?.email).toMatch(/already accepted/i);
  });

  it("re-invite on never-invited user → re-renders email form with not-found error", async () => {
    // WHY: see above — was HttpError(404) which deleted the wf token. Fix
    // routes through `wf.requireInput` so the admin retries with a different
    // email on the same wf token.
    const app = await prepareWfApp();
    const ri1 = await app.trigger({ wfid: "auth/invite/resend" });
    const ri2 = await app.trigger({
      wfs: ri1.body?.wfs as string,
      input: { email: "ghost@nowhere.test" },
    });
    expect(ri2.status).toBe(201);
    const errors = ri2.body?.errors as Record<string, string> | undefined;
    expect(errors?.email).toMatch(/no pending invite/i);
  });
});

describe("InviteWorkflow — cancel-invite", () => {
  it("cancel removes the pending user; subsequent magic-link click → 410", async () => {
    const app = await prepareWfApp();
    const r1 = await app.trigger({ wfid: "auth/invite/start" });
    await app.trigger({
      wfs: r1.body?.wfs as string,
      input: { email: "kill@test.com" },
    });
    // User row exists with pendingInvitation: true.
    expect((await app.users.getUser("kill@test.com")).account?.pendingInvitation).toBe(true);

    const token = new URL(app.emails[0].url as string).searchParams.get("wfs") as string;

    // Admin cancels.
    const c1 = await app.trigger({ wfid: "auth/invite/cancel" });
    const c2 = await app.trigger({
      wfs: c1.body?.wfs as string,
      input: { email: "kill@test.com" },
    });
    expect((c2.body?.data as Record<string, unknown>)?.cancelled).toBe(true);

    // User row gone.
    let notFound = false;
    try {
      await app.users.getUser("kill@test.com");
    } catch {
      notFound = true;
    }
    expect(notFound).toBe(true);

    // Magic link click → 410 from checkPendingInvitation.
    const replay = await app.resumeViaQuery(token);
    expect(replay.status).toBe(410);
  });

  it("cancel on already-accepted user → re-renders email form with conflict error", async () => {
    // WHY: was HttpError(409) — token deletion broke retry. Fix surfaces
    // the "already accepted" branch via `wf.requireInput` so the admin can
    // re-target a different email on the same wf token.
    const app = await prepareWfApp();
    await driveDefaultInviteAccept(app, "live@test.com");
    const c1 = await app.trigger({ wfid: "auth/invite/cancel" });
    const c2 = await app.trigger({
      wfs: c1.body?.wfs as string,
      input: { email: "live@test.com" },
    });
    expect(c2.status).toBe(201);
    const errors = c2.body?.errors as Record<string, string> | undefined;
    expect(errors?.email).toMatch(/already accepted/i);
  });

  it("cancel on no-such-user → re-renders email form with not-found error", async () => {
    // WHY: was HttpError(404) — same token-deletion regression. Fix surfaces
    // the not-found branch as a `wf.requireInput` so the admin can retry.
    const app = await prepareWfApp();
    const c1 = await app.trigger({ wfid: "auth/invite/cancel" });
    const c2 = await app.trigger({
      wfs: c1.body?.wfs as string,
      input: { email: "nobody@test.com" },
    });
    expect(c2.status).toBe(201);
    const errors = c2.body?.errors as Record<string, string> | undefined;
    expect(errors?.email).toMatch(/no invite to cancel/i);
  });

  it("cancellation.allowed=false → 403 from cancel step", async () => {
    const app = await prepareWfApp({
      invitePolicy: { cancellation: { allowed: false } },
    });
    // The `cancelInvite` step's allowed-gate fires on the first trigger
    // (before the form input pause), so the workflow returns 403 immediately
    // rather than handing back an InviteEmailForm prompt.
    const c1 = await app.trigger({ wfid: "auth/invite/cancel" });
    expect(c1.status).toBe(403);
    expect(JSON.stringify(c1.body)).toMatch(/disabled|forbidden/i);
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
      input: { email: "idem@test.com" },
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

  it("re-invite refuses after the user already accepted via the FIRST link → 409", async () => {
    // The structural pendingInvitation=false → re-invite rejects path proves
    // the alreadyAccepted invariant from the workflow level: once accepted,
    // no second token can be issued.
    const app = await prepareWfApp({
      invitePolicy: { accept: acceptPolicy({ alreadyAcceptedRedirectUrl: "/already-in" }) },
    });
    const r1 = await app.trigger({ wfid: "auth/invite/start" });
    await app.trigger({
      wfs: r1.body?.wfs as string,
      input: { email: "twice@test.com" },
    });
    const tokenA = new URL(app.emails[0].url as string).searchParams.get("wfs") as string;

    // Complete via first token.
    const r3 = await app.resumeViaQuery(tokenA);
    await app.trigger({
      wfs: r3.body?.wfs as string,
      input: { newPassword: PASSWORD, confirmPassword: PASSWORD, consents: [] },
    });
    // Sanity: user is fully accepted.
    expect((await app.users.getUser("twice@test.com")).account?.pendingInvitation).toBe(false);

    const ri1 = await app.trigger({ wfid: "auth/invite/resend" });
    const ri2 = await app.trigger({
      wfs: ri1.body?.wfs as string,
      input: { email: "twice@test.com" },
    });
    // WHY: token-eating HttpError(409) replaced with `wf.requireInput` —
    // proves a once-accepted user can't be silently re-invited and the admin
    // gets a retryable per-field error.
    expect(ri2.status).toBe(201);
    const errors = ri2.body?.errors as Record<string, string> | undefined;
    expect(errors?.email).toMatch(/already accepted/i);
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
      input: { email: "dup@test.com" },
    });
    // Second invite for same email → form re-render with the reInvite hint.
    const r2 = await app.trigger({ wfid: "auth/invite/start" });
    const r2b = await app.trigger({
      wfs: r2.body?.wfs as string,
      input: { email: "dup@test.com" },
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
      input: { email: "live@test.com" },
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
      input: { email: "fresh@test.com" },
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

describe("InviteWorkflow — audit events", () => {
  it("emits invite.created (preCreateUser), invite.accepted (activateUser)", async () => {
    const events: Array<Record<string, unknown>> = [];
    const app = await prepareWfApp({
      invitePolicy: { audit: { enabled: true } },
      auditEmitter: {
        emit(e) {
          events.push(e);
        },
      },
    });
    await driveDefaultInviteAccept(app, "audit@test.com");

    const kinds = events.map((e) => e.kind);
    expect(kinds).toContain("invite.created");
    expect(kinds).toContain("invite.accepted");
    const accepted = events.find((e) => e.kind === "invite.accepted");
    expect(accepted?.userId).toBe("audit@test.com");
    expect(accepted?.workflow).toBe("auth/invite/start");
  });

  it("emits invite.resent on auth.reInvite (loadPendingUser)", async () => {
    const events: Array<Record<string, unknown>> = [];
    const app = await prepareWfApp({
      invitePolicy: { audit: { enabled: true } },
      auditEmitter: {
        emit(e) {
          events.push(e);
        },
      },
    });
    const r1 = await app.trigger({ wfid: "auth/invite/start" });
    await app.trigger({
      wfs: r1.body?.wfs as string,
      input: { email: "resent@test.com" },
    });
    const ri1 = await app.trigger({ wfid: "auth/invite/resend" });
    await app.trigger({
      wfs: ri1.body?.wfs as string,
      input: { email: "resent@test.com" },
    });
    const resent = events.find((e) => e.kind === "invite.resent");
    expect(resent).toBeDefined();
    expect(resent?.workflow).toBe("auth/invite/resend");
    expect(resent?.userId).toBe("resent@test.com");
  });

  it("emits invite.cancelled on auth.cancelInvite", async () => {
    const events: Array<Record<string, unknown>> = [];
    const app = await prepareWfApp({
      invitePolicy: { audit: { enabled: true } },
      auditEmitter: {
        emit(e) {
          events.push(e);
        },
      },
    });
    const r1 = await app.trigger({ wfid: "auth/invite/start" });
    await app.trigger({
      wfs: r1.body?.wfs as string,
      input: { email: "bye@test.com" },
    });
    const c1 = await app.trigger({ wfid: "auth/invite/cancel" });
    await app.trigger({
      wfs: c1.body?.wfs as string,
      input: { email: "bye@test.com" },
    });
    const cancelled = events.find((e) => e.kind === "invite.cancelled");
    expect(cancelled).toBeDefined();
    expect(cancelled?.workflow).toBe("auth/invite/cancel");
    expect(cancelled?.email).toBe("bye@test.com");
  });

  it("audit.enabled=false → no invite.* events fired", async () => {
    const events: Array<Record<string, unknown>> = [];
    const app = await prepareWfApp({
      invitePolicy: { audit: { enabled: false } },
      auditEmitter: {
        emit(e) {
          events.push(e);
        },
      },
    });
    await driveDefaultInviteAccept(app, "silent@test.com");
    expect(events.filter((e) => String(e.kind).startsWith("invite."))).toHaveLength(0);
  });
});

describe("InviteWorkflow — admin form firstName/lastName/roles wiring", () => {
  it("admin submits firstName/lastName/roles → preCreateUser does NOT write form-only fields onto the user row", async () => {
    // Regression: the bundled `InviteForm` collects `firstName`/`lastName`
    // (optional) for downstream consumption — but the base
    // `AoothUserCredentials` row shape does NOT declare those columns. The
    // workflow MUST NOT inject them blindly into `users.createUser` `fields`
    // or atscript-db-backed stores reject the create with
    // `"firstName: Unexpected property"`. Consumers route the form values into
    // their custom columns via the `prepareUser({firstName, lastName, …})`
    // hook return value. `roles` IS in `AoothArbacUserCredentials` so it
    // stays a direct field.
    const seenPrepare: Array<Record<string, unknown>> = [];
    const app = await prepareWfApp({
      userStore: new StrictSchemaUserStore(BASE_USER_COLUMNS),
      inviteHooks: {
        prepareUser: (input) => {
          seenPrepare.push({ ...input });
          return {};
        },
      },
    });

    const r1 = await app.trigger({ wfid: "auth/invite/start" });
    const r2 = await app.trigger({
      wfs: r1.body?.wfs as string,
      input: {
        email: "newhire@x.com",
        firstName: "New",
        lastName: "Hire",
        roles: ["user"],
      },
    });

    // Workflow advanced past `preCreateUser` (form-only fields did not crash
    // the strict-schema store) and emitted the magic link.
    expect(r2.status).toBeLessThan(400);
    expect(app.emails).toHaveLength(1);

    // `prepareUser` saw the full form payload (consumer's mapping seam).
    expect(seenPrepare).toHaveLength(1);
    expect(seenPrepare[0]).toMatchObject({
      email: "newhire@x.com",
      firstName: "New",
      lastName: "Hire",
      roles: ["user"],
    });

    // The created user carries `roles` (base-schema field) but NOT
    // `firstName`/`lastName` (would have thrown otherwise — and the row reflects
    // that they were never persisted).
    const u = (await app.users.getUser("newhire@x.com")) as unknown as Record<string, unknown>;
    expect(u.roles).toEqual(["user"]);
    expect(u.firstName).toBeUndefined();
    expect(u.lastName).toBeUndefined();
  });

  it("prepareUser return value is the seam for mapping firstName/lastName into consumer columns", async () => {
    // Consumer maps the form's `firstName`/`lastName` into their schema's
    // own column (`displayName`) via `prepareUser`'s return. Confirms the
    // documented contract: the workflow passes form-only fields to the hook
    // and only writes what the hook returns (+ `roles` + `email`).
    const allowed = new Set([...BASE_USER_COLUMNS, "displayName"]);
    const app = await prepareWfApp({
      userStore: new StrictSchemaUserStore(allowed),
      inviteHooks: {
        prepareUser: ({ firstName, lastName }) => {
          const display = [firstName, lastName].filter(Boolean).join(" ");
          return display ? { displayName: display } : {};
        },
      },
    });

    const r1 = await app.trigger({ wfid: "auth/invite/start" });
    const r2 = await app.trigger({
      wfs: r1.body?.wfs as string,
      input: { email: "mapped@x.com", firstName: "Jane", lastName: "Doe" },
    });
    expect(r2.status).toBeLessThan(400);
    const u = (await app.users.getUser("mapped@x.com")) as unknown as Record<string, unknown>;
    expect(u.displayName).toBe("Jane Doe");
  });

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
  it("idempotent magic-link click (already-accepted parallel token) → finishWf({ next: manual }) envelope with primary + option buttons", async () => {
    // Drive the parallel-token scenario: admin invites; auth.reInvite issues
    // tokenB while the first invite still pending; user accepts via tokenA;
    // tokenB resume now lands on `inviteIdempotentRedirect`.
    const app = await prepareWfApp({
      invitePolicy: {
        accept: acceptPolicy({
          alreadyAcceptedRedirectUrl: "/request-new",
          loginUrl: "/sign-in",
        }),
      },
    });
    const r1 = await app.trigger({ wfid: "auth/invite/start" });
    await app.trigger({
      wfs: r1.body?.wfs as string,
      input: { email: "parallel@test.com" },
    });
    const tokenA = new URL(app.emails[0].url as string).searchParams.get("wfs") as string;
    // reInvite issues tokenB while pendingInvitation is still true.
    const ri = await app.trigger({ wfid: "auth/invite/resend" });
    await app.trigger({
      wfs: ri.body?.wfs as string,
      input: { email: "parallel@test.com" },
    });
    const tokenB = new URL(app.emails[1].url as string).searchParams.get("wfs") as string;

    // Complete accept via tokenA → pendingInvitation cleared.
    const a1 = await app.resumeViaQuery(tokenA);
    await app.trigger({
      wfs: a1.body?.wfs as string,
      input: { newPassword: PASSWORD, confirmPassword: PASSWORD, consents: [] },
    });

    // tokenB now resumes into the already-accepted branch → finishWf({ next: manual }).
    const b1 = await app.resumeViaQuery(tokenB);
    const body = b1.body as Record<string, unknown>;
    expect(body.finished).toBe(true);
    const end = body.next as
      | {
          trigger: string;
          primary?: { label: string; action: { type: string; target: string; reason?: string } };
          options?: Array<{
            label: string;
            action: { type: string; target: string; reason?: string };
          }>;
        }
      | undefined;
    expect(end?.trigger).toBe("manual");
    expect(end?.primary?.action?.target).toBe("/sign-in");
    expect(end?.primary?.action?.reason).toBe("already-accepted");
    expect(end?.options?.[0]?.action?.target).toBe("/request-new");
    expect(end?.options?.[0]?.action?.reason).toBe("request-new-invite");
    const message = body.message as { level: string; text: string } | undefined;
    expect(message?.level).toBe("info");
  });

  it("password-form cancel alt-action → abortWf envelope with reason='cancel'", async () => {
    const app = await prepareWfApp();
    const r1 = await app.trigger({ wfid: "auth/invite/start" });
    await app.trigger({
      wfs: r1.body?.wfs as string,
      input: { email: "abort@test.com" },
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
      input: { email: "cookie@test.com" },
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

  it("cancelInvite terminal → finishWf({ data }) envelope with data.cancelled + info message", async () => {
    const app = await prepareWfApp();
    const r1 = await app.trigger({ wfid: "auth/invite/start" });
    await app.trigger({
      wfs: r1.body?.wfs as string,
      input: { email: "wipe@test.com" },
    });
    const c1 = await app.trigger({ wfid: "auth/invite/cancel" });
    const c2 = await app.trigger({
      wfs: c1.body?.wfs as string,
      input: { email: "wipe@test.com" },
    });
    const body = c2.body as Record<string, unknown>;
    expect(body.finished).toBe(true);
    const data = body.data as Record<string, unknown> | undefined;
    expect(data?.cancelled).toBe(true);
    expect(data?.email).toBe("wipe@test.com");
    const message = body.message as { level: string; text: string } | undefined;
    expect(message?.level).toBe("info");
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

describe("InviteWorkflow — passwordPolicies surfaces on SetPasswordForm pause", () => {
  it("WF-INVITE-PWPOLICY — passwordPolicies reaches client on SetPasswordForm pause", async () => {
    // Guards two regressions at once:
    //   1. `@wf.context.pass 'passwordPolicies'` on SetPasswordForm — without
    //      it `extractPassContext` strips the key before the inputRequired
    //      envelope leaves the engine.
    //   2. `invitePreparePasswordRules` seeding `ctx.passwordPolicies` so the
    //      next step's `inviteCreatePasswordForm` ships the rules to the client.
    const app = await prepareWfApp({
      userConfig: { password: { policies: [ppHasMinLength(8)] } },
    });
    const r1 = await app.trigger({ wfid: "auth/invite/start" });
    await app.trigger({
      wfs: r1.body?.wfs as string,
      input: { email: "alice@test.com" },
    });
    const token = new URL(app.emails[0].url as string).searchParams.get("wfs") as string;
    const r3 = await app.resumeViaQuery(token);

    // Same flat-object wire shape as recovery — whitelisted ctx keys merged
    // alongside the form schema.
    const body = r3.body as { id?: string; passwordPolicies?: unknown };
    expect(body.id).toBe("SetPasswordForm");
    expect(body.passwordPolicies).toEqual(app.users.getTransferablePolicies());
    expect(Array.isArray(body.passwordPolicies)).toBe(true);
    expect((body.passwordPolicies as unknown[]).length).toBeGreaterThan(0);
  });
});
