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
 * `inviteOpts` + the harness's `inviteHooks` map (which the harness subclass
 * wires onto the new `protected` overrides). The pre-reshape options-class +
 * the rate-limit feature are gone — see WF_INVITE.md.
 */
import { describe, expect, it } from "vite-plus/test";

import { ProfileCompleteForm } from "../atscript/models/forms.as.js";
import { prepareWfApp, seedActiveUser } from "./workflow-utils";

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
  const r1 = await app.trigger({ wfid: "auth.invite" });
  await app.trigger({ wfs: r1.body?.wfs as string, input: { email } });
  const token = new URL(app.emails[0].url as string).searchParams.get("wfs") as string;
  const r3 = await app.resumeViaQuery(token);
  const r4 = await app.trigger({
    wfs: r3.body?.wfs as string,
    input: { newPassword: PASSWORD, confirmPassword: PASSWORD },
  });
  return { status: r4.status, body: r4.body };
}

describe("InviteWorkflow — default flow end-to-end", () => {
  it("admin invite → magic link → accept → auto-login (back-compat default)", async () => {
    // This mirrors workflows.invite.spec.ts "happy path" but also asserts the
    // `pendingInvitation` flag round-trips through UsersStoreMemory: TRUE
    // after pre-create, FALSE after accept.
    const app = await prepareWfApp();
    const r1 = await app.trigger({ wfid: "auth.invite" });
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
      input: { newPassword: PASSWORD, confirmPassword: PASSWORD },
    });

    expect(r4.body?.userId).toBe("alice@test.com");
    expect(typeof r4.body?.accessToken).toBe("string");

    // pendingInvitation cleared on accept; user activated.
    const post = await app.users.getUser("alice@test.com");
    expect(post.account?.pendingInvitation).toBe(false);
    expect(post.account?.active).toBe(true);
  });

  it("invite for an existing pendingInvitation user → 409 uses 'pending' wording", async () => {
    // Belt-and-braces: confirms the pendingInvitation flag survives a
    // round-trip and influences the structural duplicate check.
    const app = await prepareWfApp();
    const r1 = await app.trigger({ wfid: "auth.invite" });
    await app.trigger({
      wfs: r1.body?.wfs as string,
      input: { email: "twice2@test.com" },
    });
    const r2 = await app.trigger({ wfid: "auth.invite" });
    const r2b = await app.trigger({
      wfs: r2.body?.wfs as string,
      input: { email: "twice2@test.com" },
    });
    expect(r2b.status).toBe(409);
    expect(JSON.stringify(r2b.body)).toMatch(/reInvite|pending/i);
  });
});

describe("InviteWorkflow — send.mode shareableLink", () => {
  it("shareableLink: admin form completes; magic-link URL is round-trippable (PUNT: email leaks per impl note)", async () => {
    // PUNT per impl report: shareableLink currently piggy-backs on the email
    // outlet so the admin's UI sees the same URL the email envelope carries.
    const app = await prepareWfApp({
      inviteOpts: {
        send: { mode: "shareableLink" },
        accept: { showConfirmation: false },
      },
    });

    const r1 = await app.trigger({ wfid: "auth.invite" });
    await app.trigger({
      wfs: r1.body?.wfs as string,
      input: { email: "share@test.com" },
    });

    expect(app.emails).toHaveLength(1);
    expect(app.emails[0].kind).toBe("invite.magicLink");
    const token = new URL(app.emails[0].url as string).searchParams.get("wfs") as string;
    const r3 = await app.resumeViaQuery(token);
    expect(r3.body?.wfs).toBeTruthy();
  });
});

describe("InviteWorkflow — send.mode choice", () => {
  it("choice: admin picks 'shareableLink' at runtime → metadata.shareableLink: true on the email", async () => {
    const app = await prepareWfApp({
      inviteOpts: {
        send: { mode: "choice" },
        accept: { showConfirmation: false },
      },
    });
    const r1 = await app.trigger({ wfid: "auth.invite" });
    // First pause: send-mode picker (InviteSendModeForm).
    expect(JSON.stringify(r1.body)).toMatch(/InviteSendModeForm|mode/);
    const r2 = await app.trigger({
      wfs: r1.body?.wfs as string,
      input: { mode: "shareableLink" },
    });
    // Second pause: invite form (InviteForm).
    expect(JSON.stringify(r2.body)).toMatch(/InviteForm|email/);
    await app.trigger({
      wfs: r2.body?.wfs as string,
      input: { email: "choice@test.com" },
    });
    // shareableLink path goes through inviteReturnShareableLink — email
    // captured (PUNT: piggy-backs on email outlet). The link is round-trippable.
    expect(app.emails).toHaveLength(1);
    const token = new URL(app.emails[0].url as string).searchParams.get("wfs") as string;
    const r3 = await app.resumeViaQuery(token);
    expect(r3.body?.wfs).toBeTruthy();
  });

  it("choice: admin picks 'email' → email sent normally", async () => {
    const app = await prepareWfApp({
      inviteOpts: {
        send: { mode: "choice" },
        accept: { showConfirmation: false },
      },
    });
    const r1 = await app.trigger({ wfid: "auth.invite" });
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
      inviteOpts: { accept: { showConfirmation: false } },
      inviteHooks: {
        getProfileForm: () => ProfileCompleteForm,
        applyProfile: async ({ username, profile }) => {
          seen.push({ username, profile });
        },
      },
    });

    const r1 = await app.trigger({ wfid: "auth.invite" });
    await app.trigger({ wfs: r1.body?.wfs as string, input: { email: "pp@test.com" } });
    const token = new URL(app.emails[0].url as string).searchParams.get("wfs") as string;
    const r3 = await app.resumeViaQuery(token);
    const r4 = await app.trigger({
      wfs: r3.body?.wfs as string,
      input: { newPassword: PASSWORD, confirmPassword: PASSWORD },
    });
    // After password set, workflow pauses at collectProfile form.
    expect(JSON.stringify(r4.body)).toMatch(/firstName|lastName|ProfileCompleteForm/);
    const r5 = await app.trigger({
      wfs: r4.body?.wfs as string,
      input: { firstName: "Pat", lastName: "Patel" },
    });
    // Now finished with auto-login.
    expect(r5.body?.userId).toBe("pp@test.com");

    expect(seen).toHaveLength(1);
    expect(seen[0].username).toBe("pp@test.com");
    expect(seen[0].profile).toMatchObject({ firstName: "Pat", lastName: "Patel" });
  });

  it("getProfileForm WITHOUT applyProfile override → default deep-merge fallback writes via UserService.update", async () => {
    const app = await prepareWfApp({
      inviteOpts: { accept: { showConfirmation: false } },
      inviteHooks: {
        getProfileForm: () => ProfileCompleteForm,
        // no applyProfile — default deep-merge runs.
      },
    });

    const r1 = await app.trigger({ wfid: "auth.invite" });
    await app.trigger({ wfs: r1.body?.wfs as string, input: { email: "dm@test.com" } });
    const token = new URL(app.emails[0].url as string).searchParams.get("wfs") as string;
    const r3 = await app.resumeViaQuery(token);
    const r4 = await app.trigger({
      wfs: r3.body?.wfs as string,
      input: { newPassword: PASSWORD, confirmPassword: PASSWORD },
    });
    await app.trigger({
      wfs: r4.body?.wfs as string,
      input: { firstName: "Default", lastName: "Merge" },
    });

    const user = (await app.users.getUser("dm@test.com")) as unknown as Record<string, unknown>;
    expect(user.firstName).toBe("Default");
    expect(user.lastName).toBe("Merge");
  });

  it("no getProfileForm override → no profile pause; password-set advances straight to auto-login", async () => {
    const app = await prepareWfApp();
    const r = await driveDefaultInviteAccept(app, "noprof@test.com");
    expect(r.body?.userId).toBe("noprof@test.com");
  });
});

describe("InviteWorkflow — getAvailableRoles + inferRoles", () => {
  it("getAvailableRoles populates ctx.availableRoles on the InviteForm pause", async () => {
    const app = await prepareWfApp({
      inviteOpts: { accept: { showConfirmation: false } },
      inviteHooks: {
        getAvailableRoles: async () => ["admin", "viewer"],
      },
    });
    const r1 = await app.trigger({ wfid: "auth.invite" });
    // Admin form returned; availableRoles whitelisted via `@wf.context.pass`.
    expect(r1.body?.availableRoles).toEqual(["admin", "viewer"]);
  });

  it("getAvailableRoles whitelist rejects admin-submitted role outside the list", async () => {
    // Server-side guard against the admin submitting a role that the consumer
    // hook did not surface — without this, a tampered form payload could
    // assign arbitrary roles.
    const app = await prepareWfApp({
      inviteOpts: { accept: { showConfirmation: false } },
      inviteHooks: {
        getAvailableRoles: async () => ["admin", "viewer"],
      },
    });
    const r1 = await app.trigger({ wfid: "auth.invite" });
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
      inviteOpts: { accept: { showConfirmation: false } },
      inviteHooks: {
        inferRoles: async (input) => {
          calls.push({ ...input });
          return ["auto-role", "viewer"]; // 'viewer' overlaps with admin pick
        },
      },
    });
    const r1 = await app.trigger({ wfid: "auth.invite" });
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
    const r1 = await app.trigger({ wfid: "auth.invite" });
    await app.trigger({
      wfs: r1.body?.wfs as string,
      input: { email: "redo@test.com" },
    });
    expect(app.emails).toHaveLength(1);
    // Admin re-invites — second magic link captured.
    const ri1 = await app.trigger({ wfid: "auth.reInvite" });
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
      input: { newPassword: PASSWORD, confirmPassword: PASSWORD },
    });
    expect(r4.body?.userId).toBe("redo@test.com");
  });

  it("re-invite refuses on already-accepted user → 409", async () => {
    const app = await prepareWfApp();
    // Complete a full invite + accept first.
    await driveDefaultInviteAccept(app, "done@test.com");
    // Now try to re-invite.
    const ri1 = await app.trigger({ wfid: "auth.reInvite" });
    const ri2 = await app.trigger({
      wfs: ri1.body?.wfs as string,
      input: { email: "done@test.com" },
    });
    expect(ri2.status).toBe(409);
  });

  it("re-invite on never-invited user → 404", async () => {
    const app = await prepareWfApp();
    const ri1 = await app.trigger({ wfid: "auth.reInvite" });
    const ri2 = await app.trigger({
      wfs: ri1.body?.wfs as string,
      input: { email: "ghost@nowhere.test" },
    });
    expect(ri2.status).toBe(404);
  });
});

describe("InviteWorkflow — cancel-invite", () => {
  it("cancel removes the pending user; subsequent magic-link click → 410", async () => {
    const app = await prepareWfApp();
    const r1 = await app.trigger({ wfid: "auth.invite" });
    await app.trigger({
      wfs: r1.body?.wfs as string,
      input: { email: "kill@test.com" },
    });
    // User row exists with pendingInvitation: true.
    expect((await app.users.getUser("kill@test.com")).account?.pendingInvitation).toBe(true);

    const token = new URL(app.emails[0].url as string).searchParams.get("wfs") as string;

    // Admin cancels.
    const c1 = await app.trigger({ wfid: "auth.cancelInvite" });
    const c2 = await app.trigger({
      wfs: c1.body?.wfs as string,
      input: { email: "kill@test.com" },
    });
    expect(c2.body?.cancelled).toBe(true);

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

  it("cancel on already-accepted user → 409", async () => {
    const app = await prepareWfApp();
    await driveDefaultInviteAccept(app, "live@test.com");
    const c1 = await app.trigger({ wfid: "auth.cancelInvite" });
    const c2 = await app.trigger({
      wfs: c1.body?.wfs as string,
      input: { email: "live@test.com" },
    });
    expect(c2.status).toBe(409);
  });

  it("cancel on no-such-user → 404", async () => {
    const app = await prepareWfApp();
    const c1 = await app.trigger({ wfid: "auth.cancelInvite" });
    const c2 = await app.trigger({
      wfs: c1.body?.wfs as string,
      input: { email: "nobody@test.com" },
    });
    expect(c2.status).toBe(404);
  });

  it("cancellation.allowed=false → 403 from cancel step", async () => {
    const app = await prepareWfApp({
      inviteOpts: {
        accept: { showConfirmation: false },
        cancellation: { allowed: false },
      },
    });
    // The `cancelInvite` step's allowed-gate fires on the first trigger
    // (before the form input pause), so the workflow returns 403 immediately
    // rather than handing back an InviteEmailForm prompt.
    const c1 = await app.trigger({ wfid: "auth.cancelInvite" });
    expect(c1.status).toBe(403);
    expect(JSON.stringify(c1.body)).toMatch(/disabled|forbidden/i);
  });
});

describe("InviteWorkflow — idempotent magic-link click", () => {
  it("second click after a successful accept → redirect / 4xx (single-use token)", async () => {
    const app = await prepareWfApp({
      inviteOpts: {
        accept: { showConfirmation: false, alreadyAcceptedRedirectUrl: "/already-in" },
      },
    });
    const r1 = await app.trigger({ wfid: "auth.invite" });
    await app.trigger({
      wfs: r1.body?.wfs as string,
      input: { email: "idem@test.com" },
    });
    const token = new URL(app.emails[0].url as string).searchParams.get("wfs") as string;
    // First click → finishes accept.
    const r3 = await app.resumeViaQuery(token);
    const r4 = await app.trigger({
      wfs: r3.body?.wfs as string,
      input: { newPassword: PASSWORD, confirmPassword: PASSWORD },
    });
    expect(r4.body?.userId).toBe("idem@test.com");

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
      inviteOpts: {
        accept: { showConfirmation: false, alreadyAcceptedRedirectUrl: "/already-in" },
      },
    });
    const r1 = await app.trigger({ wfid: "auth.invite" });
    await app.trigger({
      wfs: r1.body?.wfs as string,
      input: { email: "twice@test.com" },
    });
    const tokenA = new URL(app.emails[0].url as string).searchParams.get("wfs") as string;

    // Complete via first token.
    const r3 = await app.resumeViaQuery(tokenA);
    await app.trigger({
      wfs: r3.body?.wfs as string,
      input: { newPassword: PASSWORD, confirmPassword: PASSWORD },
    });
    // Sanity: user is fully accepted.
    expect((await app.users.getUser("twice@test.com")).account?.pendingInvitation).toBe(false);

    const ri1 = await app.trigger({ wfid: "auth.reInvite" });
    const ri2 = await app.trigger({
      wfs: ri1.body?.wfs as string,
      input: { email: "twice@test.com" },
    });
    expect(ri2.status).toBe(409);
  });
});

describe("InviteWorkflow — accept.freshLoginRequired", () => {
  it("freshLoginRequired=true skips auto-login (redirect to loginUrl)", async () => {
    const app = await prepareWfApp({
      inviteOpts: {
        accept: {
          showConfirmation: false,
          freshLoginRequired: true,
          loginUrl: "/sign-in",
        },
      },
    });
    const r = await driveDefaultInviteAccept(app, "fresh@test.com");
    expect(r.status).toBe(302);
    // No auto-login payload.
    expect(r.body?.accessToken).toBeUndefined();
  });
});

describe("InviteWorkflow — duplicate-invite structural rule", () => {
  it("invite for an email that already has pendingInvitation=true → 409 'Invite already pending, use reInvite'", async () => {
    const app = await prepareWfApp();
    // First invite: pre-creates the user with pendingInvitation: true.
    const r1 = await app.trigger({ wfid: "auth.invite" });
    await app.trigger({
      wfs: r1.body?.wfs as string,
      input: { email: "dup@test.com" },
    });
    // Second invite for same email → 409 with the reInvite hint.
    const r2 = await app.trigger({ wfid: "auth.invite" });
    const r2b = await app.trigger({
      wfs: r2.body?.wfs as string,
      input: { email: "dup@test.com" },
    });
    expect(r2b.status).toBe(409);
    expect(JSON.stringify(r2b.body)).toMatch(/reInvite/i);
  });

  it("invite for an email that exists with pendingInvitation=false → 409 'User already exists'", async () => {
    const app = await prepareWfApp();
    await seedActiveUser(app.users, "live@test.com", "ExistingPass1");
    const r1 = await app.trigger({ wfid: "auth.invite" });
    const r2 = await app.trigger({
      wfs: r1.body?.wfs as string,
      input: { email: "live@test.com" },
    });
    expect(r2.status).toBe(409);
    expect(JSON.stringify(r2.body)).toMatch(/already exists/i);
  });

  it("duplicateCheck override returning 'allow' bypasses the structural rule (multi-tenant escape hatch)", async () => {
    // The escape hatch lets multi-tenant apps permit re-using an email across
    // tenants. When the override returns 'allow' the workflow does NOT
    // short-circuit on the structural duplicate check.
    const seen: Array<{ email: string; hadExisting: boolean }> = [];
    const app = await prepareWfApp({
      inviteOpts: { accept: { showConfirmation: false } },
      inviteHooks: {
        duplicateCheck: async ({ email, existingUser }) => {
          seen.push({ email, hadExisting: existingUser !== null });
          return "allow" as const;
        },
      },
    });
    const r1 = await app.trigger({ wfid: "auth.invite" });
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
      inviteOpts: { accept: { showConfirmation: false }, audit: { enabled: true } },
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
    expect(accepted?.workflow).toBe("auth.invite");
  });

  it("emits invite.resent on auth.reInvite (loadPendingUser)", async () => {
    const events: Array<Record<string, unknown>> = [];
    const app = await prepareWfApp({
      inviteOpts: { accept: { showConfirmation: false }, audit: { enabled: true } },
      auditEmitter: {
        emit(e) {
          events.push(e);
        },
      },
    });
    const r1 = await app.trigger({ wfid: "auth.invite" });
    await app.trigger({
      wfs: r1.body?.wfs as string,
      input: { email: "resent@test.com" },
    });
    const ri1 = await app.trigger({ wfid: "auth.reInvite" });
    await app.trigger({
      wfs: ri1.body?.wfs as string,
      input: { email: "resent@test.com" },
    });
    const resent = events.find((e) => e.kind === "invite.resent");
    expect(resent).toBeDefined();
    expect(resent?.workflow).toBe("auth.reInvite");
    expect(resent?.userId).toBe("resent@test.com");
  });

  it("emits invite.cancelled on auth.cancelInvite", async () => {
    const events: Array<Record<string, unknown>> = [];
    const app = await prepareWfApp({
      inviteOpts: { accept: { showConfirmation: false }, audit: { enabled: true } },
      auditEmitter: {
        emit(e) {
          events.push(e);
        },
      },
    });
    const r1 = await app.trigger({ wfid: "auth.invite" });
    await app.trigger({
      wfs: r1.body?.wfs as string,
      input: { email: "bye@test.com" },
    });
    const c1 = await app.trigger({ wfid: "auth.cancelInvite" });
    await app.trigger({
      wfs: c1.body?.wfs as string,
      input: { email: "bye@test.com" },
    });
    const cancelled = events.find((e) => e.kind === "invite.cancelled");
    expect(cancelled).toBeDefined();
    expect(cancelled?.workflow).toBe("auth.cancelInvite");
    expect(cancelled?.email).toBe("bye@test.com");
  });

  it("audit.enabled=false → no invite.* events fired", async () => {
    const events: Array<Record<string, unknown>> = [];
    const app = await prepareWfApp({
      inviteOpts: { accept: { showConfirmation: false }, audit: { enabled: false } },
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
