import { generateTotpCode } from "@aooth/user";
import { describe, expect, it } from "vite-plus/test";

import { ProfileWithRolesForm } from "./fixtures/profile-with-roles.as";
import { prepareWfApp, seedActiveUser } from "./workflow-utils";

/**
 * Wire trace for the invite workflow:
 *
 * 1. `POST /wf/trigger { wfid: 'auth.invite' }`
 *    → `createInvite` returns `outletHttp` → form (InviteForm) + wfs token.
 * 2. `POST /wf/trigger { wfs, input: { email, roles? } }`
 *    → step calls `EmailSender.send` (invite.magicLink), pauses via `outletEmail`.
 * 3. (link click) `POST /wf/trigger?wfs=<token>`
 *    → resumes at `accept` step → form (SetPasswordForm).
 * 4. `POST /wf/trigger { wfs, input: { newPassword, confirmPassword } }`
 *    → creates the user, activates, issues credential, finishes.
 */
describe("InviteWorkflow", () => {
  it("happy path: admin invites → email → accept → user created + tokens", async () => {
    const app = await prepareWfApp();

    const r1 = await app.trigger({ wfid: "auth.invite" });
    const wfs1 = r1.body?.wfs as string;
    expect(wfs1).toBeTruthy();

    await app.trigger({
      wfs: wfs1,
      input: { email: "bob@test.com", roles: ["admin", "editor"] },
    });
    expect(app.emails).toHaveLength(1);
    const email = app.emails[0];
    expect(email.kind).toBe("invite.magicLink");
    expect(email.recipient).toBe("bob@test.com");
    expect(email.metadata).toMatchObject({ roles: ["admin", "editor"] });

    const token = new URL(email.url as string).searchParams.get("wfs") as string;

    const r3 = await app.resumeViaQuery(token);
    const wfs3 = r3.body?.wfs as string;

    const r4 = await app.trigger({
      wfs: wfs3,
      input: { newPassword: "NewPassword123", confirmPassword: "NewPassword123" },
    });
    const data4 = r4.body?.data as Record<string, unknown> | undefined;
    expect(data4?.userId).toBe("bob@test.com");
    expect(typeof data4?.accessToken).toBe("string");

    // User created and active
    const user = await app.users.getUser("bob@test.com");
    expect(user.account.active).toBe(true);
  });

  it("duplicate email at invite: 409", async () => {
    const app = await prepareWfApp();
    // Pre-seed an existing user with the same email
    await seedActiveUser(app.users, "bob@test.com", "Password123");

    const r1 = await app.trigger({ wfid: "auth.invite" });
    const r2 = await app.trigger({
      wfs: r1.body?.wfs as string,
      input: { email: "bob@test.com" },
    });
    expect(r2.status).toBe(409);
  });

  it("confirm-password mismatch on accept", async () => {
    const app = await prepareWfApp();
    const r1 = await app.trigger({ wfid: "auth.invite" });
    const r2 = await app.trigger({
      wfs: r1.body?.wfs as string,
      input: { email: "carol@test.com" },
    });
    void r2;
    const token = new URL(app.emails[0].url as string).searchParams.get("wfs") as string;
    const r3 = await app.resumeViaQuery(token);
    const wfs3 = r3.body?.wfs as string;

    const r4 = await app.trigger({
      wfs: wfs3,
      input: { newPassword: "NewPassword123", confirmPassword: "Different1" },
    });
    const errors = r4.body?.errors as Record<string, string> | undefined;
    expect(errors).toMatchObject({ confirmPassword: "Passwords do not match" });
  });

  it("expired invite token: 410 on resume (TTL config-driven)", async () => {
    // BUG-12 fix: `inviteTokenTtlMs` now drives the actual replay window,
    // not just the email envelope.
    const app = await prepareWfApp({ inviteTokenTtlMs: 1000 });
    const r1 = await app.trigger({ wfid: "auth.invite" });
    await app.trigger({
      wfs: r1.body?.wfs as string,
      input: { email: "dave@test.com" },
    });
    const token = new URL(app.emails[0].url as string).searchParams.get("wfs") as string;

    // Wait past the TTL — `WfStateStoreMemory.get()` honours `expiresAt`.
    await new Promise((resolve) => setTimeout(resolve, 1100));

    const r3 = await app.resumeViaQuery(token);
    expect(r3.status).toBe(410);
  });

  it("roles trimming / parsing: empty entries skipped + duplicates collapsed", async () => {
    const app = await prepareWfApp();
    const r1 = await app.trigger({ wfid: "auth.invite" });
    await app.trigger({
      wfs: r1.body?.wfs as string,
      input: { email: "eve@test.com", roles: ["  admin  ", "", "editor", "admin"] },
    });
    expect(app.emails[0].metadata).toMatchObject({ roles: ["admin", "editor"] });
  });

  it("invite form without roles: metadata absent", async () => {
    const app = await prepareWfApp();
    const r1 = await app.trigger({ wfid: "auth.invite" });
    await app.trigger({
      wfs: r1.body?.wfs as string,
      input: { email: "frank@test.com" },
    });
    expect(app.emails[0].metadata).toBeUndefined();
  });

  it("prepareUser hook: extras merged into created user", async () => {
    const seen: Array<Record<string, unknown>> = [];
    const app = await prepareWfApp({
      prepareUser: (input) => {
        seen.push({ ...input });
        return { tenantId: "acme", roles: input.roles };
      },
    });

    const r1 = await app.trigger({ wfid: "auth.invite" });
    await app.trigger({
      wfs: r1.body?.wfs as string,
      input: { email: "grace@test.com", roles: ["admin", "viewer"] },
    });
    const token = new URL(app.emails[0].url as string).searchParams.get("wfs") as string;
    const r3 = await app.resumeViaQuery(token);
    await app.trigger({
      wfs: r3.body?.wfs as string,
      input: { newPassword: "NewPassword123", confirmPassword: "NewPassword123" },
    });

    // Hook ran with the parsed input shape we promised.
    expect(seen).toHaveLength(1);
    expect(seen[0]).toEqual({
      email: "grace@test.com",
      roles: ["admin", "viewer"],
    });

    // Returned extras land on the persisted user record.
    const user = (await app.users.getUser("grace@test.com")) as unknown as Record<string, unknown>;
    expect(user.tenantId).toBe("acme");
    expect(user.roles).toEqual(["admin", "viewer"]);
  });

  it("accept-time profile payload CANNOT escalate roles or shadow server-managed fields", async () => {
    // SECURITY REGRESSION (audit hole #6): the admin invite flow sets
    // `ctx.roles` server-side from the admin's whitelisted picks. If the
    // accept-time profile payload could carry top-level keys like `roles` /
    // `password` / `account` / `mfa` / `version` …, the default
    // `applyProfile` would deep-merge them onto the user row via
    // `UserService.update` — letting any invited user self-promote to admin
    // or overwrite the freshly-set password hash.
    //
    // The defense is the `STRIPPED_FROM_PROFILE` strip in `applyProfileStep`,
    // applied BEFORE handing off to the (consumer-overridable) `applyProfile`
    // hook. To prove the workflow itself enforces the boundary (not just
    // upstream form validation), this test wires a profile form
    // (`ProfileWithRolesForm`) that DELIBERATELY declares the privileged
    // keys as accepted fields — so atscript's form validator passes them
    // through. Only the workflow strip can stop the escalation.
    //
    // WHY this WILL FAIL without the strip: `seenAtHook[0]` would carry
    // `roles: ['admin', 'root']` and `password: { hash: 'pwned' }`, and the
    // persisted user row would reflect both (admin promotion + password
    // takeover via the magic-link landing page).
    const seenAtHook: Array<Record<string, unknown>> = [];
    const app = await prepareWfApp({
      inviteOpts: { accept: { showConfirmation: false } },
      inviteHooks: {
        // `ProfileWithRolesForm` legitimizes the privileged top-level keys
        // as accepted form fields, so the upstream atscript form validator
        // does NOT strip them. The strip we're testing is the workflow's
        // own `STRIPPED_FROM_PROFILE` set.
        getProfileForm: () => ProfileWithRolesForm,
        // Capture what the workflow hands to `applyProfile` AND persist it
        // so the post-flow user-row assertions see the merged result.
        applyProfile: async ({ username, profile }) => {
          seenAtHook.push({ ...profile });
          await app.users.update(username, profile);
        },
      },
    });

    // Admin grants the invitee only the 'user' role.
    const r1 = await app.trigger({ wfid: "auth.invite" });
    await app.trigger({
      wfs: r1.body?.wfs as string,
      input: { email: "victim@test.com", roles: ["user"] },
    });

    // User accepts via magic link, sets a real password.
    const token = new URL(app.emails[0].url as string).searchParams.get("wfs") as string;
    const r3 = await app.resumeViaQuery(token);
    const r4 = await app.trigger({
      wfs: r3.body?.wfs as string,
      input: { newPassword: "RealPassword123", confirmPassword: "RealPassword123" },
    });

    // Profile pause — submit declared legitimate fields PLUS the attacker
    // bag (all keys are accepted by `ProfileWithRolesForm`).
    const r5 = await app.trigger({
      wfs: r4.body?.wfs as string,
      input: {
        firstName: "Pat",
        lastName: "Patel",
        // ── attacker-controlled extras (must all be stripped) ──────────
        roles: ["admin", "root"],
        password: { hash: "pwned" },
        passwordHistory: ["pwned"],
        account: { active: true, locked: false, pendingInvitation: false },
        mfa: { enabled: true },
        trustedDevices: ["attacker-device"],
        backupCodes: ["attacker-code"],
        version: 9999,
        id: "spoofed-id",
        username: "spoofed",
      },
    });
    expect((r5.body?.data as Record<string, unknown>)?.userId).toBe("victim@test.com");

    // The `applyProfile` hook MUST receive a payload with all strip-list
    // keys removed (workflow-level enforcement — even though the form
    // schema declares them, the workflow does not let them through).
    expect(seenAtHook).toHaveLength(1);
    for (const key of [
      "roles",
      "password",
      "passwordHistory",
      "account",
      "mfa",
      "trustedDevices",
      "backupCodes",
      "version",
      "id",
      "username",
    ]) {
      expect(seenAtHook[0]).not.toHaveProperty(key);
    }

    // Persisted user-row consequences of the strip.
    const user = (await app.users.getUser("victim@test.com")) as unknown as Record<string, unknown>;
    // 1) Roles NOT escalated — still the admin-granted set.
    expect(user.roles).toEqual(["user"]);
    // 2) Password NOT overwritten by the bag's 'pwned' hash.
    expect((user.password as { hash?: string }).hash).not.toBe("pwned");
    expect(typeof (user.password as { hash?: string }).hash).toBe("string");
    // 3) Account flags reflect post-accept workflow state, NOT the bag.
    expect((user.account as { active?: boolean }).active).toBe(true);
    expect((user.account as { pendingInvitation?: boolean }).pendingInvitation).toBe(false);
    // 4) MFA + trustedDevices + backupCodes NOT enrolled via the strip-list.
    expect((user.mfa as { enabled?: boolean })?.enabled).toBeFalsy();
    expect(user.trustedDevices ?? []).toEqual([]);
    expect(user.backupCodes ?? []).toEqual([]);
    // 5) Legitimate profile fields still flowed through — the strip is
    //    targeted, not a blanket drop.
    expect(user.firstName).toBe("Pat");
    expect(user.lastName).toBe("Patel");
  });

  it("prepareUser hook is optional: invite still completes without it", async () => {
    // No `prepareUser` configured — `prepareWfApp` default does not set one.
    const app = await prepareWfApp();
    const r1 = await app.trigger({ wfid: "auth.invite" });
    await app.trigger({
      wfs: r1.body?.wfs as string,
      input: { email: "henry@test.com" },
    });
    const token = new URL(app.emails[0].url as string).searchParams.get("wfs") as string;
    const r3 = await app.resumeViaQuery(token);
    const r4 = await app.trigger({
      wfs: r3.body?.wfs as string,
      input: { newPassword: "NewPassword123", confirmPassword: "NewPassword123" },
    });
    expect((r4.body?.data as Record<string, unknown>)?.userId).toBe("henry@test.com");
    const user = await app.users.getUser("henry@test.com");
    expect(user.account.active).toBe(true);
  });
});

// Shared driver: admin invites → email arrives → resume magic link → set
// password. Stops at whatever pause follows password-set (e.g.
// `inviteEnrollPickMethod` when `mfa.mode: "required"`, or workflow end).
// Returns the response of the set-password POST.
async function driveToPostPassword(app: Awaited<ReturnType<typeof prepareWfApp>>, email: string) {
  const r1 = await app.trigger({ wfid: "auth.invite" });
  await app.trigger({ wfs: r1.body?.wfs as string, input: { email } });
  const token = new URL(app.emails[0].url as string).searchParams.get("wfs") as string;
  const r3 = await app.resumeViaQuery(token);
  return app.trigger({
    wfs: r3.body?.wfs as string,
    input: { newPassword: "NewPassword123", confirmPassword: "NewPassword123" },
  });
}

describe("InviteWorkflowOpts — mfa.mode='required' forced enrollment", () => {
  // WHY: the headline invariant — when policy says "MFA required", an invitee
  // must NOT be able to activate without enrolling a second factor first. The
  // 3 schema entries gated on `passwordSet && mfa.mode !== 'disabled'` MUST hold
  // the workflow at enrollment until a method is confirmed. Remove the SMS
  // branch (or invert the gate) and the user activates with `methods.length === 0`,
  // defeating the policy this option exists to enforce.
  it("sms path: invitee enrolls before activation; account active + sms method confirmed + default", async () => {
    const app = await prepareWfApp({
      inviteOpts: {
        mfa: { mode: "required" },
        accept: { showConfirmation: false },
      },
    });

    const r4 = await driveToPostPassword(app, "invitee@example.com");
    // Paused at EnrollPickMethodForm — NOT workflow-finished. `data` would
    // carry the auto-login envelope if activation slipped through.
    expect(r4.body?.wfs).toBeTruthy();
    expect(r4.body?.data).toBeUndefined();
    // Account NOT yet active — proves activation is gated behind enrollment.
    expect((await app.users.getUser("invitee@example.com")).account.active).toBe(false);

    // Phase 1: pick sms.
    const r5 = await app.trigger({
      wfs: r4.body?.wfs as string,
      input: { method: "sms" },
    });
    expect(r5.body?.wfs).toBeTruthy();
    expect(r5.body?.data).toBeUndefined();
    // No sms dispatched yet — Phase 2 (address) hasn't run.
    expect(app.sms.length).toBe(0);

    // Phase 2: supply address — pincode dispatched.
    const r6 = await app.trigger({
      wfs: r5.body?.wfs as string,
      input: { address: "+15551234567" },
    });
    expect(r6.body?.wfs).toBeTruthy();
    expect(r6.body?.data).toBeUndefined();
    expect(app.sms.length).toBe(1);
    expect(app.sms[0].recipient).toBe("+15551234567");
    const code = app.sms[0].code;

    // Phase 3: confirm pincode → enrollment commits → activation runs → finish.
    const r7 = await app.trigger({
      wfs: r6.body?.wfs as string,
      input: { code },
    });
    const data = r7.body?.data as Record<string, unknown> | undefined;
    expect(data?.userId).toBe("invitee@example.com");
    expect(typeof data?.accessToken).toBe("string");

    // Method persisted + confirmed + default — without these the next login
    // would re-trigger enrollment (or worse, accept any code).
    const user = await app.users.getUser("invitee@example.com");
    const sms = user.mfa.methods.find((m) => m.name === "sms");
    expect(sms?.value).toBe("+15551234567");
    expect(sms?.confirmed).toBe(true);
    expect(user.mfa.defaultMethod).toBe("sms");
    // Activation ran AFTER enrollment (schema order).
    expect(user.account.active).toBe(true);
  });

  // WHY: TOTP has no Phase 2 — the secret is server-provisioned in Phase 1
  // and the confirm code is derived from THAT secret. A wiring mistake could
  // either spuriously emit a pincode (TOTP secret leaks via SMS/email) or
  // accept any code (security hole at activation).
  it("totp path: secret provisioned, code accepted, method confirmed, no pincode emitted", async () => {
    const app = await prepareWfApp({
      inviteOpts: {
        mfa: { mode: "required" },
        accept: { showConfirmation: false },
      },
    });

    const r4 = await driveToPostPassword(app, "totper@example.com");
    expect(r4.body?.wfs).toBeTruthy();

    // Phase 1: pick totp — secret persisted unconfirmed on the user row.
    const r5 = await app.trigger({
      wfs: r4.body?.wfs as string,
      input: { method: "totp" },
    });
    expect(r5.body?.wfs).toBeTruthy();
    expect(r5.body?.data).toBeUndefined();

    const interimUser = await app.users.getUser("totper@example.com");
    const totp = interimUser.mfa.methods.find((m) => m.name === "totp");
    expect(totp?.confirmed).toBe(false);
    expect(typeof totp?.value).toBe("string");
    expect(totp!.value.length).toBeGreaterThan(0);

    const code = generateTotpCode(totp!.value);
    const r6 = await app.trigger({
      wfs: r5.body?.wfs as string,
      input: { code },
    });
    const data = r6.body?.data as Record<string, unknown> | undefined;
    expect(data?.userId).toBe("totper@example.com");
    expect(typeof data?.accessToken).toBe("string");

    // No pincode side-channel for TOTP — proves Phase 2 short-circuits on
    // method==='totp'. Sms stays empty; emails has ONLY the original invite
    // magic-link (no enrollment pincode email leaked).
    expect(app.sms.length).toBe(0);
    expect(app.emails.length).toBe(1);
    expect(app.emails[0].kind).toBe("invite.magicLink");

    const user = await app.users.getUser("totper@example.com");
    const totpFinal = user.mfa.methods.find((m) => m.name === "totp");
    expect(totpFinal?.confirmed).toBe(true);
    expect(user.mfa.defaultMethod).toBe("totp");
    expect(user.account.active).toBe(true);
  });

  // WHY: policy-loosening direction. With `mode: 'disabled'` the 3 enrollment
  // schema entries are gated out entirely, so the invitee MUST activate with
  // no MFA prompt. Pins that the disabled-mode branch routes around enrollment.
  // (Default `mode: 'optional'` would prompt with a skip available — different
  // semantics — so the test pins the no-prompt branch explicitly.)
  it("mode='disabled': invite skips enrollment, user activates with no MFA", async () => {
    const app = await prepareWfApp({
      inviteOpts: { accept: { showConfirmation: false }, mfa: { mode: "disabled" } },
    });

    const r4 = await driveToPostPassword(app, "nomfa@example.com");
    // No paused enrollment forms — workflow finishes directly with auto-login.
    const data = r4.body?.data as Record<string, unknown> | undefined;
    expect(data?.userId).toBe("nomfa@example.com");
    expect(typeof data?.accessToken).toBe("string");

    const user = await app.users.getUser("nomfa@example.com");
    expect(user.account.active).toBe(true);
    // Enrollment never ran — no unconfirmed method left dangling either.
    expect(user.mfa.methods).toHaveLength(0);
  });

  // WHY: if Phase 3 accepted any code, an attacker who intercepted the magic
  // link could enroll a TOTP they don't control. Pins that
  // `verifyTotpSetupCode` is actually called AND that the workflow stays
  // paused at the confirm step (does NOT progress to
  // `inviteUnsetPendingInvitation`/`inviteActivateUser`) on rejection.
  it("totp path: invalid setup code → form error, method stays unconfirmed, account NOT activated", async () => {
    const app = await prepareWfApp({
      inviteOpts: {
        mfa: { mode: "required" },
        accept: { showConfirmation: false },
      },
    });

    const r4 = await driveToPostPassword(app, "badcode@example.com");
    const r5 = await app.trigger({
      wfs: r4.body?.wfs as string,
      input: { method: "totp" },
    });
    const r6 = await app.trigger({
      wfs: r5.body?.wfs as string,
      input: { code: "000000" },
    });

    // Not finished — workflow re-prompts with a form error.
    expect(r6.body?.data).toBeUndefined();
    const errors = r6.body?.errors as Record<string, unknown> | undefined;
    expect(errors?.code).toBeTruthy();

    // Method stays unconfirmed AND account stays inactive — proves the
    // workflow paused at the enroll step and did NOT race past it to
    // unsetPendingInvitation/activate (the gates on those steps don't mention
    // `enrollDone`, so the only thing stopping activation is the pause itself).
    const user = await app.users.getUser("badcode@example.com");
    const totp = user.mfa.methods.find((m) => m.name === "totp");
    expect(totp?.confirmed).toBe(false);
    expect(user.account.active).toBe(false);
  });
});

describe("InviteWorkflowOpts — mfa.mode='optional' skip action", () => {
  // WHY (I1): mirrors L1 for invite — under optional mode the invitee MUST be
  // able to decline MFA via the `skip` action and still complete onboarding
  // (account activated, tokens issued). Without the helper's
  // `mode === 'optional' && resolveAction() === 'skip'` short-circuit, optional
  // would be indistinguishable from required at the invite tail, breaking the
  // onboarding opt-out contract.
  it("optional + invitee skips MFA setup → invite completes, account active, no MFA on user", async () => {
    const app = await prepareWfApp({
      inviteOpts: {
        mfa: { mode: "optional" },
        accept: { showConfirmation: false },
      },
    });

    const r4 = await driveToPostPassword(app, "optskip@example.com");
    // Paused at EnrollPickMethodForm (optional still PROMPTS) — not finished.
    expect(r4.body?.wfs).toBeTruthy();
    expect(r4.body?.data).toBeUndefined();
    // Account NOT yet active — proves activation is gated behind enrollment
    // (or its skip) at the schema level.
    expect((await app.users.getUser("optskip@example.com")).account.active).toBe(false);

    // Submit `skip` — short-circuit fires, schema falls through to activation.
    const r5 = await app.trigger({
      wfs: r4.body?.wfs as string,
      input: { action: "skip" },
    });
    const data = r5.body?.data as Record<string, unknown> | undefined;
    expect(data?.userId).toBe("optskip@example.com");
    expect(typeof data?.accessToken).toBe("string");

    const user = await app.users.getUser("optskip@example.com");
    expect(user.account.active).toBe(true);
    // No method persisted — proves the skip path ran, not a covert enroll.
    expect(user.mfa.methods).toHaveLength(0);
  });

  // WHY (I2): mirrors L2 for invite — under optional mode invitees who DO
  // pick a method must still get the full 3-phase enrollment. A regression
  // that hardwired optional→skip in the invite tail would silently leave
  // would-be MFA users without a confirmed second factor while still flipping
  // the account active.
  it("optional + invitee enrolls totp → totp confirmed + default, account active", async () => {
    const app = await prepareWfApp({
      inviteOpts: {
        mfa: { mode: "optional" },
        accept: { showConfirmation: false },
      },
    });

    const r4 = await driveToPostPassword(app, "optenroll@example.com");
    expect(r4.body?.wfs).toBeTruthy();

    // Phase 1: pick totp — secret persisted unconfirmed.
    const r5 = await app.trigger({
      wfs: r4.body?.wfs as string,
      input: { method: "totp" },
    });
    expect(r5.body?.wfs).toBeTruthy();
    expect(r5.body?.data).toBeUndefined();

    const interimUser = await app.users.getUser("optenroll@example.com");
    const totp = interimUser.mfa.methods.find((m) => m.name === "totp");
    expect(totp?.confirmed).toBe(false);
    expect(typeof totp?.value).toBe("string");
    expect(totp!.value.length).toBeGreaterThan(0);

    const code = generateTotpCode(totp!.value);
    const r6 = await app.trigger({
      wfs: r5.body?.wfs as string,
      input: { code },
    });
    const data = r6.body?.data as Record<string, unknown> | undefined;
    expect(data?.userId).toBe("optenroll@example.com");
    expect(typeof data?.accessToken).toBe("string");

    const user = await app.users.getUser("optenroll@example.com");
    const totpFinal = user.mfa.methods.find((m) => m.name === "totp");
    expect(totpFinal?.confirmed).toBe(true);
    expect(user.mfa.defaultMethod).toBe("totp");
    expect(user.account.active).toBe(true);
  });
});

describe("InviteWorkflowOpts — mfa enrollment ergonomics (PR7-1)", () => {
  // WHY (T-I1): pins the new `inviteEnrollAutoPick` schema entry
  // (gated on `transports.length === 1`) AND the matching update to
  // `inviteEnrollPickMethod`'s gate (`transports.length > 1`). The invite
  // schema is linear (no loop), so a 1-transport config MUST be routed via
  // the auto-pick step or no step would set `enrollMethod` — the schema
  // would then skip both address (no method) AND confirm (no method) and
  // race straight into activation with NO MFA enrolled, defeating
  // `mode: 'required'`. The "no picker pause + secret on user row + code
  // accepted" sequence pins all three pieces: auto-pick schema entry
  // present, helper's TOTP-secret provisioning runs inside auto-pick, and
  // the schema downstream `inviteEnrollConfirm` step routes correctly.
  it("T-I1: required + transports=['totp'] → no picker pause, secret auto-provisioned, code accepted", async () => {
    const app = await prepareWfApp({
      inviteOpts: {
        mfa: { mode: "required", transports: ["totp"] },
        accept: { showConfirmation: false },
      },
    });

    const r4 = await driveToPostPassword(app, "auto-totp@example.com");
    // No picker pause — body MUST be the confirm form (carries `code`),
    // NOT the picker form (which would carry `method`).
    expect(r4.body?.wfs).toBeTruthy();
    expect(r4.body?.data).toBeUndefined();
    const bodyJson = JSON.stringify(r4.body);
    expect(bodyJson).toMatch(/"code"/);
    // The picker form would expose a `method` field. Negative assertion
    // pins that the auto-pick step bypassed the picker. (Avoid matching
    // `methodName` which belongs to a different form unused in invite.)
    expect(bodyJson).not.toMatch(/"method"(?!Name)/);

    // Secret WAS provisioned in auto-pick — confirms the TOTP branch of
    // the helper's `transports.length === 1` block ran.
    const interim = await app.users.getUser("auto-totp@example.com");
    const totp = interim.mfa.methods.find((m) => m.name === "totp");
    expect(totp?.confirmed).toBe(false);
    expect(typeof totp?.value).toBe("string");
    expect(totp!.value.length).toBeGreaterThan(0);
    // Account NOT yet active — proves the schema is genuinely paused at
    // the confirm step, not racing past activation.
    expect(interim.account.active).toBe(false);

    const code = generateTotpCode(totp!.value);
    const r5 = await app.trigger({ wfs: r4.body?.wfs as string, input: { code } });
    const data = r5.body?.data as Record<string, unknown> | undefined;
    expect(data?.userId).toBe("auto-totp@example.com");
    expect(typeof data?.accessToken).toBe("string");

    const user = await app.users.getUser("auto-totp@example.com");
    const totpFinal = user.mfa.methods.find((m) => m.name === "totp");
    expect(totpFinal?.confirmed).toBe(true);
    expect(user.mfa.defaultMethod).toBe("totp");
    expect(user.account.active).toBe(true);
  });

  // WHY (T-I2): mirrors login T2 for invite — pins the Phase 2 `skip`
  // branch in the invite tail. Without it, an optional-mode invitee who
  // picks sms (commits to a method) then changes their mind at the address
  // form would be trapped (the schema entries for address/confirm both
  // gate on `enrollMethod` being set, with no escape hatch other than
  // the helper's skip handler). The post-skip assertions (account active +
  // 0 methods) prove the skip ran AND that activation proceeded normally.
  it("T-I2: optional + picks sms + skip from address form → activates, no method persisted", async () => {
    const app = await prepareWfApp({
      inviteOpts: {
        mfa: { mode: "optional" },
        accept: { showConfirmation: false },
      },
    });

    const r4 = await driveToPostPassword(app, "opt-addr-skip@example.com");
    // Pick sms → pause at address form.
    const r5 = await app.trigger({
      wfs: r4.body?.wfs as string,
      input: { method: "sms" },
    });
    expect(r5.body?.wfs).toBeTruthy();
    expect(app.sms.length).toBe(0);

    // Skip at address → schema falls through to activation.
    const r6 = await app.trigger({
      wfs: r5.body?.wfs as string,
      input: { action: "skip" },
    });
    const data = r6.body?.data as Record<string, unknown> | undefined;
    expect(data?.userId).toBe("opt-addr-skip@example.com");
    expect(typeof data?.accessToken).toBe("string");

    const user = await app.users.getUser("opt-addr-skip@example.com");
    expect(user.account.active).toBe(true);
    expect(user.mfa.methods).toHaveLength(0);
  });

  // WHY (T-I3): mirrors login T5 for invite — pins that
  // `cleanupEnrollment` runs in the invite tail too AND that the schema's
  // while-loop wrapper around the 4 enrolment entries causes re-entry to
  // `inviteEnrollPickMethod` after the switch. TOTP-then-switch is the
  // load-bearing case: Phase 1 has already persisted the unconfirmed TOTP
  // row, so without cleanup the user would activate (post-re-pick) with a
  // stale unconfirmed TOTP row PLUS the confirmed sms. Without the
  // while-loop wrapper, control would fall through to
  // `inviteCollectProfile` → `inviteActivateUser` with zero confirmed
  // methods (defeating `mfa.mode: 'required'`). The final assertion
  // (only sms present + account active) pins both halves.
  it("T-I3: useDifferentMethod from Phase 3 (totp) → totp row REMOVED, re-pick sms completes", async () => {
    const app = await prepareWfApp({
      inviteOpts: {
        mfa: { mode: "required" },
        accept: { showConfirmation: false },
      },
    });

    const r4 = await driveToPostPassword(app, "invite-switch@example.com");
    const r5 = await app.trigger({
      wfs: r4.body?.wfs as string,
      input: { method: "totp" },
    });
    expect(r5.body?.wfs).toBeTruthy();
    const interim = await app.users.getUser("invite-switch@example.com");
    expect(interim.mfa.methods.find((m) => m.name === "totp")?.confirmed).toBe(false);

    const r6 = await app.trigger({
      wfs: r5.body?.wfs as string,
      input: { action: "useDifferentMethod" },
    });
    // Required-mode invariant: schema MUST hold at enrolment (re-prompt
    // at picker), NOT activate the account with no confirmed method.
    expect(r6.body?.wfs).toBeTruthy();
    expect(r6.body?.data).toBeUndefined();
    const afterSwitch = await app.users.getUser("invite-switch@example.com");
    expect(afterSwitch.mfa.methods.find((m) => m.name === "totp")).toBeUndefined();
    expect(afterSwitch.account.active).toBe(false);

    const r7 = await app.trigger({
      wfs: r6.body?.wfs as string,
      input: { method: "sms" },
    });
    const r8 = await app.trigger({
      wfs: r7.body?.wfs as string,
      input: { address: "+15558889999" },
    });
    expect(app.sms.length).toBe(1);
    const code = app.sms[0].code;
    const r9 = await app.trigger({ wfs: r8.body?.wfs as string, input: { code } });
    const data = r9.body?.data as Record<string, unknown> | undefined;
    expect(typeof data?.accessToken).toBe("string");

    const final = await app.users.getUser("invite-switch@example.com");
    expect(final.mfa.methods).toHaveLength(1);
    expect(final.mfa.methods[0].name).toBe("sms");
    expect(final.mfa.methods[0].confirmed).toBe(true);
    expect(final.mfa.defaultMethod).toBe("sms");
    expect(final.account.active).toBe(true);
  });
});
