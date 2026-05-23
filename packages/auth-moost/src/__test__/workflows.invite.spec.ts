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
