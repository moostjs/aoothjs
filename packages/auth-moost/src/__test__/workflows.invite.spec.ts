import { describe, expect, it } from "vite-plus/test";

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
    expect(r4.body?.userId).toBe("bob@test.com");
    expect(typeof r4.body?.accessToken).toBe("string");

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
    expect(r4.body?.userId).toBe("henry@test.com");
    const user = await app.users.getUser("henry@test.com");
    expect(user.account.active).toBe(true);
  });
});
