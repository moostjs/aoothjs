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
      input: { email: "bob@test.com", roles: "admin, editor" },
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

  it("expired invite token: 410 on resume", async () => {
    const app = await prepareWfApp({ inviteTokenTtlMs: 1000 });
    const r1 = await app.trigger({ wfid: "auth.invite" });
    await app.trigger({
      wfs: r1.body?.wfs as string,
      input: { email: "dave@test.com" },
    });
    const token = new URL(app.emails[0].url as string).searchParams.get("wfs") as string;

    // Simulate expiry by deleting the row.
    await app.store.delete(token);

    const r3 = await app.resumeViaQuery(token);
    expect(r3.status).toBe(410);
  });

  it("roles trimming / parsing: empty entries skipped", async () => {
    const app = await prepareWfApp();
    const r1 = await app.trigger({ wfid: "auth.invite" });
    await app.trigger({
      wfs: r1.body?.wfs as string,
      input: { email: "eve@test.com", roles: ", admin , , editor ,  " },
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
});
