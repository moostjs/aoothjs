import { afterEach, beforeEach, describe, expect, it } from "vite-plus/test";

import { buildTestApp, expectOk, readWfPause, sleep, type TestApp } from "./harness";

const STRONG_PASSWORD = "WelcomeP1ss!";
const NEW_INVITEE_EMAIL = "newhire@acme.test";

describe("WF-INVITE — admin-gated invite", () => {
  let app: TestApp;

  beforeEach(async () => {
    app = await buildTestApp();
  });
  afterEach(async () => {
    await app.close();
  });

  it("WF-INVITE-01 — non-admin caller is rejected; admin caller succeeds + email captured", async () => {
    const alice = app.fixtures.users.t1_alice;
    const aliceTokens = await app.loginAs(alice);

    const nonAdminStart = await app.triggerWf(
      "admin",
      { wfid: "auth.invite" },
      {
        token: aliceTokens.accessToken,
      },
    );
    expect(nonAdminStart.status).toBe(403);

    const dave = app.fixtures.users.t1_dave;
    const daveTokens = await app.loginAs(dave);

    const start = await app.triggerWf(
      "admin",
      { wfid: "auth.invite" },
      {
        token: daveTokens.accessToken,
      },
    );
    expectOk(start);
    const startBody = await readWfPause(start);
    expect(startBody.wfs).toBeTruthy();

    const submit = await app.triggerWf(
      "admin",
      {
        wfid: "auth.invite",
        wfs: startBody.wfs,
        input: { email: NEW_INVITEE_EMAIL, roles: "member, viewer" },
      },
      { token: daveTokens.accessToken },
    );
    expectOk(submit);

    const email = await app.emailSender.next(
      (e) => e.kind === "invite.magicLink" && e.recipient === NEW_INVITEE_EMAIL,
      2000,
    );
    expect(email.url).toContain("?wfs=");
    expect(email.metadata).toMatchObject({ roles: ["member", "viewer"] });
  });

  it("WF-INVITE-02 — accept activates user, issues tokens, user can log in fresh", async () => {
    const dave = app.fixtures.users.t1_dave;
    const daveTokens = await app.loginAs(dave);

    const start = await app.triggerWf(
      "admin",
      { wfid: "auth.invite" },
      {
        token: daveTokens.accessToken,
      },
    );
    const startBody = await readWfPause(start);
    await app.triggerWf(
      "admin",
      {
        wfid: "auth.invite",
        wfs: startBody.wfs,
        input: { email: NEW_INVITEE_EMAIL, roles: "member" },
      },
      { token: daveTokens.accessToken },
    );

    const email = await app.emailSender.next(
      (e) => e.kind === "invite.magicLink" && e.recipient === NEW_INVITEE_EMAIL,
      2000,
    );

    const resumed = await app.resumeWfFromUrl(email.url as string);
    const resumedBody = await readWfPause(resumed);
    expect(resumedBody.wfs).toBeTruthy();
    expect(resumedBody.inputRequired).toBeTruthy();

    const finalRes = await app.triggerWf("public", {
      wfid: "auth.invite",
      wfs: resumedBody.wfs,
      input: { newPassword: STRONG_PASSWORD, confirmPassword: STRONG_PASSWORD },
    });
    const finalBody = (await finalRes.json()) as { userId?: string; accessToken?: string };
    expect(finalBody.userId).toBe(NEW_INVITEE_EMAIL);
    expect(typeof finalBody.accessToken).toBe("string");

    const login = await app.fetch("/auth/login", {
      method: "POST",
      json: { username: NEW_INVITEE_EMAIL, password: STRONG_PASSWORD },
    });
    expectOk(login);
  });

  it("WF-INVITE-03 — invite for an existing user email returns 409", async () => {
    const dave = app.fixtures.users.t1_dave;
    const daveTokens = await app.loginAs(dave);
    const bob = app.fixtures.users.t1_bob;

    const start = await app.triggerWf(
      "admin",
      { wfid: "auth.invite" },
      {
        token: daveTokens.accessToken,
      },
    );
    const startBody = await readWfPause(start);
    const conflict = await app.triggerWf(
      "admin",
      {
        wfid: "auth.invite",
        wfs: startBody.wfs,
        input: { email: bob.email },
      },
      { token: daveTokens.accessToken },
    );
    expect(conflict.status).toBe(409);
  });

  it("WF-INVITE-05 — magic link is single-use; replay after consumption returns 4xx", async () => {
    const dave = app.fixtures.users.t1_dave;
    const daveTokens = await app.loginAs(dave);
    const email1 = "single-use@acme.test";

    const start = await app.triggerWf(
      "admin",
      { wfid: "auth.invite" },
      {
        token: daveTokens.accessToken,
      },
    );
    const startBody = await readWfPause(start);
    await app.triggerWf(
      "admin",
      {
        wfid: "auth.invite",
        wfs: startBody.wfs,
        input: { email: email1 },
      },
      { token: daveTokens.accessToken },
    );

    const captured = await app.emailSender.next(
      (e) => e.kind === "invite.magicLink" && e.recipient === email1,
      2000,
    );

    const first = await app.resumeWfFromUrl(captured.url as string);
    const firstBody = await readWfPause(first);
    expect(firstBody.wfs).toBeTruthy();

    const finalize = await app.triggerWf("public", {
      wfid: "auth.invite",
      wfs: firstBody.wfs,
      input: { newPassword: STRONG_PASSWORD, confirmPassword: STRONG_PASSWORD },
    });
    expectOk(finalize);

    const replay = await app.resumeWfFromUrl(captured.url as string);
    expect(replay.status).toBeGreaterThanOrEqual(400);
    expect(replay.status).toBeLessThan(500);
  });
});

describe("WF-INVITE — TTL expiry", () => {
  it("WF-INVITE-04 — invite link expires after TTL (config-driven)", async () => {
    // BUG-12 fix: `inviteTokenTtlMs` (env.INVITE_TTL_MS) now drives the
    // persisted wf-state token expiry, not just the email envelope display.
    const app = await buildTestApp({ envOverrides: { INVITE_TTL_MS: 1000 } });
    try {
      const dave = app.fixtures.users.t1_dave;
      const daveTokens = await app.loginAs(dave);
      const inviteEmail = "ttl-test@acme.test";

      const start = await app.triggerWf(
        "admin",
        { wfid: "auth.invite" },
        {
          token: daveTokens.accessToken,
        },
      );
      const startBody = await readWfPause(start);
      await app.triggerWf(
        "admin",
        {
          wfid: "auth.invite",
          wfs: startBody.wfs,
          input: { email: inviteEmail },
        },
        { token: daveTokens.accessToken },
      );

      const captured = await app.emailSender.next(
        (e) => e.kind === "invite.magicLink" && e.recipient === inviteEmail,
        2000,
      );

      // Wait past the TTL so the persisted token expires before resume.
      await sleep(1100);

      const replay = await app.resumeWfFromUrl(captured.url as string);
      expect(replay.status).toBe(410);
    } finally {
      await app.close();
    }
  });
});
