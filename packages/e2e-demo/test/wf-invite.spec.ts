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

  it("WF-INVITE-01 — non-admin gated; admin caller succeeds + email captured", async () => {
    // Non-admin caller is denied at the first phase-A event (class-level
    // `@ArbacResource('auth.invite') @ArbacAction('start')` on the bundled
    // `InviteWorkflow`). Admin holds `allow('auth.invite', 'start')` and
    // drives the workflow to the magic-link send.
    const alice = app.fixtures.users.t1_alice; // member/viewer — no auth.invite grant
    const aliceTokens = await app.loginAs(alice);
    const denied = await app.triggerWf(
      "admin",
      { wfid: "auth.invite" },
      { token: aliceTokens.accessToken },
    );
    expect(denied.status).toBe(403);

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
        input: { email: NEW_INVITEE_EMAIL, roles: ["member", "viewer"] },
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
        input: { email: NEW_INVITEE_EMAIL, roles: ["member"] },
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

    const passwordRes = await app.triggerWf("public", {
      wfid: "auth.invite",
      wfs: resumedBody.wfs,
      input: { newPassword: STRONG_PASSWORD, confirmPassword: STRONG_PASSWORD },
    });
    // Demo wires `acceptProfileForm: InviteAcceptProfileForm` — workflow
    // pauses for profile collection after password-set.
    const profileBody = await readWfPause(passwordRes);
    const finalRes = await app.triggerWf("public", {
      wfid: "auth.invite",
      wfs: profileBody.wfs,
      input: { displayName: "New Hire" },
    });
    const finalBody = (await finalRes.json()) as { userId?: string; accessToken?: string };
    expect(finalBody.userId).toBe(NEW_INVITEE_EMAIL);
    expect(typeof finalBody.accessToken).toBe("string");

    const login = await app.loginRequest(NEW_INVITEE_EMAIL, STRONG_PASSWORD);
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

  it("WF-INVITE-06 — acceptProfileForm + applyProfile end-to-end (displayName/phone persisted)", async () => {
    // Demo wiring (src/app.ts) sets `acceptProfileForm: InviteAcceptProfileForm`
    // + custom `applyProfile` that calls `aooth.userService.update(...)`.
    // This test proves the form is rendered between password-set and accept,
    // the consumer callback fires with the raw profile, and the demo user
    // record carries the captured fields after accept.
    const dave = app.fixtures.users.t1_dave;
    const daveTokens = await app.loginAs(dave);
    const profileEmail = "profileuser@acme.test";

    const start = await app.triggerWf(
      "admin",
      { wfid: "auth.invite" },
      { token: daveTokens.accessToken },
    );
    const startBody = await readWfPause(start);
    await app.triggerWf(
      "admin",
      {
        wfid: "auth.invite",
        wfs: startBody.wfs,
        input: { email: profileEmail, roles: ["member"] },
      },
      { token: daveTokens.accessToken },
    );

    const captured = await app.emailSender.next(
      (e) => e.kind === "invite.magicLink" && e.recipient === profileEmail,
      2000,
    );

    const resumed = await app.resumeWfFromUrl(captured.url as string);
    const resumedBody = await readWfPause(resumed);

    // Step 1 of accept tail: set-password form.
    const afterPw = await app.triggerWf("public", {
      wfid: "auth.invite",
      wfs: resumedBody.wfs,
      input: { newPassword: STRONG_PASSWORD, confirmPassword: STRONG_PASSWORD },
    });
    const profileBody = await readWfPause(afterPw);
    // Workflow must pause again — this time for the consumer-supplied profile form.
    expect(profileBody.wfs).toBeTruthy();
    expect(JSON.stringify(profileBody)).toMatch(/displayName|phone/);

    // Submit the profile form → workflow continues into activate + auto-login.
    const finalRes = await app.triggerWf("public", {
      wfid: "auth.invite",
      wfs: profileBody.wfs,
      input: { displayName: "Profile User", phone: "+15555550100" },
    });
    const finalBody = (await finalRes.json()) as { userId?: string };
    expect(finalBody.userId).toBe(profileEmail);

    // The applyProfile callback wrote through to the user record.
    const userRow = (await app.appHandle.aooth.userStore.findByUsername(profileEmail)) as Record<
      string,
      unknown
    > | null;
    expect(userRow).toBeTruthy();
    expect(userRow?.displayName).toBe("Profile User");
    expect(userRow?.phone).toBe("+15555550100");
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

    const passwordRes = await app.triggerWf("public", {
      wfid: "auth.invite",
      wfs: firstBody.wfs,
      input: { newPassword: STRONG_PASSWORD, confirmPassword: STRONG_PASSWORD },
    });
    // Demo wires `acceptProfileForm` — submit the profile to fully consume.
    const profileBody = await readWfPause(passwordRes);
    const finalize = await app.triggerWf("public", {
      wfid: "auth.invite",
      wfs: profileBody.wfs,
      input: { displayName: "Single Use" },
    });
    expectOk(finalize);

    const replay = await app.resumeWfFromUrl(captured.url as string);
    expect(replay.status).toBeGreaterThanOrEqual(400);
    expect(replay.status).toBeLessThan(500);
  });
});

describe("WF-INVITE — accept options", () => {
  it("WF-INVITE-07 — accept.freshLoginRequired=true + loginUrl: terminal redirect honours custom URL", async () => {
    // End-to-end signal: demo defaults `freshLoginRequired:false` (auto-login
    // JSON). Flipping to true must bypass the auto-login finish and emit a
    // 302 to the configured `loginUrl` — proves the option threads through
    // the HTTP outlet on the real demo server. (Unit suite covers the schema
    // condition; this asserts the redirect headers reach the client.)
    const app = await buildTestApp({
      inviteOpts: {
        accept: { freshLoginRequired: true, loginUrl: "/welcome" },
      },
    });
    try {
      const dave = app.fixtures.users.t1_dave;
      const daveTokens = await app.loginAs(dave);
      const inviteEmail = "freshlogin-test@acme.test";

      const start = await app.triggerWf(
        "admin",
        { wfid: "auth.invite" },
        { token: daveTokens.accessToken },
      );
      const startBody = await readWfPause(start);
      await app.triggerWf(
        "admin",
        {
          wfid: "auth.invite",
          wfs: startBody.wfs,
          input: { email: inviteEmail, roles: ["member"] },
        },
        { token: daveTokens.accessToken },
      );
      const email = await app.emailSender.next(
        (e) => e.kind === "invite.magicLink" && e.recipient === inviteEmail,
        2000,
      );

      const resumed = await app.resumeWfFromUrl(email.url as string);
      const resumedBody = await readWfPause(resumed);
      // Submit set-password → demo's profile form fires next.
      const afterPw = await app.triggerWf("public", {
        wfid: "auth.invite",
        wfs: resumedBody.wfs,
        input: { newPassword: STRONG_PASSWORD, confirmPassword: STRONG_PASSWORD },
      });
      const profileBody = await readWfPause(afterPw);
      // Submit profile → terminal step. With freshLoginRequired on, this
      // must redirect to loginUrl, NOT return tokens.
      const finalize = await globalThis.fetch(`${app.baseUrl}/auth/trigger`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          wfid: "auth.invite",
          wfs: profileBody.wfs,
          input: { displayName: "Fresh Login User" },
        }),
        redirect: "manual",
      });
      expect(finalize.status).toBe(302);
      expect(finalize.headers.get("location")).toBe("/welcome");
    } finally {
      await app.close();
    }
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
