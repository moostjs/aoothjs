import { generateTotpCode } from "@aooth/user";
import type { TAtscriptAnnotatedType } from "@atscript/typescript/utils";
import { afterEach, beforeEach, describe, expect, it } from "vite-plus/test";

import { ExtraInfoForm } from "../src/test-fixtures/extra-info.as";
import {
  buildTestApp,
  expectFinished,
  expectOk,
  expectRedirect,
  readWfPause,
  sleep,
  type TestApp,
  wfErrors,
} from "./harness";

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
    const finalBody = await expectFinished<{ userId?: string; accessToken?: string }>(finalRes);
    expect(finalBody.data?.userId).toBe(NEW_INVITEE_EMAIL);
    expect(typeof finalBody.data?.accessToken).toBe("string");

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
    const finalBody = await expectFinished<{ userId?: string }>(finalRes);
    expect(finalBody.data?.userId).toBe(profileEmail);

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
    // Defence: with freshLoginRequired on, the terminal envelope MUST NOT
    // carry tokens — invitee is forced through a fresh sign-in.
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
      const afterPw = await app.triggerWf("public", {
        wfid: "auth.invite",
        wfs: resumedBody.wfs,
        input: { newPassword: STRONG_PASSWORD, confirmPassword: STRONG_PASSWORD },
      });
      const profileBody = await readWfPause(afterPw);
      const finalize = await app.triggerWf("public", {
        wfid: "auth.invite",
        wfs: profileBody.wfs,
        input: { displayName: "Fresh Login User" },
      });
      expectOk(finalize);
      const body = await expectFinished<{ accessToken?: unknown; refreshToken?: unknown }>(
        finalize,
      );
      const redirect = expectRedirect(body);
      expect(redirect.target).toBe("/welcome");
      expect(redirect.reason).toBe("fresh-login-required");
      expect(body.data?.accessToken).toBeUndefined();
      expect(body.data?.refreshToken).toBeUndefined();
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

// Drives the invite happy-path tail: admin invites → invitee receives magic
// link → resumes → sets password. Returns the password-POST response (which,
// depending on opts, either finishes or pauses on the next form). Email param
// scopes the captured magic-link event so parallel apps can't cross-talk.
async function startInviteAcceptTail(
  app: TestApp,
  email: string,
): Promise<{ resp: Response; pwBody: Awaited<ReturnType<typeof readWfPause>> }> {
  const dave = app.fixtures.users.t1_dave;
  const daveTokens = await app.loginAs(dave);

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
      input: { email, roles: ["member"] },
    },
    { token: daveTokens.accessToken },
  );

  const magicLink = await app.emailSender.next(
    (e) => e.kind === "invite.magicLink" && e.recipient === email,
    2000,
  );
  const resumed = await app.resumeWfFromUrl(magicLink.url as string);
  const resumedBody = await readWfPause(resumed);

  const pwRes = await app.triggerWf("public", {
    wfid: "auth.invite",
    wfs: resumedBody.wfs,
    input: { newPassword: STRONG_PASSWORD, confirmPassword: STRONG_PASSWORD },
  });
  return { resp: pwRes, pwBody: await readWfPause(pwRes) };
}

describe("WF-INVITE — MFA enrollment", () => {
  it("WF-INVITE-08 — mode='required' + email enrollment: account inactive until confirmed, then activates with email default", async () => {
    // Pins invite-time forced enrollment end-to-end. The mid-flow
    // `account.active === false` check (after password-set, before pincode
    // confirm) pins the schema-level activation gate — a regression letting
    // activation race past a paused enroll step would produce active accounts
    // with no second factor.
    const inviteEmail = "newcomer-email@acme.test";
    const otpEmail = "newcomer-otp@acme.test";
    const app = await buildTestApp({
      inviteOpts: { mfa: { mode: "required" }, accept: { showConfirmation: false } },
    });
    try {
      const { pwBody } = await startInviteAcceptTail(app, inviteEmail);
      // Paused at EnrollPickMethodForm, activation gate NOT yet flipped.
      expect(pwBody.wfs).toBeTruthy();
      expect((await app.appHandle.aooth.userService.getUser(inviteEmail)).account.active).toBe(
        false,
      );

      const r5 = await app.triggerWf("public", {
        wfid: "auth.invite",
        wfs: pwBody.wfs,
        input: { method: "email" },
      });
      const r5Body = await readWfPause(r5);
      expect(r5Body.wfs).toBeTruthy();

      const r6 = await app.triggerWf("public", {
        wfid: "auth.invite",
        wfs: r5Body.wfs,
        input: { address: otpEmail },
      });
      const r6Body = await readWfPause(r6);
      expect(r6Body.wfs).toBeTruthy();

      const pincodeEmail = await app.emailSender.next(
        (e) => e.kind === "login.pincode" && e.recipient === otpEmail,
        2000,
      );
      expect(pincodeEmail.code).toBeTruthy();

      const r7 = await app.triggerWf("public", {
        wfid: "auth.invite",
        wfs: r6Body.wfs,
        input: { code: pincodeEmail.code },
      });
      // Demo wires `acceptProfileForm: InviteAcceptProfileForm` — one more pause.
      const profileBody = await readWfPause(r7);
      const finalRes = await app.triggerWf("public", {
        wfid: "auth.invite",
        wfs: profileBody.wfs,
        input: { displayName: "New Comer" },
      });
      const finalBody = await expectFinished<{ userId?: string; accessToken?: string }>(finalRes);
      expect(finalBody.data?.userId).toBe(inviteEmail);
      expect(typeof finalBody.data?.accessToken).toBe("string");

      const user = await app.appHandle.aooth.userService.getUser(inviteEmail);
      const emailMethod = user.mfa.methods.find((m) => m.name === "email");
      expect(emailMethod?.value).toBe(otpEmail);
      expect(emailMethod?.confirmed).toBe(true);
      expect(user.mfa.defaultMethod).toBe("email");
      expect(user.account.active).toBe(true);
    } finally {
      await app.close();
    }
  });

  it("WF-INVITE-09 — mode='required' + TOTP enrollment: secret persisted, code accepted, no pincode side-channel", async () => {
    // Pins the TOTP Phase-2 short-circuit + `verifyTotpSetupCode` round-trip
    // at invite time. The no-pincode assertion guards against a wiring
    // regression that leaks the secret via email/SMS; the persisted-secret
    // round-trip guards against accepting any code (activation without a
    // real second factor).
    const inviteEmail = "newcomer-totp@acme.test";
    const app = await buildTestApp({
      inviteOpts: { mfa: { mode: "required" }, accept: { showConfirmation: false } },
    });
    try {
      const { pwBody } = await startInviteAcceptTail(app, inviteEmail);
      expect(pwBody.wfs).toBeTruthy();

      const r5 = await app.triggerWf("public", {
        wfid: "auth.invite",
        wfs: pwBody.wfs,
        input: { method: "totp" },
      });
      const r5Body = await readWfPause(r5);
      expect(r5Body.wfs).toBeTruthy();

      const interim = await app.appHandle.aooth.userService.getUser(inviteEmail);
      const totp = interim.mfa.methods.find((m) => m.name === "totp");
      expect(totp?.confirmed).toBe(false);
      expect(typeof totp?.value).toBe("string");
      expect(totp!.value.length).toBeGreaterThan(0);

      const code = generateTotpCode(totp!.value);
      const r6 = await app.triggerWf("public", {
        wfid: "auth.invite",
        wfs: r5Body.wfs,
        input: { code },
      });
      const profileBody = await readWfPause(r6);
      const finalRes = await app.triggerWf("public", {
        wfid: "auth.invite",
        wfs: profileBody.wfs,
        input: { displayName: "Totp User" },
      });
      const finalBody = await expectFinished<{ userId?: string }>(finalRes);
      expect(finalBody.data?.userId).toBe(inviteEmail);

      const pincodeLeak = app.emailSender.events.find(
        (e) => e.kind === "login.pincode" && e.recipient === inviteEmail,
      );
      expect(pincodeLeak).toBeUndefined();

      const user = await app.appHandle.aooth.userService.getUser(inviteEmail);
      expect(user.mfa.methods.find((m) => m.name === "totp")?.confirmed).toBe(true);
      expect(user.mfa.defaultMethod).toBe("totp");
      expect(user.account.active).toBe(true);
    } finally {
      await app.close();
    }
  });

  it("WF-INVITE-10 — mode='optional' + invitee picks `skip` → account active, no MFA enrolled", async () => {
    // Pins the invite-side optional-mode skip short-circuit. An inverted gate
    // would either force every invitee through full enrollment (breaks opt-out)
    // or leave a covert half-committed `mfa.methods` row behind.
    const inviteEmail = "newcomer-skip@acme.test";
    const app = await buildTestApp({
      inviteOpts: { mfa: { mode: "optional" }, accept: { showConfirmation: false } },
    });
    try {
      const { pwBody } = await startInviteAcceptTail(app, inviteEmail);
      // Optional STILL prompts — pause is expected here.
      expect(pwBody.wfs).toBeTruthy();
      expect((await app.appHandle.aooth.userService.getUser(inviteEmail)).account.active).toBe(
        false,
      );

      const r5 = await app.triggerWf("public", {
        wfid: "auth.invite",
        wfs: pwBody.wfs,
        input: { action: "skip" },
      });
      const profileBody = await readWfPause(r5);
      const finalRes = await app.triggerWf("public", {
        wfid: "auth.invite",
        wfs: profileBody.wfs,
        input: { displayName: "Skip User" },
      });
      const finalBody = await expectFinished<{ userId?: string }>(finalRes);
      expect(finalBody.data?.userId).toBe(inviteEmail);

      const user = await app.appHandle.aooth.userService.getUser(inviteEmail);
      expect(user.account.active).toBe(true);
      // No leftover unconfirmed method — proves skip ran, not a covert enroll.
      expect(user.mfa.methods).toHaveLength(0);
    } finally {
      await app.close();
    }
  });
});

describe("WF-INVITE — extraSteps", () => {
  it("WF-INVITE-11 — single extraStep: handler invoked with sanitized data; user activates", async () => {
    // Pins the consumer-facing extraSteps API: typed form values round-trip
    // through the wire and arrive at the handler as `{ username, data }`
    // (not a raw request body), and activation still runs after the loop.
    const inviteEmail = "newcomer-extra@acme.test";
    const captured: Array<{ username: string; data: Record<string, unknown> }> = [];
    const app = await buildTestApp({
      inviteOpts: {
        accept: { showConfirmation: false },
        extraSteps: [
          {
            id: "info",
            form: ExtraInfoForm as unknown as TAtscriptAnnotatedType,
            handle: ({ username, data }) => {
              captured.push({ username, data });
            },
          },
        ],
      },
    });
    try {
      const { pwBody } = await startInviteAcceptTail(app, inviteEmail);
      // Demo wires acceptProfileForm — profile prompt runs BEFORE extraSteps.
      const afterProfile = await app.triggerWf("public", {
        wfid: "auth.invite",
        wfs: pwBody.wfs,
        input: { displayName: "Extra User" },
      });
      const extraBody = await readWfPause(afterProfile);
      expect(extraBody.wfs).toBeTruthy();

      const submit = await app.triggerWf("public", {
        wfid: "auth.invite",
        wfs: extraBody.wfs,
        input: { fullName: "Alice Cooper", dateOfBirth: "1990-05-15" },
      });
      const finalBody = await expectFinished<{ userId?: string }>(submit);
      expect(finalBody.data?.userId).toBe(inviteEmail);

      expect(captured).toHaveLength(1);
      expect(captured[0].username).toBe(inviteEmail);
      expect(captured[0].data.fullName).toBe("Alice Cooper");
      expect(captured[0].data.dateOfBirth).toBe("1990-05-15");

      expect((await app.appHandle.aooth.userService.getUser(inviteEmail)).account.active).toBe(
        true,
      );
    } finally {
      await app.close();
    }
  });

  it("WF-INVITE-12 — extraStep handler throws Error → form re-prompt with formMessage; retry succeeds", async () => {
    // Pins error-recovery wire: a handler throwing `Error("...")` must surface
    // as a re-prompt with the message on `inputRequired.context.errors.__form`
    // (NOT a 500, NOT a workflow abort), and account activation must NOT
    // advance past the rejected step. The `fullName.length < 5` rule is
    // server-side ONLY — the form's `@expect.minLength 2` accepts both inputs
    // so the handler is the isolated rejector under test.
    const inviteEmail = "newcomer-retry@acme.test";
    let invocations = 0;
    const app = await buildTestApp({
      inviteOpts: {
        accept: { showConfirmation: false },
        extraSteps: [
          {
            id: "info",
            form: ExtraInfoForm as unknown as TAtscriptAnnotatedType,
            handle: ({ data }) => {
              invocations++;
              const raw = data.fullName;
              const name = typeof raw === "string" ? raw : "";
              if (name.length < 5) throw new Error("Name too short");
            },
          },
        ],
      },
    });
    try {
      const { pwBody } = await startInviteAcceptTail(app, inviteEmail);
      const afterProfile = await app.triggerWf("public", {
        wfid: "auth.invite",
        wfs: pwBody.wfs,
        input: { displayName: "Retry User" },
      });
      const extraBody = await readWfPause(afterProfile);
      expect(extraBody.wfs).toBeTruthy();

      const reject = await app.triggerWf("public", {
        wfid: "auth.invite",
        wfs: extraBody.wfs,
        input: { fullName: "Bob", dateOfBirth: "1985-01-01" },
      });
      const rejectBody = await readWfPause(reject);
      expect(rejectBody.wfs).toBeTruthy();
      expect((rejectBody as { finished?: unknown }).finished).not.toBe(true);
      expect(wfErrors(rejectBody)["__form"]).toBe("Name too short");
      expect(invocations).toBe(1);
      expect((await app.appHandle.aooth.userService.getUser(inviteEmail)).account.active).toBe(
        false,
      );

      const accept = await app.triggerWf("public", {
        wfid: "auth.invite",
        wfs: rejectBody.wfs,
        input: { fullName: "Robert", dateOfBirth: "1985-01-01" },
      });
      const finalBody = await expectFinished<{ userId?: string }>(accept);
      expect(finalBody.data?.userId).toBe(inviteEmail);
      expect(invocations).toBe(2);
      expect((await app.appHandle.aooth.userService.getUser(inviteEmail)).account.active).toBe(
        true,
      );
    } finally {
      await app.close();
    }
  });
});
