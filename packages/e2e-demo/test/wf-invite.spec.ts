// Value imports (not `type`) — these classes are referenced by the
// `OverrideInviteWorkflow` constructor's design:paramtypes metadata that
// moost's DI reads to resolve dependencies. A `type`-only import erases at
// compile time, leaving the metadata `undefined` and moost throwing
// "Class is not Injectable and not Optional" on first request.
import { AuthCredential } from "@aooth/auth";
import { InviteWorkflow } from "@aooth/auth-moost";
import { generateTotpCode, UserService } from "@aooth/user";
import { Controller, Inherit } from "moost";
import { afterEach, beforeEach, describe, expect, it } from "vite-plus/test";

import {
  buildTestApp,
  expectFinished,
  expectOk,
  expectRedirect,
  readWfPause,
  sleep,
  type TestApp,
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
      inviteOpts: { accept: { showConfirmation: false } },
      inviteMfaCtx: { mfaMode: "required" },
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
      inviteOpts: { accept: { showConfirmation: false } },
      inviteMfaCtx: { mfaMode: "required" },
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

  it("WF-INVITE-12 — mode='required' + transports=['totp'] auto-pick during invite: NO picker pause, account activates after confirm", async () => {
    // PR7-1: invite-side adds `inviteEnrollAutoPick` schema entry gated on
    // `transports.length === 1`, while existing `inviteEnrollPickMethod` is
    // now gated on `transports.length > 1`. WHY: without `inviteEnrollAutoPick`,
    // single-transport invites would slip past MFA entirely — the gated-out
    // pick step would be filtered, but address/confirm steps require
    // `enrollMethod` to be set, so they'd no-op and the account would activate
    // with no second factor. The mid-flow form-id assertion (EnrollConfirmForm,
    // NOT EnrollPickMethodForm) pins the new auto-pick step firing through the
    // demo's HTTP wire; the post-confirm assertion proves the second factor
    // landed before activation.
    const inviteEmail = "newcomer-autopick@acme.test";
    const app = await buildTestApp({
      inviteOpts: { accept: { showConfirmation: false } },
      inviteMfaCtx: { mfaMode: "required", availableMfaTransports: ["totp"] },
    });
    try {
      const { pwBody } = await startInviteAcceptTail(app, inviteEmail);
      expect(pwBody.wfs).toBeTruthy();
      // Critical: NO picker pause. With a single transport, `inviteEnrollAutoPick`
      // fires transparently between password-set and confirm. A regression that
      // removed the auto-pick step would either pause on EnrollPickMethodForm
      // (if it ungated back) or skip MFA entirely (if it didn't).
      // The demo uses `createAsHttpOutlet` which wraps the form schema under
      // `inputRequired.payload` (see workflows.recovery.options.spec.ts:610-614);
      // if auto-pick is removed, the payload id would be "EnrollPickMethodForm".
      expect((pwBody.inputRequired?.payload as { id?: string } | undefined)?.id).toBe(
        "EnrollConfirmForm",
      );
      // Account NOT yet active — activation must wait for confirm.
      expect((await app.appHandle.aooth.userService.getUser(inviteEmail)).account.active).toBe(
        false,
      );
      // TOTP must NOT route through email at invite time either.
      const pincodeLeak = app.emailSender.events.find(
        (e) => e.kind === "login.pincode" && e.recipient === inviteEmail,
      );
      expect(pincodeLeak).toBeUndefined();

      // Read the auto-provisioned secret, compute a code, submit confirm.
      const interim = await app.appHandle.aooth.userService.getUser(inviteEmail);
      const totp = interim.mfa.methods.find((m) => m.name === "totp");
      expect(totp?.confirmed).toBe(false);
      expect(typeof totp?.value).toBe("string");
      expect(totp!.value.length).toBeGreaterThan(0);
      const code = generateTotpCode(totp!.value);

      const confirm = await app.triggerWf("public", {
        wfid: "auth.invite",
        wfs: pwBody.wfs,
        input: { code },
      });
      // Demo wires acceptProfileForm — one more pause after MFA confirm.
      const profileBody = await readWfPause(confirm);
      const finalRes = await app.triggerWf("public", {
        wfid: "auth.invite",
        wfs: profileBody.wfs,
        input: { displayName: "Auto Pick" },
      });
      const finalBody = await expectFinished<{ userId?: string; accessToken?: string }>(finalRes);
      expect(finalBody.data?.userId).toBe(inviteEmail);
      expect(typeof finalBody.data?.accessToken).toBe("string");

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
      inviteOpts: { accept: { showConfirmation: false } },
      inviteMfaCtx: { mfaMode: "optional" },
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

/**
 * Drive `auth.invite` admin path far enough to leave a `pendingInvitation`
 * row in the user store, then STOP (don't accept the magic link). Returns
 * the admin tokens so callers (e.g. `startReInviteAcceptTail`) can reuse
 * them for the subsequent `auth.reInvite` admin call without a second
 * `loginAs` round-trip.
 */
async function createPendingInvitee(
  app: TestApp,
  email: string,
): Promise<{ daveTokens: Awaited<ReturnType<TestApp["loginAs"]>> }> {
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
  // Drain the first magic-link email so the reInvite path can assert on a
  // fresh one without the test grabbing the stale auth.invite send.
  await app.emailSender.next((e) => e.kind === "invite.magicLink" && e.recipient === email, 2000);
  return { daveTokens };
}

/**
 * Re-invite an existing pendingInvitation user. Mirrors `startInviteAcceptTail`
 * but starts via `auth.reInvite` (InviteEmailForm — just `email`, no roles)
 * instead of the admin invite form, then drives the magic-link resume + the
 * password-set step. Returns the paused body so the caller can inspect the
 * next step (enrollment, etc.).
 */
async function startReInviteAcceptTail(
  app: TestApp,
  email: string,
): Promise<{ pwBody: Awaited<ReturnType<typeof readWfPause>> }> {
  const { daveTokens } = await createPendingInvitee(app, email);
  const start = await app.triggerWf(
    "admin",
    { wfid: "auth.reInvite" },
    { token: daveTokens.accessToken },
  );
  const startBody = await readWfPause(start);
  await app.triggerWf(
    "admin",
    {
      wfid: "auth.reInvite",
      wfs: startBody.wfs,
      input: { email },
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
    wfid: "auth.reInvite",
    wfs: resumedBody.wfs,
    input: { newPassword: STRONG_PASSWORD, confirmPassword: STRONG_PASSWORD },
  });
  return { pwBody: await readWfPause(pwRes) };
}

describe("WF-INVITE — reInvite enrollment", () => {
  it("WF-INVITE-15 — reInvite + mode='required' + transports=['totp'] auto-pick: same enrollment branches as auth.invite", async () => {
    // Pins schema symmetry between `auth.invite` and `auth.reInvite`: both
    // wrap the 4 enrolment entries in the same while-loop with identical
    // conditions (invite.workflow.ts:557-592 mirrors invite.workflow.ts:391+).
    // A regression that drifted one schema (e.g. dropped the while-loop in
    // reInvite or re-typed `inviteEnrollAutoPick`'s condition) would silently
    // ship reInvitees past activation without a second factor even when
    // `mode='required'` — this test fails if reInvite's auto-pick branch
    // doesn't fire OR if the post-confirm activation gate is bypassed.
    const inviteEmail = "reinvite-autopick@acme.test";
    const app = await buildTestApp({
      inviteOpts: { accept: { showConfirmation: false } },
      inviteMfaCtx: { mfaMode: "required", availableMfaTransports: ["totp"] },
    });
    try {
      const { pwBody } = await startReInviteAcceptTail(app, inviteEmail);
      expect(pwBody.wfs).toBeTruthy();
      // Auto-pick → straight to confirm, no picker pause.
      expect((pwBody.inputRequired?.payload as { id?: string } | undefined)?.id).toBe(
        "EnrollConfirmForm",
      );
      // Activation gated until confirm completes.
      expect((await app.appHandle.aooth.userService.getUser(inviteEmail)).account.active).toBe(
        false,
      );

      const interim = await app.appHandle.aooth.userService.getUser(inviteEmail);
      const totp = interim.mfa.methods.find((m) => m.name === "totp");
      expect(totp?.confirmed).toBe(false);
      const code = generateTotpCode(totp!.value);

      const confirm = await app.triggerWf("public", {
        wfid: "auth.reInvite",
        wfs: pwBody.wfs,
        input: { code },
      });
      const profileBody = await readWfPause(confirm);
      const finalRes = await app.triggerWf("public", {
        wfid: "auth.reInvite",
        wfs: profileBody.wfs,
        input: { displayName: "ReInvite Auto" },
      });
      const finalBody = await expectFinished<{ userId?: string; accessToken?: string }>(finalRes);
      expect(finalBody.data?.userId).toBe(inviteEmail);
      expect(typeof finalBody.data?.accessToken).toBe("string");

      const user = await app.appHandle.aooth.userService.getUser(inviteEmail);
      expect(user.mfa.methods.find((m) => m.name === "totp")?.confirmed).toBe(true);
      expect(user.mfa.defaultMethod).toBe("totp");
      expect(user.account.active).toBe(true);
    } finally {
      await app.close();
    }
  });

  it("WF-INVITE-16 — reInvite + mode='optional' + invitee picks `skip`: activates with no MFA enrolled", async () => {
    // Pins the reInvite-side optional-mode skip short-circuit. If the
    // while-loop guard or the cleanupEnrollment branch drifted, an opt-out
    // reInvite would either fall through with a covert unconfirmed `mfa.methods`
    // row OR loop forever on the picker.
    const inviteEmail = "reinvite-skip@acme.test";
    const app = await buildTestApp({
      inviteOpts: { accept: { showConfirmation: false } },
      inviteMfaCtx: { mfaMode: "optional" },
    });
    try {
      const { pwBody } = await startReInviteAcceptTail(app, inviteEmail);
      expect(pwBody.wfs).toBeTruthy();
      expect((pwBody.inputRequired?.payload as { id?: string } | undefined)?.id).toBe(
        "EnrollPickMethodForm",
      );
      expect((await app.appHandle.aooth.userService.getUser(inviteEmail)).account.active).toBe(
        false,
      );

      const r5 = await app.triggerWf("public", {
        wfid: "auth.reInvite",
        wfs: pwBody.wfs,
        input: { action: "skip" },
      });
      const profileBody = await readWfPause(r5);
      const finalRes = await app.triggerWf("public", {
        wfid: "auth.reInvite",
        wfs: profileBody.wfs,
        input: { displayName: "ReInvite Skip" },
      });
      const finalBody = await expectFinished<{ userId?: string }>(finalRes);
      expect(finalBody.data?.userId).toBe(inviteEmail);

      const user = await app.appHandle.aooth.userService.getUser(inviteEmail);
      expect(user.account.active).toBe(true);
      expect(user.mfa.methods).toHaveLength(0);
    } finally {
      await app.close();
    }
  });
});

// Module-level capture for the `inviteExtraStep` override test. The custom
// workflow class is defined once at module scope so its decorators run a
// single time; the per-test reset in `beforeEach` keeps the captured value
// from leaking between runs.
let extraStepCapture: { fired: boolean; runs: number } = { fired: false, runs: 0 };

@Inherit()
@Controller()
class OverrideInviteWorkflow extends InviteWorkflow {
  constructor(users: UserService, authCred: AuthCredential) {
    // Profile form left undefined (base default) so the accept tail goes
    // password → extraStep → activate directly. MFA is disabled via the
    // `inviteMfaCtx: { mfaMode: 'disabled' }` knob on `buildTestApp` (PR9
    // stripped `mfa.mode` from `InviteWorkflowOpts`; the value now lives on
    // ctx via the `inviteSetupMfa` setter step — `buildApp` wraps this
    // class with `withInviteMfaCtx` when `inviteMfaCtx` is supplied).
    super({ accept: { showConfirmation: false } }, users, authCred);
  }
  // DemoUser requires tenantId on insert; without this override the
  // `invitePreCreateUser` step would 500 inside `userService.createUser`.
  protected override async prepareUser(): Promise<Record<string, unknown>> {
    return { tenantId: "_global" };
  }
  override async inviteExtraStep(): Promise<unknown> {
    extraStepCapture.fired = true;
    extraStepCapture.runs += 1;
    return undefined;
  }
}

describe("WF-INVITE — consumer subclass via inviteWorkflowClass", () => {
  beforeEach(() => {
    extraStepCapture = { fired: false, runs: 0 };
  });

  it("WF-INVITE-17 — custom InviteWorkflow subclass registered via inviteWorkflowClass: overridden `inviteExtraStep` fires through the HTTP+DI stack", async () => {
    // Pins the documented OOP extension point end-to-end: the unit test in
    // workflows.invite.subclass.spec.ts proves the override fires under the
    // in-memory test harness; this proves it ALSO fires when the subclass is
    // resolved by the demo's full DI graph + reaches the inviteExtraStep slot
    // via the real HTTP wire. A regression that re-typed the parent's
    // `inviteExtraStep` signature (e.g. added a required arg) would silently
    // break subclass overrides that didn't add the matching arg — those
    // wouldn't dispatch, this test would catch it.
    const inviteEmail = "override-extrastep@acme.test";
    const app = await buildTestApp({
      inviteWorkflowClass: OverrideInviteWorkflow,
      inviteMfaCtx: { mfaMode: "disabled" },
    });
    try {
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
          input: { email: inviteEmail, roles: ["member"] },
        },
        { token: daveTokens.accessToken },
      );
      const magicLink = await app.emailSender.next(
        (e) => e.kind === "invite.magicLink" && e.recipient === inviteEmail,
        2000,
      );
      const resumed = await app.resumeWfFromUrl(magicLink.url as string);
      const resumedBody = await readWfPause(resumed);
      const finalRes = await app.triggerWf("public", {
        wfid: "auth.invite",
        wfs: resumedBody.wfs,
        input: { newPassword: STRONG_PASSWORD, confirmPassword: STRONG_PASSWORD },
      });
      const finalBody = await expectFinished<{ userId?: string; accessToken?: string }>(finalRes);
      expect(finalBody.data?.userId).toBe(inviteEmail);
      expect(typeof finalBody.data?.accessToken).toBe("string");

      // The core proof: the override ran exactly once in the accept-tail
      // slot. `runs === 1` rules out a regression where the schema iterated
      // the step or skipped it.
      expect(extraStepCapture.fired).toBe(true);
      expect(extraStepCapture.runs).toBe(1);

      const user = await app.appHandle.aooth.userService.getUser(inviteEmail);
      expect(user.account.active).toBe(true);
    } finally {
      await app.close();
    }
  });
});
