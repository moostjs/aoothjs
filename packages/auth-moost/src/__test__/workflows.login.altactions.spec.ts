/**
 * Alt-action routing tests for `LoginWorkflow`. One test per row of the
 * "Alt-action catalog" table in WF_LOGIN.md §"Alt-action catalog".
 *
 * The alt-action delivery model the workflow uses is documented at the top of
 * `login.workflow.ts`: form payloads carry `action?: string` alongside the
 * normal fields. Each form-bearing step inspects `input.action` for routing.
 *
 * NB: BUG-LOGIN-1 (credentials alt actions) is covered in `workflows.login.options.spec.ts`.
 * Several alt actions on later steps (`useDifferentMethod`, `resend`) are
 * affected by the same general "alt handler returns undefined → falls through
 * to form validation" pattern (see BUG-LOGIN-3 / BUG-LOGIN-4 markers below).
 */
import { generateTotpSecret } from "@aooth/user";
import { describe, expect, it } from "vite-plus/test";

import { LoginWorkflow } from "../workflows/index";
import { prepareWfApp, seedActiveUser, withLoginMfaCtx } from "./workflow-utils";

/** Drives credentials + select2fa pick to land at `pincode-check-login` (email transport). */
async function driveToPincodeCheck(
  app: Awaited<ReturnType<typeof prepareWfApp>>,
  username = "alice",
): Promise<{ wfs: string; pin: string }> {
  await seedActiveUser(app.users, username, "Password123");
  await app.users.addMfaMethod(username, {
    name: "email",
    value: `${username}@example.com`,
    confirmed: true,
  });
  const secret = generateTotpSecret();
  await app.users.addMfaMethod(username, { name: "totp", value: secret, confirmed: true });

  const r1 = await app.trigger({ wfid: "auth/login/flow" });
  const credResp = await app.trigger({
    wfs: r1.body?.wfs as string,
    input: { username, password: "Password123" },
  });
  // 2 methods → select2fa fires.
  const sel = await app.trigger({
    wfs: credResp.body?.wfs as string,
    input: { methodName: "email", saveAsDefault: false },
  });
  // Now paused for pincode entry — pin was sent via email transport.
  const last = app.emails[app.emails.length - 1];
  if (!last?.code) throw new Error(`expected email with code, got ${JSON.stringify(last)}`);
  return { wfs: sel.body?.wfs as string, pin: last.code };
}

describe("LoginWorkflow alt-actions — pincode-check-login", () => {
  it("resend within pinTimeout → form error 'Please wait Ns'", async () => {
    const app = await prepareWfApp({
      authOpts: { mfa: { pincodeResendTimeoutMs: 60_000 } }, // generous so we land inside the window
    });
    const { wfs } = await driveToPincodeCheck(app);
    const r = await app.trigger({ wfs, input: { action: "resend" } });
    const errors = r.body?.errors as Record<string, string> | undefined;
    expect(errors?.__form).toMatch(/wait \d+s/i);
  });

  // Phase 4 MFA steps are wrapped in a `while: !mfaChecked` loop so
  // `useDifferentMethod` (which clears `mfaMethod`) re-enters select2fa.
  it("useDifferentMethod → loops back to select2fa", async () => {
    const app = await prepareWfApp();
    const { wfs } = await driveToPincodeCheck(app);
    const r = await app.trigger({ wfs, input: { action: "useDifferentMethod" } });
    expect(r.body?.wfs).toBeTruthy();
    expect(JSON.stringify(r.body)).toMatch(/methodName/);
  });

  // SECURITY: useDifferentMethod → select2fa → re-pick same channel must not
  // re-send another SMS/email within the per-method cooldown. Without this
  // throttle an attacker could spam SMS/email by alternating pick → switch →
  // pick. The `select2fa` step rejects with a `methodName` error and the
  // pincode-send step never re-fires.
  it("useDifferentMethod → re-pick same method within cooldown → rejected, no new send", async () => {
    const app = await prepareWfApp({
      authOpts: { mfa: { pincodeResendTimeoutMs: 60_000 } },
    });
    const { wfs } = await driveToPincodeCheck(app);
    const sentBefore = app.emails.length;

    const sw = await app.trigger({ wfs, input: { action: "useDifferentMethod" } });
    const back = await app.trigger({
      wfs: sw.body?.wfs as string,
      input: { methodName: "email", saveAsDefault: false },
    });
    const errors = back.body?.errors as Record<string, string> | undefined;
    expect(errors?.methodName).toMatch(/wait \d+s before requesting another email code/i);
    expect(app.emails.length).toBe(sentBefore);
  });

  // SECURITY: per-METHOD cooldown — not per-pick. The test above proves the
  // throttle exists when the attacker re-picks the SAME channel back-to-back.
  // The bypass would be alternation: pick sms → switch (useDifferentMethod →
  // select2fa) → pick email (different channel, fresh) → switch again → pick
  // sms. If the cooldown were per-pick the second sms send would re-fire and
  // an attacker could spam an arbitrary phone (SMS-pumping fraud) or burn an
  // email address by toggling channels. Per-method scoping closes that loop:
  // the timestamp travels with the channel, not the pick action, so coming
  // back to sms within its own window is rejected — and crucially the captured
  // sms array length is unchanged from the first send.
  it("useDifferentMethod → sms→email→sms alternation: sms cooldown holds across channel switches (per-method, not per-pick)", async () => {
    const app = await prepareWfApp({
      authOpts: { mfa: { pincodeResendTimeoutMs: 60_000 } },
      loginWorkflowClass: withLoginMfaCtx(LoginWorkflow, {
        availableMfaTransports: ["email", "sms"],
      }),
    });
    // Enrol BOTH sms and email so select2fa offers two picks.
    await seedActiveUser(app.users, "alice", "Password123");
    await app.users.addMfaMethod("alice", {
      name: "email",
      value: "alice@example.com",
      confirmed: true,
    });
    await app.users.addMfaMethod("alice", {
      name: "sms",
      value: "+15555550100",
      confirmed: true,
    });

    const r1 = await app.trigger({ wfid: "auth/login/flow" });
    const cred = await app.trigger({
      wfs: r1.body?.wfs as string,
      input: { username: "alice", password: "Password123" },
    });
    // 2 methods → select2fa pauses. Pick sms first → captures first sms send.
    const pickSms = await app.trigger({
      wfs: cred.body?.wfs as string,
      input: { methodName: "sms", saveAsDefault: false },
    });
    expect(app.sms.length).toBe(1);
    const smsCountAfterFirstPick = app.sms.length;

    // Switch away to select2fa.
    const sw1 = await app.trigger({
      wfs: pickSms.body?.wfs as string,
      input: { action: "useDifferentMethod" },
    });
    // Pick email — DIFFERENT channel, must be allowed and must send an email
    // (this proves the throttle is per-channel, not a global cooldown that
    // would also block the email pick).
    const emailsBeforeEmailPick = app.emails.length;
    const pickEmail = await app.trigger({
      wfs: sw1.body?.wfs as string,
      input: { methodName: "email", saveAsDefault: false },
    });
    expect(app.emails.length).toBe(emailsBeforeEmailPick + 1);

    // Switch away again to select2fa.
    const sw2 = await app.trigger({
      wfs: pickEmail.body?.wfs as string,
      input: { action: "useDifferentMethod" },
    });
    // Re-pick sms — still inside its own 60s window → must be rejected with
    // the per-method cooldown error and the sms array length must NOT grow.
    const repickSms = await app.trigger({
      wfs: sw2.body?.wfs as string,
      input: { methodName: "sms", saveAsDefault: false },
    });
    const errors = repickSms.body?.errors as Record<string, string> | undefined;
    expect(errors?.methodName).toMatch(/wait \d+s before requesting another sms code/i);
    expect(app.sms.length).toBe(smsCountAfterFirstPick);
  });

  it("valid code → mfaChecked true → tokens issued", async () => {
    const app = await prepareWfApp();
    const { wfs, pin } = await driveToPincodeCheck(app);
    const r = await app.trigger({ wfs, input: { code: pin, rememberDevice: false } });
    expect((r.body?.data as Record<string, unknown>)?.userId).toBe("alice");
  });

  it("invalid code → form error 'Invalid code'", async () => {
    const app = await prepareWfApp();
    const { wfs } = await driveToPincodeCheck(app);
    const r = await app.trigger({ wfs, input: { code: "999999", rememberDevice: false } });
    const errors = r.body?.errors as Record<string, string> | undefined;
    expect(errors?.code).toMatch(/Invalid code/);
  });
});

describe("LoginWorkflow alt-actions — mfa-totp", () => {
  // Same loop wrapping as BUG-LOGIN-3 — `useDifferentMethod` re-enters select2fa.
  it("useDifferentMethod → loops back to select2fa", async () => {
    const app = await prepareWfApp({
      loginWorkflowClass: withLoginMfaCtx(LoginWorkflow, {
        availableMfaTransports: ["email", "totp"],
      }),
    });
    await seedActiveUser(app.users, "alice", "Password123");
    await app.users.addMfaMethod("alice", {
      name: "email",
      value: "alice@example.com",
      confirmed: true,
    });
    const secret = generateTotpSecret();
    // Make totp the default so it's auto-picked on first round.
    await app.users.addMfaMethod("alice", { name: "totp", value: secret, confirmed: true });
    await app.users.setDefaultMfaMethod("alice", "totp");

    const r1 = await app.trigger({ wfid: "auth/login/flow" });
    const cred = await app.trigger({
      wfs: r1.body?.wfs as string,
      input: { username: "alice", password: "Password123" },
    });
    // Paused for TOTP code — submit useDifferentMethod.
    const r = await app.trigger({
      wfs: cred.body?.wfs as string,
      input: { action: "useDifferentMethod" },
    });
    expect(r.body?.wfs).toBeTruthy();
    expect(JSON.stringify(r.body)).toMatch(/methodName/);
  });

  it("invalid TOTP code → form error 'Invalid code'", async () => {
    const app = await prepareWfApp();
    await seedActiveUser(app.users, "alice", "Password123");
    const secret = generateTotpSecret();
    await app.users.addMfaMethod("alice", { name: "totp", value: secret, confirmed: true });

    const r1 = await app.trigger({ wfid: "auth/login/flow" });
    const cred = await app.trigger({
      wfs: r1.body?.wfs as string,
      input: { username: "alice", password: "Password123" },
    });
    const r = await app.trigger({ wfs: cred.body?.wfs as string, input: { code: "000000" } });
    const errors = r.body?.errors as Record<string, string> | undefined;
    expect(errors?.code).toMatch(/Invalid code/);
  });
});

// `create-password-form` no longer has any alt-actions. The bundled
// `SetPasswordForm` dropped `logout` / `cancel` / `backToLogin` because the
// user-facing escape mechanism is just closing the page (the wf state token
// expires per the engine's TTL). The previous two `'logout' alt` tests in
// this block were removed alongside the action.
//
// Terms-accept standalone step + `decline` alt-action were dropped — inline
// consent on `WithInlineConsentForm` replaces them (see Phase 1 of the
// terms/consent inlining refactor). Comprehensive coverage moves to Phase 2.
