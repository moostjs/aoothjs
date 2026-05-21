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

import { prepareWfApp, seedActiveUser } from "./workflow-utils";

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

  const r1 = await app.trigger({ wfid: "auth.login" });
  const credResp = await app.trigger({
    wfs: r1.body?.wfs as string,
    input: { username, password: "Password123" },
  });
  // 2 methods → select2fa fires.
  const sel = await app.trigger({
    wfs: credResp.body?.wfs as string,
    input: { methodName: "email" },
  });
  // Now paused for pincode entry — pin was sent via email transport.
  const last = app.emails[app.emails.length - 1];
  if (!last?.code) throw new Error(`expected email with code, got ${JSON.stringify(last)}`);
  return { wfs: sel.body?.wfs as string, pin: last.code };
}

describe("LoginWorkflow alt-actions — select2fa", () => {
  it("useBackupCode → pauses for MfaCodeForm (backup code entry)", async () => {
    const app = await prepareWfApp({
      loginOpts: { mfa: { backupCodes: true } },
    });
    await seedActiveUser(app.users, "alice", "Password123");
    await app.users.addMfaMethod("alice", {
      name: "email",
      value: "alice@example.com",
      confirmed: true,
    });
    const secret = generateTotpSecret();
    await app.users.addMfaMethod("alice", { name: "totp", value: secret, confirmed: true });

    const r1 = await app.trigger({ wfid: "auth.login" });
    const cred = await app.trigger({
      wfs: r1.body?.wfs as string,
      input: { username: "alice", password: "Password123" },
    });
    // 2 methods → select2fa.
    const sel = await app.trigger({
      wfs: cred.body?.wfs as string,
      input: { action: "useBackupCode" },
    });
    // Pauses for backup-code entry (MfaCodeForm).
    expect(sel.body?.wfs).toBeTruthy();
    // Body is the MfaCodeForm schema — has `code` field.
    expect(JSON.stringify(sel.body)).toMatch(/"code"/);
  });
});

describe("LoginWorkflow alt-actions — pincode-check-login", () => {
  it("resend within pinTimeout → form error 'Please wait Ns'", async () => {
    const app = await prepareWfApp({
      loginOpts: { mfa: { pincodeResendTimeoutMs: 60_000 } }, // generous so we land inside the window
    });
    const { wfs } = await driveToPincodeCheck(app);
    const r = await app.trigger({ wfs, input: { action: "resend" } });
    const errors = r.body?.errors as Record<string, string> | undefined;
    expect(errors?.__form).toMatch(/wait \d+s/i);
  });

  it("useBackupCode → branches to backup-code entry (MfaCodeForm)", async () => {
    const app = await prepareWfApp({
      loginOpts: { mfa: { backupCodes: true } },
    });
    const { wfs } = await driveToPincodeCheck(app);
    const r = await app.trigger({ wfs, input: { action: "useBackupCode" } });
    // Pauses for backup-code entry.
    expect(r.body?.wfs).toBeTruthy();
    expect(JSON.stringify(r.body)).toMatch(/"code"/);
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
      loginOpts: { mfa: { pincodeResendTimeoutMs: 60_000 } },
    });
    const { wfs } = await driveToPincodeCheck(app);
    const sentBefore = app.emails.length;

    const sw = await app.trigger({ wfs, input: { action: "useDifferentMethod" } });
    const back = await app.trigger({
      wfs: sw.body?.wfs as string,
      input: { methodName: "email" },
    });
    const errors = back.body?.errors as Record<string, string> | undefined;
    expect(errors?.methodName).toMatch(/wait \d+s before requesting another email code/i);
    expect(app.emails.length).toBe(sentBefore);
  });

  it("valid code → mfaChecked true → tokens issued", async () => {
    const app = await prepareWfApp();
    const { wfs, pin } = await driveToPincodeCheck(app);
    const r = await app.trigger({ wfs, input: { code: pin } });
    expect((r.body?.data as Record<string, unknown>)?.userId).toBe("alice");
  });

  it("invalid code → form error 'Invalid code'", async () => {
    const app = await prepareWfApp();
    const { wfs } = await driveToPincodeCheck(app);
    const r = await app.trigger({ wfs, input: { code: "999999" } });
    const errors = r.body?.errors as Record<string, string> | undefined;
    expect(errors?.code).toMatch(/Invalid code/);
  });
});

describe("LoginWorkflow alt-actions — mfa-totp", () => {
  it("useBackupCode → branches to backup-code entry", async () => {
    const app = await prepareWfApp({
      loginOpts: { mfa: { backupCodes: true, transports: ["totp"] } },
    });
    await seedActiveUser(app.users, "alice", "Password123");
    const secret = generateTotpSecret();
    await app.users.addMfaMethod("alice", { name: "totp", value: secret, confirmed: true });

    const r1 = await app.trigger({ wfid: "auth.login" });
    const cred = await app.trigger({
      wfs: r1.body?.wfs as string,
      input: { username: "alice", password: "Password123" },
    });
    // 1 method → no select2fa → paused at mfa-totp.
    const r = await app.trigger({
      wfs: cred.body?.wfs as string,
      input: { action: "useBackupCode" },
    });
    expect(r.body?.wfs).toBeTruthy();
    expect(JSON.stringify(r.body)).toMatch(/"code"/);
  });

  // Same loop wrapping as BUG-LOGIN-3 — `useDifferentMethod` re-enters select2fa.
  it("useDifferentMethod → loops back to select2fa", async () => {
    const app = await prepareWfApp({
      loginOpts: { mfa: { transports: ["email", "totp"] } },
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

    const r1 = await app.trigger({ wfid: "auth.login" });
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

    const r1 = await app.trigger({ wfid: "auth.login" });
    const cred = await app.trigger({
      wfs: r1.body?.wfs as string,
      input: { username: "alice", password: "Password123" },
    });
    const r = await app.trigger({ wfs: cred.body?.wfs as string, input: { code: "000000" } });
    const errors = r.body?.errors as Record<string, string> | undefined;
    expect(errors?.code).toMatch(/Invalid code/);
  });
});

describe("LoginWorkflow alt-actions — create-password-form", () => {
  // Abort alt-actions set `ctx.aborted = true`; all terminal steps gate on
  // `!ctx.aborted` so the abort response set via `useWfFinished()` survives.
  it("'logout' alt → aborts workflow with { aborted: true, reason: 'logout' }", async () => {
    const app = await prepareWfApp({
      loginOpts: {
        guards: { passwordInitial: true },
        mfa: { enabled: false },
      },
    });
    await seedActiveUser(app.users, "alice", "Password123");
    const store = (app.users as unknown as { store: { update: Function } }).store;
    await store.update("alice", { set: { password: { isInitial: true } } });
    const r1 = await app.trigger({ wfid: "auth.login" });
    const cred = await app.trigger({
      wfs: r1.body?.wfs as string,
      input: { username: "alice", password: "Password123" },
    });
    const r = await app.trigger({
      wfs: cred.body?.wfs as string,
      input: { action: "logout" },
    });
    expect(r.body).toMatchObject({ finished: true, aborted: true, reason: "logout" });
  });

  it("logout abort emits WfFinished envelope with aborted+reason:logout + info message", async () => {
    // Pins the WfFinished migration: abort callsites must carry the structured
    // `message` envelope (level + text) so the UI can render a banner instead
    // of stalling silently.
    const app = await prepareWfApp({
      loginOpts: {
        guards: { passwordInitial: true },
        mfa: { enabled: false },
      },
    });
    await seedActiveUser(app.users, "alice", "Password123");
    const store = (app.users as unknown as { store: { update: Function } }).store;
    await store.update("alice", { set: { password: { isInitial: true } } });
    const r1 = await app.trigger({ wfid: "auth.login" });
    const cred = await app.trigger({
      wfs: r1.body?.wfs as string,
      input: { username: "alice", password: "Password123" },
    });
    const r = await app.trigger({
      wfs: cred.body?.wfs as string,
      input: { action: "logout" },
    });
    expect(r.body).toMatchObject({
      finished: true,
      aborted: true,
      reason: "logout",
      message: { level: "info", text: "Signed out." },
    });
  });
});

describe("LoginWorkflow alt-actions — terms-accept", () => {
  // Abort alt-action gates the schema via `ctx.aborted` (see BUG-LOGIN-5 fix).
  it("'decline' alt → aborts workflow with friendly 'You must accept to continue' message", async () => {
    const app = await prepareWfApp({
      loginOpts: {
        acceptance: { termsVersion: "v2" },
        mfa: { enabled: false },
      },
    });
    await seedActiveUser(app.users, "alice", "Password123");
    const r1 = await app.trigger({ wfid: "auth.login" });
    const cred = await app.trigger({
      wfs: r1.body?.wfs as string,
      input: { username: "alice", password: "Password123" },
    });
    const r = await app.trigger({
      wfs: cred.body?.wfs as string,
      input: { action: "decline" },
    });
    expect(r.body).toMatchObject({
      finished: true,
      aborted: true,
      reason: "termsDeclined",
      message: { level: "info", text: expect.stringMatching(/must accept/i) },
    });
  });

  it("accept submit with mismatched version → form error", async () => {
    const app = await prepareWfApp({
      loginOpts: {
        acceptance: { termsVersion: "v2" },
        mfa: { enabled: false },
      },
    });
    await seedActiveUser(app.users, "alice", "Password123");
    const r1 = await app.trigger({ wfid: "auth.login" });
    const cred = await app.trigger({
      wfs: r1.body?.wfs as string,
      input: { username: "alice", password: "Password123" },
    });
    const r = await app.trigger({
      wfs: cred.body?.wfs as string,
      input: { acceptedVersion: "v1", accepted: true },
    });
    expect((r.body?.errors as Record<string, string>)?.acceptedVersion).toMatch(/mismatch/i);
  });

  it("accept submit with accepted=false → form error on `accepted` field", async () => {
    // The `accepted: boolean` field has @meta.required (an unchecked box ≡
    // missing required value), so the atscript validator returns the
    // ‘Must be checked’ message before the workflow's custom `accepted !== true`
    // branch runs. Either rejection path satisfies the spec intent: the user
    // can't proceed without checking the box.
    const app = await prepareWfApp({
      loginOpts: {
        acceptance: { termsVersion: "v2" },
        mfa: { enabled: false },
      },
    });
    await seedActiveUser(app.users, "alice", "Password123");
    const r1 = await app.trigger({ wfid: "auth.login" });
    const cred = await app.trigger({
      wfs: r1.body?.wfs as string,
      input: { username: "alice", password: "Password123" },
    });
    const r = await app.trigger({
      wfs: cred.body?.wfs as string,
      input: { acceptedVersion: "v2", accepted: false },
    });
    expect((r.body?.errors as Record<string, string>)?.accepted).toBeTruthy();
  });
});
