/**
 * Negative-path and edge-case coverage for `LoginWorkflow`. One test per row
 * of WF_LOGIN.md §"Tasks" item #6 "Edge cases" + the SMS-transport happy-path
 * + backup-code consume-twice.
 *
 * Existing tests in `workflows.login.spec.ts` already cover locked/inactive
 * on the credentials step — we add SMS, backup-code, and explicit MFA-lockout
 * coverage here.
 */
import { generateTotpSecret, hashMfaCode as _hash } from "@aooth/user";
import { describe, expect, it } from "vite-plus/test";

import { prepareWfApp, seedActiveUser } from "./workflow-utils";

// Touch the import so the linter doesn't strip it (used as a doc anchor).
void _hash;

describe("LoginWorkflow edge cases — credentials guards", () => {
  it("wrong password → form error 'Invalid credentials' (no enumeration, no 401)", async () => {
    // Existing covers: this — adding a sibling test that asserts the EXACT
    // error key shape used by the form (`__form` not `password`) so a refactor
    // that switches to per-field errors trips this test.
    const app = await prepareWfApp();
    await seedActiveUser(app.users, "alice", "Password123");
    const r1 = await app.trigger({ wfid: "auth.login" });
    const r2 = await app.trigger({
      wfs: r1.body?.wfs as string,
      input: { username: "alice", password: "Wrong0000" },
    });
    expect(r2.status).toBe(201);
    const errors = r2.body?.errors as Record<string, string> | undefined;
    expect(errors?.__form).toBe("Invalid credentials");
    // Anti-enumeration: no field-level "wrong password" message.
    expect(errors?.password).toBeUndefined();
  });

  it("unknown username → same form error key/value as wrong password (anti-enumeration)", async () => {
    const app = await prepareWfApp();
    await seedActiveUser(app.users, "alice", "Password123");
    const r1 = await app.trigger({ wfid: "auth.login" });
    const r2 = await app.trigger({
      wfs: r1.body?.wfs as string,
      input: { username: "ghost", password: "Password123" },
    });
    const errors = r2.body?.errors as Record<string, string> | undefined;
    expect(errors?.__form).toBe("Invalid credentials");
  });
});

describe("LoginWorkflow edge cases — MFA", () => {
  it("wrong MFA code repeatedly → eventually 423 (account locked) once UserService's lockout fires", async () => {
    // Tight lockout threshold so the test isn't slow. UserService's
    // `lockout.threshold` counts failed credential+MFA attempts together;
    // once `failedLoginAttempts >= threshold` the next miss locks the account
    // and the workflow translates `MFA_INVALID(lockEnds: …)` to 423.
    const app = await prepareWfApp({
      loginOpts: { mfa: { transports: ["totp"] } },
      userConfig: { lockout: { threshold: 2, duration: 60_000 } },
    });
    await seedActiveUser(app.users, "alice", "Password123");
    const secret = generateTotpSecret();
    await app.users.addMfaMethod("alice", { name: "totp", value: secret, confirmed: true });

    const r1 = await app.trigger({ wfid: "auth.login" });
    let last = await app.trigger({
      wfs: r1.body?.wfs as string,
      input: { username: "alice", password: "Password123" },
    });
    // Submit wrong codes until the workflow throws 423.
    let lastStatus = 0;
    for (let attempt = 0; attempt < 5; attempt++) {
      const r = await app.trigger({
        wfs: last.body?.wfs as string,
        input: { code: "000000" },
      });
      lastStatus = r.status;
      if (r.status === 423) return; // success path
      last = r;
    }
    throw new Error(`expected 423 within 5 wrong attempts; last status=${lastStatus}`);
  });

  // Backup codes validate against `BackupCodeForm` (alphanumeric + hyphens) —
  // separate from `MfaCodeForm` (digits-only for TOTP). See BUG-LOGIN-6 fix.
  it("backup code consumed twice → second use fails (one-time semantics)", async () => {
    const app = await prepareWfApp({
      loginOpts: { mfa: { backupCodes: true, transports: ["totp"] } },
    });
    await seedActiveUser(app.users, "alice", "Password123");
    const secret = generateTotpSecret();
    await app.users.addMfaMethod("alice", { name: "totp", value: secret, confirmed: true });
    const codes = await app.users.generateBackupCodes("alice", 2);
    const [first, second] = codes;

    const r1 = await app.trigger({ wfid: "auth.login" });
    const cred1 = await app.trigger({
      wfs: r1.body?.wfs as string,
      input: { username: "alice", password: "Password123" },
    });
    const bc1 = await app.trigger({
      wfs: cred1.body?.wfs as string,
      input: { action: "useBackupCode" },
    });
    const consume1 = await app.trigger({
      wfs: bc1.body?.wfs as string,
      input: { action: "useBackupCode", code: first },
    });
    expect((consume1.body?.data as Record<string, unknown>)?.userId).toBe("alice");

    const r2 = await app.trigger({ wfid: "auth.login" });
    const cred2 = await app.trigger({
      wfs: r2.body?.wfs as string,
      input: { username: "alice", password: "Password123" },
    });
    const bc2 = await app.trigger({
      wfs: cred2.body?.wfs as string,
      input: { action: "useBackupCode" },
    });
    const consume2 = await app.trigger({
      wfs: bc2.body?.wfs as string,
      input: { action: "useBackupCode", code: first },
    });
    expect((consume2.body?.errors as Record<string, string>)?.code).toMatch(/Invalid backup code/);

    const r3 = await app.trigger({ wfid: "auth.login" });
    const cred3 = await app.trigger({
      wfs: r3.body?.wfs as string,
      input: { username: "alice", password: "Password123" },
    });
    const bc3 = await app.trigger({
      wfs: cred3.body?.wfs as string,
      input: { action: "useBackupCode" },
    });
    const consume3 = await app.trigger({
      wfs: bc3.body?.wfs as string,
      input: { action: "useBackupCode", code: second },
    });
    expect((consume3.body?.data as Record<string, unknown>)?.userId).toBe("alice");
  });

  it("SMS transport: enrolled-via-sms user receives pin via SmsSender, can verify and finish", async () => {
    const app = await prepareWfApp({
      loginOpts: { mfa: { transports: ["sms"] } },
    });
    await seedActiveUser(app.users, "alice", "Password123");
    await app.users.addMfaMethod("alice", {
      name: "sms",
      value: "+15555550100",
      confirmed: true,
    });

    const r1 = await app.trigger({ wfid: "auth.login" });
    const cred = await app.trigger({
      wfs: r1.body?.wfs as string,
      input: { username: "alice", password: "Password123" },
    });
    // 1 method (sms) → auto-picked → paused at pincode-check-login.
    // SMS pin was sent via SmsSender — check captured payload.
    expect(app.sms.length).toBe(1);
    const sent = app.sms[0];
    expect(sent.kind).toBe("login.pincode");
    expect(sent.recipient).toBe("+15555550100");
    expect(sent.code).toMatch(/^\d{6}$/);

    const final = await app.trigger({
      wfs: cred.body?.wfs as string,
      input: { code: sent.code, rememberDevice: false },
    });
    expect((final.body?.data as Record<string, unknown>)?.userId).toBe("alice");
  });

  it("Email transport: pin email carries 'login.pincode' kind + numeric code", async () => {
    const app = await prepareWfApp({
      loginOpts: { mfa: { transports: ["email"] } },
    });
    await seedActiveUser(app.users, "alice", "Password123");
    await app.users.addMfaMethod("alice", {
      name: "email",
      value: "alice@example.com",
      confirmed: true,
    });
    const r1 = await app.trigger({ wfid: "auth.login" });
    const cred = await app.trigger({
      wfs: r1.body?.wfs as string,
      input: { username: "alice", password: "Password123" },
    });
    const pinMail = app.emails.find((e) => e.kind === "login.pincode");
    expect(pinMail).toBeTruthy();
    expect(pinMail?.code).toMatch(/^\d{6}$/);
    expect(pinMail?.recipient).toBe("alice@example.com");

    const final = await app.trigger({
      wfs: cred.body?.wfs as string,
      input: { code: pinMail?.code, rememberDevice: false },
    });
    expect((final.body?.data as Record<string, unknown>)?.userId).toBe("alice");
  });
});

describe("LoginWorkflow edge cases — JSON-safety of opts snapshot", () => {
  // ── snapshotOpts proof via observable behaviour ────────────────────────────
  // The workflow's `init` step stashes the resolved opts on `ctx` so the
  // schema can read flags. The default `forms.*` entries are atscript class
  // instances — if `snapshotOpts` let them through, the in-memory state store
  // would either fail to serialize or hold stale class references, breaking
  // pause+resume.
  it("default forms group (atscript classes) does NOT poison ctx.opts — pause+resume survives", async () => {
    const app = await prepareWfApp({
      loginOpts: { mfa: { enabled: false } },
    });
    await seedActiveUser(app.users, "alice", "Password123");
    const r1 = await app.trigger({ wfid: "auth.login" });
    expect(r1.body?.wfs).toBeTruthy(); // first pause → state was persisted
    const r2 = await app.trigger({
      wfs: r1.body?.wfs as string,
      input: { username: "alice", password: "Password123" },
    });
    // Resume worked → tokens issued.
    expect((r2.body?.data as Record<string, unknown>)?.userId).toBe("alice");
  });
});

describe("LoginWorkflow edge cases — silent-audit fallback", () => {
  it("auditLogin true + no-op AuditEmitter → workflow still completes (no crash)", async () => {
    // The helper auto-wires a capture emitter when `finalize.auditLogin` is
    // truthy — provide an explicit no-op so we're testing the FALLBACK path
    // when the registered emitter does nothing (proxies the absence case).
    const app = await prepareWfApp({
      loginOpts: { finalize: { auditLogin: true }, mfa: { enabled: false } },
      auditEmitter: { emit: () => undefined },
    });
    await seedActiveUser(app.users, "alice", "Password123");
    const r1 = await app.trigger({ wfid: "auth.login" });
    const r2 = await app.trigger({
      wfs: r1.body?.wfs as string,
      input: { username: "alice", password: "Password123" },
    });
    expect((r2.body?.data as Record<string, unknown>)?.userId).toBe("alice");
    // Capture emitter was a noop → no events captured (harness array empty).
    expect(app.auditEvents.length).toBe(0);
  });
});
