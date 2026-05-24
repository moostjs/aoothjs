import { generateTotpCode } from "@aooth/user";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vite-plus/test";

import {
  buildTestApp,
  expectFinished,
  expectOk,
  expectRedirect,
  readWfPause,
  type TestApp,
  wfErrors,
} from "./harness";

describe("WF-LOGIN — auth.login workflow", () => {
  let app: TestApp;

  beforeAll(async () => {
    app = await buildTestApp();
  });
  afterAll(async () => {
    await app.close();
  });
  beforeEach(() => {
    app.emailSender.reset();
  });

  it("WF-LOGIN-01 — credentials step (no MFA) finishes immediately with tokens", async () => {
    const start = await app.triggerWf("public", { wfid: "auth.login" });
    expectOk(start);
    const startBody = await readWfPause(start);
    expect(startBody.wfs).toBeTruthy();
    expect(startBody.inputRequired).toBeTruthy();

    const alice = app.fixtures.users.t1_alice;
    const submit = await app.triggerWf("public", {
      wfid: "auth.login",
      wfs: startBody.wfs,
      input: { username: alice.username, password: alice.password },
    });
    expectOk(submit);
    const finished = await expectFinished<{
      userId?: string;
      accessToken?: string;
      refreshToken?: string;
    }>(submit);
    expect(finished.data?.userId).toBe(alice.username);
    expect(typeof finished.data?.accessToken).toBe("string");
    expect(typeof finished.data?.refreshToken).toBe("string");
  });

  // WF-LOGIN-02 (MFA required) lives in its own describe (below) so that
  // building a fresh app with `mfa.mode: 'optional'` doesn't clobber the
  // process-global Wooks router this describe's shared `app` is bound to.

  // ── BIG 3.1 coverage (subset wired in the demo app) ──────────────────────
  // The demo wires LoginWorkflowOptions({ mfaTransports: ['email','totp'],
  // forgotPasswordAction: true, passwordInitialGuard: true }). Tests below
  // exercise the two demo-only flags. Other LoginWorkflowOptions surfaces
  // (deviceTrust, notifyNewDevice, riskStepUp, …) are covered in unit tests
  // in `@aooth/auth-moost` per WF_LOGIN.md §"Tasks" item #6.

  it("WF-LOGIN-04 — forgotPassword alt-action redirects to /recover", async () => {
    const start = await app.triggerWf("public", { wfid: "auth.login" });
    const startBody = await readWfPause(start);
    const r = await app.triggerWf("public", {
      wfid: "auth.login",
      wfs: startBody.wfs,
      input: { username: "alice@demo.test", action: "forgotPassword" },
    });
    expectOk(r);
    const redirect = expectRedirect(await expectFinished(r));
    expect(redirect.reason).toBe("forgot-password");
    expect(redirect.target).toMatch(/\/recover\?username=/);
  });

  it("WF-LOGIN-05 — passwordInitialGuard: user with password.isInitial=true must change password before token issue", async () => {
    // The seeded users all have isInitial=false. Directly flip the flag via
    // the @atscript/db `updateMany` API (the only path that knows the
    // DemoUser schema's nested `password.isInitial` set semantics).
    // Use t1_alice (no MFA enrolled) so this test doesn't intersect MFA.
    const alice = app.fixtures.users.t1_alice;
    const usersTbl = app.appHandle.appDb.tables.users as unknown as {
      updateMany: (
        filter: Record<string, unknown>,
        patch: Record<string, unknown>,
      ) => Promise<unknown>;
    };
    await usersTbl.updateMany({ username: alice.username }, {
      password: { isInitial: true },
    } as never);

    const start = await app.triggerWf("public", { wfid: "auth.login" });
    const startBody = await readWfPause(start);
    const cred = await app.triggerWf("public", {
      wfid: "auth.login",
      wfs: startBody.wfs,
      input: { username: alice.username, password: alice.password },
    });
    expectOk(cred);
    const credBody = await readWfPause(cred);
    // Paused with the SetPasswordForm — payload contains `newPassword` field.
    expect(credBody.inputRequired).toBeTruthy();
    const payloadStr = JSON.stringify(credBody.inputRequired);
    expect(payloadStr).toMatch(/newPassword/);
    expect(payloadStr).toMatch(/confirmPassword/);

    // Submit a fresh password.
    const setResp = await app.triggerWf("public", {
      wfid: "auth.login",
      wfs: credBody.wfs,
      input: { newPassword: "FreshPass99!", confirmPassword: "FreshPass99!" },
    });
    expectOk(setResp);
    const issued = await expectFinished<{ userId?: string; accessToken?: string }>(setResp);
    expect(issued.data?.userId).toBe(alice.username);
    expect(typeof issued.data?.accessToken).toBe("string");

    // After the workflow succeeded, alice's password is `FreshPass99!` —
    // patch `alice.password` on the in-memory fixture so any LATER test in
    // the suite that uses it still authenticates. We can't reset to the seed
    // password because UserService history forbids reuse.
    (alice as { password: string }).password = "FreshPass99!";
  });

  it("WF-LOGIN-03 — MFA bypass attempt with empty/skip input still requires a code", async () => {
    const grace = app.fixtures.users.t1_grace;
    const start = await app.triggerWf("public", { wfid: "auth.login" });
    const startBody = await readWfPause(start);

    const credResp = await app.triggerWf("public", {
      wfid: "auth.login",
      wfs: startBody.wfs,
      input: { username: grace.username, password: grace.password },
    });
    const credBody = await readWfPause(credResp);

    const skipAttempt = await app.triggerWf("public", {
      wfid: "auth.login",
      wfs: credBody.wfs,
      input: { __skip: true },
    });
    expect([200, 201, 400]).toContain(skipAttempt.status);
    const skipBody = await readWfPause(skipAttempt);
    expect(skipBody.inputRequired ?? skipBody.wfs).toBeTruthy();
    if (skipBody.inputRequired) {
      expect(wfErrors(skipBody)).toBeTruthy();
    }

    const emptyAttempt = await app.triggerWf("public", {
      wfid: "auth.login",
      wfs: skipBody.wfs ?? credBody.wfs,
      input: {},
    });
    const emptyBody = await readWfPause(emptyAttempt);
    expect(emptyBody.inputRequired).toBeTruthy();
    expect(wfErrors(emptyBody)).toBeTruthy();
  });
});

// New LoginWorkflowOpts coverage — each test builds its own isolated app via
// buildTestApp (which calls clearGlobalWooks), so they're segregated from the
// shared `app` in the suite above (a fresh-app call mid-suite would invalidate
// it). Each test exercises ONE option flag's end-to-end runtime effect.
describe("WF-LOGIN — option overrides (isolated apps)", () => {
  it("WF-LOGIN-06 — mfa.mode='disabled': TOTP-enrolled user logs in WITHOUT MFA prompt", async () => {
    // End-to-end signal: when the demo flips `mfa.mode` to 'disabled', the
    // workflow skips Phase 4 entirely even for a user with a confirmed TOTP
    // secret. Verifies the option threads through buildApp → DemoLoginWorkflow
    // over the real HTTP / DI stack (the unit suite proves the schema-level
    // skip in isolation; this test proves the demo wiring honours it).
    const mfaOff = await buildTestApp({ loginMfaCtx: { mfaMode: "disabled" } });
    try {
      const grace = mfaOff.fixtures.users.t1_grace;
      expect(grace.totpSecret).toBeTruthy();
      const start = await mfaOff.triggerWf("public", { wfid: "auth.login" });
      const startBody = await readWfPause(start);
      const submit = await mfaOff.triggerWf("public", {
        wfid: "auth.login",
        wfs: startBody.wfs,
        input: { username: grace.username, password: grace.password },
      });
      expectOk(submit);
      const issued = await expectFinished<{ userId?: string; accessToken?: string }>(submit);
      expect(issued.data?.userId).toBe(grace.username);
      expect(typeof issued.data?.accessToken).toBe("string");
    } finally {
      await mfaOff.close();
    }
  });

  it("WF-LOGIN-07 — finalize.redirect='home': successful login emits redirect envelope to '/'", async () => {
    const redirApp = await buildTestApp({
      loginPolicy: {
        finalize: { auditLogin: true, notifyNewDevice: false, redirect: "home" },
      },
    });
    try {
      const alice = redirApp.fixtures.users.t1_alice;
      const start = await redirApp.triggerWf("public", { wfid: "auth.login" });
      const startBody = await readWfPause(start);
      const submit = await redirApp.triggerWf("public", {
        wfid: "auth.login",
        wfs: startBody.wfs,
        input: { username: alice.username, password: alice.password },
      });
      expectOk(submit);
      const redirect = expectRedirect(await expectFinished(submit));
      expect(redirect.trigger).toBe("immediate");
      expect(redirect.target).toBe("/");
    } finally {
      await redirApp.close();
    }
  });

  it("WF-LOGIN-02 — MFA required branch: credentials → MFA form → valid TOTP → tokens", async () => {
    // Demo default is `mfa.mode: 'disabled'` (per the 3-state opts shift) so
    // the Phase-4 loop is filtered out at the schema guard. This test exercises
    // the TOTP verification branch and spins its own app with
    // `mode: 'optional'` (or `'required'` — either fires the loop; grace HAS
    // a confirmed TOTP method so prepare-mfa-options auto-picks it and routes
    // straight to mfa-totp).
    const mfaOn = await buildTestApp({ loginMfaCtx: { mfaMode: "optional" } });
    try {
      const grace = mfaOn.fixtures.users.t1_grace;
      expect(grace.totpSecret).toBeTruthy();

      const start = await mfaOn.triggerWf("public", { wfid: "auth.login" });
      const startBody = await readWfPause(start);

      const credResp = await mfaOn.triggerWf("public", {
        wfid: "auth.login",
        wfs: startBody.wfs,
        input: { username: grace.username, password: grace.password },
      });
      expectOk(credResp);
      const credBody = await readWfPause(credResp);
      expect(credBody.inputRequired).toBeTruthy();

      const wrong = await mfaOn.triggerWf("public", {
        wfid: "auth.login",
        wfs: credBody.wfs,
        input: { code: "000000" },
      });
      const wrongBody = await readWfPause(wrong);
      expect(wfErrors(wrongBody)).toMatchObject({ code: "Invalid code" });

      const code = generateTotpCode(grace.totpSecret as string);
      const final = await mfaOn.triggerWf("public", {
        wfid: "auth.login",
        wfs: wrongBody.wfs,
        input: { code },
      });
      expectOk(final);
      const issued = await expectFinished<{ userId?: string; accessToken?: string }>(final);
      expect(issued.data?.userId).toBe(grace.username);
      expect(typeof issued.data?.accessToken).toBe("string");
    } finally {
      await mfaOn.close();
    }
  });

  it("WF-LOGIN-08 — mfa.mode='required' + 0 methods: email enrollment (pick → address → confirm) end-to-end", async () => {
    // Pins forced enrollment through the demo's HTTP wire + deliver() override +
    // atscript-db `addMfaMethod` / `confirmMfaMethod` persistence — a wrong
    // transport route or a nested-array set regression would slip past unit
    // tests and surface only here.
    const reqApp = await buildTestApp({ loginMfaCtx: { mfaMode: "required" } });
    try {
      const alice = reqApp.fixtures.users.t1_alice;
      const seeded = await reqApp.appHandle.aooth.userService.getUser(alice.username);
      expect(seeded.mfa.methods).toHaveLength(0);

      const start = await reqApp.triggerWf("public", { wfid: "auth.login" });
      const startBody = await readWfPause(start);
      const cred = await reqApp.triggerWf("public", {
        wfid: "auth.login",
        wfs: startBody.wfs,
        input: { username: alice.username, password: alice.password },
      });
      expectOk(cred);
      const pickBody = await readWfPause(cred);
      expect(pickBody.wfs).toBeTruthy();
      expect(pickBody.inputRequired).toBeTruthy();

      const pick = await reqApp.triggerWf("public", {
        wfid: "auth.login",
        wfs: pickBody.wfs,
        input: { method: "email" },
      });
      expectOk(pick);
      const addrBody = await readWfPause(pick);
      expect(addrBody.wfs).toBeTruthy();
      // No pincode yet — only fires after address is submitted.
      expect(reqApp.emailSender.events.filter((e) => e.kind === "login.pincode")).toHaveLength(0);

      const enrollAddress = "alice-mfa@demo.test";
      const addr = await reqApp.triggerWf("public", {
        wfid: "auth.login",
        wfs: addrBody.wfs,
        input: { address: enrollAddress },
      });
      expectOk(addr);
      const confirmBody = await readWfPause(addr);
      expect(confirmBody.wfs).toBeTruthy();

      const pinMail = await reqApp.emailSender.next(
        (e) => e.kind === "login.pincode" && e.recipient === enrollAddress,
        2000,
      );
      expect(typeof pinMail.code).toBe("string");

      const confirm = await reqApp.triggerWf("public", {
        wfid: "auth.login",
        wfs: confirmBody.wfs,
        input: { code: pinMail.code },
      });
      expectOk(confirm);
      const issued = await expectFinished<{ userId?: string; accessToken?: string }>(confirm);
      expect(issued.data?.userId).toBe(alice.username);
      expect(typeof issued.data?.accessToken).toBe("string");

      const after = await reqApp.appHandle.aooth.userService.getUser(alice.username);
      const emailMethod = after.mfa.methods.find((m) => m.name === "email");
      expect(emailMethod?.value).toBe(enrollAddress);
      expect(emailMethod?.confirmed).toBe(true);
      // defaultMethod must be set on confirm — otherwise future required-mode
      // logins re-prompt to pick instead of auto-selecting the enrolled method.
      expect(after.mfa.defaultMethod).toBe("email");
    } finally {
      await reqApp.close();
    }
  });

  it("WF-LOGIN-09 — mfa.mode='required' + 0 methods: TOTP enrollment (pick → confirm) end-to-end", async () => {
    // Pins the TOTP secret round-trip through @atscript/db-sqlite text storage —
    // an encoding regression would corrupt the secret silently and the
    // round-trip generateTotpCode(persisted) → server-recompute would fail.
    // Also asserts no pincode email fires (TOTP path must NOT route to email).
    const reqApp = await buildTestApp({ loginMfaCtx: { mfaMode: "required" } });
    try {
      const alice = reqApp.fixtures.users.t1_alice;
      const seeded = await reqApp.appHandle.aooth.userService.getUser(alice.username);
      expect(seeded.mfa.methods).toHaveLength(0);

      const start = await reqApp.triggerWf("public", { wfid: "auth.login" });
      const startBody = await readWfPause(start);
      const cred = await reqApp.triggerWf("public", {
        wfid: "auth.login",
        wfs: startBody.wfs,
        input: { username: alice.username, password: alice.password },
      });
      expectOk(cred);
      const pickBody = await readWfPause(cred);

      // TOTP skips the address phase — server provisions the secret on pick
      // and pauses on the confirm form directly.
      const pick = await reqApp.triggerWf("public", {
        wfid: "auth.login",
        wfs: pickBody.wfs,
        input: { method: "totp" },
      });
      expectOk(pick);
      const confirmBody = await readWfPause(pick);
      expect(confirmBody.wfs).toBeTruthy();

      const mid = await reqApp.appHandle.aooth.userService.getUser(alice.username);
      const totp = mid.mfa.methods.find((m) => m.name === "totp");
      expect(totp?.confirmed).toBe(false);
      expect(typeof totp?.value).toBe("string");
      const code = generateTotpCode(totp!.value);

      const confirm = await reqApp.triggerWf("public", {
        wfid: "auth.login",
        wfs: confirmBody.wfs,
        input: { code },
      });
      expectOk(confirm);
      const issued = await expectFinished<{ userId?: string; accessToken?: string }>(confirm);
      expect(issued.data?.userId).toBe(alice.username);
      expect(typeof issued.data?.accessToken).toBe("string");

      const after = await reqApp.appHandle.aooth.userService.getUser(alice.username);
      expect(after.mfa.methods.find((m) => m.name === "totp")?.confirmed).toBe(true);
      expect(after.mfa.defaultMethod).toBe("totp");
      expect(reqApp.emailSender.events.filter((e) => e.kind === "login.pincode")).toHaveLength(0);
    } finally {
      await reqApp.close();
    }
  });

  it("WF-LOGIN-10 — mfa.mode='optional' + 0 methods + skip action: tokens issued, no enrollment persisted", async () => {
    // Pins the `action: 'skip'` envelope through atscript-moost-wf's action
    // serialization into the server-side `mode === 'optional'` short-circuit.
    // An inverted gate or a stripped action key would either silently persist
    // an unconfirmed method or refuse to finish — both surface here.
    const optApp = await buildTestApp({ loginMfaCtx: { mfaMode: "optional" } });
    try {
      const alice = optApp.fixtures.users.t1_alice;
      const seeded = await optApp.appHandle.aooth.userService.getUser(alice.username);
      expect(seeded.mfa.methods).toHaveLength(0);

      const start = await optApp.triggerWf("public", { wfid: "auth.login" });
      const startBody = await readWfPause(start);
      const cred = await optApp.triggerWf("public", {
        wfid: "auth.login",
        wfs: startBody.wfs,
        input: { username: alice.username, password: alice.password },
      });
      expectOk(cred);
      const pickBody = await readWfPause(cred);
      // Optional STILL prompts — the gate is the action, not absence of prompt.
      expect(pickBody.wfs).toBeTruthy();
      expect(pickBody.inputRequired).toBeTruthy();

      const skip = await optApp.triggerWf("public", {
        wfid: "auth.login",
        wfs: pickBody.wfs,
        input: { action: "skip" },
      });
      expectOk(skip);
      const issued = await expectFinished<{ userId?: string; accessToken?: string }>(skip);
      expect(issued.data?.userId).toBe(alice.username);
      expect(typeof issued.data?.accessToken).toBe("string");

      // No leftover unconfirmed row — proves skip short-circuited Phase 1.
      const after = await optApp.appHandle.aooth.userService.getUser(alice.username);
      expect(after.mfa.methods).toHaveLength(0);
    } finally {
      await optApp.close();
    }
  });

  it("WF-LOGIN-12 — mfa.mode='required' + transports=['totp'] auto-pick: no picker pause, secret auto-provisioned, code submission goes straight to confirm and finishes", async () => {
    // PR7-1: runMfaEnrollment Phase 1 auto-picks when transports.length === 1.
    // WHY: a regression that removed the auto-pick branch would either force
    // a 1-option picker (degraded UX) or stall the loop with no input form.
    // The mid-flow form-id assertion (EnrollConfirmForm, NOT EnrollPickMethodForm)
    // pins the auto-pick path end-to-end through the demo's HTTP + DI +
    // atscript-db stack; a wiring regression would surface here, not in the
    // unit suite, because the schema-level gating involves both Phase 1
    // (auto-pick + secret provisioning) and Phase 3 (skip-to-confirm with
    // no Phase 2 pincode delivery for totp).
    const reqApp = await buildTestApp({
      loginMfaCtx: { mfaMode: "required", availableMfaTransports: ["totp"] },
    });
    try {
      const alice = reqApp.fixtures.users.t1_alice;
      const seeded = await reqApp.appHandle.aooth.userService.getUser(alice.username);
      expect(seeded.mfa.methods).toHaveLength(0);

      const start = await reqApp.triggerWf("public", { wfid: "auth.login" });
      const startBody = await readWfPause(start);
      const cred = await reqApp.triggerWf("public", {
        wfid: "auth.login",
        wfs: startBody.wfs,
        input: { username: alice.username, password: alice.password },
      });
      expectOk(cred);
      const confirmBody = await readWfPause(cred);
      expect(confirmBody.wfs).toBeTruthy();
      // The critical invariant: NO picker pause when transports.length === 1.
      // The demo uses `createAsHttpOutlet` which wraps the form schema under
      // `inputRequired.payload` (see workflows.recovery.options.spec.ts:610-614);
      // if auto-pick is removed, the payload id would be "EnrollPickMethodForm".
      expect((confirmBody.inputRequired?.payload as { id?: string } | undefined)?.id).toBe(
        "EnrollConfirmForm",
      );
      // No pincode side-channel — TOTP must NOT route through email.
      expect(reqApp.emailSender.events.filter((e) => e.kind === "login.pincode")).toHaveLength(0);

      // Secret was auto-provisioned by Phase 1's auto-pick branch — read and
      // use it to confirm the round-trip.
      const interim = await reqApp.appHandle.aooth.userService.getUser(alice.username);
      const totp = interim.mfa.methods.find((m) => m.name === "totp");
      expect(totp?.confirmed).toBe(false);
      expect(typeof totp?.value).toBe("string");
      expect(totp!.value.length).toBeGreaterThan(0);
      const code = generateTotpCode(totp!.value);

      const confirm = await reqApp.triggerWf("public", {
        wfid: "auth.login",
        wfs: confirmBody.wfs,
        input: { code },
      });
      expectOk(confirm);
      const issued = await expectFinished<{ userId?: string; accessToken?: string }>(confirm);
      expect(issued.data?.userId).toBe(alice.username);
      expect(typeof issued.data?.accessToken).toBe("string");

      const after = await reqApp.appHandle.aooth.userService.getUser(alice.username);
      expect(after.mfa.methods.find((m) => m.name === "totp")?.confirmed).toBe(true);
      expect(after.mfa.defaultMethod).toBe("totp");
    } finally {
      await reqApp.close();
    }
  });

  it("WF-LOGIN-13 — mfa.mode='optional' + skip from EnrollConfirmForm: cleanup runs, no unconfirmed method persisted, tokens issued", async () => {
    // PR7-1: skip / useDifferentMethod alt-actions on EnrollConfirmForm
    // trigger `cleanupEnrollment` which removes the unconfirmed method row.
    // WHY: without the cleanup, a Phase 3 skip would leave stale unconfirmed
    // rows in atscript-db that would corrupt future enrollments (the user's
    // next login would see an "email" method that was never confirmed, which
    // could be auto-picked or rejected unpredictably). The mid-flow assertion
    // that the unconfirmed row WAS persisted (Phase 2 wrote it) is the proof
    // that this test exercises the cleanup branch — without it, "no methods
    // after skip" could be a vacuous pass on a system that never persisted.
    const optApp = await buildTestApp({ loginMfaCtx: { mfaMode: "optional" } });
    try {
      const alice = optApp.fixtures.users.t1_alice;
      const seeded = await optApp.appHandle.aooth.userService.getUser(alice.username);
      expect(seeded.mfa.methods).toHaveLength(0);

      const start = await optApp.triggerWf("public", { wfid: "auth.login" });
      const startBody = await readWfPause(start);
      const cred = await optApp.triggerWf("public", {
        wfid: "auth.login",
        wfs: startBody.wfs,
        input: { username: alice.username, password: alice.password },
      });
      expectOk(cred);
      const pickBody = await readWfPause(cred);
      expect(pickBody.wfs).toBeTruthy();

      // Pick email — drives Phase 2 (address) then pauses on confirm.
      const pick = await optApp.triggerWf("public", {
        wfid: "auth.login",
        wfs: pickBody.wfs,
        input: { method: "email" },
      });
      expectOk(pick);
      const addrBody = await readWfPause(pick);
      expect(addrBody.wfs).toBeTruthy();

      const enrollAddress = "foo@demo.test";
      const addr = await optApp.triggerWf("public", {
        wfid: "auth.login",
        wfs: addrBody.wfs,
        input: { address: enrollAddress },
      });
      expectOk(addr);
      const confirmBody = await readWfPause(addr);
      expect(confirmBody.wfs).toBeTruthy();
      expect((confirmBody.inputRequired?.payload as { id?: string } | undefined)?.id).toBe(
        "EnrollConfirmForm",
      );

      // Pincode WAS sent (Phase 2 fired delivery as a side-effect of address submit).
      const pinMail = await optApp.emailSender.next(
        (e) => e.kind === "login.pincode" && e.recipient === enrollAddress,
        2000,
      );
      expect(typeof pinMail.code).toBe("string");

      // Mid-flow: the unconfirmed email method MUST exist now — proves Phase 2
      // persisted it via `addMfaMethod`. If this assertion fails, the post-skip
      // "no methods" check below would be a vacuous pass.
      const mid = await optApp.appHandle.aooth.userService.getUser(alice.username);
      const midEmail = mid.mfa.methods.find((m) => m.name === "email");
      expect(midEmail?.value).toBe(enrollAddress);
      expect(midEmail?.confirmed).toBe(false);

      // Skip from EnrollConfirmForm — cleanupEnrollment must remove the row.
      const skip = await optApp.triggerWf("public", {
        wfid: "auth.login",
        wfs: confirmBody.wfs,
        input: { action: "skip" },
      });
      expectOk(skip);
      const issued = await expectFinished<{ userId?: string; accessToken?: string }>(skip);
      expect(issued.data?.userId).toBe(alice.username);
      expect(typeof issued.data?.accessToken).toBe("string");

      // Critical: cleanup removed the unconfirmed row. A regression that
      // skipped cleanup on the skip path would leave the email method in place.
      const after = await optApp.appHandle.aooth.userService.getUser(alice.username);
      expect(after.mfa.methods.find((m) => m.name === "email")).toBeUndefined();
      expect(after.mfa.methods).toHaveLength(0);
    } finally {
      await optApp.close();
    }
  });

  it("WF-LOGIN-11 — mfa.mode='optional' + 0 methods + picks email: full enrollment runs (skip does NOT preempt pick)", async () => {
    // Positive branch of optional: users who DO opt in must still complete
    // the 3-phase enrollment. A regression hardwiring optional → skip would
    // treat every submit as a decline and silently break opt-in intent.
    const optApp = await buildTestApp({ loginMfaCtx: { mfaMode: "optional" } });
    try {
      const alice = optApp.fixtures.users.t1_alice;

      const start = await optApp.triggerWf("public", { wfid: "auth.login" });
      const startBody = await readWfPause(start);
      const cred = await optApp.triggerWf("public", {
        wfid: "auth.login",
        wfs: startBody.wfs,
        input: { username: alice.username, password: alice.password },
      });
      expectOk(cred);
      const pickBody = await readWfPause(cred);

      const pick = await optApp.triggerWf("public", {
        wfid: "auth.login",
        wfs: pickBody.wfs,
        input: { method: "email" },
      });
      expectOk(pick);
      const addrBody = await readWfPause(pick);

      const enrollAddress = "alice-optin@demo.test";
      const addr = await optApp.triggerWf("public", {
        wfid: "auth.login",
        wfs: addrBody.wfs,
        input: { address: enrollAddress },
      });
      expectOk(addr);
      const confirmBody = await readWfPause(addr);

      const pinMail = await optApp.emailSender.next(
        (e) => e.kind === "login.pincode" && e.recipient === enrollAddress,
        2000,
      );

      const confirm = await optApp.triggerWf("public", {
        wfid: "auth.login",
        wfs: confirmBody.wfs,
        input: { code: pinMail.code },
      });
      expectOk(confirm);
      const issued = await expectFinished<{ userId?: string; accessToken?: string }>(confirm);
      expect(issued.data?.userId).toBe(alice.username);
      expect(typeof issued.data?.accessToken).toBe("string");

      const after = await optApp.appHandle.aooth.userService.getUser(alice.username);
      const emailMethod = after.mfa.methods.find((m) => m.name === "email");
      expect(emailMethod?.value).toBe(enrollAddress);
      expect(emailMethod?.confirmed).toBe(true);
      expect(after.mfa.defaultMethod).toBe("email");
    } finally {
      await optApp.close();
    }
  });
});
