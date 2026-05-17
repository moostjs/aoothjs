import { generateTotpCode } from "@aoothjs/user";
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

  it("WF-LOGIN-02 — MFA required branch: credentials → MFA form → valid TOTP → tokens", async () => {
    const grace = app.fixtures.users.t1_grace;
    expect(grace.totpSecret).toBeTruthy();

    const start = await app.triggerWf("public", { wfid: "auth.login" });
    const startBody = await readWfPause(start);

    const credResp = await app.triggerWf("public", {
      wfid: "auth.login",
      wfs: startBody.wfs,
      input: { username: grace.username, password: grace.password },
    });
    expectOk(credResp);
    const credBody = await readWfPause(credResp);
    expect(credBody.inputRequired).toBeTruthy();

    const wrong = await app.triggerWf("public", {
      wfid: "auth.login",
      wfs: credBody.wfs,
      input: { code: "000000" },
    });
    const wrongBody = await readWfPause(wrong);
    expect(wfErrors(wrongBody)).toMatchObject({ code: "Invalid code" });

    const code = generateTotpCode(grace.totpSecret as string);
    const final = await app.triggerWf("public", {
      wfid: "auth.login",
      wfs: wrongBody.wfs,
      input: { code },
    });
    expectOk(final);
    const issued = await expectFinished<{ userId?: string; accessToken?: string }>(final);
    expect(issued.data?.userId).toBe(grace.username);
    expect(typeof issued.data?.accessToken).toBe("string");
  });

  // ── BIG 3.1 coverage (subset wired in the demo app) ──────────────────────
  // The demo wires LoginWorkflowOptions({ mfaTransports: ['email','totp'],
  // forgotPasswordAction: true, passwordInitialGuard: true }). Tests below
  // exercise the two demo-only flags. Other LoginWorkflowOptions surfaces
  // (deviceTrust, notifyNewDevice, riskStepUp, …) are covered in unit tests
  // in `@aoothjs/auth-moost` per WF_LOGIN.md §"Tasks" item #6.

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
  it("WF-LOGIN-06 — mfa.enabled=false: TOTP-enrolled user logs in WITHOUT MFA prompt", async () => {
    // End-to-end signal: when the demo flips `mfa.enabled` off, the workflow
    // skips Phase 4 entirely even for a user with a confirmed TOTP secret.
    // Verifies the option threads through buildApp → DemoLoginWorkflow over
    // the real HTTP / DI stack (the unit suite proves the schema-level skip
    // in isolation; this test proves the demo wiring honours it).
    const mfaOff = await buildTestApp({ loginOpts: { mfa: { enabled: false } } });
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
    const redirApp = await buildTestApp({ loginOpts: { finalize: { redirect: "home" } } });
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
      expect(redirect.mode).toBe("immediate");
      expect(redirect.target).toBe("/");
    } finally {
      await redirApp.close();
    }
  });
});
