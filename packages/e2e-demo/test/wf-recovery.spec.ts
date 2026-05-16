import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from "vite-plus/test";

import {
  buildTestApp,
  expectOk,
  readWfPause,
  sleep,
  startRecoveryAndResume,
  type TestApp,
} from "./harness";

const STRONG_PASSWORD = "RecoveredP1ss!";

describe("WF-RECOVERY — auth.recovery happy path + enumeration + single-use", () => {
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

  it("WF-RECOVERY-01 — known email triggers magic link, set new password, log in with it", async () => {
    const bob = app.fixtures.users.t1_bob;

    const { emailEvent, resumedBody } = await startRecoveryAndResume(app, bob.email);
    expect(emailEvent.url).toContain("?wfs=");
    expect(emailEvent.expiresAt).toBeGreaterThan(Date.now());
    expect(resumedBody.inputRequired).toBeTruthy();

    const finalRes = await app.triggerWf("public", {
      wfid: "auth.recovery",
      wfs: resumedBody.wfs,
      input: { newPassword: STRONG_PASSWORD, confirmPassword: STRONG_PASSWORD },
    });
    const finalBody = (await finalRes.json()) as { userId?: string; accessToken?: string };
    expect(finalBody.userId).toBe(bob.username);
    expect(typeof finalBody.accessToken).toBe("string");

    const oldLogin = await app.fetch("/auth/login", {
      method: "POST",
      json: { username: bob.username, password: bob.password },
    });
    expect(oldLogin.status).toBe(401);

    const newLogin = await app.fetch("/auth/login", {
      method: "POST",
      json: { username: bob.username, password: STRONG_PASSWORD },
    });
    expectOk(newLogin);
  });

  it("WF-RECOVERY-02 — unknown email: no enumeration, no email captured", async () => {
    const start = await app.triggerWf("public", { wfid: "auth.recovery" });
    const startBody = await readWfPause(start);

    const submit = await app.triggerWf("public", {
      wfid: "auth.recovery",
      wfs: startBody.wfs,
      input: { email: "ghost-no-such-user@nowhere.test" },
    });
    expectOk(submit);
    const body = (await submit.json()) as { sent?: boolean };
    expect(body.sent).toBe(true);

    // Wait briefly for any erroneous outlet emit; absence is the assertion.
    await sleep(200);
    const captured = app.emailSender.events.find(
      (e) => e.recipient === "ghost-no-such-user@nowhere.test",
    );
    expect(captured).toBeUndefined();
  });
});

describe("WF-RECOVERY — single-use + session-survival", () => {
  let app: TestApp;

  beforeEach(async () => {
    app = await buildTestApp();
  });
  afterEach(async () => {
    await app.close();
  });

  it("WF-RECOVERY-03 — magic link is single-use, replay returns 4xx", async () => {
    const carol = app.fixtures.users.t1_carol;
    const { emailEvent, resumedBody } = await startRecoveryAndResume(app, carol.email);

    const finalize = await app.triggerWf("public", {
      wfid: "auth.recovery",
      wfs: resumedBody.wfs,
      input: { newPassword: STRONG_PASSWORD, confirmPassword: STRONG_PASSWORD },
    });
    const finalized = (await finalize.json()) as { userId?: string };
    expect(finalized.userId).toBe(carol.username);

    const replay = await app.resumeWfFromUrl(emailEvent.url as string);
    expect(replay.status).toBeGreaterThanOrEqual(400);
    expect(replay.status).toBeLessThan(500);
  });

  it("WF-RECOVERY-05 — recovery does NOT revoke pre-existing sessions (current behavior)", async () => {
    const carol = app.fixtures.users.t1_carol;
    const pre = await app.loginAs(carol);

    const { resumedBody } = await startRecoveryAndResume(app, carol.email);
    const finalize = await app.triggerWf("public", {
      wfid: "auth.recovery",
      wfs: resumedBody.wfs,
      input: { newPassword: STRONG_PASSWORD, confirmPassword: STRONG_PASSWORD },
    });
    expectOk(finalize);

    const stillActive = await app.authedFetch(pre.accessToken)("/auth/status");
    expect(stillActive.status).toBe(200);
  });
});

describe("WF-RECOVERY — rate-limit (BIG 3.2 — default 2/day per email)", () => {
  // The demo app wires `WorkflowRateLimitStoreMemory` and the BIG-3.2 default
  // `RecoveryWorkflowOptions.rateLimit = { count: 2, windowMs: 24h }`. Past
  // the cap, the workflow short-circuits to the same generic body the unknown
  // email path returns — anti-enumeration parity for an attacker probing
  // whether an account exists.
  it("WF-RECOVERY-06 — third request for the same email is rate-limited; no third email sent; parity with unknown-email body", async () => {
    const app = await buildTestApp();
    try {
      const bob = app.fixtures.users.t1_bob;

      // Reset state to start clean.
      app.emailSender.reset();

      async function submitFor(email: string): Promise<Record<string, unknown>> {
        const start = await app.triggerWf("public", { wfid: "auth.recovery" });
        const startBody = await readWfPause(start);
        const res = await app.triggerWf("public", {
          wfid: "auth.recovery",
          wfs: startBody.wfs,
          input: { email },
        });
        return (await res.json()) as Record<string, unknown>;
      }

      // 1st + 2nd: allowed (cap=2).
      await submitFor(bob.email);
      await submitFor(bob.email);

      // Wait briefly for any in-flight email captures.
      await sleep(150);
      const beforeThird = app.emailSender.events.filter(
        (e) => e.kind === "recovery.magicLink" && e.recipient === bob.email,
      ).length;
      expect(beforeThird).toBe(2);

      // 3rd: rate-limited → generic body, no new email.
      const rateLimited = await submitFor(bob.email);
      // Unknown email: generic body too.
      const unknown = await submitFor("anyone-not-real@nowhere.test");

      expect(rateLimited.sent).toBe(true);
      expect(unknown.sent).toBe(true);
      // Identical body (THE anti-enumeration invariant).
      expect(JSON.stringify(rateLimited)).toBe(JSON.stringify(unknown));

      await sleep(150);
      const afterThird = app.emailSender.events.filter(
        (e) => e.kind === "recovery.magicLink" && e.recipient === bob.email,
      ).length;
      expect(afterThird).toBe(2); // still 2 — no new email after rate-limit hit
    } finally {
      await app.close();
    }
  });
});

describe("WF-RECOVERY — TTL expiry", () => {
  it("WF-RECOVERY-04 — magic link expires after TTL (config-driven)", async () => {
    // BUG-12 fix: `recoveryTokenTtlMs` (env.RECOVERY_TTL_MS) now drives the
    // persisted wf-state token expiry, not just the email envelope display.
    const app = await buildTestApp({ envOverrides: { RECOVERY_TTL_MS: 1000 } });
    try {
      const bob = app.fixtures.users.t1_bob;
      const start = await app.triggerWf("public", { wfid: "auth.recovery" });
      const startBody = await readWfPause(start);
      await app.triggerWf("public", {
        wfid: "auth.recovery",
        wfs: startBody.wfs,
        input: { email: bob.email },
      });
      const email = await app.emailSender.next(
        (e) => e.kind === "recovery.magicLink" && e.recipient === bob.email,
        2000,
      );

      // Wait past the TTL so the persisted token expires before resume.
      await sleep(1100);

      const replay = await app.resumeWfFromUrl(email.url as string);
      expect(replay.status).toBe(410);
    } finally {
      await app.close();
    }
  });
});
