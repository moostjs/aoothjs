import type { AuthDeliveryPayload } from "../workflow/auth-workflow";
import { Controller, Inherit, Injectable } from "moost";
import { afterEach, describe, expect, it, vi } from "vite-plus/test";

import type { RateLimitInterceptorOptions } from "../rate-limit/interceptor";
import { FlowWorkflow, prepareFlowApp, type PreparedFlowApp, setPasswordInput } from "./flow-utils";

// WHY: the one-time-code recovery must not tell whether an account exists.
// An identifier no code can go to (unknown, inactive, M2 without a deliverable
// channel) runs a ghost OTP pause: the same strategy, token prefix, response,
// form, persisted pause, expiry, error answers, attempt limit and resend wait
// as a real run — nothing is sent and no code is ever accepted.

let deliverySource: "typed" | "registered" = "typed";
const delivered: AuthDeliveryPayload[] = [];
/** Every code minted, sent or not (a ghost's code is never delivered). */
const minted: string[] = [];
/** Subjects `afterLogin` fired for. */
const afterLogins: string[] = [];

@Inherit()
@Injectable()
@Controller()
class EnumWorkflow extends FlowWorkflow {
  protected override resolveRecoveryDeliverySource(): "typed" | "registered" {
    return deliverySource;
  }
  protected override async deliver(payload: AuthDeliveryPayload): Promise<void> {
    delivered.push(payload);
  }
  protected override afterLogin(ctx: { subject?: string }): void {
    afterLogins.push(ctx.subject ?? "");
  }
  protected override mintPin(
    ctx: { pinNonce?: string; pinDigest?: string; pinExpire?: number },
    binding: string,
    length?: number,
    ttlMs?: number,
  ): string {
    const code = super.mintPin(ctx, binding, length, ttlMs);
    minted.push(code);
    return code;
  }
}

const PASSWORD = "Password123!";
const KNOWN = "alice@example.test";
const UNKNOWN = "ghost@example.test";

async function boot(
  source: "typed" | "registered" = "typed",
  storeMode: "durable" | "encapsulated" = "durable",
  rateLimit?: RateLimitInterceptorOptions,
): Promise<PreparedFlowApp> {
  deliverySource = source;
  delivered.length = 0;
  minted.length = 0;
  const app = await prepareFlowApp({
    workflowClass: EnumWorkflow,
    storeMode,
    ...(rateLimit && { rateLimit }),
  });
  await app.seedUser(KNOWN, PASSWORD);
  return app;
}

async function request(app: PreparedFlowApp, identifier: string) {
  const started = await app.start("auth/recovery/flow");
  return app.submit(started.body.wfs, { formData: { email: identifier } });
}

/**
 * The response with what legitimately varies between two requests masked:
 * the token's random part, timestamps, and the masked typed address (it is
 * derived from what the caller typed, identically for both).
 */
function shape(res: { status: number; body: Record<string, unknown> }) {
  const json = JSON.stringify(res.body)
    .replace(/"wfs":"([a-z-]+)\.[^"]+"/g, '"wfs":"$1.<handle>"')
    .replace(/"resendAllowedAt":\d+/g, '"resendAllowedAt":0')
    .replace(/"sentTo":"[^"]*"/g, '"sentTo":"<masked typed address>"')
    .replace(/Please wait \d+s/g, "Please wait Ns");
  return { status: res.status, body: JSON.parse(json) as unknown };
}

describe("recovery by one-time code: no account-existence oracle", () => {
  it("an unknown identifier gets a byte-identical answer and one persisted pause", async () => {
    const app = await boot();
    const known = await request(app, KNOWN);
    const rowsAfterKnown = app.savedStates.length;
    const unknown = await request(app, UNKNOWN);
    expect(known.body.inputRequired).toBeDefined();
    expect(known.body.wfs).toMatch(/^store\./);
    expect(unknown.body.wfs).toMatch(/^store\./);
    expect(shape(unknown)).toEqual(shape(known));
    expect(app.savedStates.length - rowsAfterKnown).toBe(rowsAfterKnown); // one pause each
    // the masked hint is derived from the typed address, the same way for both
    expect(JSON.stringify(unknown.body)).toContain('"sentTo":"g***t@example.test"');
    // nothing was sent for the ghost
    expect(delivered.map((d) => d.recipient)).toEqual([KNOWN]);
  });

  it("an inactive (e.g. pending invitation) account is a ghost too", async () => {
    const app = await boot();
    await app.users.createUser("pending@example.test", PASSWORD); // never activated
    const known = await request(app, KNOWN);
    const pending = await request(app, "pending@example.test");
    expect(shape(pending)).toEqual(shape(known));
    expect(delivered.map((d) => d.recipient)).toEqual([KNOWN]);
  });

  it("M2: an account without a deliverable channel answers like one with it — and no run shows the destination", async () => {
    const app = await boot("registered");
    const withSms = await app.seedUser("bob@example.test", PASSWORD, {
      mfa: { methods: [{ name: "sms", value: "+15555550100", confirmed: true }] },
    });
    expect(withSms).toBeTruthy();
    const known = await request(app, "bob@example.test");
    const noChannel = await request(app, KNOWN); // no confirmed sms/email method
    const unknown = await request(app, UNKNOWN);
    expect(shape(noChannel)).toEqual(shape(known));
    expect(shape(unknown)).toEqual(shape(known));
    // M2 never discloses (part of) the account's own channel
    const pub = (b: Record<string, unknown>) =>
      (b.inputRequired as { context: { public: { pincode: Record<string, unknown> } } }).context
        .public.pincode;
    expect(pub(known.body)).not.toHaveProperty("sentTo");
    expect(delivered.map((d) => d.recipient)).toEqual(["+15555550100"]);
  });

  it("the ghost pause expires exactly like a real one (recoveryStateTtlMs)", async () => {
    const app = await boot();
    const t0 = Date.now();
    await request(app, KNOWN);
    await request(app, UNKNOWN);
    const [knownExp, ghostExp] = app.savedExpiries.slice(-2);
    const ttl = 60 * 60 * 1000;
    for (const exp of [knownExp, ghostExp]) {
      expect(exp).toBeGreaterThanOrEqual(t0 + ttl);
      expect(exp).toBeLessThanOrEqual(Date.now() + ttl);
    }
  });

  it("a wrong code answers the same for both; the ghost accepts no code", async () => {
    const app = await boot();
    const known = await request(app, KNOWN);
    const ghost = await request(app, UNKNOWN);
    const wrong = { formData: { code: "000000", rememberDevice: false } };
    const knownWrong = await app.submit(known.body.wfs, wrong);
    const ghostWrong = await app.submit(ghost.body.wfs, wrong);
    expect(shape(ghostWrong)).toEqual(shape(knownWrong));
    expect(JSON.stringify(knownWrong.body)).toContain("Invalid code");
  });

  it("the attempt limit, the code's invalidation and the resend wait behave the same", async () => {
    const app = await boot();
    const known = await request(app, KNOWN);
    const ghost = await request(app, UNKNOWN);
    // resend right away → the same "please wait" answer
    const knownResend = await app.submit(known.body.wfs, { action: "resend" });
    const ghostResend = await app.submit(ghost.body.wfs, { action: "resend" });
    expect(shape(ghostResend)).toEqual(shape(knownResend));
    expect(JSON.stringify(knownResend.body)).toContain("Please wait");
    // five wrong codes, then one more after the code is used up
    const answers = async (wfs: string) => {
      const out: unknown[] = [];
      for (let i = 0; i < 6; i++) {
        out.push(
          shape(
            await app.submit(wfs, {
              formData: { code: String(100000 + i), rememberDevice: false },
            }),
          ),
        );
      }
      return out;
    };
    const knownAnswers = await answers(known.body.wfs as string);
    const ghostAnswers = await answers(ghost.body.wfs as string);
    expect(ghostAnswers).toEqual(knownAnswers);
    // the 5th wrong code and every submit after it: "too many"
    for (const answer of knownAnswers.slice(-2)) {
      expect(JSON.stringify(answer)).toContain("Too many invalid attempts");
    }
  });
});

describe("recovery by one-time code: nothing about the account in the token's length (H3)", () => {
  // WHY: an encapsulated token is the encrypted state, so its length — and
  // the response's — followed whatever the state held (a subject, the
  // registered address). Same-length typed identifiers, so only the account
  // could make a difference.
  const sizes = (res: { body: Record<string, unknown> }) => ({
    wfs: String(res.body.wfs).length,
    body: Buffer.byteLength(JSON.stringify(res.body)),
  });

  for (const storeMode of ["encapsulated", "durable"] as const) {
    it(`M1, ${storeMode} store: known, unknown and inactive give equal token and response lengths, before and after a wrong code`, async () => {
      const app = await boot("typed", storeMode);
      await app.users.createUser("pendi@example.test", PASSWORD); // inactive
      const runs = [
        await request(app, KNOWN),
        await request(app, UNKNOWN),
        await request(app, "pendi@example.test"),
      ];
      expect(runs[0].body.wfs).toMatch(storeMode === "durable" ? /^store\./ : /^store\./);
      const first = runs.map(sizes);
      expect(new Set(first.map((x) => JSON.stringify(x))).size).toBe(1);
      const wrong = { formData: { code: "000000", rememberDevice: false } };
      const after = [];
      for (const run of runs) after.push(sizes(await app.submit(run.body.wfs, wrong)));
      expect(new Set(after.map((x) => JSON.stringify(x))).size).toBe(1);
    });

    it(`M2, ${storeMode} store: registered addresses of different lengths, no channel and unknown give equal lengths`, async () => {
      const app = await boot("registered", storeMode);
      await app.seedUser("bob00@example.test", PASSWORD, {
        mfa: { methods: [{ name: "sms", value: "+15555550100", confirmed: true }] },
      });
      await app.seedUser("bob01@example.test", PASSWORD, {
        mfa: {
          methods: [
            { name: "email", value: "a.much.longer.inbox@mail.example.test", confirmed: true },
          ],
        },
      });
      const runs = [
        await request(app, "bob00@example.test"),
        await request(app, "bob01@example.test"),
        await request(app, KNOWN), // no deliverable channel
        await request(app, UNKNOWN),
      ];
      expect(new Set(runs.map((r) => JSON.stringify(sizes(r)))).size).toBe(1);
      expect(delivered.map((d) => d.recipient)).toEqual([
        "+15555550100",
        "a.much.longer.inbox@mail.example.test",
      ]);
    });
  }

  it("the state holds nothing about the account before the code is verified", async () => {
    const app = await boot();
    await request(app, KNOWN);
    const known = JSON.stringify(app.savedStates.at(-1));
    await request(app, UNKNOWN);
    const ghost = JSON.stringify(app.savedStates.at(-1));
    for (const state of [known, ghost]) {
      expect(state).not.toContain('"subject"');
      expect(state).not.toContain("deliveredTo");
    }
  });

  it("a ghost refuses even its own stored code, with the wrong-code answer (L5)", async () => {
    // WHY: no account behind it — the check refuses explicitly, whatever the code.
    const app = await boot();
    const ghost = await request(app, UNKNOWN);
    const res = await app.submit(ghost.body.wfs, {
      formData: { code: minted.at(-1), rememberDevice: false },
    });
    expect(res.body.finished).toBeUndefined();
    expect(JSON.stringify(res.body)).toContain("Invalid code");
  });

  it("known and unknown identifiers make the same user-store reads (L2)", async () => {
    const app = await boot();
    expect(await storeReads(app, UNKNOWN)).toEqual(await storeReads(app, KNOWN));
  });

  it("M2: known, unknown and inactive identifiers make the same user-store reads (L-a)", async () => {
    // WHY: a known M2 account reads its row again to pick the registered
    // channel; without the same placeholder read an unknown one answers faster.
    const app = await boot("registered");
    await app.seedUser("bob@example.test", PASSWORD, {
      mfa: { methods: [{ name: "sms", value: "+15555550100", confirmed: true }] },
    });
    await app.users.createUser("pending@example.test", PASSWORD); // never activated
    const known = await storeReads(app, "bob@example.test");
    expect(known.filter((c) => c === "getUser").length).toBeGreaterThan(1);
    expect(await storeReads(app, UNKNOWN)).toEqual(known);
    expect(await storeReads(app, "pending@example.test")).toEqual(known);
  });
});

/** The user-store reads one recovery request plus one wrong code make. */
async function storeReads(app: PreparedFlowApp, identifier: string): Promise<string[]> {
  const calls: string[] = [];
  for (const name of ["findByHandle", "getUser"] as const) {
    const original = app.users[name].bind(app.users) as (...a: unknown[]) => unknown;
    (app.users as unknown as Record<string, unknown>)[name] = (...args: unknown[]) => {
      calls.push(name);
      return original(...args);
    };
  }
  const run = await request(app, identifier);
  await app.submit(run.body.wfs, { formData: { code: "000000", rememberDevice: false } });
  for (const name of ["findByHandle", "getUser"] as const) {
    delete (app.users as unknown as Record<string, unknown>)[name];
  }
  return calls;
}

describe("the bundled per-IP limit on anonymous sends (aooth.send, M2/L4)", () => {
  // WHY: every recovery request sends (or, for a ghost, looks like it sends)
  // a message — without a limit one caller can mail-bomb any inbox.
  it("counts every send attempt, known and unknown alike, and answers the coded 429", async () => {
    const app = await boot("typed", "durable", { policies: { "aooth.send": "2/15m" } });
    expect((await request(app, KNOWN)).status).toBe(201);
    expect((await request(app, UNKNOWN)).status).toBe(201);
    const limited = await request(app, KNOWN);
    expect(limited.status).toBe(429);
    expect(limited.body).toMatchObject({
      code: "RATE_LIMITED",
      params: { policy: "aooth.send", limit: 2 },
    });
    expect(delivered).toHaveLength(1);
  });

  it("words its 429 with the app-wide `message`; a rule message through policies still wins", async () => {
    // WHY: the interceptor's `message` is the app-wide 429 text, but the sends
    // checked inside the workflow never received it and showed the built-in text.
    const message = "Slow down: {{limit}} per {{window}}.";
    const app = await boot("typed", "durable", { message, policies: { "aooth.send": "1/15m" } });
    expect((await request(app, UNKNOWN)).status).toBe(201);
    const limited = await request(app, UNKNOWN);
    expect(limited.status).toBe(429);
    expect(limited.body).toMatchObject({
      code: "RATE_LIMITED",
      message: "Slow down: 1 per 15 minutes.",
      params: { policy: "aooth.send", limit: 1 },
    });

    const worded = await boot("typed", "durable", {
      message,
      policies: { "aooth.send": "1/15m | Too many codes requested ({{limit}} per {{window}})." },
    });
    expect((await request(worded, UNKNOWN)).status).toBe(201);
    expect((await request(worded, UNKNOWN)).body.message).toBe(
      "Too many codes requested (1 per 15 minutes).",
    );
  });

  it("can be switched off with policies", async () => {
    const app = await boot("typed", "durable", { policies: { "aooth.send": false } });
    for (let i = 0; i < 25; i++) expect((await request(app, UNKNOWN)).status).toBe(201);
  });

  it("applies by default (20 per 15 minutes) once the interceptors are installed", async () => {
    const app = await boot("typed", "durable", {});
    for (let i = 0; i < 20; i++) expect((await request(app, UNKNOWN)).status).toBe(201);
    expect((await request(app, UNKNOWN)).status).toBe(429);
  });
});

describe("auto-login refuses an inactive account (H2, L-b)", () => {
  it("an account deactivated before the reset completes gets no session, no lastLogin stamp and no afterLogin, even with autoLoginOnRecover", async () => {
    deliverySource = "typed";
    delivered.length = 0;
    afterLogins.length = 0;
    const app = await prepareFlowApp({
      workflowClass: EnumWorkflow,
      workflowOpts: { autoLoginOnRecover: true },
    });
    const userId = await app.seedUser(KNOWN, PASSWORD);
    const run = await request(app, KNOWN);
    const code = (delivered[0] as { code: string }).code;
    const atPassword = await app.submit(run.body.wfs, {
      formData: { code, rememberDevice: false },
    });
    expect(JSON.stringify(atPassword.body.inputRequired)).toContain("newPassword");
    await app.users.deactivateAccount(userId);
    const done = await app.submit(atPassword.body.wfs, setPasswordInput);
    expect(done.body.finished).toBe(true);
    expect((done.body.data as { accessToken?: string } | undefined)?.accessToken).toBeFalsy();
    expect((await app.users.getUser(userId)).account.lastLogin).toBeFalsy();
    expect(afterLogins).toEqual([]);
  });

  it("an active account still auto-logs in, stamped and announced once", async () => {
    deliverySource = "typed";
    delivered.length = 0;
    afterLogins.length = 0;
    const app = await prepareFlowApp({
      workflowClass: EnumWorkflow,
      workflowOpts: { autoLoginOnRecover: true },
    });
    const userId = await app.seedUser(KNOWN, PASSWORD);
    const run = await request(app, KNOWN);
    const code = (delivered[0] as { code: string }).code;
    const atPassword = await app.submit(run.body.wfs, {
      formData: { code, rememberDevice: false },
    });
    const done = await app.submit(atPassword.body.wfs, setPasswordInput);
    expect(typeof (done.body.data as { accessToken?: string }).accessToken).toBe("string");
    expect((await app.users.getUser(userId)).account.lastLogin).toBeTruthy();
    expect(afterLogins).toEqual([userId]);
  });
});

/** Freeze the clock at `t0`, boot (optionally with a store default) and seed the known account. */
async function bootAt(storeDefaultTtl?: number) {
  const t0 = Date.now();
  vi.useFakeTimers({ toFake: ["Date"], now: t0 });
  deliverySource = "typed";
  delivered.length = 0;
  minted.length = 0;
  const app = await prepareFlowApp({
    workflowClass: EnumWorkflow,
    ...(storeDefaultTtl !== undefined && { storeDefaultTtl }),
  });
  await app.seedUser(KNOWN, PASSWORD);
  return { app, t0 };
}

describe("each recovery step lives recoveryStateTtlMs from when it is shown; retries keep it", () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  const MIN = 60_000;
  const TTL = 60 * MIN;
  const wrongCode = { formData: { code: "000000", rememberDevice: false } };
  const mismatch = {
    formData: { newPassword: "NewPassword456!", confirmPassword: "Different456!", consents: [] },
  };

  for (const [label, storeDefaultTtl] of [
    ["no store default", undefined],
    ["a 30-day store default", 30 * 24 * 60 * MIN],
  ] as const) {
    it(`a wrong code and a password mismatch keep their step's window (${label})`, async () => {
      // WHY: retries carried no expiry and fell to the state store's default —
      // never, under a store without one; a retry must not extend it either.
      const { app, t0 } = await bootAt(storeDefaultTtl);
      const atCode = await request(app, KNOWN);
      expect(app.savedExpiries.at(-1)).toBe(t0 + TTL);
      vi.setSystemTime(t0 + MIN);
      const wrong = await app.submit(atCode.body.wfs, wrongCode);
      expect(wrong.body.inputRequired?.context?.errors).toBeDefined();
      expect(app.savedExpiries.at(-1)).toBe(t0 + TTL);

      // The password form is a new step: a new window from when it is shown.
      vi.setSystemTime(t0 + 2 * MIN);
      const atPassword = await app.submit(wrong.body.wfs, {
        formData: { code: minted.at(-1), rememberDevice: false },
      });
      expect(atPassword.body.inputRequired?.payload?.id).toBe("SetPasswordForm");
      const passwordWindow = t0 + 2 * MIN + TTL;
      expect(app.savedExpiries.at(-1)).toBe(passwordWindow);
      vi.setSystemTime(t0 + 3 * MIN);
      const refused = await app.submit(atPassword.body.wfs, mismatch);
      expect(refused.body.inputRequired?.context?.errors).toHaveProperty("confirmPassword");
      expect(app.savedExpiries.at(-1)).toBe(passwordWindow);

      vi.setSystemTime(passwordWindow + 1);
      expect((await app.submit(refused.body.wfs, setPasswordInput)).status).toBe(410);
    });
  }

  it("the resend wait keeps the code form's window; a resend shows the form again with a new one", async () => {
    // WHY: pins 0.2.20 for a resend (a new code, a new window) while the
    // refused early resend is a retry that keeps the window.
    const { app, t0 } = await bootAt();
    const atCode = await request(app, KNOWN);
    vi.setSystemTime(t0 + 10_000);
    const early = await app.submit(atCode.body.wfs, { action: "resend" });
    expect(early.body.inputRequired?.context?.errors?.__form).toMatch(/wait/i);
    expect(app.savedExpiries.at(-1)).toBe(t0 + TTL);
    vi.setSystemTime(t0 + 2 * MIN);
    const resent = await app.submit(early.body.wfs, { action: "resend" });
    expect(resent.body.inputRequired?.payload?.id).toBe("PincodeForm");
    expect(minted).toHaveLength(2);
    expect(app.savedExpiries.at(-1)).toBe(t0 + 2 * MIN + TTL);
  });

  it("a retry on a state paused before 0.2.21 (no recorded window) gets a bounded one", async () => {
    // WHY: runs in flight at the upgrade carry no recorded window; their retries
    // must still expire, not fall to the store's default.
    const { app, t0 } = await bootAt();
    const atCode = await request(app, KNOWN);
    const handle = String(atCode.body.wfs).slice("store.".length);
    const entry = (await app.durableStore.get(handle))!;
    const ctx = entry.state.context as { recoveryStepExpiresAt?: number };
    expect(ctx.recoveryStepExpiresAt).toBe(t0 + TTL);
    delete ctx.recoveryStepExpiresAt;
    await app.durableStore.set(handle, entry.state, entry.expiresAt);

    vi.setSystemTime(t0 + 10 * MIN);
    await app.submit(atCode.body.wfs, wrongCode);
    expect(app.savedExpiries.at(-1)).toBe(t0 + 10 * MIN + TTL);
  });
});
