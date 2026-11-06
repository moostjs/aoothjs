import { UserStoreMemory } from "@aooth/user";
import { HttpError } from "@moostjs/event-http";
import { useRequest } from "@wooksjs/event-http";
import { Controller, Inherit, Injectable } from "moost";
import { afterEach, beforeEach, describe, expect, it, vi } from "vite-plus/test";

import type { AuthDeliveryPayload } from "../workflow/auth-workflow";
import type { AuthWfCtx } from "../workflow/auth-workflow.ctx";
import type { RateLimitInterceptorOptions } from "../rate-limit/interceptor";
import type { AuthWorkflowOpts } from "../workflow/auth-workflow.opts";
import type { WfTriggerHooks } from "../wf-trigger/provider";
import { FlowWorkflow, prepareFlowApp, type PreparedFlowApp } from "./flow-utils";

// Cooldowns and expiries read `Date.now()`: a faked clock moves past them at once.
beforeEach(() => {
  vi.useFakeTimers({ toFake: ["Date"] });
});
afterEach(() => {
  vi.useRealTimers();
});

// WHY: a one-time code (recovery, sign-in second factor, signup) is a 6-digit
// secret. Its attempt limit and single use must hold on the server: with the
// default client-held (encapsulated) state a client can resubmit any older
// copy of the state, so a limit kept in the state alone is no limit. And a
// recovery code is bound to the account it was sent for — the identifier
// typed can resolve to another account by the time the code is entered.

let deliverySource: "typed" | "registered" = "typed";
const delivered: AuthDeliveryPayload[] = [];
/** Subjects `afterLogin` fired for. */
const afterLogins: string[] = [];
/** L-2: an app `resolvePincodeTarget` that fails on rows it cannot find. */
let throwingTarget = false;
const PLACEHOLDER = "00000000-0000-4000-8000-000000000000";

@Inherit()
@Injectable()
@Controller()
class CodeWorkflow extends FlowWorkflow {
  protected override resolveRecoveryDeliverySource(): "typed" | "registered" {
    return deliverySource;
  }
  protected override resolveSignupPolicy(_ctx: AuthWfCtx): NonNullable<AuthWfCtx["signup"]> {
    return { allowSignup: true, collectUsername: false };
  }
  protected override async deliver(payload: AuthDeliveryPayload): Promise<void> {
    delivered.push(payload);
  }
  protected override afterLogin(ctx: AuthWfCtx): void {
    afterLogins.push(ctx.subject ?? "");
  }
  protected override resolvePincodeTarget(ctx: AuthWfCtx) {
    if (throwingTarget && ctx.subject === PLACEHOLDER) throw new HttpError(400, "No such tenant");
    return super.resolvePincodeTarget(ctx);
  }
}

const PASSWORD = "Password123!";
const MAX = 5; // default pincodeMaxAttempts
type StoreMode = "durable" | "encapsulated";
type Res = Awaited<ReturnType<PreparedFlowApp["submit"]>>;

async function boot(
  storeMode: StoreMode,
  source: "typed" | "registered" = "typed",
  extra: {
    workflowOpts?: Partial<AuthWorkflowOpts>;
    rateLimit?: RateLimitInterceptorOptions;
    triggerHooks?: WfTriggerHooks;
  } = {},
): Promise<PreparedFlowApp> {
  deliverySource = source;
  delivered.length = 0;
  afterLogins.length = 0;
  throwingTarget = false;
  return prepareFlowApp({
    workflowClass: CodeWorkflow,
    storeMode,
    userStore: new UserStoreMemory(undefined, { handleFields: ["email"] }),
    ...extra,
  });
}

function lastCode(kind: string): string {
  const sent = delivered.findLast((d) => d.kind === kind) as { code?: string } | undefined;
  if (!sent?.code) throw new Error(`no ${kind} delivered`);
  return sent.code;
}

/** What a code submit answered: the inline code error, or `ok` once past the code. */
function answer(res: Res): string {
  const errors = res.body.inputRequired?.context?.errors as { code?: string } | undefined;
  if (errors?.code) return errors.code;
  return res.status < 400 ? "ok" : `http ${res.status}`;
}

const wrongFor = (code: string) => (code === "000000" ? "000001" : "000000");
const codeInput = (code: string) => ({ formData: { code, rememberDevice: false } });

/** A run paused on a code form: its state token and the code that was sent. */
interface Paused {
  wfs: string;
  code: string;
}

interface FlowDef {
  /** The delivery kind of its code. */
  kind: string;
  seed: (app: PreparedFlowApp) => Promise<unknown>;
  /** Start a run and bring it to the code form (one send). */
  run: (app: PreparedFlowApp) => Promise<Res>;
}

const flowDefs: Record<string, FlowDef> = {
  recovery: {
    kind: "recovery-pincode",
    seed: (app) => app.seedUser("alice@example.test", PASSWORD),
    run: async (app) => {
      const started = await app.start("auth/recovery/flow");
      return app.submit(started.body.wfs, { formData: { email: "alice@example.test" } });
    },
  },
  "sign-in second factor (email)": {
    kind: "mfa-pincode",
    seed: (app) =>
      app.seedUser("alice", PASSWORD, {
        mfa: { methods: [{ name: "email", value: "alice@example.test", confirmed: true }] },
      }),
    run: (app) => app.login("alice", PASSWORD),
  },
  signup: {
    kind: "signup-pincode",
    seed: async () => undefined,
    run: async (app) => {
      const started = await app.start("auth/signup/flow");
      return app.submit(started.body.wfs, { formData: { email: "new@example.test" } });
    },
  },
};

const flows: Record<string, (app: PreparedFlowApp) => Promise<Paused>> = Object.fromEntries(
  Object.entries(flowDefs).map(([name, def]) => [
    name,
    async (app: PreparedFlowApp) => {
      await def.seed(app);
      const res = await def.run(app);
      expect(res.body.inputRequired?.context?.public?.pincode).toBeDefined();
      return { wfs: res.body.wfs as string, code: lastCode(def.kind) };
    },
  ]),
);

/** Put a durable pause back the way it was (a stale copy of the state, e.g. a restored row). */
async function snapshot(
  app: PreparedFlowApp,
  storeMode: StoreMode,
  wfs: string,
): Promise<() => Promise<void>> {
  if (storeMode === "encapsulated") return async () => undefined; // the token IS the copy
  const handle = wfs.slice(wfs.indexOf(".") + 1);
  const entry = await app.durableStore.get(handle);
  if (!entry) throw new Error("no durable state for the pause");
  const copy = structuredClone(entry);
  // a fresh copy per restore: the store keeps (and a resume mutates) the object
  return () => app.durableStore.set(handle, structuredClone(copy.state), copy.expiresAt);
}

for (const storeMode of ["encapsulated", "durable"] as const) {
  for (const [flow, pause] of Object.entries(flows)) {
    describe(`${flow} code, ${storeMode} state: limits held on the server (P1)`, () => {
      it("8 wrong codes on one token hit the limit, and the right code after it is refused", async () => {
        const app = await boot(storeMode);
        const { wfs, code } = await pause(app);
        const answers: string[] = [];
        for (let i = 0; i < 8; i++)
          answers.push(answer(await app.submit(wfs, codeInput(wrongFor(code)))));
        expect(answers.slice(0, MAX - 1)).toEqual(Array(MAX - 1).fill("Invalid code"));
        for (const later of answers.slice(MAX - 1)) {
          expect(later).toBe("Too many invalid attempts. Please request a new code.");
        }
        expect(answer(await app.submit(wfs, codeInput(code)))).toBe(
          "Too many invalid attempts. Please request a new code.",
        );
      });

      it("a used code is spent: replaying the state from before it was entered refuses it", async () => {
        const app = await boot(storeMode);
        const { wfs, code } = await pause(app);
        const restore = await snapshot(app, storeMode, wfs);
        expect(answer(await app.submit(wfs, codeInput(code)))).toBe("ok");
        await restore();
        const replay = await app.submit(wfs, codeInput(code));
        expect(answer(replay)).toBe("Code expired");
        expect(replay.body.finished).toBeUndefined();
      });

      it("parallel submits of one token cannot exceed the limit", async () => {
        const app = await boot(storeMode);
        const { wfs, code } = await pause(app);
        const answers = await Promise.all(
          Array.from({ length: 12 }, () => app.submit(wfs, codeInput(wrongFor(code)))),
        );
        const invalid = answers.filter((r) => answer(r) === "Invalid code").length;
        expect(invalid).toBeLessThanOrEqual(MAX - 1);
        expect(answers.some((r) => answer(r) === "ok")).toBe(false);
      });

      it("four wrong codes, then the right one still verifies", async () => {
        const app = await boot(storeMode);
        const { wfs, code } = await pause(app);
        for (let i = 0; i < MAX - 1; i++) await app.submit(wfs, codeInput(wrongFor(code)));
        expect(answer(await app.submit(wfs, codeInput(code)))).toBe("ok");
      });
    });
  }
}

async function requestRecovery(app: PreparedFlowApp, identifier: string): Promise<string> {
  const started = await app.start("auth/recovery/flow");
  const res = await app.submit(started.body.wfs, { formData: { email: identifier } });
  return res.body.wfs as string;
}
const atPasswordForm = (res: Res) =>
  res.body.inputRequired?.context?.public?.password !== undefined;

describe("a recovery code is bound to the account it was sent for (N1)", () => {
  for (const storeMode of ["encapsulated", "durable"] as const) {
    it(`M2 rename swap: a code sent to the attacker's channel does not reset the victim (${storeMode})`, async () => {
      const app = await boot(storeMode, "registered");
      await app.seedUser("victim", PASSWORD, {
        email: "victim@example.test",
        mfa: { methods: [{ name: "sms", value: "+15555550101", confirmed: true }] },
      });
      const attacker = await app.seedUser("attacker", PASSWORD, {
        email: "attacker@example.test",
        mfa: { methods: [{ name: "sms", value: "+15555550199", confirmed: true }] },
      });
      // The attacker's username takes the victim's email: the identifier now
      // resolves to the attacker (usernames first), so the code goes to them.
      await app.users.update(attacker, { username: "victim@example.test" });
      const wfs = await requestRecovery(app, "victim@example.test");
      expect(delivered.map((d) => d.recipient)).toEqual(["+15555550199"]);
      const code = lastCode("recovery-pincode");
      // Renamed back: the same identifier resolves to the victim now.
      await app.users.update(attacker, { username: "attacker" });
      const res = await app.submit(wfs, codeInput(code));
      expect(answer(res)).toBe("Invalid code");
      expect(atPasswordForm(res)).toBe(false);
    });

    it(`M1: an address moved to another account between send and check refuses the code (${storeMode})`, async () => {
      const app = await boot(storeMode, "typed");
      const first = await app.seedUser("first", PASSWORD, { email: "shared@example.test" });
      const second = await app.seedUser("second", PASSWORD, { email: "second@example.test" });
      const wfs = await requestRecovery(app, "shared@example.test");
      const code = lastCode("recovery-pincode");
      // An admin moves the address to the other account.
      await app.users.update(first, { email: "first@example.test" } as never);
      await app.users.update(second, { email: "shared@example.test" } as never);
      const res = await app.submit(wfs, codeInput(code));
      expect(answer(res)).toBe("Invalid code");
      expect(atPasswordForm(res)).toBe(false);
    });

    it(`an account deleted and recreated between send and check refuses the code (${storeMode})`, async () => {
      const app = await boot(storeMode, "typed");
      const old = await app.seedUser("alice@example.test", PASSWORD);
      const wfs = await requestRecovery(app, "alice@example.test");
      const code = lastCode("recovery-pincode");
      await app.users.deleteUser(old);
      await app.seedUser("alice@example.test", PASSWORD);
      const res = await app.submit(wfs, codeInput(code));
      expect(answer(res)).toBe("Invalid code");
      expect(atPasswordForm(res)).toBe(false);
    });

    it(`an unchanged account still recovers with its code (${storeMode})`, async () => {
      const app = await boot(storeMode, "registered");
      await app.seedUser("victim", PASSWORD, {
        email: "victim@example.test",
        mfa: { methods: [{ name: "sms", value: "+15555550101", confirmed: true }] },
      });
      const wfs = await requestRecovery(app, "victim@example.test");
      const res = await app.submit(wfs, codeInput(lastCode("recovery-pincode")));
      expect(answer(res)).toBe("ok");
      expect(atPasswordForm(res)).toBe(true);
    });
  }
});

/** Move the (faked) clock forward. */
const advanceClock = async (ms: number) => {
  vi.setSystemTime(Date.now() + ms);
};
const LIMIT_REACHED = { status: 429, code: "AOOTH_CODE_LIMIT_REACHED" };
const limitOf = (res: Res) => ({ status: res.status, code: (res.body as { code?: string }).code });

/** A response with what varies between runs masked (token, timestamps, masked hint). */
const shape = (res: Res) => ({
  status: res.status,
  length: JSON.stringify(res.body).length,
  body: JSON.parse(
    JSON.stringify(res.body)
      .replace(/"wfs":"([a-z-]+)\.[^"]+"/g, '"wfs":"$1.<token>"')
      .replace(/"resendAllowedAt":\d+/g, '"resendAllowedAt":0')
      .replace(/"sentTo":"[^"]*"/g, '"sentTo":"<masked>"'),
  ) as unknown,
});

describe("code sends are bounded on the server (M-1)", () => {
  for (const storeMode of ["encapsulated", "durable"] as const) {
    for (const [flow, def] of Object.entries(flowDefs)) {
      it(`${flow}, ${storeMode}: replaying a resend of one state sends once per cooldown`, async () => {
        const app = await boot(storeMode, "typed", {
          workflowOpts: { mfa: { pincodeResendTimeoutMs: 150 } },
        });
        const { wfs } = await flows[flow](app);
        const restore = await snapshot(app, storeMode, wfs);
        await advanceClock(200);
        const before = delivered.length;
        for (let i = 0; i < 5; i++) {
          await restore();
          await app.submit(wfs, { action: "resend" });
        }
        expect(delivered.length - before).toBe(1);
      });

      it(`${flow}, ${storeMode}: new runs within the cooldown send once`, async () => {
        const app = await boot(storeMode);
        await def.seed(app);
        for (let i = 0; i < 3; i++) {
          const res = await def.run(app);
          expect(res.body.inputRequired?.context?.public?.pincode).toBeDefined();
        }
        expect(delivered.filter((d) => d.kind === def.kind)).toHaveLength(1);
      });

      it(`${flow}, ${storeMode}: wrong codes across resends use up the budget, then sends and checks answer 429`, async () => {
        const app = await boot(storeMode, "typed", {
          workflowOpts: { mfa: { pincodeResendTimeoutMs: 100, pincodeMaxFailures: 6 } },
        });
        const first = await flows[flow](app);
        for (let i = 0; i < MAX; i++) await app.submit(first.wfs, codeInput(wrongFor(first.code)));
        await advanceClock(150);
        const resent = await app.submit(first.wfs, { action: "resend" });
        const wfs = resent.body.wfs as string;
        expect(delivered.filter((d) => d.kind === def.kind)).toHaveLength(2);
        const code = lastCode(def.kind);
        expect(answer(await app.submit(wfs, codeInput(wrongFor(code))))).toBe("Invalid code");
        // budget (6) spent: the right code, a resend and a new run all answer 429
        expect(limitOf(await app.submit(wfs, codeInput(code)))).toEqual(LIMIT_REACHED);
        await advanceClock(150);
        const sends = delivered.length;
        expect(limitOf(await def.run(app))).toEqual(LIMIT_REACHED);
        expect(delivered.length).toBe(sends);
      });
    }
  }

  it("sends after a first factor count per account (aooth.send-user)", async () => {
    const app = await boot("durable", "typed", {
      workflowOpts: { mfa: { pincodeResendTimeoutMs: 50 } },
      rateLimit: { policies: { "aooth.send-user": "2/1h" } },
    });
    const def = flowDefs["sign-in second factor (email)"];
    await def.seed(app);
    for (let i = 0; i < 2; i++) {
      expect((await def.run(app)).body.inputRequired?.context?.public?.pincode).toBeDefined();
      await advanceClock(70);
    }
    const limited = await def.run(app);
    expect(limited.status).toBe(429);
    expect(limited.body).toMatchObject({
      code: "RATE_LIMITED",
      params: { policy: "aooth.send-user", limit: 2 },
    });
    expect(delivered.filter((d) => d.kind === "mfa-pincode")).toHaveLength(2);
  });

  for (const storeMode of ["encapsulated", "durable"] as const) {
    it(`recovery, ${storeMode}: known and unknown identifiers answer the cooldown and the budget identically`, async () => {
      const app = await boot(storeMode, "typed", {
        workflowOpts: { mfa: { pincodeMaxFailures: 2 } },
      });
      await app.seedUser("alice@example.test", PASSWORD);
      const recover = async (identifier: string) => {
        const started = await app.start("auth/recovery/flow");
        return app.submit(started.body.wfs, { formData: { email: identifier } });
      };
      // same length as the known one, so the masked hints match in length
      const answers = async (identifier: string) => {
        const first = await recover(identifier);
        const cooling = await recover(identifier); // a second run in the cooldown sends nothing
        const wrong1 = await app.submit(first.body.wfs, codeInput("000000"));
        const wrong2 = await app.submit(first.body.wfs, codeInput("000000"));
        const limited = await app.submit(first.body.wfs, codeInput("000000"));
        const newRun = await recover(identifier);
        return [first, cooling, wrong1, wrong2, limited, newRun];
      };
      const known = await answers("alice@example.test");
      const unknown = await answers("ghost@example.test");
      expect(delivered.map((d) => d.recipient)).toEqual(["alice@example.test"]);
      expect(unknown.map(shape)).toEqual(known.map(shape));
      expect(limitOf(known[4])).toEqual(LIMIT_REACHED);
      expect(limitOf(known[5])).toEqual(LIMIT_REACHED);
    });
  }
});

describe("recovery binding and resolvers (L-1, L-2)", () => {
  it("M2: a code sent to a registered channel that changed before the check is refused", async () => {
    const app = await boot("durable", "registered");
    const userId = await app.seedUser("bob", PASSWORD, {
      email: "bob@example.test",
      mfa: { methods: [{ name: "email", value: "old@example.test", confirmed: true }] },
    });
    const started = await app.start("auth/recovery/flow");
    const paused = await app.submit(started.body.wfs, { formData: { email: "bob@example.test" } });
    expect(delivered.map((d) => d.recipient)).toEqual(["old@example.test"]);
    const code = lastCode("recovery-pincode");
    await app.users.update(userId, {
      mfa: { methods: [{ name: "email", value: "new@example.test", confirmed: true }] },
    } as never);
    const res = await app.submit(paused.body.wfs as string, codeInput(code));
    expect(answer(res)).toBe("Invalid code");
    expect((await app.users.getUser(userId)).account.verifiedEmail).toBeFalsy();
  });

  for (const source of ["typed", "registered"] as const) {
    it(`${source}: a resolver that fails on the placeholder row still answers like a known identifier`, async () => {
      const app = await boot("durable", source);
      throwingTarget = true;
      await app.seedUser("alice@example.test", PASSWORD, {
        mfa: { methods: [{ name: "sms", value: "+15555550101", confirmed: true }] },
      });
      const recover = async (identifier: string) => {
        const started = await app.start("auth/recovery/flow");
        return app.submit(started.body.wfs, { formData: { email: identifier } });
      };
      const known = await recover("alice@example.test");
      const unknown = await recover("ghost@example.test");
      expect(unknown.status).toBe(known.status);
      expect(unknown.body.inputRequired?.context?.public?.pincode).toBeDefined();
      const wrong = await app.submit(unknown.body.wfs as string, codeInput("000000"));
      expect(answer(wrong)).toBe("Invalid code");
    });
  }
});

async function pausedAtCode() {
  const app = await boot("durable");
  const userId = await app.seedUser("alice", PASSWORD, {
    mfa: { methods: [{ name: "email", value: "alice@example.test", confirmed: true }] },
  });
  const res = await app.login("alice", PASSWORD);
  return { app, userId, wfs: res.body.wfs as string, code: lastCode("mfa-pincode") };
}

describe("a login paused at its second factor (L-4)", () => {
  it("gets no session once the account is deactivated meanwhile", async () => {
    const { app, userId, wfs, code } = await pausedAtCode();
    await app.users.deactivateAccount(userId);
    const res = await app.submit(wfs, codeInput(code));
    expect(res.body.finished).toBe(true);
    expect((res.body.data as { accessToken?: string } | undefined)?.accessToken).toBeUndefined();
    expect(res.body.message).toMatchObject({ level: "error", text: "Invalid credentials" });
    expect(afterLogins).toEqual([]);
    expect(await app.auth.listSessions(userId)).toEqual([]);
  });

  it("gets no session once the account is locked meanwhile", async () => {
    const { app, userId, wfs, code } = await pausedAtCode();
    await app.users.lockAccount(userId, "admin");
    const res = await app.submit(wfs, codeInput(code));
    expect((res.body.data as { accessToken?: string } | undefined)?.accessToken).toBeUndefined();
    expect(res.body.message).toMatchObject({
      level: "error",
      text: "Account locked, please try again later",
    });
    expect(afterLogins).toEqual([]);
  });

  it("an active account still signs in", async () => {
    const { app, userId, wfs, code } = await pausedAtCode();
    const res = await app.submit(wfs, codeInput(code));
    expect(typeof (res.body.data as { accessToken?: string }).accessToken).toBe("string");
    expect(afterLogins).toEqual([userId]);
  });
});

/** Recovery for `identifier` from client `ip` (forwarded; the limiter trusts one proxy hop). */
async function recoverFrom(app: PreparedFlowApp, identifier: string, ip: string): Promise<Res> {
  const headers = { "x-forwarded-for": ip };
  const started = await app.start("auth/recovery/flow", headers);
  return app.submit(started.body.wfs, { formData: { email: identifier } }, headers);
}

/**
 * Behind a trusted proxy (an in-process request has no socket peer — give it
 * the proxy's address, as a real socket has), with the per-IP send limit out
 * of the way.
 */
const behindProxy = (mfa: Partial<NonNullable<AuthWorkflowOpts["mfa"]>>) => ({
  triggerHooks: {
    around: (run: () => Promise<unknown>) => {
      Object.defineProperty(useRequest().raw.socket, "remoteAddress", { value: "10.0.0.1" });
      return run();
    },
  },
  workflowOpts: { mfa: { pincodeResendTimeoutMs: 20, ...mfa } },
  rateLimit: { trustProxy: true, policies: { "aooth.send": false as const } },
});

describe("the failure budget is per client IP, with a global cap per destination", () => {
  for (const storeMode of ["encapsulated", "durable"] as const) {
    it(`${storeMode}: an attacker IP spending its budget does not block the owner's IP — known and unknown alike`, async () => {
      const app = await boot(storeMode, "typed", behindProxy({ pincodeMaxFailures: 3 }));
      await app.seedUser("alice@example.test", PASSWORD);
      const scenario = async (identifier: string) => {
        const attacker = "203.0.113.7";
        const run = await recoverFrom(app, identifier, attacker);
        const headers = { "x-forwarded-for": attacker };
        const wrong = [];
        for (let i = 0; i < 4; i++) {
          wrong.push(await app.submit(run.body.wfs as string, codeInput("000000"), headers));
        }
        await advanceClock(30);
        const attackerAgain = await recoverFrom(app, identifier, attacker);
        await advanceClock(30);
        const owner = await recoverFrom(app, identifier, "198.51.100.20");
        return { wrong, attackerAgain, owner };
      };
      const known = await scenario("alice@example.test");
      const unknown = await scenario("ghost@example.test");
      for (const r of [known, unknown]) {
        expect(r.wrong.slice(0, 3).map(answer)).toEqual(Array(3).fill("Invalid code"));
        expect(limitOf(r.wrong[3])).toEqual(LIMIT_REACHED);
        expect(limitOf(r.attackerAgain)).toEqual(LIMIT_REACHED);
        expect(r.owner.body.inputRequired?.context?.public?.pincode).toBeDefined();
      }
      // the owner's code went out, and it verifies from the owner's IP
      const ownerCode = lastCode("recovery-pincode");
      const ok = await app.submit(known.owner.body.wfs as string, codeInput(ownerCode), {
        "x-forwarded-for": "198.51.100.20",
      });
      expect(answer(ok)).toBe("ok");
      expect([...known.wrong, known.attackerAgain, known.owner].map(shape)).toEqual(
        [...unknown.wrong, unknown.attackerAgain, unknown.owner].map(shape),
      );
    });
  }

  it("the global cap stops guessing spread over many IPs", async () => {
    const app = await boot(
      "durable",
      "typed",
      behindProxy({ pincodeMaxFailures: 3, pincodeMaxFailuresGlobal: 5 }),
    );
    await app.seedUser("alice@example.test", PASSWORD);
    // three IPs, two wrong codes each: 6 > 5 across IPs, none over its own 3
    for (const ip of ["203.0.113.1", "203.0.113.2", "203.0.113.3"]) {
      const run = await recoverFrom(app, "alice@example.test", ip);
      for (let i = 0; i < 2; i++) {
        await app.submit(run.body.wfs as string, codeInput("000000"), { "x-forwarded-for": ip });
      }
      await advanceClock(30);
    }
    const fresh = await recoverFrom(app, "alice@example.test", "203.0.113.4");
    expect(limitOf(fresh)).toEqual(LIMIT_REACHED);
  });
});

describe("the resend wait is per client IP, with a send cap per destination", () => {
  const OWNER = "198.51.100.20";
  const ATTACKER = "203.0.113.7";

  for (const storeMode of ["encapsulated", "durable"] as const) {
    it(`${storeMode}: an attacker IP inside the wait does not stop the owner's IP from getting a code — known and unknown alike`, async () => {
      const app = await boot(storeMode, "typed", behindProxy({ pincodeResendTimeoutMs: 60_000 }));
      await app.seedUser("alice@example.test", PASSWORD);
      const scenario = async (identifier: string) => {
        const first = await recoverFrom(app, identifier, ATTACKER);
        const again = await recoverFrom(app, identifier, ATTACKER); // inside the attacker's wait
        const owner = await recoverFrom(app, identifier, OWNER);
        return [first, again, owner];
      };
      const known = await scenario("alice@example.test");
      // the attacker's first request and the owner's both sent; the repeat did not
      expect(delivered.map((d) => d.recipient)).toEqual([
        "alice@example.test",
        "alice@example.test",
      ]);
      const ok = await app.submit(
        known[2].body.wfs as string,
        codeInput(lastCode("recovery-pincode")),
        {
          "x-forwarded-for": OWNER,
        },
      );
      expect(answer(ok)).toBe("ok");
      const unknown = await scenario("ghost@example.test");
      expect(unknown.map(shape)).toEqual(known.map(shape));
    });
  }

  it("the send cap stops sends spread over many IPs — known and unknown alike", async () => {
    const app = await boot("durable", "typed", behindProxy({ pincodeMaxSendsGlobal: 3 }));
    await app.seedUser("alice@example.test", PASSWORD);
    const spread = async (identifier: string) => {
      const answers = [];
      for (let i = 1; i <= 5; i++)
        answers.push(await recoverFrom(app, identifier, `203.0.113.${i}`));
      return answers;
    };
    const known = await spread("alice@example.test");
    expect(delivered).toHaveLength(3);
    for (const res of known) expect(res.body.inputRequired?.context?.public?.pincode).toBeDefined();
    const unknown = await spread("ghost@example.test");
    expect(delivered).toHaveLength(3);
    expect(unknown.map(shape)).toEqual(known.map(shape));
  });
});
