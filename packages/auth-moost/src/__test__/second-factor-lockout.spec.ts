import { generateTotpCode, generateTotpSecret, UserStoreMemory } from "@aooth/user";
import { Controller, Inherit, Injectable } from "moost";
import { afterEach, beforeEach, describe, expect, it, vi } from "vite-plus/test";

import { OAUTH_CSRF_COOKIE } from "../oauth/oauth-csrf";
import type { OAuthRuntime } from "../oauth/oauth-runtime";
import type { AuthDeliveryPayload } from "../workflow/auth-workflow";
import type { AuthWfCtx } from "../workflow/auth-workflow.ctx";
import {
  type FlowResponse,
  FlowWorkflow,
  type PreparedFlowApp,
  prepareFlowApp,
} from "./flow-utils";

// WHY: a correct password reset the shared failed sign-in count even with a
// second factor still due — so whoever knows the password got `threshold - 1`
// TOTP guesses per password entry, without end. The count is now reset only
// when the sign-in completes.

beforeEach(() => {
  vi.useFakeTimers({ toFake: ["Date"] });
});
afterEach(() => {
  vi.useRealTimers();
});

const PASSWORD = "Password123!";
const LOCKED = "Account locked, please try again later";
const delivered: AuthDeliveryPayload[] = [];
/** Test seams of {@link Capturing}. */
const seams = {
  trustDevices: false,
  mfaDisabled: false,
  federatedCandidate: "",
  federatedOutcome: "needs-link" as "needs-link" | "linked",
};

@Inherit()
@Injectable()
@Controller()
class Capturing extends FlowWorkflow {
  protected override async deliver(payload: AuthDeliveryPayload): Promise<void> {
    delivered.push(payload);
  }
  protected override resolveDeviceTrust(ctx: AuthWfCtx): NonNullable<AuthWfCtx["deviceTrust"]> {
    return seams.trustDevices
      ? { enabled: true, optIn: true, skipsMfa: true }
      : (super.resolveDeviceTrust(ctx) as NonNullable<AuthWfCtx["deviceTrust"]>);
  }
  protected override resolveMfaPolicy(ctx: AuthWfCtx) {
    const base = super.resolveMfaPolicy(ctx) as NonNullable<AuthWfCtx["mfaPolicy"]>;
    return seams.mfaDisabled ? { ...base, mode: "disabled" as const } : base;
  }
  /** A provider whose verified profile matches an existing account (needs-link). */
  protected override oauthRuntime(): Promise<OAuthRuntime> {
    const profile = { provider: "test", subject: "sub-1", email: "fed@example.test" };
    return Promise.resolve({
      registry: {
        verifyState: async () => ({ provider: "test", random: "seed" }),
        deriveSeededPkce: () => ({ verifier: "v", nonce: "n" }),
        require: () => ({ exchange: async () => profile }),
        redirectUri: () => "https://app.test/callback",
      },
      federated: {
        resolveUser: async () =>
          seams.federatedOutcome === "linked"
            ? { kind: "linked", userId: seams.federatedCandidate }
            : { kind: "needs-link", candidateUserId: seams.federatedCandidate },
        linkIdentity: async () => undefined,
      },
    } as unknown as OAuthRuntime);
  }
}

async function boot(): Promise<PreparedFlowApp> {
  delivered.length = 0;
  seams.trustDevices = false;
  seams.mfaDisabled = false;
  seams.federatedOutcome = "needs-link";
  return prepareFlowApp({
    workflowClass: Capturing,
    userStore: new UserStoreMemory(undefined, { handleFields: ["email"] }),
    userConfig: {
      lockout: { threshold: 3, duration: 60_000 },
      deviceTrust: { secret: "test-device-trust-secret" },
    },
  });
}

const lastCode = (kind: string) =>
  (delivered.findLast((d) => d.kind === kind) as { code: string }).code;

/** Two wrong passwords: the count is 2 (threshold 3). */
async function twoFailures(app: PreparedFlowApp, handle: string, id: string) {
  for (let i = 0; i < 2; i++) await app.login(handle, "wrong-password");
  expect(await count(app, id)).toBe(2);
}

const count = async (app: PreparedFlowApp, id: string) =>
  (await app.users.getUser(id)).account.failedLoginAttempts;

describe("a second factor's failures are not wiped by the password", () => {
  it("wrong TOTP codes keep counting across password entries and lock the account", async () => {
    const app = await boot();
    const secret = generateTotpSecret();
    const id = await app.seedUser("alice", PASSWORD, {
      mfa: { methods: [{ name: "totp", value: secret, confirmed: true }] },
    });
    for (let round = 1; round <= 3; round++) {
      const atCode = await app.login("alice", PASSWORD);
      expect(atCode.body.inputRequired?.context?.errors ?? {}).toEqual({});
      const wrong = await app.submit(atCode.body.wfs, {
        formData: { code: "000000", rememberDevice: false },
      });
      const context = wrong.body.inputRequired?.context;
      if (round < 3) expect(context?.errors).toHaveProperty("code");
      else expect(context?.errors?.__form).toBe(LOCKED);
    }
    expect((await app.users.getUser(id)).account.locked).toBe(true);
    const again = await app.login("alice", PASSWORD);
    expect(again.body.inputRequired?.context?.errors?.__form).toBe(LOCKED);
  });

  it("a correct TOTP code completes the sign-in and resets the count", async () => {
    const app = await boot();
    const secret = generateTotpSecret();
    const id = await app.seedUser("alice", PASSWORD, {
      mfa: { methods: [{ name: "totp", value: secret, confirmed: true }] },
    });
    const atCode = await app.login("alice", PASSWORD);
    await app.submit(atCode.body.wfs, { formData: { code: "000000", rememberDevice: false } });
    const again = await app.login("alice", PASSWORD);
    expect(await count(app, id)).toBe(1);
    const done = await app.submit(again.body.wfs, {
      formData: { code: generateTotpCode(secret), rememberDevice: false },
    });
    expect(done.body.finished, JSON.stringify(done.body).slice(0, 300)).toBe(true);
    expect(await count(app, id)).toBe(0);
  });

  it("an emailed code: the count is kept at the password and reset when the sign-in completes", async () => {
    const app = await boot();
    const email = "bob@example.test";
    const id = await app.seedUser(email, PASSWORD, {
      mfa: { methods: [{ name: "email", value: email, confirmed: true }] },
    });
    for (let i = 0; i < 2; i++) await app.login(email, "wrong-password");
    const atCode = await app.login(email, PASSWORD);
    expect(atCode.body.inputRequired?.context?.public?.pincode).toBeDefined();
    expect(await count(app, id)).toBe(2);
    const sent = delivered.findLast((d) => d.kind === "mfa-pincode") as { code: string };
    const done = await app.submit(atCode.body.wfs, {
      formData: { code: sent.code, rememberDevice: false },
    });
    expect(done.body.finished, JSON.stringify(done.body).slice(0, 300)).toBe(true);
    expect(await count(app, id)).toBe(0);
  });

  it("a single-factor sign-in still resets the count at the password", async () => {
    const app = await boot();
    const id = await app.seedUser("carol", PASSWORD);
    for (let i = 0; i < 2; i++) await app.login("carol", "wrong-password");
    // No factor to pass: the password completes the first factor's check.
    const after = await app.login("carol", PASSWORD);
    expect(after.status).toBeLessThan(300);
    expect(await count(app, id)).toBe(0);
  });
});

describe("the count is reset when the sign-in completes — whatever completes it", () => {
  const withEmailFactor = (email: string) => ({
    mfa: { methods: [{ name: "email", value: email, confirmed: true }] },
  });

  it("a remembered device that skips the second factor", async () => {
    const app = await boot();
    seams.trustDevices = true;
    const email = "trust@example.test";
    const id = await app.seedUser(email, PASSWORD, withEmailFactor(email));
    const first = await app.login(email, PASSWORD);
    const remembered = await app.submit(first.body.wfs, {
      formData: { code: lastCode("mfa-pincode"), rememberDevice: true },
    });
    const cookie = remembered.setCookies.find((c) => c.startsWith("aooth_trusted_device="))!;
    vi.setSystemTime(Date.now() + 120_000);
    await twoFailures(app, email, id);
    const started = await app.start("auth/login/flow", { cookie: cookie.split(";")[0] });
    const done = await app.submit(
      started.body.wfs,
      { formData: { username: email, password: PASSWORD } },
      { cookie: cookie.split(";")[0] },
    );
    expect(done.body.finished, JSON.stringify(done.body).slice(0, 300)).toBe(true);
    expect(await count(app, id)).toBe(0);
  });

  it("MFA switched off while the account still has confirmed factors", async () => {
    const app = await boot();
    seams.mfaDisabled = true;
    const id = await app.seedUser("dave", PASSWORD, {
      mfa: { methods: [{ name: "totp", value: generateTotpSecret(), confirmed: true }] },
    });
    await twoFailures(app, "dave", id);
    const done = await app.login("dave", PASSWORD);
    expect(done.body.finished, JSON.stringify(done.body).slice(0, 300)).toBe(true);
    expect(await count(app, id)).toBe(0);
  });

  it("a federated account link proven with the password (prove-control)", async () => {
    const app = await boot();
    const email = "fed@example.test";
    const id = await app.seedUser(email, PASSWORD, withEmailFactor(email));
    seams.federatedCandidate = id;
    await twoFailures(app, email, id);
    const atProof = await app.post(
      "/auth/trigger",
      { wfid: "auth/login/flow", input: { formData: { state: "s", code: "c" } } },
      { cookie: `${OAUTH_CSRF_COOKIE}=seed` },
    );
    expect(atProof.body.inputRequired, JSON.stringify(atProof.body).slice(0, 300)).toBeDefined();
    const atCode = await app.submit(atProof.body.wfs, { formData: { password: PASSWORD } });
    // The password proof keeps the count: a second factor is still due.
    expect(await count(app, id)).toBe(2);
    const done = await app.submit(atCode.body.wfs, {
      formData: { code: lastCode("mfa-pincode"), rememberDevice: false },
    });
    expect(done.body.finished, JSON.stringify(done.body).slice(0, 300)).toBe(true);
    expect(await count(app, id)).toBe(0);
  });

  it("an abandoned run keeps the count", async () => {
    const app = await boot();
    const id = await app.seedUser("erin", PASSWORD, {
      mfa: { methods: [{ name: "totp", value: generateTotpSecret(), confirmed: true }] },
    });
    await twoFailures(app, "erin", id);
    const atCode: FlowResponse = await app.login("erin", PASSWORD);
    expect(atCode.body.inputRequired).toBeDefined();
    expect(await count(app, id)).toBe(2);
  });
});

// WHY: the sign-ins without a password judge a lock as a password sign-in does
// — a timed lock that lapsed is lifted (count back to 0), not refused until a
// password sign-in lifts it; a lock that holds still refuses.
describe("sso-callback and the account's lock", () => {
  async function federatedSignIn(lock: object) {
    const app = await boot();
    seams.federatedOutcome = "linked";
    const id = await app.seedUser("fed-linked@example.test", PASSWORD);
    await app.users.update(id, { account: { locked: true, lockReason: "x", ...lock } } as never);
    seams.federatedCandidate = id;
    const res = await app.post(
      "/auth/trigger",
      { wfid: "auth/login/flow", input: { formData: { state: "s", code: "c" } } },
      { cookie: `${OAUTH_CSRF_COOKIE}=seed` },
    );
    return { res, account: (await app.users.getUser(id)).account };
  }
  const refusedByGate = (res: FlowResponse) => res.body.next?.action?.reason === "oauth-failed";

  it("a lapsed timed lock: the account signs in, the lock is lifted and the count starts over", async () => {
    const { res, account } = await federatedSignIn({
      lockEnds: Date.now() - 1000,
      failedLoginAttempts: 2,
    });
    expect(refusedByGate(res), JSON.stringify(res.body).slice(0, 300)).toBe(false);
    expect(account).toMatchObject({ locked: false, failedLoginAttempts: 0 });
  });

  it("a lock that holds: refused", async () => {
    const { res, account } = await federatedSignIn({ lockEnds: Date.now() + 60_000 });
    expect(refusedByGate(res), JSON.stringify(res.body).slice(0, 300)).toBe(true);
    expect(account.locked).toBe(true);
  });
});
