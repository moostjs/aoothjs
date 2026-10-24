import { describe, expect, it } from "vite-plus/test";

import {
  AuthCredential,
  CredentialStoreJwt,
  CredentialStoreMemory,
  DenylistStoreMemory,
} from "@aooth/auth";
import { Controller, Inherit, Injectable } from "moost";

import type { AuthWfCtx } from "../workflow/auth-workflow.ctx";
import { FlowWorkflow, type PreparedFlowApp, prepareFlowApp } from "./flow-utils";

// F120: a password change must end the session it was made from. The new pair
// is minted under a fresh session id, so the pre-change access + refresh
// tokens must stop working — whatever `revokeOtherSessions` says about the
// user's OTHER sessions.

const OLD_PASSWORD = "Password123!";
const NEW_PASSWORD = "NewPassword456!";

@Inherit()
@Injectable()
@Controller()
class KeepOtherSessionsWorkflow extends FlowWorkflow {
  protected override resolveChangePasswordPolicy(
    _ctx: AuthWfCtx,
  ): NonNullable<AuthWfCtx["changePassword"]> {
    return { revokeOtherSessions: false };
  }
}

interface Pair {
  accessToken: string;
  refreshToken: string;
}

async function issuePair(app: PreparedFlowApp, userId: string): Promise<Pair> {
  const issue = await app.auth.issue(userId);
  return { accessToken: issue.accessToken, refreshToken: issue.refreshToken as string };
}

/** Run the guarded change-password flow end to end with `accessToken`; returns the new pair. */
async function changePassword(app: PreparedFlowApp, accessToken: string): Promise<Pair> {
  const headers = { authorization: `Bearer ${accessToken}` };
  const started = await app.post(
    "/auth/change-password",
    { wfid: "auth/change-password/flow" },
    headers,
  );
  expect(started.status).toBe(201);
  expect(started.body.wfs).toBeTypeOf("string");
  const done = await app.post(
    "/auth/change-password",
    {
      wfs: started.body.wfs,
      input: {
        formData: {
          currentPassword: OLD_PASSWORD,
          newPassword: NEW_PASSWORD,
          confirmPassword: NEW_PASSWORD,
        },
      },
    },
    headers,
  );
  expect(done.status).toBe(201);
  expect(done.body.finished).toBe(true);
  const data = done.body.data as Partial<Pair>;
  expect(data.accessToken).toBeTypeOf("string");
  expect(data.refreshToken).toBeTypeOf("string");
  return data as Pair;
}

async function expectPairDead(app: PreparedFlowApp, pair: Pair): Promise<void> {
  expect(await app.auth.validate(pair.accessToken)).toBeNull();
  const status = await app.get("/auth/status", { authorization: `Bearer ${pair.accessToken}` });
  expect(status.status).toBe(401);
  const refreshed = await app.post("/auth/refresh", { refreshToken: pair.refreshToken });
  expect(refreshed.status).toBe(401);
}

async function expectPairAlive(app: PreparedFlowApp, pair: Pair, userId: string): Promise<void> {
  expect((await app.auth.validate(pair.accessToken))?.userId).toBe(userId);
  const refreshed = await app.post("/auth/refresh", { refreshToken: pair.refreshToken });
  expect(refreshed.status).toBe(201);
}

/** JWT-backed credential (no session enumeration) with a hand-advanced clock. */
function statelessCredential(): AuthCredential & { tick(): void } {
  let t = 1_000_000_800_000;
  const clock = { now: () => t };
  const auth = new AuthCredential({
    store: new CredentialStoreJwt({
      secret: "a-32-byte-or-longer-test-secret-value!",
      denylist: new DenylistStoreMemory(),
      clock,
    }),
    method: "token",
    accessTtl: 60_000,
    refresh: { ttl: 600_000, rotation: "always" },
    clock,
  });
  return Object.assign(auth, {
    tick: () => {
      t += 1000;
    },
  });
}

describe("F120: change-password ends the pre-change session", () => {
  it("rejects the old access + refresh tokens and keeps the new pair working", async () => {
    const app = await prepareFlowApp();
    const userId = await app.seedUser("alice", OLD_PASSWORD);
    const old = await issuePair(app, userId);

    const fresh = await changePassword(app, old.accessToken);

    await expectPairDead(app, old);
    await expectPairAlive(app, fresh, userId);
    // Exactly one session survives: the one the change issued.
    const sessions = await app.auth.listSessions(userId);
    expect(sessions).toHaveLength(1);
    expect(sessions[0].sessionId).toBe((await app.auth.validate(fresh.accessToken))?.sessionId);
  });

  it("revokes the user's other sessions by default (revokeOtherSessions: true)", async () => {
    const app = await prepareFlowApp();
    const userId = await app.seedUser("alice", OLD_PASSWORD);
    const old = await issuePair(app, userId);
    const other = await issuePair(app, userId);

    const fresh = await changePassword(app, old.accessToken);

    await expectPairDead(app, old);
    await expectPairDead(app, other);
    await expectPairAlive(app, fresh, userId);
  });

  it("revokeOtherSessions: false keeps OTHER sessions but still ends the pre-change one", async () => {
    const app = await prepareFlowApp({ workflowClass: KeepOtherSessionsWorkflow });
    const userId = await app.seedUser("alice", OLD_PASSWORD);
    const old = await issuePair(app, userId);
    const other = await issuePair(app, userId);

    const fresh = await changePassword(app, old.accessToken);

    await expectPairDead(app, old);
    await expectPairAlive(app, other, userId);
    await expectPairAlive(app, fresh, userId);
  });

  it("an old refresh token rotated BEFORE the change cannot be replayed after it", async () => {
    const app = await prepareFlowApp();
    const userId = await app.seedUser("alice", OLD_PASSWORD);
    const old = await issuePair(app, userId);
    // The client rotated once; an attacker holds the rotated-out token and the
    // client's current pair. Both belong to the pre-change session family.
    const rotated = await app.post("/auth/refresh", { refreshToken: old.refreshToken });
    expect(rotated.status).toBe(201);
    const current = rotated.body as Pair;

    await changePassword(app, current.accessToken);

    await expectPairDead(app, current);
    const replay = await app.post("/auth/refresh", { refreshToken: old.refreshToken });
    expect(replay.status).toBe(401);
  });

  it("still succeeds and ends the pre-change session under a tight maxConcurrent cap", async () => {
    // The pre-change session is revoked BEFORE the new pair is minted, so the
    // cap never refuses the issue and leaves the old session standing.
    const credential = new AuthCredential({
      store: new CredentialStoreMemory(),
      method: "token",
      accessTtl: 60_000,
      refresh: { ttl: 600_000, rotation: "always" },
      maxConcurrent: 1,
      onLimit: "reject",
    });
    const app = await prepareFlowApp({ credential, workflowClass: KeepOtherSessionsWorkflow });
    const userId = await app.seedUser("alice", OLD_PASSWORD);
    const old = await issuePair(app, userId);

    const fresh = await changePassword(app, old.accessToken);

    await expectPairDead(app, old);
    await expectPairAlive(app, fresh, userId);
  });

  it("ends a legacy (pre-sessionId) session's refresh token too, with revokeOtherSessions: false", async () => {
    // Rows minted before sessionId existed surface as singleton sessions keyed
    // by the access token's fingerprint — that key can't reach the refresh row,
    // so the change falls back to revoking every session of the user.
    const store = new CredentialStoreMemory();
    const credential = new AuthCredential({
      store,
      method: "token",
      accessTtl: 60_000,
      refresh: { ttl: 600_000, rotation: "always" },
    });
    const app = await prepareFlowApp({ credential, workflowClass: KeepOtherSessionsWorkflow });
    const userId = await app.seedUser("alice", OLD_PASSWORD);
    const now = Date.now();
    const legacy: Pair = {
      accessToken: await store.persist(
        { userId, issuedAt: now, expiresAt: now + 60_000, kind: "access" },
        60_000,
      ),
      refreshToken: await store.persist(
        { userId, issuedAt: now, expiresAt: now + 600_000, kind: "refresh" },
        600_000,
      ),
    };

    const fresh = await changePassword(app, legacy.accessToken);

    await expectPairDead(app, legacy);
    await expectPairAlive(app, fresh, userId);
  });

  describe("stateless store (no session enumeration)", () => {
    it.each([
      ["revokeOtherSessions: true", undefined],
      ["revokeOtherSessions: false", KeepOtherSessionsWorkflow],
    ])("%s — the pre-change pair stops working", async (_label, workflowClass) => {
      const credential = statelessCredential();
      const app = await prepareFlowApp({ credential, workflowClass });
      const userId = await app.seedUser("alice", OLD_PASSWORD);
      const old = await issuePair(app, userId);
      credential.tick();

      const fresh = await changePassword(app, old.accessToken);

      expect(await app.auth.validate(old.accessToken)).toBeNull();
      const replay = await app.post("/auth/refresh", { refreshToken: old.refreshToken });
      expect(replay.status).toBe(401);
      await expectPairAlive(app, fresh, userId);
    });
  });
});

describe("forced password change at login revokes the user's existing sessions", () => {
  it.each([
    ["initial", { password: { isInitial: true } }],
    ["expired", { password: { lastChanged: 1 } }],
  ])("%s password", async (_label, patch) => {
    const app = await prepareFlowApp({
      userConfig: { password: { maxAgeMs: 30 * 24 * 3600_000 } },
    });
    const userId = await app.seedUser("alice", OLD_PASSWORD);
    const old = await issuePair(app, userId);
    await app.users.update(userId, patch as never);

    const atForm = await app.login("alice", OLD_PASSWORD);
    expect(atForm.status).toBe(201);
    expect(atForm.body.inputRequired).toBeDefined();
    const enrol = await app.submit(atForm.body.wfs, {
      formData: { newPassword: NEW_PASSWORD, confirmPassword: NEW_PASSWORD, consents: [] },
    });
    // The optional MFA enrolment offer follows; skip it.
    const done = await app.submit(enrol.body.wfs, { action: "skip" });
    expect(done.status).toBe(201);
    expect(done.body.finished).toBe(true);
    const fresh = done.body.data as Pair;

    await expectPairDead(app, old);
    await expectPairAlive(app, fresh, userId);
  });
});

describe("forced password change at login: ordering against MFA", () => {
  it("does not revoke anything before the second factor is verified", async () => {
    const app = await prepareFlowApp();
    const userId = await app.seedUser("alice", OLD_PASSWORD);
    const old = await issuePair(app, userId);
    await app.users.update(userId, {
      password: { isInitial: true },
      mfa: { methods: [{ name: "email", value: "alice@example.com", confirmed: true }] },
    } as never);

    const atForm = await app.login("alice", OLD_PASSWORD);
    const atMfa = await app.submit(atForm.body.wfs, {
      formData: { newPassword: NEW_PASSWORD, confirmPassword: NEW_PASSWORD, consents: [] },
    });
    // Paused on the MFA challenge: whoever holds only the old password must
    // not be able to sign the user out everywhere.
    expect(atMfa.body.inputRequired?.context?.public?.pincode).toBeDefined();
    await expectPairAlive(app, old, userId);
  });
});

describe("a login run paused across a password change", () => {
  it("does not sign in with the password that was replaced meanwhile", async () => {
    const app = await prepareFlowApp();
    const userId = await app.seedUser("alice", OLD_PASSWORD);
    // Verified the (old) password, now paused on the optional MFA offer.
    const paused = await app.login("alice", OLD_PASSWORD);
    expect(paused.body.inputRequired).toBeDefined();
    await app.users.setPassword(userId, NEW_PASSWORD);

    const resumed = await app.submit(paused.body.wfs, { action: "skip" });
    expect(resumed.body.data?.accessToken).toBeUndefined();
    expect(resumed.body.message?.level).toBe("error");
    expect(await app.auth.listSessions(userId)).toEqual([]);
  });
});

describe("an authorize-initiated login paused on consent across a password change", () => {
  it("mints no authorization code", async () => {
    const app = await prepareFlowApp({ authorizationServer: true });
    const userId = await app.seedUser("alice", OLD_PASSWORD);
    const loopback = "http://127.0.0.1:5000/callback";
    const authorize = await app.get(
      `/auth/authorize?response_type=code&redirect_uri=${encodeURIComponent(loopback)}` +
        "&state=cs&code_challenge=chal&code_challenge_method=S256",
    );
    expect(authorize.status).toBe(302);
    const location = authorize.response!.headers.get("location")!;
    const handle = new URLSearchParams(location.split("?")[1]).get("authz")!;
    const cookie = authorize.setCookies.map((c) => c.split(";")[0]).join("; ");

    const started = await app.start("auth/login/flow", { cookie }, { formData: { authz: handle } });
    let res = await app.submit(
      started.body.wfs,
      { formData: { username: "alice", password: OLD_PASSWORD } },
      { cookie },
    );
    if (res.body.inputRequired?.context?.public?.mfaEnroll) {
      res = await app.submit(res.body.wfs, { action: "skip" }, { cookie });
    }
    // Parked on the consent prompt; the password changes elsewhere meanwhile.
    expect(res.body.inputRequired?.context?.public?.authz).toBeDefined();
    await app.users.setPassword(userId, NEW_PASSWORD);

    const approved = await app.submit(res.body.wfs, { formData: {} }, { cookie });
    expect(JSON.stringify(approved.body)).not.toContain("code=");
    expect(approved.body.message?.level).toBe("error");
  });
});
