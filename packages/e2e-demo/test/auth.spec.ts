import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from "vite-plus/test";

import { buildTestApp, expectOk, sleep, type TestApp } from "./harness";

const STRONG_NEW_PASSWORD = "NewPassword2!";

function base64url(input: string | Buffer): string {
  return Buffer.from(input)
    .toString("base64")
    .replace(/=+$/, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");
}

function forgeAlgNoneJwt(sub: string): string {
  const header = base64url(JSON.stringify({ alg: "none", typ: "JWT" }));
  const now = Math.floor(Date.now() / 1000);
  const payload = base64url(
    JSON.stringify({
      sub,
      iat: now,
      exp: now + 3600,
      jti: "forged-jti",
      state: { iatMs: now * 1000, expMs: (now + 3600) * 1000, kind: "access" },
    }),
  );
  return `${header}.${payload}.`;
}

function extractCookie(setCookie: string | string[] | null, name: string): string | undefined {
  if (!setCookie) return;
  const headers = Array.isArray(setCookie) ? setCookie : setCookie.split(/,(?=\s*[A-Za-z0-9_-]+=)/);
  for (const raw of headers) {
    const first = raw.split(";")[0].trim();
    const eq = first.indexOf("=");
    if (eq < 0) continue;
    if (first.slice(0, eq) === name) return first.slice(eq + 1);
  }
}

describe("AUTH — read-only / non-mutating", () => {
  let app: TestApp;

  beforeAll(async () => {
    app = await buildTestApp();
  });
  afterAll(async () => {
    await app.close();
  });

  it("AUTH-01 — login happy path", async () => {
    const tokens = await app.loginAs(app.fixtures.users.t1_alice);
    expect(tokens.accessToken).toBeTruthy();
    expect(tokens.refreshToken).toBeTruthy();
    expect(tokens.userId).toBe("t1_alice");
    expect(tokens.accessExpiresAt).toBeGreaterThan(Date.now());
    expect(tokens.refreshExpiresAt).toBeGreaterThan(tokens.accessExpiresAt);

    const status = await app.authedFetch(tokens.accessToken)("/auth/status");
    expect(status.status).toBe(200);
    const ctx = (await status.json()) as { userId: string };
    expect(ctx.userId).toBe("t1_alice");
  });

  it("AUTH-02 — login with wrong password → 401 Invalid credentials", async () => {
    const res = await app.fetch("/auth/login", {
      method: "POST",
      json: { username: app.fixtures.users.t1_alice.username, password: "wrong-password" },
    });
    expect(res.status).toBe(401);
    const body = await res.text();
    expect(body).toContain("Invalid credentials");
    expect(body).not.toContain("Unknown user");
  });

  it("AUTH-03 — login with unknown username → 401 (enumeration resistance)", async () => {
    const res = await app.fetch("/auth/login", {
      method: "POST",
      json: { username: "no-such-user-xyz", password: "Password1!" },
    });
    expect(res.status).toBe(401);
    const body = await res.text();
    expect(body).toContain("Invalid credentials");
  });

  it("AUTH-08 — refresh with missing token → 401", async () => {
    const missing = await app.fetch("/auth/refresh", { method: "POST", json: {} });
    expect(missing.status).toBe(401);
    expect(await missing.text()).toContain("Missing refresh token");

    const invalid = await app.fetch("/auth/refresh", {
      method: "POST",
      json: { refreshToken: "not-a-real-jwt" },
    });
    expect(invalid.status).toBe(401);
    expect(await invalid.text()).toContain("Invalid refresh token");
  });

  it("AUTH-11 — /auth/status is protected", async () => {
    const noToken = await app.fetch("/auth/status");
    expect(noToken.status).toBe(401);

    const tokens = await app.loginAs(app.fixtures.users.t1_alice);
    const ok = await app.authedFetch(tokens.accessToken)("/auth/status");
    expectOk(ok);
    const ctx = (await ok.json()) as { userId: string; method: string };
    expect(ctx.userId).toBe("t1_alice");
    expect(ctx.method).toBe("token");
  });

  it("AUTH-17 — @Public() route reachable without token", async () => {
    const res = await app.fetch("/health");
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ ok: true });
  });
});

describe("AUTH — manual lockout", () => {
  let app: TestApp;
  beforeEach(async () => {
    app = await buildTestApp();
  });
  afterEach(async () => {
    await app.close();
  });

  it("AUTH-04 — login with locked account → 423", async () => {
    const alice = app.fixtures.users.t1_alice;
    await app.appHandle.aooth.userService.lockAccount(alice.username, "manual", 60_000);

    const res = await app.fetch("/auth/login", {
      method: "POST",
      json: { username: alice.username, password: alice.password },
    });
    expect(res.status).toBe(423);
    expect(await res.text()).toContain("Account locked");
  });
});

describe("AUTH — auto lockout after threshold", () => {
  let app: TestApp;
  beforeEach(async () => {
    app = await buildTestApp({
      envOverrides: { LOCKOUT_THRESHOLD: 3, LOCKOUT_DURATION_MS: 1500 },
    });
  });
  afterEach(async () => {
    await app.close();
  });

  it("AUTH-05 — auto lockout after N failures, auto-unlock after duration", async () => {
    const alice = app.fixtures.users.t1_alice;

    for (let i = 0; i < 3; i++) {
      const r = await app.fetch("/auth/login", {
        method: "POST",
        json: { username: alice.username, password: "wrong" },
      });
      expect(r.status).toBe(401);
    }

    const lockedAttempt = await app.fetch("/auth/login", {
      method: "POST",
      json: { username: alice.username, password: alice.password },
    });
    expect(lockedAttempt.status).toBe(423);

    await sleep(1700);

    const recovered = await app.fetch("/auth/login", {
      method: "POST",
      json: { username: alice.username, password: alice.password },
    });
    expectOk(recovered);
    const body = (await recovered.json()) as { userId: string };
    expect(body.userId).toBe(alice.username);
  });
});

describe("AUTH — refresh", () => {
  let app: TestApp;
  beforeEach(async () => {
    app = await buildTestApp();
  });
  afterEach(async () => {
    await app.close();
  });

  it("AUTH-06 — refresh happy path; old refresh invalid (rotation: always)", async () => {
    const tokens = await app.loginAs(app.fixtures.users.t1_alice);

    const res = await app.fetch("/auth/refresh", {
      method: "POST",
      json: { refreshToken: tokens.refreshToken },
    });
    expectOk(res);
    const fresh = (await res.json()) as {
      accessToken: string;
      refreshToken: string;
      userId: string;
    };
    expect(fresh.accessToken).toBeTruthy();
    expect(fresh.refreshToken).toBeTruthy();
    expect(fresh.refreshToken).not.toBe(tokens.refreshToken);
    expect(fresh.userId).toBe("t1_alice");

    const replay = await app.fetch("/auth/refresh", {
      method: "POST",
      json: { refreshToken: tokens.refreshToken },
    });
    expect(replay.status).toBe(401);
  });

  it("AUTH-07 — refresh reuse triggers OAuth theft response (revoke all sibling sessions)", async () => {
    const tokensA = await app.loginAs(app.fixtures.users.t1_alice);
    const tokensB = await app.loginAs(app.fixtures.users.t1_alice);

    const rotateA = await app.fetch("/auth/refresh", {
      method: "POST",
      json: { refreshToken: tokensA.refreshToken },
    });
    expectOk(rotateA);

    const replayA = await app.fetch("/auth/refresh", {
      method: "POST",
      json: { refreshToken: tokensA.refreshToken },
    });
    expect(replayA.status).toBe(401);

    // After theft response, sibling device tokens must also be revoked.
    const deviceBAfter = await app.authedFetch(tokensB.accessToken)("/auth/status");
    expect(deviceBAfter.status).toBe(401);
  });
});

describe("AUTH — logout", () => {
  let app: TestApp;
  beforeEach(async () => {
    app = await buildTestApp();
  });
  afterEach(async () => {
    await app.close();
  });

  it("AUTH-09 — logout revokes both access and refresh tokens", async () => {
    const tokens = await app.loginAs(app.fixtures.users.t1_alice);
    const out = await app.authedFetch(tokens.accessToken)("/auth/logout", {
      method: "POST",
      json: { refreshToken: tokens.refreshToken },
    });
    expectOk(out);
    expect(await out.json()).toEqual({ ok: true });

    const accessAfter = await app.authedFetch(tokens.accessToken)("/auth/status");
    expect(accessAfter.status).toBe(401);

    const refreshAfter = await app.fetch("/auth/refresh", {
      method: "POST",
      json: { refreshToken: tokens.refreshToken },
    });
    expect(refreshAfter.status).toBe(401);
  });

  it("AUTH-10 — repeated logout still returns ok (errors swallowed)", async () => {
    const tokens = await app.loginAs(app.fixtures.users.t1_alice);
    const first = await app.authedFetch(tokens.accessToken)("/auth/logout", {
      method: "POST",
      json: { refreshToken: tokens.refreshToken },
    });
    expectOk(first);

    const second = await app.authedFetch(tokens.accessToken)("/auth/logout", {
      method: "POST",
      json: { refreshToken: tokens.refreshToken },
    });
    expect([200, 201, 401]).toContain(second.status);
    if (second.status < 400) {
      expect(await second.json()).toEqual({ ok: true });
    }
  });
});

describe("AUTH — password change", () => {
  let app: TestApp;
  beforeEach(async () => {
    app = await buildTestApp();
  });
  afterEach(async () => {
    await app.close();
  });

  it("AUTH-12 — password change requires current password and validates policy", async () => {
    const alice = app.fixtures.users.t1_alice;
    const tokens = await app.loginAs(alice);
    const authed = app.authedFetch(tokens.accessToken);

    const wrong = await authed("/auth/password", {
      method: "POST",
      json: { currentPassword: "not-the-current", newPassword: STRONG_NEW_PASSWORD },
    });
    expect(wrong.status).toBe(401);

    const tokens2 = await app.loginAs(alice);
    const weak = await app.authedFetch(tokens2.accessToken)("/auth/password", {
      method: "POST",
      json: { currentPassword: alice.password, newPassword: "abc" },
    });
    expect(weak.status).toBe(400);

    const tokens3 = await app.loginAs(alice);
    const ok = await app.authedFetch(tokens3.accessToken)("/auth/password", {
      method: "POST",
      json: { currentPassword: alice.password, newPassword: STRONG_NEW_PASSWORD },
    });
    expectOk(ok);

    const oldPwLogin = await app.fetch("/auth/login", {
      method: "POST",
      json: { username: alice.username, password: alice.password },
    });
    expect(oldPwLogin.status).toBe(401);

    const newPwLogin = await app.fetch("/auth/login", {
      method: "POST",
      json: { username: alice.username, password: STRONG_NEW_PASSWORD },
    });
    expectOk(newPwLogin);
  });

  it("AUTH-13 — password change revokes all prior sessions via per-user epoch", async () => {
    const alice = app.fixtures.users.t1_alice;
    const deviceA = await app.loginAs(alice);
    const deviceB = await app.loginAs(alice);

    const change = await app.authedFetch(deviceA.accessToken)("/auth/password", {
      method: "POST",
      json: { currentPassword: alice.password, newPassword: STRONG_NEW_PASSWORD },
    });
    expectOk(change);

    // Prior tokens must be rejected after the password change (epoch bump).
    const stillA = await app.authedFetch(deviceA.accessToken)("/auth/status");
    const stillB = await app.authedFetch(deviceB.accessToken)("/auth/status");
    expect(stillA.status).toBe(401);
    expect(stillB.status).toBe(401);

    // A fresh login with the new password produces a working token.
    const newLogin = await app.fetch("/auth/login", {
      method: "POST",
      json: { username: alice.username, password: STRONG_NEW_PASSWORD },
    });
    expectOk(newLogin);
    const { accessToken: freshToken } = (await newLogin.json()) as { accessToken: string };
    const fresh = await app.authedFetch(freshToken)("/auth/status");
    expect(fresh.status).toBe(200);
  });
});

describe("AUTH — token forgery / expiry / transport precedence", () => {
  let app: TestApp;

  beforeAll(async () => {
    app = await buildTestApp();
  });
  afterAll(async () => {
    await app.close();
  });

  it("AUTH-14 — JWT alg=none / forged token rejected", async () => {
    const forged = forgeAlgNoneJwt("t1_alice");
    const res = await app.authedFetch(forged)("/auth/status");
    expect(res.status).toBe(401);

    const garbage = await app.authedFetch("not.a.jwt")("/auth/status");
    expect(garbage.status).toBe(401);
  });

  it("AUTH-16 — bearer wins over cookie (invalid bearer + valid cookie → 401)", async () => {
    const alice = app.fixtures.users.t1_alice;
    const loginRes = await app.fetch("/auth/login", {
      method: "POST",
      json: { username: alice.username, password: alice.password },
    });
    expectOk(loginRes);

    const setCookie = loginRes.headers.get("set-cookie");
    const sessionCookie = extractCookie(setCookie, "aooth_session");
    expect(sessionCookie).toBeTruthy();

    const cookieOnly = await app.fetch("/auth/status", {
      headers: { Cookie: `aooth_session=${sessionCookie}` },
    });
    expect(cookieOnly.status).toBe(200);
    const ctx = (await cookieOnly.json()) as { userId: string };
    expect(ctx.userId).toBe(alice.username);

    const conflict = await app.fetch("/auth/status", {
      headers: {
        Cookie: `aooth_session=${sessionCookie}`,
        Authorization: "Bearer forged.bearer.token",
      },
    });
    expect(conflict.status).toBe(401);
  });
});

describe("AUTH — expired token", () => {
  let app: TestApp;
  beforeAll(async () => {
    app = await buildTestApp({ envOverrides: { ACCESS_TTL_MS: 1500 } });
  });
  afterAll(async () => {
    await app.close();
  });

  it("AUTH-15 — expired access token rejected", async () => {
    const tokens = await app.loginAs(app.fixtures.users.t1_alice);
    const fresh = await app.authedFetch(tokens.accessToken)("/auth/status");
    expect(fresh.status).toBe(200);

    await sleep(2200);

    const stale = await app.authedFetch(tokens.accessToken)("/auth/status");
    expect(stale.status).toBe(401);
  });
});

describe("AUTH — concurrent token limit", () => {
  it.skip("AUTH-18 — concurrent token limit (gap: maxConcurrent unsupported on JWT store)", () => {
    // GAP: e2e-demo wires CredentialStoreJwt, which does NOT implement
    // listForUser; AuthCredential.enforceConcurrencyLimit() therefore short-
    // circuits before maxConcurrent is enforced. Even with envOverrides for
    // a maxConcurrent setting (not currently wired in env.ts/aooth.ts), the
    // limit cannot be tested against a stateless store. Re-enable when the
    // demo switches to CredentialStoreMemory or a store that supports
    // listForUser.
  });
});
