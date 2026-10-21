/**
 * Integration tests for the cookie-writing path through a real Moost +
 * MoostHttp stack. Goal: pin the Set-Cookie header text so regressions in
 * `cookieAttrsFrom` (or in `@wooksjs/event-http`'s renderer) surface as a
 * failing assertion.
 *
 * The original bug: `cookieAttrsFrom` unconditionally spread `domain: c.domain`
 * even when `c.domain === undefined`, and pre-0.7.13 wooks rendered that as
 * the literal string `Domain=undefined`. Browsers reject the entire cookie,
 * which makes login appear to succeed (201 + body) while no session is stored.
 *
 * Covered scenarios:
 * - **dev profile** (`http://localhost`, `secure: false`, no `domain`):
 *   Set-Cookie has no `Domain=…` and no `Secure`.
 * - **prod profile** (`https`, `secure: true`, no `domain`): Set-Cookie has
 *   `Secure` but still no `Domain=…` (regression guard for the original bug).
 * - **explicit domain** (`cookie: { domain: 'auth.example.com' }`):
 *   Set-Cookie carries `Domain=auth.example.com`.
 */
import { describe, expect, it } from "vite-plus/test";

import { prepareControllerApp } from "./controller-utils";

async function issueRefresh(app: Awaited<ReturnType<typeof prepareControllerApp>>) {
  const issue = await app.auth.issue("alice");
  if (!issue.refreshToken) {
    throw new Error("test setup: refresh tokens must be enabled");
  }
  return issue;
}

const SESSION_COOKIE_RX = /^aooth_session=[^;]+/;
const REFRESH_COOKIE_RX = /^aooth_refresh=[^;]+/;

describe("Set-Cookie integration — dev profile (http, secure:false, no domain)", () => {
  it("emits cookies with no `Domain=…` and no `Secure` attribute", async () => {
    const app = await prepareControllerApp({ cookie: { secure: false } });
    const { refreshToken } = await issueRefresh(app);

    const r = await app.request("/auth/refresh", { method: "POST", json: { refreshToken } });
    expect(r.status).toBe(201);

    expect(r.setCookies).toHaveLength(2);
    const [session, refresh] = r.setCookies;

    expect(session).toMatch(SESSION_COOKIE_RX);
    expect(session).toContain("HttpOnly");
    expect(session).toContain("SameSite=Lax");
    expect(session).toContain("Path=/");
    expect(session).not.toContain("Secure");
    // Regression: must NOT contain `Domain=…` at all when not configured.
    expect(session).not.toMatch(/Domain=/i);

    expect(refresh).toMatch(REFRESH_COOKIE_RX);
    expect(refresh).toContain("Path=/auth/refresh");
    expect(refresh).not.toContain("Secure");
    expect(refresh).not.toMatch(/Domain=/i);
  });
});

describe("Set-Cookie integration — prod profile (https-equivalent, secure:true, no domain)", () => {
  it("emits cookies with `Secure` but still no `Domain=…` (regression guard)", async () => {
    const app = await prepareControllerApp(); // default = { secure: true, no domain }
    const { refreshToken } = await issueRefresh(app);

    const r = await app.request("/auth/refresh", { method: "POST", json: { refreshToken } });
    expect(r.status).toBe(201);

    expect(r.setCookies).toHaveLength(2);
    const [session, refresh] = r.setCookies;

    expect(session).toContain("HttpOnly");
    expect(session).toContain("Secure");
    expect(session).toContain("SameSite=Lax");
    expect(session).toContain("Path=/");
    // The bug: pre-fix this assertion fails because the header reads
    // `; Domain=undefined`. After fix, the substring must not appear at all.
    expect(session).not.toMatch(/Domain=/i);

    expect(refresh).toContain("Secure");
    expect(refresh).toContain("Path=/auth/refresh");
    expect(refresh).not.toMatch(/Domain=/i);
  });
});

describe("Set-Cookie integration — explicit domain", () => {
  it("passes `cookie.domain` through to both access and refresh cookies", async () => {
    const app = await prepareControllerApp({
      cookie: { domain: "auth.example.com" },
    });
    const { refreshToken } = await issueRefresh(app);

    const r = await app.request("/auth/refresh", { method: "POST", json: { refreshToken } });
    expect(r.status).toBe(201);

    expect(r.setCookies).toHaveLength(2);
    const [session, refresh] = r.setCookies;

    expect(session).toContain("Domain=auth.example.com");
    expect(session).not.toContain("Domain=undefined");
    expect(refresh).toContain("Domain=auth.example.com");
    expect(refresh).not.toContain("Domain=undefined");
  });
});

describe("Set-Cookie integration — logout clears cookies cleanly", () => {
  it("clearCookies emits empty-value Set-Cookie with Max-Age=0 and no Domain=undefined", async () => {
    const app = await prepareControllerApp({ cookie: { secure: false } });
    const { accessToken } = await issueRefresh(app);

    const r = await app.request("/auth/logout", {
      method: "POST",
      headers: { authorization: `Bearer ${accessToken}` },
      json: {},
    });
    expect(r.status).toBe(201);

    expect(r.setCookies).toHaveLength(2);
    for (const cookie of r.setCookies) {
      expect(cookie).toContain("Max-Age=0");
      expect(cookie).not.toMatch(/Domain=/i);
    }
  });
});

describe("A3: persistent cookies", () => {
  function maxAgeOf(setCookie: string): number | undefined {
    const m = /Max-Age=(\d+)/i.exec(setCookie);
    return m ? Number(m[1]) : undefined;
  }

  it("cookies stay session-only by default", async () => {
    const app = await prepareControllerApp({ cookie: { secure: false } });
    const { refreshToken } = await issueRefresh(app);
    const r = await app.request("/auth/refresh", { method: "POST", json: { refreshToken } });
    for (const c of r.setCookies) {
      expect(c).not.toMatch(/Max-Age=|Expires=/i);
    }
  });

  it("refreshCookie.persistent sets Max-Age from the refresh token's expiry, renewed on rotation", async () => {
    const app = await prepareControllerApp({
      cookie: { secure: false },
      refreshCookie: { persistent: true },
    });
    const { refreshToken } = await issueRefresh(app);
    const r = await app.request("/auth/refresh", { method: "POST", json: { refreshToken } });
    const session = r.setCookies.find((c) => SESSION_COOKIE_RX.test(c))!;
    const refresh = r.setCookies.find((c) => REFRESH_COOKIE_RX.test(c))!;
    // Access cookie stays session-only; refresh follows its 600s token TTL.
    expect(maxAgeOf(session)).toBeUndefined();
    const age = maxAgeOf(refresh)!;
    expect(age).toBeGreaterThan(590);
    expect(age).toBeLessThanOrEqual(600);
  });

  it("cookie.persistent sets the access cookie's Max-Age from the access token's expiry", async () => {
    const app = await prepareControllerApp({ cookie: { secure: false, persistent: true } });
    const { refreshToken } = await issueRefresh(app);
    const r = await app.request("/auth/refresh", { method: "POST", json: { refreshToken } });
    const session = r.setCookies.find((c) => SESSION_COOKIE_RX.test(c))!;
    const age = maxAgeOf(session)!;
    expect(age).toBeGreaterThan(50);
    expect(age).toBeLessThanOrEqual(60);
  });
});
