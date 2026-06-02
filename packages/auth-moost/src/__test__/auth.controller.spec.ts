import type { TArbacRole } from "@aooth/arbac-moost";
import { type AuthContext, AuthCredential, CredentialStoreMemory } from "@aooth/auth";
import { UserService } from "@aooth/user";
import { Controller, Inherit, Optional } from "moost";
import { beforeEach, describe, expect, it } from "vite-plus/test";

import { AuthController } from "../auth.controller";
import type { AuthLoginResponse } from "../auth.dto";
import { type MyClaims, prepareControllerApp } from "./controller-utils";

// A consumer subclass — the real downstream shape (extend AuthController, add
// app workflows). Defined once at module scope so its moost/infact identity is
// stable across tests. Used to prove the `@MoostInit` refresh-route resolution
// is inherited and runs on a SUBCLASS mounted under a prefix.
@Inherit()
@Controller("auth")
class PortalAuthController extends AuthController {
  constructor(auth: AuthCredential, @Optional() users?: UserService) {
    super(auth, users);
  }
}

async function seedAndIssue(
  app: Awaited<ReturnType<typeof prepareControllerApp>>,
  username: string,
  password: string,
): Promise<{ accessToken: string; refreshToken: string }> {
  await app.users.createUser(username, password);
  await app.users.activateAccount(username);
  const issue = await app.auth.issue(username);
  return {
    accessToken: issue.accessToken,
    refreshToken: issue.refreshToken as string,
  };
}

describe("AuthController", () => {
  // The historical `/auth/login` and `/auth/password` REST endpoints were
  // dropped in AUTH-MOOST-5. The login + recovery + invite flows now go
  // through the workflow trigger (`POST /auth/trigger`), which is exercised
  // end-to-end by the workflow specs and the e2e-demo. Token issuance is
  // simulated here via `app.auth.issue(...)` because the four endpoints kept
  // on this controller (logout / refresh / status / trigger) only need a
  // valid token pair to drive — not the full credential flow.

  describe("POST /auth/logout", () => {
    it("revokes the token and clears cookies", async () => {
      const app = await prepareControllerApp();
      const { accessToken } = await seedAndIssue(app, "alice", "Password123");

      const out = await app.request("/auth/logout", {
        method: "POST",
        headers: { authorization: `Bearer ${accessToken}` },
        // `@Body()` requires a request body to parse — empty body would stall
        // the body composable. Real clients send `{}` (or a refreshToken).
        json: {},
      });
      expect(out.status).toBe(201);

      // The same token should no longer validate.
      expect(await app.auth.validate(accessToken)).toBeNull();

      // Cookies cleared (Max-Age=0).
      expect(out.setCookies.some((c) => /aooth_session=;.*Max-Age=0/i.test(c))).toBe(true);
      expect(out.setCookies.some((c) => /aooth_refresh=;.*Max-Age=0/i.test(c))).toBe(true);
    });

    it("returns 401 without auth (defence-in-depth on @Public() bypass)", async () => {
      const app = await prepareControllerApp();
      // `@Body()` needs a body to parse; previously the auth guard threw
      // before the body composable ran. Now logout is `@Public()` so the
      // guard sets a null AuthContext and the handler's own null-check 401s.
      const res = await app.request("/auth/logout", { method: "POST", json: {} });
      expect(res.status).toBe(401);
    });

    it("revokes the refresh token when supplied in the body", async () => {
      const app = await prepareControllerApp();
      const { accessToken, refreshToken } = await seedAndIssue(app, "alice", "Password123");

      const out = await app.request("/auth/logout", {
        method: "POST",
        headers: { authorization: `Bearer ${accessToken}` },
        json: { refreshToken },
      });
      expect(out.status).toBe(201);

      // The refresh token can no longer be used to mint a new access token.
      const refreshed = await app.request("/auth/refresh", {
        method: "POST",
        json: { refreshToken },
      });
      expect(refreshed.status).toBe(401);
    });

    it("ends THIS device's whole session family even with no refresh token in the body", async () => {
      // The real SPA footgun: the httpOnly refresh cookie sits on a narrow path
      // and never reaches /auth/logout, and the client can't read it to echo in
      // the body. Pre-family logout left that refresh credential alive for its
      // full TTL, so the "logged-out" session lingered in listSessions. Logout
      // now revokes the whole family by sessionId.
      const app = await prepareControllerApp();
      await app.users.createUser("alice", "Password123");
      await app.users.activateAccount("alice");
      const deviceA = await app.auth.issue("alice");
      const deviceB = await app.auth.issue("alice");
      expect(await app.auth.listSessions("alice")).toHaveLength(2);

      const out = await app.request("/auth/logout", {
        method: "POST",
        headers: { authorization: `Bearer ${deviceA.accessToken}` },
        json: {}, // no refreshToken — exactly the SPA case
      });
      expect(out.status).toBe(201);

      // Device A's whole family is gone: access dead AND refresh unusable.
      expect(await app.auth.validate(deviceA.accessToken)).toBeNull();
      const refreshed = await app.request("/auth/refresh", {
        method: "POST",
        json: { refreshToken: deviceA.refreshToken as string },
      });
      expect(refreshed.status).toBe(401);

      // Only this device was logged out — device B keeps working and the
      // active-sessions list drops to one.
      const sessions = await app.auth.listSessions("alice");
      expect(sessions).toHaveLength(1);
      expect(await app.auth.validate(deviceB.accessToken)).not.toBeNull();
    });
  });

  describe("POST /auth/refresh", () => {
    let app: Awaited<ReturnType<typeof prepareControllerApp>>;
    let refreshToken: string;
    beforeEach(async () => {
      app = await prepareControllerApp();
      const tokens = await seedAndIssue(app, "alice", "Password123");
      refreshToken = tokens.refreshToken;
    });

    it("rotates tokens when given a body refreshToken", async () => {
      const res = await app.request("/auth/refresh", {
        method: "POST",
        json: { refreshToken },
      });
      expect(res.status).toBe(201);
      const body = res.body as AuthLoginResponse;
      expect(body.userId).toBe("alice");
      expect(typeof body.accessToken).toBe("string");
      expect(body.accessToken).not.toBe(refreshToken);
      // The new access token validates:
      const ctx = await app.auth.validate(body.accessToken as string);
      expect(ctx?.userId).toBe("alice");
    });

    it("rotates tokens when given the refresh cookie", async () => {
      const res = await app.request("/auth/refresh", {
        method: "POST",
        headers: { cookie: `aooth_refresh=${refreshToken}` },
        json: {},
      });
      expect(res.status).toBe(201);
      const body = res.body as AuthLoginResponse;
      expect(body.userId).toBe("alice");
      expect(typeof body.accessToken).toBe("string");
    });

    it("returns 401 on missing refresh token", async () => {
      const res = await app.request("/auth/refresh", { method: "POST", json: {} });
      expect(res.status).toBe(401);
    });

    it("returns 401 on bogus refresh token", async () => {
      const res = await app.request("/auth/refresh", {
        method: "POST",
        json: { refreshToken: "not-a-real-token" },
      });
      expect(res.status).toBe(401);
    });
  });

  describe("refresh cookie path (mount-prefix aware)", () => {
    function refreshCookieOf(setCookies: string[]): string | undefined {
      return setCookies.find((c) => c.startsWith("aooth_refresh="));
    }

    it("scopes the refresh cookie to the controller's mounted prefix", async () => {
      // Mounted under `api/auth` → real endpoint is /api/auth/refresh. The
      // cookie path must follow, not stay at the hardcoded /auth/refresh.
      const app = await prepareControllerApp({ controllerPrefix: "api/auth" });
      const { refreshToken } = await seedAndIssue(app, "alice", "Password123");
      const out = await app.request("/api/auth/refresh", {
        method: "POST",
        json: { refreshToken },
      });
      expect(out.status).toBe(201);
      expect(refreshCookieOf(out.setCookies)).toMatch(/;\s*Path=\/api\/auth\/refresh(;|$)/i);
    });

    it("lets an explicit refreshCookie.path win over derivation", async () => {
      const app = await prepareControllerApp({
        controllerPrefix: "api/auth",
        refreshCookie: { path: "/custom/refresh" },
      });
      const { refreshToken } = await seedAndIssue(app, "alice", "Password123");
      const out = await app.request("/api/auth/refresh", {
        method: "POST",
        json: { refreshToken },
      });
      expect(refreshCookieOf(out.setCookies)).toMatch(/;\s*Path=\/custom\/refresh(;|$)/i);
    });

    it("defaults to /auth/refresh at root mount", async () => {
      const app = await prepareControllerApp();
      const { refreshToken } = await seedAndIssue(app, "alice", "Password123");
      const out = await app.request("/auth/refresh", {
        method: "POST",
        json: { refreshToken },
      });
      expect(refreshCookieOf(out.setCookies)).toMatch(/;\s*Path=\/auth\/refresh(;|$)/i);
    });

    it("never guesses when AuthController resolves to >1 refresh route — keeps the default", async () => {
      // Mount AuthController under TWO non-root prefixes (api/auth + v2/auth) so
      // `@HandlerPaths('refresh')` returns two paths. The boot `@MoostInit` hook
      // must take its ambiguity branch — warn (exercising the injected logger)
      // and leave the holder unset — so the cookie falls back to the configured
      // DEFAULT `/auth/refresh` rather than guessing one of the two mounts.
      // Both prefixes are non-root, so the default is distinct from either
      // resolved path: a Path of /auth/refresh can ONLY mean the holder stayed
      // unset. That `init()` resolves at all also proves `@InjectMoostLogger`
      // injects a usable logger inside `@MoostInit`.
      const app = await prepareControllerApp({
        controllerPrefix: "api/auth",
        // biome-ignore lint/suspicious/noExplicitAny: prefixed-tuple registration shape.
        extraControllers: [["v2/auth", AuthController] as any],
      });
      const { refreshToken } = await seedAndIssue(app, "alice", "Password123");
      const out = await app.request("/api/auth/refresh", {
        method: "POST",
        json: { refreshToken },
      });
      expect(out.status).toBe(201);
      expect(refreshCookieOf(out.setCookies)).toMatch(/;\s*Path=\/auth\/refresh(;|$)/i);
    });

    it("follows a SUBCLASSED AuthController mounted under a prefix (the consumer case)", async () => {
      // The motivating downstream scenario: a consumer subclasses AuthController
      // and mounts it under a prefix. The inherited `@MoostInit` hook must run on
      // the subclass and `@HandlerPaths('refresh')` must resolve the subclass's
      // own prefixed route → cookie Path follows, with no config.
      const app = await prepareControllerApp({
        controllerClass: PortalAuthController,
        controllerPrefix: "api/auth",
      });
      const { refreshToken } = await seedAndIssue(app, "alice", "Password123");
      const out = await app.request("/api/auth/refresh", {
        method: "POST",
        json: { refreshToken },
      });
      expect(out.status).toBe(201);
      expect(refreshCookieOf(out.setCookies)).toMatch(/;\s*Path=\/api\/auth\/refresh(;|$)/i);
    });
  });

  describe("GET /auth/status", () => {
    it("returns the AuthContext for an authenticated user", async () => {
      const app = await prepareControllerApp();
      const { accessToken } = await seedAndIssue(app, "alice", "Password123");
      const res = await app.request("/auth/status", {
        headers: { authorization: `Bearer ${accessToken}` },
      });
      expect(res.status).toBe(200);
      const body = res.body as AuthContext;
      expect(body.userId).toBe("alice");
      expect(body.method).toBe("token");
      expect(typeof body.credentialId).toBe("string");
      expect(body.expiresAt).toBeGreaterThan(Date.now());
    });

    it("returns 401 without auth", async () => {
      const app = await prepareControllerApp();
      const res = await app.request("/auth/status", { method: "GET" });
      expect(res.status).toBe(401);
    });
  });

  describe("POST /auth/trigger", () => {
    // Smoke test: the bundled controller's `@WfTrigger` decorator + the
    // default `WfTriggerProvider` must wire correctly when `AuthController`
    // is registered. The full workflow behaviour is exercised by the
    // workflow specs (using their own test harness); here we only assert the
    // trigger endpoint exists, is `@Public()`, and rejects unknown
    // workflow ids (`allow` whitelist enforced).
    it("is reachable anonymously (no auth guard)", async () => {
      const app = await prepareControllerApp();
      // No wfid → the outlet trigger returns an error envelope, but the
      // request reaches the handler (not 401). The exact error shape is
      // owned by `@atscript/moost-wf`; we only assert "not 401, not 404".
      const res = await app.request("/auth/trigger", { method: "POST", json: {} });
      expect(res.status).not.toBe(401);
      expect(res.status).not.toBe(404);
    });

    it("rejects unknown workflow ids (allow-list enforced)", async () => {
      const app = await prepareControllerApp();
      const res = await app.request("/auth/trigger", {
        method: "POST",
        json: { wfid: "not.a.real.workflow" },
      });
      // The outlet trigger throws when wfid is not in `allow`. The HTTP
      // adapter surfaces uncaught throws as 500.
      expect(res.status).toBeGreaterThanOrEqual(400);
    });
  });

  // ISSUE-9 — auth + config deps split. After AUTH-MOOST-5 the controller
  // no longer touches `UserService` at all, so logout + refresh + status +
  // trigger all work with `UserService` unregistered.
  describe("UserService independence (ISSUE-9 follow-up)", () => {
    async function noUserAppWithToken(): Promise<{
      noUserApp: Awaited<ReturnType<typeof prepareControllerApp>>;
      accessToken: string;
      refreshToken: string;
    }> {
      // Mint a valid token pair on a real-deps app, then re-bootstrap a
      // second app WITHOUT UserService but sharing the same in-memory token
      // store. Proves the controller doesn't require UserService.
      const sharedStore = new CredentialStoreMemory<MyClaims>();
      const seedApp = await prepareControllerApp({
        authOptions: { store: sharedStore },
      });
      await seedApp.users.createUser("alice", "Password123");
      await seedApp.users.activateAccount("alice");
      const issue = await seedApp.auth.issue("alice");

      const noUserApp = await prepareControllerApp({
        withoutUserService: true,
        authOptions: { store: sharedStore },
      });

      return {
        noUserApp,
        accessToken: issue.accessToken,
        refreshToken: issue.refreshToken as string,
      };
    }

    it("/auth/logout succeeds when UserService is NOT provided", async () => {
      const { noUserApp, accessToken } = await noUserAppWithToken();
      const out = await noUserApp.request("/auth/logout", {
        method: "POST",
        headers: { authorization: `Bearer ${accessToken}` },
        json: {},
      });
      expect(out.status).toBe(201);
      expect(await noUserApp.auth.validate(accessToken)).toBeNull();
    });

    it("/auth/refresh succeeds when UserService is NOT provided", async () => {
      const { noUserApp, refreshToken } = await noUserAppWithToken();
      const res = await noUserApp.request("/auth/refresh", {
        method: "POST",
        json: { refreshToken },
      });
      expect(res.status).toBe(201);
      const body = res.body as AuthLoginResponse;
      expect(body.userId).toBe("alice");
    });
  });

  // ARBAC integration. The controller carries `@ArbacResource("auth")` at
  // class level, but `/auth/status`, `/auth/logout`, `/auth/refresh`, and
  // `/auth/trigger` are all `@Public()` — they bypass ARBAC because they are
  // self-scoped primitives (status = "tell me my principal"; logout = "kill
  // my session"; refresh = gated by the refresh token itself; trigger =
  // gated by the workflow interceptor). Authentication is still required for
  // status/logout via the auth guard's defence-in-depth null check.
  describe("ARBAC integration (status/logout/refresh are @Public())", () => {
    const ROLE_BARE: TArbacRole<object, object> = {
      id: "bare",
      rules: [{ resource: "other", action: "*" }],
    };

    async function loginAs(
      username: string,
      password: string,
      roles: string[],
    ): Promise<{
      app: Awaited<ReturnType<typeof prepareControllerApp>>;
      accessToken: string;
    }> {
      const userRoles = new Map<string, string[]>([[username, roles]]);
      const app = await prepareControllerApp({
        arbac: {
          userRoles,
          roles: [ROLE_BARE],
        },
      });
      await app.users.createUser(username, password);
      await app.users.activateAccount(username);
      const issue = await app.auth.issue(username);
      return { app, accessToken: issue.accessToken };
    }

    it("/auth/trigger is reachable anonymously — @Public() bypasses BOTH guards", async () => {
      const userRoles = new Map<string, string[]>();
      const app = await prepareControllerApp({
        arbac: { userRoles, roles: [ROLE_BARE] },
      });
      const res = await app.request("/auth/trigger", { method: "POST", json: {} });
      expect(res.status).not.toBe(401);
      expect(res.status).not.toBe(403);
    });

    it("/auth/logout succeeds for an authenticated user with NO arbac grants", async () => {
      const { app, accessToken } = await loginAs("alice", "Password123", ["bare"]);
      const out = await app.request("/auth/logout", {
        method: "POST",
        headers: { authorization: `Bearer ${accessToken}` },
        json: {},
      });
      expect(out.status).toBe(201);
    });

    it("/auth/status succeeds for an authenticated user with NO arbac grants", async () => {
      const { app, accessToken } = await loginAs("alice", "Password123", ["bare"]);
      const res = await app.request("/auth/status", {
        headers: { authorization: `Bearer ${accessToken}` },
      });
      expect(res.status).toBe(200);
      expect((res.body as AuthContext).userId).toBe("alice");
    });

    it("/auth/logout returns 401 anonymously — defence-in-depth on the @Public() bypass", async () => {
      const app = await prepareControllerApp({
        arbac: { userRoles: new Map(), roles: [ROLE_BARE] },
      });
      const out = await app.request("/auth/logout", {
        method: "POST",
        json: {},
      });
      expect(out.status).toBe(401);
    });

    it("/auth/status returns 401 anonymously — defence-in-depth on the @Public() bypass", async () => {
      const app = await prepareControllerApp({
        arbac: { userRoles: new Map(), roles: [ROLE_BARE] },
      });
      const res = await app.request("/auth/status", { method: "GET" });
      expect(res.status).toBe(401);
    });
  });
});
