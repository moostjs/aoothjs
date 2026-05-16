import type { TArbacRole } from "@aoothjs/arbac-moost";
import { type AuthContext, CredentialStoreMemory } from "@aoothjs/auth";
import { ppHasMinLength } from "@aoothjs/user";
import { beforeEach, describe, expect, it } from "vite-plus/test";

import type { AuthLoginResponse } from "../auth.dto";
import { type MyClaims, parseCookieValue, prepareControllerApp } from "./controller-utils";

async function seedActiveUser(
  users: import("@aoothjs/user").UserService,
  username: string,
  password: string,
): Promise<void> {
  await users.createUser(username, password);
  await users.activateAccount(username);
}

describe("AuthController", () => {
  describe("POST /auth/login", () => {
    it("issues tokens and sets cookies for a valid user", async () => {
      const app = await prepareControllerApp();
      await seedActiveUser(app.users, "alice", "Password123");

      const res = await app.request("/auth/login", {
        method: "POST",
        json: { username: "alice", password: "Password123" },
      });

      expect(res.status).toBe(201);
      const body = res.body as AuthLoginResponse;
      expect(body.userId).toBe("alice");
      expect(typeof body.accessToken).toBe("string");
      expect(typeof body.refreshToken).toBe("string");
      expect(body.accessExpiresAt).toBeGreaterThan(Date.now());
      expect(body.refreshExpiresAt).toBeGreaterThan(Date.now());

      // Cookies set:
      const accessCookie = res.setCookies.find((c) => c.startsWith("aooth_session="));
      const refreshCookie = res.setCookies.find((c) => c.startsWith("aooth_refresh="));
      expect(accessCookie).toBeTruthy();
      expect(refreshCookie).toBeTruthy();
      expect(refreshCookie).toContain("Path=/auth/refresh");
      expect(accessCookie).toContain("HttpOnly");
      expect(refreshCookie).toContain("HttpOnly");
    });

    it("returns 401 on wrong password", async () => {
      const app = await prepareControllerApp();
      await seedActiveUser(app.users, "alice", "Password123");

      const res = await app.request("/auth/login", {
        method: "POST",
        json: { username: "alice", password: "WrongOne1" },
      });
      expect(res.status).toBe(401);
    });

    it("returns 401 on unknown user (no enumeration)", async () => {
      const app = await prepareControllerApp();
      const res = await app.request("/auth/login", {
        method: "POST",
        json: { username: "ghost", password: "whatever" },
      });
      expect(res.status).toBe(401);
    });

    it("returns 423 Locked when the account is locked", async () => {
      const app = await prepareControllerApp();
      await seedActiveUser(app.users, "alice", "Password123");
      await app.users.lockAccount("alice", "manual");

      const res = await app.request("/auth/login", {
        method: "POST",
        json: { username: "alice", password: "Password123" },
      });
      expect(res.status).toBe(423);
    });

    it("returns 400 when body is missing required fields", async () => {
      const app = await prepareControllerApp();
      const res = await app.request("/auth/login", { method: "POST", json: {} });
      expect(res.status).toBe(400);
    });

    it("omits tokens from body when enableBearer=false but still sets cookies", async () => {
      const app = await prepareControllerApp({
        enableBearer: false,
        cookie: { secure: false },
      });
      await seedActiveUser(app.users, "alice", "Password123");
      const res = await app.request("/auth/login", {
        method: "POST",
        json: { username: "alice", password: "Password123" },
      });
      expect(res.status).toBe(201);
      const body = res.body as AuthLoginResponse;
      expect(body.userId).toBe("alice");
      expect(body.accessToken).toBeUndefined();
      expect(body.refreshToken).toBeUndefined();
      expect(res.setCookies.find((c) => c.startsWith("aooth_session="))).toBeTruthy();
    });
  });

  describe("POST /auth/logout", () => {
    it("revokes the token and clears cookies", async () => {
      const app = await prepareControllerApp();
      await seedActiveUser(app.users, "alice", "Password123");
      const login = (
        await app.request("/auth/login", {
          method: "POST",
          json: { username: "alice", password: "Password123" },
        })
      ).body as AuthLoginResponse;

      const accessToken = login.accessToken as string;
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

    it("returns 401 without auth (guard protects logout)", async () => {
      const app = await prepareControllerApp();
      const res = await app.request("/auth/logout", { method: "POST" });
      expect(res.status).toBe(401);
    });

    it("revokes the refresh token when supplied in the body", async () => {
      const app = await prepareControllerApp();
      await seedActiveUser(app.users, "alice", "Password123");
      const login = (
        await app.request("/auth/login", {
          method: "POST",
          json: { username: "alice", password: "Password123" },
        })
      ).body as AuthLoginResponse;

      const accessToken = login.accessToken as string;
      const refreshToken = login.refreshToken as string;

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
  });

  describe("POST /auth/refresh", () => {
    let app: Awaited<ReturnType<typeof prepareControllerApp>>;
    let refreshToken: string;
    beforeEach(async () => {
      app = await prepareControllerApp();
      await seedActiveUser(app.users, "alice", "Password123");
      const login = (
        await app.request("/auth/login", {
          method: "POST",
          json: { username: "alice", password: "Password123" },
        })
      ).body as AuthLoginResponse;
      refreshToken = login.refreshToken as string;
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

  describe("GET /auth/status", () => {
    it("returns the AuthContext for an authenticated user", async () => {
      const app = await prepareControllerApp();
      await seedActiveUser(app.users, "alice", "Password123");
      const login = (
        await app.request("/auth/login", {
          method: "POST",
          json: { username: "alice", password: "Password123" },
        })
      ).body as AuthLoginResponse;

      const res = await app.request("/auth/status", {
        headers: { authorization: `Bearer ${login.accessToken}` },
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

    it("authenticates via the access cookie", async () => {
      const app = await prepareControllerApp();
      await seedActiveUser(app.users, "alice", "Password123");
      const login = await app.request("/auth/login", {
        method: "POST",
        json: { username: "alice", password: "Password123" },
      });
      const accessCookieValue = parseCookieValue(
        login.setCookies.find((c) => c.startsWith("aooth_session=")) as string,
        "aooth_session",
      );
      expect(accessCookieValue).toBeTruthy();

      const res = await app.request("/auth/status", {
        headers: { cookie: `aooth_session=${accessCookieValue}` },
      });
      expect(res.status).toBe(200);
      expect((res.body as AuthContext).userId).toBe("alice");
    });
  });

  describe("POST /auth/password", () => {
    async function loginAlice(): Promise<{
      app: Awaited<ReturnType<typeof prepareControllerApp>>;
      accessToken: string;
    }> {
      const app = await prepareControllerApp({
        userConfig: {
          password: { policies: [ppHasMinLength(8)] },
        },
      });
      await seedActiveUser(app.users, "alice", "Password123");
      const login = (
        await app.request("/auth/login", {
          method: "POST",
          json: { username: "alice", password: "Password123" },
        })
      ).body as AuthLoginResponse;
      return { app, accessToken: login.accessToken as string };
    }

    it("changes the password when current is correct", async () => {
      const { app, accessToken } = await loginAlice();
      const res = await app.request("/auth/password", {
        method: "POST",
        headers: { authorization: `Bearer ${accessToken}` },
        json: { currentPassword: "Password123", newPassword: "AnotherSecret9" },
      });
      expect(res.status).toBe(201);

      // The new password works for verification.
      const ok = await app.users.verifyPassword("alice", "AnotherSecret9");
      expect(ok).toBe(true);
    });

    it("revokes all tokens for the user on successful password change", async () => {
      const { app, accessToken } = await loginAlice();
      // Issue a second token for alice to simulate a parallel session.
      const second = await app.auth.issue("alice");
      expect(await app.auth.validate(second.accessToken)).not.toBeNull();

      const res = await app.request("/auth/password", {
        method: "POST",
        headers: { authorization: `Bearer ${accessToken}` },
        json: { currentPassword: "Password123", newPassword: "AnotherSecret9" },
      });
      expect(res.status).toBe(201);

      // Both the caller's token AND the parallel session are revoked.
      expect(await app.auth.validate(accessToken)).toBeNull();
      expect(await app.auth.validate(second.accessToken)).toBeNull();
      // Cookies are cleared so the browser drops its session.
      expect(res.setCookies.some((c) => /aooth_session=;.*Max-Age=0/i.test(c))).toBe(true);
      expect(res.setCookies.some((c) => /aooth_refresh=;.*Max-Age=0/i.test(c))).toBe(true);
    });

    it("returns 401 when current password is wrong", async () => {
      const { app, accessToken } = await loginAlice();
      const res = await app.request("/auth/password", {
        method: "POST",
        headers: { authorization: `Bearer ${accessToken}` },
        json: { currentPassword: "Wrong___", newPassword: "AnotherSecret9" },
      });
      expect(res.status).toBe(401);
    });

    it("returns 400 with a policy error when new password is too short", async () => {
      const { app, accessToken } = await loginAlice();
      const res = await app.request("/auth/password", {
        method: "POST",
        headers: { authorization: `Bearer ${accessToken}` },
        json: { currentPassword: "Password123", newPassword: "x" },
      });
      expect(res.status).toBe(400);
      // The error body should carry the policy message.
      expect(JSON.stringify(res.body)).toMatch(/8/);
    });

    it("returns 401 without auth", async () => {
      const app = await prepareControllerApp();
      const res = await app.request("/auth/password", {
        method: "POST",
        json: { currentPassword: "x", newPassword: "y" },
      });
      expect(res.status).toBe(401);
    });
  });

  // ISSUE-9: `AuthController` no longer takes ctor-injected deps. It splits
  // dependency resolution into `resolveCoreDeps()` (auth + config only) and
  // `resolveDepsWithUsers()` (also pulls UserService). The split exists so
  // apps that don't expose a UserService (e.g. workflows-only deployments)
  // can still use /auth/logout + /auth/refresh — only /auth/login and
  // /auth/password must fail loud, and only with a helpful message that
  // points at the missing registration.
  describe("lazy dependency resolution split (ISSUE-9)", () => {
    async function loginThenDropUserService(): Promise<{
      noUserApp: Awaited<ReturnType<typeof prepareControllerApp>>;
      accessToken: string;
      refreshToken: string;
    }> {
      // Mint a valid token pair on a real-deps app, then re-bootstrap a
      // second app WITHOUT UserService but sharing the same in-memory token
      // store so the access token still validates. This proves the split:
      // refresh + logout don't even look at UserService, so they must work
      // even when none is provided.
      const sharedStore = new CredentialStoreMemory<MyClaims>();
      const seedApp = await prepareControllerApp({
        authOptions: { store: sharedStore },
      });
      await seedApp.users.createUser("alice", "Password123");
      await seedApp.users.activateAccount("alice");
      const login = (
        await seedApp.request("/auth/login", {
          method: "POST",
          json: { username: "alice", password: "Password123" },
        })
      ).body as AuthLoginResponse;

      const noUserApp = await prepareControllerApp({
        withoutUserService: true,
        authOptions: { store: sharedStore },
      });

      return {
        noUserApp,
        accessToken: login.accessToken as string,
        refreshToken: login.refreshToken as string,
      };
    }

    it("/auth/logout succeeds when UserService is NOT provided", async () => {
      // logout uses resolveCoreDeps() — UserService is irrelevant.
      const { noUserApp, accessToken } = await loginThenDropUserService();
      const out = await noUserApp.request("/auth/logout", {
        method: "POST",
        headers: { authorization: `Bearer ${accessToken}` },
        json: {},
      });
      expect(out.status).toBe(201);
      // Token revocation still happens — proves the auth + config deps did resolve.
      expect(await noUserApp.auth.validate(accessToken)).toBeNull();
    });

    it("/auth/refresh succeeds when UserService is NOT provided", async () => {
      // refresh also uses resolveCoreDeps() — UserService is irrelevant.
      const { noUserApp, refreshToken } = await loginThenDropUserService();
      const res = await noUserApp.request("/auth/refresh", {
        method: "POST",
        json: { refreshToken },
      });
      expect(res.status).toBe(201);
      const body = res.body as AuthLoginResponse;
      expect(body.userId).toBe("alice");
      expect(typeof body.accessToken).toBe("string");
    });

    it("/auth/login throws a helpful 500 mentioning 'UserService is not provided'", async () => {
      // login is the canonical UserService-requiring endpoint. The error
      // message must name the missing token AND point at the registration
      // call — anything vaguer wastes consumer time when they hit this in
      // the wild.
      const app = await prepareControllerApp({ withoutUserService: true });
      const res = await app.request("/auth/login", {
        method: "POST",
        json: { username: "alice", password: "Password123" },
      });
      // Internal config error — moost surfaces it as 500.
      expect(res.status).toBe(500);
      // The error must self-identify so the consumer can grep their setup.
      // Backticks around `UserService` in the message are decorative — match
      // the substring regardless.
      expect(JSON.stringify(res.body)).toMatch(/UserService.{0,3}is not provided/);
    });
  });

  // ISSUE-4 — the combined `@Public()` decorator and the `public.*` action
  // convention. These tests exercise the AuthController under a globally
  // installed `arbacAuthorizeInterceptor` to prove three intents end-to-end:
  //
  // 1. `@Public()` opts out of BOTH guards atomically: an anonymous request
  //    to `/auth/login` succeeds even though the controller class has
  //    `@ArbacResource("auth")` (which would otherwise force a 403 when no
  //    principal/role exists). This is the regression risk of splitting the
  //    flag into two decorators.
  //
  // 2. The middle-ground methods (`logout`, `status`, `password`) carry
  //    `@ArbacAction("public.<verb>")`. A role granting `allow("auth",
  //    "public.*")` reaches them; a role without that grant gets 403. This
  //    pins the convention — any handler still labelled `@Public()` would
  //    invisibly bypass ARBAC; any handler missing the action prefix would
  //    require a per-method grant.
  //
  // 3. The action id actually written by `@ArbacAction("public.logout")` is
  //    what the resolver reads — i.e. a wildcard like `allow("auth", "log*")`
  //    that does NOT cover `public.logout` must 403. This guards against a
  //    silent regression where the action-resolution chain (atscript-db
  //    action arg, mate `arbacActionId`, method name) reorders.
  describe("ISSUE-4 combined @Public + public.* action gating", () => {
    // TArbacRule typing: allow rules are denoted by *omitting* the `effect`
    // field (the union has `effect?: never` on the allow arm and
    // `effect: "deny"` on the deny arm). The arbac-core engine defaults a
    // missing effect to "allow" — see `Arbac.evalRoleForResource`.
    const ROLE_VIEWER: TArbacRole<object, object> = {
      id: "viewer",
      rules: [
        // Grants every "public.*" action on the "auth" resource — the
        // convention the bundled controller's middle-ground methods use.
        { resource: "auth", action: "public.*" },
      ],
    };
    const ROLE_BARE: TArbacRole<object, object> = {
      id: "bare",
      rules: [
        // Deliberately grants nothing on `auth`. Used to assert that a
        // logged-in user without the `public.*` grant gets 403.
        { resource: "other", action: "*" },
      ],
    };
    // Used by the action-mapping test: grants only an action prefix that
    // does NOT cover `public.logout` etc. A wildcard like `logout*` would
    // accidentally match the method name — `public.logout` proves the mate
    // arbacActionId wins over the method name in the resolver.
    const ROLE_WRONG_PREFIX: TArbacRole<object, object> = {
      id: "wrongprefix",
      rules: [{ resource: "auth", action: "logout" }],
    };

    async function loginAs(
      username: string,
      password: string,
      roles: string[],
    ): Promise<{
      app: Awaited<ReturnType<typeof prepareControllerApp>>;
      accessToken: string;
      refreshToken: string;
    }> {
      const userRoles = new Map<string, string[]>([[username, roles]]);
      const app = await prepareControllerApp({
        userConfig: { password: { policies: [ppHasMinLength(8)] } },
        arbac: {
          userRoles,
          roles: [ROLE_VIEWER, ROLE_BARE, ROLE_WRONG_PREFIX],
        },
      });
      await app.users.createUser(username, password);
      await app.users.activateAccount(username);
      const login = (
        await app.request("/auth/login", {
          method: "POST",
          json: { username, password },
        })
      ).body as AuthLoginResponse;
      return {
        app,
        accessToken: login.accessToken as string,
        refreshToken: login.refreshToken as string,
      };
    }

    it("/auth/login is reachable anonymously — @Public() bypasses BOTH guards", async () => {
      // The combined-bypass intent. The controller class has
      // `@ArbacResource("auth")`; without `arbacPublic` the interceptor
      // would force a 403 on anonymous requests even though auth-moost's
      // own bearer guard was disarmed. This test fails the moment @Public()
      // stops writing `arbacPublic`.
      const userRoles = new Map<string, string[]>();
      const app = await prepareControllerApp({
        arbac: { userRoles, roles: [ROLE_VIEWER] },
      });
      await app.users.createUser("alice", "Password123");
      await app.users.activateAccount("alice");
      const res = await app.request("/auth/login", {
        method: "POST",
        json: { username: "alice", password: "Password123" },
      });
      expect(res.status).toBe(201);
      const body = res.body as AuthLoginResponse;
      expect(body.userId).toBe("alice");
    });

    it("/auth/logout succeeds for a user with `allow(auth, public.*)`", async () => {
      const { app, accessToken } = await loginAs("alice", "Password123", ["viewer"]);
      const out = await app.request("/auth/logout", {
        method: "POST",
        headers: { authorization: `Bearer ${accessToken}` },
        json: {},
      });
      expect(out.status).toBe(201);
    });

    it("/auth/status succeeds for a user with `allow(auth, public.*)`", async () => {
      const { app, accessToken } = await loginAs("alice", "Password123", ["viewer"]);
      const res = await app.request("/auth/status", {
        headers: { authorization: `Bearer ${accessToken}` },
      });
      expect(res.status).toBe(200);
      expect((res.body as AuthContext).userId).toBe("alice");
    });

    it("/auth/password succeeds for a user with `allow(auth, public.*)`", async () => {
      const { app, accessToken } = await loginAs("alice", "Password123", ["viewer"]);
      const res = await app.request("/auth/password", {
        method: "POST",
        headers: { authorization: `Bearer ${accessToken}` },
        json: { currentPassword: "Password123", newPassword: "AnotherSecret9" },
      });
      expect(res.status).toBe(201);
    });

    it("/auth/logout returns 403 for a user WITHOUT `public.*` on `auth`", async () => {
      const { app, accessToken } = await loginAs("alice", "Password123", ["bare"]);
      const out = await app.request("/auth/logout", {
        method: "POST",
        headers: { authorization: `Bearer ${accessToken}` },
        json: {},
      });
      expect(out.status).toBe(403);
    });

    it("/auth/status returns 403 for a user WITHOUT `public.*` on `auth`", async () => {
      const { app, accessToken } = await loginAs("alice", "Password123", ["bare"]);
      const res = await app.request("/auth/status", {
        headers: { authorization: `Bearer ${accessToken}` },
      });
      expect(res.status).toBe(403);
    });

    it("/auth/password returns 403 for a user WITHOUT `public.*` on `auth`", async () => {
      const { app, accessToken } = await loginAs("alice", "Password123", ["bare"]);
      const res = await app.request("/auth/password", {
        method: "POST",
        headers: { authorization: `Bearer ${accessToken}` },
        json: { currentPassword: "Password123", newPassword: "AnotherSecret9" },
      });
      expect(res.status).toBe(403);
    });

    it("the resolver reads `public.logout` from @ArbacAction, not the method name", async () => {
      // ROLE_WRONG_PREFIX grants `allow("auth", "logout")`. If the resolver
      // were keyed on the JS method name (`logout`) instead of the
      // `@ArbacAction("public.logout")` mate value, this request would 200.
      // The expected 403 proves `@ArbacAction("public.<verb>")` is what the
      // engine actually evaluates.
      const { app, accessToken } = await loginAs("alice", "Password123", ["wrongprefix"]);
      const out = await app.request("/auth/logout", {
        method: "POST",
        headers: { authorization: `Bearer ${accessToken}` },
        json: {},
      });
      expect(out.status).toBe(403);
    });
  });
});
