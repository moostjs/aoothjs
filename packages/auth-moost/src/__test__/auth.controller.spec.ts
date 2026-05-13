import type { AuthContext } from "@aoothjs/auth";
import { ppHasMinLength } from "@aoothjs/user";
import { beforeEach, describe, expect, it } from "vite-plus/test";

import type { AuthLoginResponse } from "../auth.dto";
import { parseCookieValue, prepareControllerApp } from "./controller-utils";

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
});
