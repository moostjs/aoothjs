import { HttpError } from "@wooksjs/event-http";
import { describe, expect, it } from "vite-plus/test";

import { Public } from "../auth.decorator";
import { Controller, prepareTestApp, runGuardForHandler, TestHandler } from "./test-utils";

@Controller("protected")
class ProtectedController {
  @TestHandler()
  handler() {
    return "ok";
  }
}

@Controller("public-method")
class PublicMethodController {
  @TestHandler()
  @Public()
  handler() {
    return "ok";
  }
}

@Public()
@Controller("public-class")
class PublicClassController {
  @TestHandler()
  handler() {
    return "ok";
  }
}

function isHttpError(e: Error | undefined): e is HttpError {
  return e instanceof HttpError;
}

describe("AuthGuard interceptor", () => {
  it("throws 401 when a protected route has no credential", async () => {
    const app = await prepareTestApp([ProtectedController]);
    const result = await runGuardForHandler(app, "ProtectedController", "handler", {});
    expect(result.ok).toBe(false);
    expect(isHttpError(result.thrown)).toBe(true);
    expect((result.thrown as HttpError | undefined)?.message).toContain("Unauthorized");
  });

  it("admits a protected route with a valid Bearer token and populates AuthContext", async () => {
    const app = await prepareTestApp([ProtectedController]);
    const { accessToken } = await app.auth.issue("alice", { roles: ["admin"] });
    const result = await runGuardForHandler(app, "ProtectedController", "handler", {
      headers: { authorization: `Bearer ${accessToken}` },
    });
    expect(result.ok).toBe(true);
    // AuthContext should have been written into the event slot.
    expect(result.authContext?.userId).toBe("alice");
    expect(result.authContext?.method).toBe("token");
  });

  it("admits a protected route with a valid cookie", async () => {
    const app = await prepareTestApp([ProtectedController]);
    const { accessToken } = await app.auth.issue("bob");
    const result = await runGuardForHandler(app, "ProtectedController", "handler", {
      cookies: `aooth_session=${accessToken}`,
    });
    expect(result.ok).toBe(true);
    expect(result.authContext?.userId).toBe("bob");
  });

  it("prefers Bearer over cookie when both are present (Bearer wins)", async () => {
    const app = await prepareTestApp([ProtectedController]);
    const a = await app.auth.issue("alice");
    const b = await app.auth.issue("bob");
    // a's accessToken in Bearer, b's in cookie. Guard should validate a (Bearer).
    const result = await runGuardForHandler(app, "ProtectedController", "handler", {
      headers: { authorization: `Bearer ${a.accessToken}` },
      cookies: `aooth_session=${b.accessToken}`,
    });
    expect(result.ok).toBe(true);
    expect(result.authContext?.userId).toBe("alice");
  });

  it("rejects an invalid token on a protected route", async () => {
    const app = await prepareTestApp([ProtectedController]);
    const result = await runGuardForHandler(app, "ProtectedController", "handler", {
      headers: { authorization: "Bearer bogus" },
    });
    expect(result.ok).toBe(false);
    expect((result.thrown as HttpError | undefined)?.message).toContain("Invalid credential");
  });

  it("admits a method-level @Public route with no token and sets null context", async () => {
    const app = await prepareTestApp([PublicMethodController]);
    const result = await runGuardForHandler(app, "PublicMethodController", "handler", {});
    expect(result.ok).toBe(true);
    expect(result.authContext).toBeNull();
    expect(result.isAuthenticated).toBe(false);
  });

  it("admits a method-level @Public route with an invalid token", async () => {
    const app = await prepareTestApp([PublicMethodController]);
    const result = await runGuardForHandler(app, "PublicMethodController", "handler", {
      headers: { authorization: "Bearer bogus" },
    });
    expect(result.ok).toBe(true);
    expect(result.authContext).toBeNull();
  });

  it("admits a class-level @Public route with no token", async () => {
    const app = await prepareTestApp([PublicClassController]);
    const result = await runGuardForHandler(app, "PublicClassController", "handler", {});
    expect(result.ok).toBe(true);
    expect(result.authContext).toBeNull();
  });

  it("ignores the header when enableBearer=false (cookie-only)", async () => {
    const app = await prepareTestApp([ProtectedController], { enableBearer: false });
    const { accessToken } = await app.auth.issue("alice");

    // Bearer alone: rejected (because bearer is disabled).
    const header = await runGuardForHandler(app, "ProtectedController", "handler", {
      headers: { authorization: `Bearer ${accessToken}` },
    });
    expect(header.ok).toBe(false);

    // Cookie alone: admitted.
    const cookie = await runGuardForHandler(app, "ProtectedController", "handler", {
      cookies: `aooth_session=${accessToken}`,
    });
    expect(cookie.ok).toBe(true);
  });

  it("ignores the cookie when enableCookie=false (bearer-only)", async () => {
    const app = await prepareTestApp([ProtectedController], { enableCookie: false });
    const { accessToken } = await app.auth.issue("alice");

    const cookie = await runGuardForHandler(app, "ProtectedController", "handler", {
      cookies: `aooth_session=${accessToken}`,
    });
    expect(cookie.ok).toBe(false);

    const header = await runGuardForHandler(app, "ProtectedController", "handler", {
      headers: { authorization: `Bearer ${accessToken}` },
    });
    expect(header.ok).toBe(true);
  });

  it("respects custom cookie name", async () => {
    const app = await prepareTestApp([ProtectedController], {
      cookie: { name: "sid" },
    });
    const { accessToken } = await app.auth.issue("alice");

    // Default name: rejected.
    const wrong = await runGuardForHandler(app, "ProtectedController", "handler", {
      cookies: `aooth_session=${accessToken}`,
    });
    expect(wrong.ok).toBe(false);

    // Custom name: admitted.
    const right = await runGuardForHandler(app, "ProtectedController", "handler", {
      cookies: `sid=${accessToken}`,
    });
    expect(right.ok).toBe(true);
  });
});
