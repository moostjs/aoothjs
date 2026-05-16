import { describe, expect, it } from "vite-plus/test";

import { resolveAuthOptions } from "../auth.config";

describe("resolveAuthOptions", () => {
  it("applies safe defaults", () => {
    const c = resolveAuthOptions();
    expect(c.cookie.name).toBe("aooth_session");
    expect(c.cookie.path).toBe("/");
    expect(c.refreshCookie.name).toBe("aooth_refresh");
    expect(c.refreshCookie.path).toBe("/auth/refresh");
    expect(c.refreshCookie.httpOnly).toBe(true);
    expect(c.refreshCookie.secure).toBe(true);
    expect(c.refreshCookie.sameSite).toBe("lax");
    expect(c.enableBearer).toBe(true);
    expect(c.enableCookie).toBe(true);
  });

  it("propagates access-cookie transport attrs to the refresh cookie", () => {
    const c = resolveAuthOptions({
      cookie: { secure: false, sameSite: "strict", httpOnly: true, domain: "example.com" },
    });
    expect(c.refreshCookie.secure).toBe(false);
    expect(c.refreshCookie.sameSite).toBe("strict");
    expect(c.refreshCookie.domain).toBe("example.com");
    // path is independent — refresh cookie keeps its narrower default.
    expect(c.refreshCookie.path).toBe("/auth/refresh");
  });

  it("refresh-cookie overrides win over inherited access-cookie attrs", () => {
    const c = resolveAuthOptions({
      cookie: { secure: true, sameSite: "lax" },
      refreshCookie: { name: "rt", path: "/api/refresh", sameSite: "strict" },
    });
    expect(c.refreshCookie.name).toBe("rt");
    expect(c.refreshCookie.path).toBe("/api/refresh");
    expect(c.refreshCookie.sameSite).toBe("strict");
    expect(c.refreshCookie.secure).toBe(true); // inherited
  });

  it("toggles transports flags", () => {
    const c = resolveAuthOptions({ enableBearer: false, enableCookie: true });
    expect(c.enableBearer).toBe(false);
    expect(c.enableCookie).toBe(true);
  });

  // ISSUE-9 (and now AUTH-MOOST-1) pinned a single construction contract:
  // partial opts must only touch the requested sub-field while every default
  // elsewhere survives. The 'resolve' fn replaces the old class constructor
  // body and inherits the same invariant.
  it("partial cookie opts preserve all other access-cookie defaults", () => {
    const c = resolveAuthOptions({ cookie: { secure: false } });
    expect(c.cookie.secure).toBe(false);
    expect(c.cookie.name).toBe("aooth_session");
    expect(c.cookie.path).toBe("/");
    expect(c.cookie.sameSite).toBe("lax");
    expect(c.cookie.httpOnly).toBe(true);
    expect(c.enableBearer).toBe(true);
    expect(c.enableCookie).toBe(true);
    expect(c.refreshCookie.name).toBe("aooth_refresh");
    expect(c.refreshCookie.path).toBe("/auth/refresh");
  });
});
