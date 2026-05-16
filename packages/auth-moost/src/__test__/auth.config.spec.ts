import { describe, expect, it } from "vite-plus/test";

import { MoostAuthConfig } from "../auth.config";

describe("MoostAuthConfig", () => {
  it("applies safe defaults", () => {
    const c = new MoostAuthConfig();
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
    const c = new MoostAuthConfig({
      cookie: { secure: false, sameSite: "strict", httpOnly: true, domain: "example.com" },
    });
    expect(c.refreshCookie.secure).toBe(false);
    expect(c.refreshCookie.sameSite).toBe("strict");
    expect(c.refreshCookie.domain).toBe("example.com");
    // path is independent — refresh cookie keeps its narrower default.
    expect(c.refreshCookie.path).toBe("/auth/refresh");
  });

  it("refresh-cookie overrides win over inherited access-cookie attrs", () => {
    const c = new MoostAuthConfig({
      cookie: { secure: true, sameSite: "lax" },
      refreshCookie: { name: "rt", path: "/api/refresh", sameSite: "strict" },
    });
    expect(c.refreshCookie.name).toBe("rt");
    expect(c.refreshCookie.path).toBe("/api/refresh");
    expect(c.refreshCookie.sameSite).toBe("strict");
    expect(c.refreshCookie.secure).toBe(true); // inherited
  });

  it("toggles transports flags", () => {
    const c = new MoostAuthConfig({ enableBearer: false, enableCookie: true });
    expect(c.enableBearer).toBe(false);
    expect(c.enableCookie).toBe(true);
  });

  // ISSUE-9: the old `configure()` method was deleted in favour of a real
  // ctor — consumers used to build a no-op instance and then mutate it,
  // which produced two construction paths for the same shape. The asserts
  // below pin the new contract: partial opts must only touch the requested
  // sub-field while every default elsewhere survives.
  it("partial cookie opts preserve all other access-cookie defaults", () => {
    const c = new MoostAuthConfig({ cookie: { secure: false } });
    expect(c.cookie.secure).toBe(false);
    // Every other default on the access cookie must be untouched.
    expect(c.cookie.name).toBe("aooth_session");
    expect(c.cookie.path).toBe("/");
    expect(c.cookie.sameSite).toBe("lax");
    expect(c.cookie.httpOnly).toBe(true);
    // Sibling defaults survive too.
    expect(c.enableBearer).toBe(true);
    expect(c.enableCookie).toBe(true);
    expect(c.refreshCookie.name).toBe("aooth_refresh");
    expect(c.refreshCookie.path).toBe("/auth/refresh");
  });

  it("configure() is NOT a method on MoostAuthConfig (hard-cut — ISSUE-9)", () => {
    // The legacy `cfg.configure({...})` was the second construction path that
    // ISSUE-9 collapsed into the constructor. Re-introducing it would split
    // the contract again — this assertion catches that regression at the
    // class-shape level.
    const c = new MoostAuthConfig();
    expect((c as unknown as { configure?: unknown }).configure).toBeUndefined();
  });
});
