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
    expect(c.endpoints).toBe(true);
  });

  it("propagates access-cookie transport attrs to the refresh cookie", () => {
    const c = new MoostAuthConfig();
    c.configure({
      cookie: { secure: false, sameSite: "strict", httpOnly: true, domain: "example.com" },
    });
    expect(c.refreshCookie.secure).toBe(false);
    expect(c.refreshCookie.sameSite).toBe("strict");
    expect(c.refreshCookie.domain).toBe("example.com");
    // path is independent — refresh cookie keeps its narrower default.
    expect(c.refreshCookie.path).toBe("/auth/refresh");
  });

  it("refresh-cookie overrides win over inherited access-cookie attrs", () => {
    const c = new MoostAuthConfig();
    c.configure({
      cookie: { secure: true, sameSite: "lax" },
      refreshCookie: { name: "rt", path: "/api/refresh", sameSite: "strict" },
    });
    expect(c.refreshCookie.name).toBe("rt");
    expect(c.refreshCookie.path).toBe("/api/refresh");
    expect(c.refreshCookie.sameSite).toBe("strict");
    expect(c.refreshCookie.secure).toBe(true); // inherited
  });

  it("toggles transports + endpoints flags", () => {
    const c = new MoostAuthConfig();
    c.configure({ enableBearer: false, enableCookie: true, endpoints: false });
    expect(c.enableBearer).toBe(false);
    expect(c.enableCookie).toBe(true);
    expect(c.endpoints).toBe(false);
  });
});
