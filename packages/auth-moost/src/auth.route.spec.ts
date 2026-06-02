import { describe, expect, it } from "vite-plus/test";

import { normalizeCookiePath } from "./auth.route";

// The mount-prefix-aware refresh-route resolution now lives in moost core
// (`@MoostInit` + `@HandlerPaths('refresh')` on `AuthController`) instead of a
// hand-rolled `getControllersOverview()` walk. Its end-to-end behavior — the
// cookie's actual `Path` under a prefixed mount, an explicit override, and the
// root-mount default — is covered by the integration tests in
// `__test__/auth.controller.spec.ts` ("refresh cookie path (mount-prefix aware)")
// and the e2e RF-002 spec, so only the cookie-path formatter is unit-tested here.

describe("normalizeCookiePath", () => {
  it("adds a leading slash", () => {
    expect(normalizeCookiePath("api/auth/refresh")).toBe("/api/auth/refresh");
  });
  it("collapses doubled slashes", () => {
    expect(normalizeCookiePath("//api//auth/refresh")).toBe("/api/auth/refresh");
  });
  it("strips a trailing slash", () => {
    expect(normalizeCookiePath("/auth/refresh/")).toBe("/auth/refresh");
  });
  it("keeps the bare root", () => {
    expect(normalizeCookiePath("/")).toBe("/");
  });
});
