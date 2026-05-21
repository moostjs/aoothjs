import type { AuthContext } from "@aooth/auth";
import { current } from "@wooksjs/event-core";
import { prepareTestHttpContext } from "@wooksjs/event-http";
import { describe, expect, it } from "vite-plus/test";

import { resolveAuthOptions } from "../auth.config";
import { authOptionsKey, setAuthContext, useAuth } from "../auth.composables";

describe("useAuth composable", () => {
  it("getAuthContext returns null when no AuthContext is in the event", () => {
    const run = prepareTestHttpContext({ url: "/test" });
    run(() => {
      const auth = useAuth();
      expect(auth.getAuthContext()).toBeNull();
      expect(auth.isAuthenticated()).toBe(false);
    });
  });

  it("getUserId throws HttpError(401) when no AuthContext is present", () => {
    const run = prepareTestHttpContext({ url: "/test" });
    run(() => {
      const auth = useAuth();
      expect(() => auth.getUserId()).toThrow(/Not authenticated/);
    });
  });

  it("returns the AuthContext written by setAuthContext", () => {
    const run = prepareTestHttpContext({ url: "/test" });
    run(() => {
      const ctx: AuthContext = {
        userId: "alice",
        method: "token",
        credentialId: "deadbeef",
        expiresAt: Date.now() + 60_000,
      };

      // Before write: no auth.
      expect(useAuth().getAuthContext()).toBeNull();

      setAuthContext(current(), ctx);

      // After write: subsequent useAuth() calls inherit the value, because
      // useAuth's bindings memoize the accessor closures (not the value).
      const auth = useAuth();
      expect(auth.getAuthContext()).toBe(ctx);
      expect(auth.getUserId()).toBe("alice");
      expect(auth.isAuthenticated()).toBe(true);
    });
  });

  it("memoizes the bindings object across calls within the same event", () => {
    const run = prepareTestHttpContext({ url: "/test" });
    run(() => {
      const a = useAuth();
      const b = useAuth();
      expect(a).toBe(b);
    });
  });
});

describe("useAuth().cookieAttrs — Domain=undefined regression guard", () => {
  // Reason: wooks pre-0.7.13 serializes `domain: undefined` as the literal
  // string `Domain=undefined`, which browsers reject — the cookie is dropped
  // and the login flow appears to succeed (201 + body) but no session is
  // stored. `cookieAttrsFrom` must therefore omit the `domain` key entirely
  // when `ResolvedAuthCookieConfig.domain` is `undefined` (the default), not
  // just rely on the wooks fix landing downstream.
  it("omits domain entirely when cookie.domain is not configured (default config)", () => {
    const run = prepareTestHttpContext({ url: "/test" });
    run(() => {
      current().set(authOptionsKey, resolveAuthOptions());
      const attrs = useAuth().cookieAttrs();
      expect(Object.prototype.hasOwnProperty.call(attrs, "domain")).toBe(false);
      // sanity: the rest of the bag is still present
      expect(attrs).toMatchObject({
        httpOnly: true,
        secure: true,
        sameSite: "Lax",
        path: "/",
      });
    });
  });

  it("passes domain through when cookie.domain is configured", () => {
    const run = prepareTestHttpContext({ url: "/test" });
    run(() => {
      current().set(authOptionsKey, resolveAuthOptions({ cookie: { domain: "auth.example.com" } }));
      const attrs = useAuth().cookieAttrs();
      expect(attrs.domain).toBe("auth.example.com");
    });
  });

  it("dev profile (secure:false, no domain) emits no domain key", () => {
    // Mirrors the typical local-dev override: drop `Secure` for HTTP, leave
    // `domain` unset.
    const run = prepareTestHttpContext({ url: "/test" });
    run(() => {
      current().set(authOptionsKey, resolveAuthOptions({ cookie: { secure: false } }));
      const attrs = useAuth().cookieAttrs();
      expect(Object.prototype.hasOwnProperty.call(attrs, "domain")).toBe(false);
      expect(attrs.secure).toBe(false);
    });
  });

  it("extra overrides win over the resolved cookie config", () => {
    const run = prepareTestHttpContext({ url: "/test" });
    run(() => {
      current().set(authOptionsKey, resolveAuthOptions());
      const attrs = useAuth().cookieAttrs({ maxAge: 0, path: "/auth/refresh" });
      expect(attrs.maxAge).toBe(0);
      expect(attrs.path).toBe("/auth/refresh");
    });
  });
});
