import type { AuthContext } from "@aoothjs/auth";
import { current } from "@wooksjs/event-core";
import { prepareTestHttpContext } from "@wooksjs/event-http";
import { describe, expect, it } from "vite-plus/test";

import { setAuthContext, useAuth } from "../auth.composables";

describe("useAuth composable", () => {
  it("getCurrentUser returns null when no AuthContext is in the event", () => {
    const run = prepareTestHttpContext({ url: "/test" });
    run(() => {
      const auth = useAuth();
      expect(auth.getCurrentUser()).toBeNull();
      expect(auth.isAuthenticated()).toBe(false);
    });
  });

  it("getCurrentUserId throws HttpError(401) when no AuthContext is present", () => {
    const run = prepareTestHttpContext({ url: "/test" });
    run(() => {
      const auth = useAuth();
      expect(() => auth.getCurrentUserId()).toThrow(/Not authenticated/);
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
      expect(useAuth().getCurrentUser()).toBeNull();

      setAuthContext(current(), ctx);

      // After write: subsequent useAuth() calls inherit the value, because
      // useAuth's bindings memoize the accessor closures (not the value).
      const auth = useAuth();
      expect(auth.getCurrentUser()).toBe(ctx);
      expect(auth.getCurrentUserId()).toBe("alice");
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
