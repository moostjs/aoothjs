import { createHash } from "node:crypto";
import { describe, expect, it } from "vite-plus/test";
import { AuthError } from "../errors";
import { DenylistStoreMemory } from "../stores/denylist-memory";
import { CredentialStoreMemory } from "../stores/memory";
import type { Clock } from "../utils/clock";
import { AuthCredential } from "./auth-credential";

function fingerprint(token: string): string {
  return createHash("sha256").update(token).digest("hex");
}

class FakeClock implements Clock {
  constructor(public time = 1_000_000) {}
  now(): number {
    return this.time;
  }
  advance(ms: number): void {
    this.time += ms;
  }
}

interface MyClaims extends Record<string, unknown> {
  roles: string[];
  email?: string;
}

function makeAuth(
  opts: Partial<ConstructorParameters<typeof AuthCredential<MyClaims>>[0]> & {
    clock?: FakeClock;
  } = {},
) {
  const clock = opts.clock ?? new FakeClock();
  const store = opts.store ?? new CredentialStoreMemory<MyClaims>({ clock });
  const auth = new AuthCredential<MyClaims>({
    store,
    clock,
    accessTtl: opts.accessTtl ?? 60_000,
    refresh: opts.refresh,
    denylist: opts.denylist,
    method: opts.method,
    maxConcurrent: opts.maxConcurrent,
    onLimit: opts.onLimit,
  });
  return { auth, store, clock };
}

describe("AuthCredential", () => {
  describe("issue + validate", () => {
    it("roundtrips userId, claims, metadata, and expiresAt", async () => {
      const { auth, clock } = makeAuth({ accessTtl: 5000 });
      const result = await auth.issue("alice", {
        claims: { roles: ["admin"], email: "a@x" },
        metadata: { ip: "1.1.1.1", label: "browser" },
      });
      expect(result.accessToken).toBeTruthy();
      expect(result.accessExpiresAt).toBe(clock.now() + 5000);
      expect(result.refreshToken).toBeUndefined();
      const ctx = await auth.validate(result.accessToken);
      expect(ctx).not.toBeNull();
      expect(ctx?.userId).toBe("alice");
      expect(ctx?.method).toBe("token");
      // credentialId is a sha256 fingerprint of the access token, not the
      // token itself — safe to log/persist without leaking a live bearer.
      expect(ctx?.credentialId).toBe(fingerprint(result.accessToken));
      expect(ctx?.credentialId).not.toBe(result.accessToken);
      expect(ctx?.expiresAt).toBe(result.accessExpiresAt);
      expect(ctx?.claims).toEqual({ roles: ["admin"], email: "a@x" });
    });

    it("returns null for unknown token", async () => {
      const { auth } = makeAuth();
      expect(await auth.validate("nope")).toBeNull();
    });

    it("returns null for expired token", async () => {
      const { auth, clock } = makeAuth({ accessTtl: 100 });
      const { accessToken } = await auth.issue("alice");
      clock.advance(101);
      expect(await auth.validate(accessToken)).toBeNull();
    });

    it("returns null for revoked token", async () => {
      const { auth } = makeAuth();
      const { accessToken } = await auth.issue("alice");
      await auth.revoke(accessToken);
      expect(await auth.validate(accessToken)).toBeNull();
    });

    it("uses configured method (session)", async () => {
      const { auth } = makeAuth({ method: "session" });
      const { accessToken } = await auth.issue("alice");
      const ctx = await auth.validate(accessToken);
      expect(ctx?.method).toBe("session");
    });
  });

  describe("revoke + revokeAllForUser", () => {
    it("revokeAllForUser invalidates every active token", async () => {
      const { auth } = makeAuth();
      const a = await auth.issue("alice");
      const b = await auth.issue("alice");
      const c = await auth.issue("bob");
      const count = await auth.revokeAllForUser("alice");
      expect(count).toBe(2);
      expect(await auth.validate(a.accessToken)).toBeNull();
      expect(await auth.validate(b.accessToken)).toBeNull();
      expect(await auth.validate(c.accessToken)).not.toBeNull();
    });
  });

  describe("denylist integration", () => {
    it("validate returns null when token is on denylist", async () => {
      const clock = new FakeClock();
      const denylist = new DenylistStoreMemory({ clock });
      const { auth } = makeAuth({ denylist, clock });
      const { accessToken } = await auth.issue("alice");
      await denylist.add(accessToken, clock.now() + 60_000);
      expect(await auth.validate(accessToken)).toBeNull();
    });
  });

  describe("listForUser", () => {
    it("returns only access-kind credentials", async () => {
      const { auth } = makeAuth({
        refresh: { ttl: 60_000, rotation: "none" },
      });
      const issued1 = await auth.issue("alice");
      const issued2 = await auth.issue("alice");
      const list = await auth.listForUser("alice");
      const ids = list.map((c) => c.credentialId).toSorted();
      expect(ids).toEqual(
        [fingerprint(issued1.accessToken), fingerprint(issued2.accessToken)].toSorted(),
      );
    });
  });

  describe("refresh: rotation 'none'", () => {
    it("issues new access; old refresh keeps working", async () => {
      const { auth, clock } = makeAuth({
        accessTtl: 1000,
        refresh: { ttl: 60_000, rotation: "none" },
      });
      const initial = await auth.issue("alice");
      clock.advance(10);
      const refreshed = await auth.refresh(initial.refreshToken!);
      expect(refreshed.accessToken).not.toBe(initial.accessToken);
      expect(refreshed.refreshToken).toBe(initial.refreshToken);
      // The refresh token still works again.
      clock.advance(10);
      const refreshed2 = await auth.refresh(initial.refreshToken!);
      expect(refreshed2.accessToken).not.toBe(refreshed.accessToken);
      expect(refreshed2.refreshToken).toBe(initial.refreshToken);
    });
  });

  describe("refresh: rotation 'always'", () => {
    it("consumes old refresh; new pair issued; old refresh fails", async () => {
      const { auth } = makeAuth({
        accessTtl: 1000,
        refresh: { ttl: 60_000, rotation: "always" },
      });
      const initial = await auth.issue("alice");
      const refreshed = await auth.refresh(initial.refreshToken!);
      expect(refreshed.refreshToken).not.toBe(initial.refreshToken);
      await expect(auth.refresh(initial.refreshToken!)).rejects.toMatchObject({
        type: "INVALID_TOKEN",
      });
    });
  });

  describe("refresh: rotation 'sliding'", () => {
    it("happy path issues new pair and marks the old refresh as rotated", async () => {
      const { auth, store, clock } = makeAuth({
        accessTtl: 1000,
        refresh: { ttl: 60_000, rotation: "sliding", rotationGraceMs: 5000 },
      });
      const initial = await auth.issue("alice");
      clock.advance(10);
      const refreshed = await auth.refresh(initial.refreshToken!);
      expect(refreshed.refreshToken).not.toBe(initial.refreshToken);
      const oldRefreshState = await store.retrieve(initial.refreshToken!);
      expect(oldRefreshState?.rotatedAt).toBe(clock.now());
    });

    it("race within grace period accepts the old refresh again", async () => {
      const { auth, clock } = makeAuth({
        accessTtl: 1000,
        refresh: { ttl: 60_000, rotation: "sliding", rotationGraceMs: 5000 },
      });
      const initial = await auth.issue("alice");
      clock.advance(10);
      const first = await auth.refresh(initial.refreshToken!);
      clock.advance(10); // still inside the 5s grace
      const second = await auth.refresh(initial.refreshToken!);
      expect(second.accessToken).toBeTruthy();
      expect(second.refreshToken).toBeTruthy();
      // The newest refresh should also work.
      const third = await auth.refresh(first.refreshToken!);
      expect(third.accessToken).toBeTruthy();
    });

    it("reuse after grace fires onRotationReuse and throws REFRESH_REUSE_DETECTED", async () => {
      let reuseFired = 0;
      const { auth, clock } = makeAuth({
        accessTtl: 1000,
        refresh: {
          ttl: 60_000,
          rotation: "sliding",
          rotationGraceMs: 1000,
          onRotationReuse: () => {
            reuseFired++;
          },
        },
      });
      const initial = await auth.issue("alice");
      clock.advance(10);
      await auth.refresh(initial.refreshToken!);
      clock.advance(2000); // beyond 1000ms grace
      await expect(auth.refresh(initial.refreshToken!)).rejects.toMatchObject({
        type: "REFRESH_REUSE_DETECTED",
      });
      expect(reuseFired).toBe(1);
    });

    it("throws if refresh is not configured", async () => {
      const { auth } = makeAuth();
      await expect(auth.refresh("anything")).rejects.toMatchObject({
        type: "INVALID_CONFIG",
      });
    });

    it("throws INVALID_TOKEN on unknown refresh token", async () => {
      const { auth } = makeAuth({
        refresh: { ttl: 60_000, rotation: "sliding" },
      });
      await expect(auth.refresh("nope")).rejects.toBeInstanceOf(AuthError);
    });

    it("rejects an access token used as refresh", async () => {
      const { auth } = makeAuth({
        refresh: { ttl: 60_000, rotation: "sliding" },
      });
      const issued = await auth.issue("alice");
      await expect(auth.refresh(issued.accessToken)).rejects.toMatchObject({
        type: "INVALID_TOKEN",
      });
    });
  });

  describe("maxConcurrent", () => {
    it("'reject' throws once limit is reached", async () => {
      const { auth } = makeAuth({ maxConcurrent: 2, onLimit: "reject" });
      await auth.issue("alice");
      await auth.issue("alice");
      await expect(auth.issue("alice")).rejects.toMatchObject({
        type: "MAX_CONCURRENT_REACHED",
      });
    });

    it("'evict-oldest' revokes the oldest token", async () => {
      const { auth, clock } = makeAuth({
        maxConcurrent: 2,
        onLimit: "evict-oldest",
      });
      const oldest = await auth.issue("alice");
      clock.advance(1);
      const middle = await auth.issue("alice");
      clock.advance(1);
      const newest = await auth.issue("alice");
      expect(await auth.validate(oldest.accessToken)).toBeNull();
      expect(await auth.validate(middle.accessToken)).not.toBeNull();
      expect(await auth.validate(newest.accessToken)).not.toBeNull();
    });

    it("counts only access-kind credentials, ignoring refresh tokens", async () => {
      // With refresh enabled, each issue creates 2 entries (access + refresh).
      // The limit must still allow `maxConcurrent` issuances.
      const { auth } = makeAuth({
        maxConcurrent: 2,
        refresh: { ttl: 60_000, rotation: "none" },
      });
      const a = await auth.issue("alice");
      const b = await auth.issue("alice");
      expect(a.refreshToken).toBeTruthy();
      expect(b.refreshToken).toBeTruthy();
      await expect(auth.issue("alice")).rejects.toMatchObject({
        type: "MAX_CONCURRENT_REACHED",
      });
    });
  });
});
