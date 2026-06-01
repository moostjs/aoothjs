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
    trackLastSeen: opts.trackLastSeen,
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

    it("rejects a refresh token used as an access token (kind discriminant)", async () => {
      // Pin: validate() must filter out kind==='refresh' even on stateful
      // stores so a refresh credential cannot be replayed as a bearer access
      // token. Previously only covered for stateless stores in the
      // integration spec.
      const { auth } = makeAuth({ refresh: { ttl: 60_000, rotation: "none" } });
      const issued = await auth.issue("alice");
      expect(issued.refreshToken).toBeTruthy();
      expect(await auth.validate(issued.refreshToken!)).toBeNull();
    });

    it("rejects accessTtl<=0 at construction (INVALID_CONFIG)", () => {
      // Misconfigured 0 / negative TTL would produce tokens that immediately
      // fail validate(). The constructor surfaces the bad config eagerly so
      // bootstrap fails loudly instead of issuing tokens that never work.
      expect(() => makeAuth({ accessTtl: 0 })).toThrow(AuthError);
      expect(() => makeAuth({ accessTtl: -100 })).toThrow(AuthError);
    });

    it("rejects refresh.ttl<=0 at construction (INVALID_CONFIG)", () => {
      expect(() => makeAuth({ refresh: { ttl: 0, rotation: "none" } })).toThrow(AuthError);
      expect(() => makeAuth({ refresh: { ttl: -1, rotation: "none" } })).toThrow(AuthError);
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
    it("consumes old refresh; new pair issued; replay triggers theft response", async () => {
      // Reuse-after-rotation must fire the OAuth theft response in 'always'
      // mode — same signal as 'sliding' beyond grace. Sibling sessions for
      // the same user must be revoked, not just the replayed token rejected.
      let reuseFired = 0;
      const { auth } = makeAuth({
        accessTtl: 1000,
        refresh: {
          ttl: 60_000,
          rotation: "always",
          onRotationReuse: () => {
            reuseFired++;
          },
        },
      });
      const sibling = await auth.issue("alice");
      const initial = await auth.issue("alice");
      const refreshed = await auth.refresh(initial.refreshToken!);
      expect(refreshed.refreshToken).not.toBe(initial.refreshToken);
      await expect(auth.refresh(initial.refreshToken!)).rejects.toMatchObject({
        type: "REFRESH_REUSE_DETECTED",
      });
      expect(reuseFired).toBe(1);
      // Sibling session for the same user must be revoked too.
      expect(await auth.validate(sibling.accessToken)).toBeNull();
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

  describe("sessionId (token family)", () => {
    it("stamps one sessionId on access + refresh, surfaced by validate()", async () => {
      const { auth } = makeAuth({ refresh: { ttl: 60_000, rotation: "always" } });
      const issued = await auth.issue("alice");
      const ctxA = await auth.validate(issued.accessToken);
      expect(ctxA?.sessionId).toBeTruthy();
      // The refresh token shares the same session family.
      const sessions = await auth.listSessions("alice");
      expect(sessions).toHaveLength(1);
      expect(sessions[0].sessionId).toBe(ctxA?.sessionId);
    });

    it("stays one session across N refreshes (rotation 'always')", async () => {
      const { auth, clock } = makeAuth({ refresh: { ttl: 60_000, rotation: "always" } });
      const first = await auth.issue("alice");
      const original = (await auth.validate(first.accessToken))?.sessionId;
      let refreshToken = first.refreshToken!;
      for (let i = 0; i < 3; i++) {
        clock.advance(10);
        const rotated = await auth.refresh(refreshToken);
        refreshToken = rotated.refreshToken!;
        expect((await auth.validate(rotated.accessToken))?.sessionId).toBe(original);
      }
      const sessions = await auth.listSessions("alice");
      expect(sessions).toHaveLength(1);
      expect(sessions[0].sessionId).toBe(original);
    });

    it("legacy rows without sessionId fall back to the token fingerprint", async () => {
      const { auth, store } = makeAuth();
      const issued = await auth.issue("alice");
      // Simulate a pre-sessionId row by stripping it in the store.
      const list = await store.listForUser!("alice");
      for (const e of list) {
        delete (e as { sessionId?: string }).sessionId;
        await store.update(e.token, e);
      }
      const ctx = await auth.validate(issued.accessToken);
      expect(ctx?.sessionId).toBe(fingerprint(issued.accessToken));
      const sessions = await auth.listSessions("alice");
      expect(sessions[0].sessionId).toBe(fingerprint(issued.accessToken));
    });
  });

  describe("listSessions", () => {
    it("collapses access + refresh into one row with metadata + refresh expiry", async () => {
      const { auth, clock } = makeAuth({
        accessTtl: 1000,
        refresh: { ttl: 60_000, rotation: "none" },
      });
      await auth.issue("alice", { metadata: { ip: "1.2.3.4", userAgent: "UA/1" } });
      const sessions = await auth.listSessions("alice");
      expect(sessions).toHaveLength(1);
      expect(sessions[0].metadata).toEqual({ ip: "1.2.3.4", userAgent: "UA/1" });
      expect(sessions[0].createdAt).toBe(clock.now());
      // Refresh outlives access — its expiry is the session lifetime.
      expect(sessions[0].expiresAt).toBe(clock.now() + 60_000);
    });

    it("returns one row per device, newest first", async () => {
      const { auth, clock } = makeAuth();
      await auth.issue("alice");
      clock.advance(100);
      await auth.issue("alice");
      const sessions = await auth.listSessions("alice");
      expect(sessions).toHaveLength(2);
      expect(sessions[0].createdAt).toBeGreaterThan(sessions[1].createdAt);
    });

    it("maps each row through an enricher when provided", async () => {
      const { auth } = makeAuth();
      await auth.issue("alice", { metadata: { userAgent: "Chrome" } });
      const [enriched] = await auth.listSessions("alice", {
        enrich: (s) => ({ ...s, browser: s.metadata?.userAgent }),
      });
      expect((enriched as { browser?: string }).browser).toBe("Chrome");
    });
  });

  describe("revokeSession + revokeOtherSessions", () => {
    it("revokeSession kills exactly one device's family; others keep working", async () => {
      const { auth } = makeAuth({ refresh: { ttl: 60_000, rotation: "none" } });
      const a = await auth.issue("alice");
      const b = await auth.issue("alice");
      const sidA = (await auth.validate(a.accessToken))?.sessionId as string;
      await auth.revokeSession("alice", sidA);
      expect(await auth.validate(a.accessToken)).toBeNull();
      // The refresh side of the same family is gone too.
      await expect(auth.refresh(a.refreshToken!)).rejects.toMatchObject({ type: "INVALID_TOKEN" });
      expect(await auth.validate(b.accessToken)).not.toBeNull();
    });

    it("revokeOtherSessions leaves only the current session", async () => {
      const { auth } = makeAuth();
      const a = await auth.issue("alice");
      await auth.issue("alice");
      await auth.issue("alice");
      const sidA = (await auth.validate(a.accessToken))?.sessionId as string;
      const revoked = await auth.revokeOtherSessions("alice", sidA);
      expect(revoked).toBe(2);
      const sessions = await auth.listSessions("alice");
      expect(sessions).toHaveLength(1);
      expect(sessions[0].sessionId).toBe(sidA);
    });
  });

  describe("trackLastSeen", () => {
    it("default false: no lastSeenAt, listSessions falls back to createdAt", async () => {
      const { auth, clock } = makeAuth({ refresh: { ttl: 60_000, rotation: "always" } });
      const first = await auth.issue("alice");
      clock.advance(500);
      await auth.refresh(first.refreshToken!);
      const [s] = await auth.listSessions("alice");
      expect(s.lastSeenAt).toBeUndefined();
    });

    it("'refresh': a refresh advances the session's lastSeenAt", async () => {
      const { auth, clock } = makeAuth({
        refresh: { ttl: 60_000, rotation: "always" },
        trackLastSeen: "refresh",
      });
      const first = await auth.issue("alice");
      clock.advance(500);
      await auth.refresh(first.refreshToken!);
      const [s] = await auth.listSessions("alice");
      expect(s.lastSeenAt).toBe(clock.now());
    });

    it("'validate': touches lastSeenAt on each successful validate", async () => {
      const { auth, clock } = makeAuth({ trackLastSeen: "validate" });
      const issued = await auth.issue("alice");
      clock.advance(250);
      await auth.validate(issued.accessToken);
      const [s] = await auth.listSessions("alice");
      expect(s.lastSeenAt).toBe(clock.now());
    });
  });
});
