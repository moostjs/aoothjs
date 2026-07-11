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

// Typed credential payload — flat root fields (replacing the dropped `claims`
// container). Optional, since a normal token carries none.
interface MyClaims {
  roles?: string[];
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
    it("roundtrips userId, payload, metadata, and expiresAt", async () => {
      const { auth, clock } = makeAuth({ accessTtl: 5000 });
      const result = await auth.issue("alice", {
        roles: ["admin"],
        email: "a@x",
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
      expect(ctx?.roles).toEqual(["admin"]);
      expect(ctx?.email).toBe("a@x");
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

  describe("issue: per-mint TTL / expiresAt override", () => {
    it("defaults to the instance accessTtl when neither ttl nor expiresAt is given", async () => {
      const { auth, clock } = makeAuth({ accessTtl: 5000 });
      const r = await auth.issue("alice");
      expect(r.accessExpiresAt).toBe(clock.now() + 5000);
    });

    it("ttl overrides the instance accessTtl for THIS mint only", async () => {
      // One instance mints both a short session and a long-lived PAT — the whole
      // point of the per-mint override (no second AuthCredential/posture).
      const { auth, clock } = makeAuth({ accessTtl: 30 * 60_000 });
      const oneYear = 365 * 24 * 60 * 60_000;
      const pat = await auth.issue("alice", { ttl: oneYear });
      expect(pat.accessExpiresAt).toBe(clock.now() + oneYear);

      // Still valid after the instance accessTtl would have expired.
      clock.advance(30 * 60_000 + 1);
      expect(await auth.validate(pat.accessToken)).not.toBeNull();

      // A second mint on the same instance keeps the default lifetime.
      const session = await auth.issue("alice");
      expect(session.accessExpiresAt).toBe(clock.now() + 30 * 60_000);
    });

    it("expiresAt sets the absolute expiry instant", async () => {
      const { auth, clock } = makeAuth({ accessTtl: 1000 });
      const at = clock.now() + 7 * 24 * 60 * 60_000;
      const r = await auth.issue("alice", { expiresAt: at });
      expect(r.accessExpiresAt).toBe(at);
      const ctx = await auth.validate(r.accessToken);
      expect(ctx?.expiresAt).toBe(at);
    });

    it("the per-mint ttl does NOT affect the refresh token (it keeps refresh.ttl)", async () => {
      const { auth, clock } = makeAuth({
        accessTtl: 1000,
        refresh: { ttl: 60_000, rotation: "none" },
      });
      const oneDay = 24 * 60 * 60_000;
      const r = await auth.issue("alice", { ttl: oneDay });
      expect(r.accessExpiresAt).toBe(clock.now() + oneDay);
      expect(r.refreshExpiresAt).toBe(clock.now() + 60_000); // unchanged
    });

    it("rejects ttl + expiresAt together (INVALID_CONFIG)", async () => {
      const { auth, clock } = makeAuth();
      await expect(
        auth.issue("alice", { ttl: 1000, expiresAt: clock.now() + 1000 }),
      ).rejects.toThrow(AuthError);
    });

    it("rejects ttl <= 0 (INVALID_CONFIG)", async () => {
      const { auth } = makeAuth();
      await expect(auth.issue("alice", { ttl: 0 })).rejects.toThrow(AuthError);
      await expect(auth.issue("alice", { ttl: -1 })).rejects.toThrow(AuthError);
    });

    it("a past expiresAt yields a born-expired token (validate rejects), not a no-expiry one", async () => {
      const { auth, clock } = makeAuth();
      const r = await auth.issue("alice", { expiresAt: clock.now() - 1 });
      expect(await auth.validate(r.accessToken)).toBeNull();
    });

    it("ttl/expiresAt are stripped from the persisted payload (reserved keys)", async () => {
      const { auth } = makeAuth({ accessTtl: 5000 });
      const r = await auth.issue("alice", { ttl: 9999, roles: ["admin"] });
      const ctx = await auth.validate(r.accessToken);
      expect(ctx?.roles).toEqual(["admin"]);
      // The reserved hints must not leak onto the typed payload / AuthContext.
      const rec = ctx as unknown as Record<string, unknown>;
      expect(rec.ttl).toBeUndefined();
      expect(rec.expiresAt).toBe(r.accessExpiresAt);
    });
  });

  describe("issue: semantic kind + kind-aware listSessions", () => {
    it("stamps the semantic kind into metadata.credentialKind and surfaces SessionInfo.kind", async () => {
      const { auth } = makeAuth();
      await auth.issue("alice", { kind: "cli-session", metadata: { ip: "1.2.3.4" } });
      const [s] = await auth.listSessions("alice", { kind: "cli-session" });
      expect(s.kind).toBe("cli-session");
      // It lives in the metadata bag (the zero-migration storage), alongside ip.
      expect(s.metadata).toEqual({ ip: "1.2.3.4", credentialKind: "cli-session" });
    });

    it("listSessions defaults to the browser-safe set — cli-session / pat are excluded", async () => {
      const { auth } = makeAuth();
      await auth.issue("alice"); // ordinary interactive session (no kind)
      await auth.issue("alice", { kind: "cli-session" });
      await auth.issue("alice", { kind: "pat" });
      const browser = await auth.listSessions("alice");
      expect(browser).toHaveLength(1);
      expect(browser[0].kind).toBeUndefined(); // ordinary sessions omit it
    });

    it("filters to an explicit kind, supports an array, and '*' returns every kind", async () => {
      const { auth } = makeAuth();
      await auth.issue("alice");
      await auth.issue("alice", { kind: "cli-session" });
      await auth.issue("alice", { kind: "pat" });

      expect(await auth.listSessions("alice", { kind: "cli-session" })).toHaveLength(1);
      expect(await auth.listSessions("alice", { kind: ["cli-session", "pat"] })).toHaveLength(2);
      // "*" bypasses the filter — the interactive session + both labelled ones.
      expect(await auth.listSessions("alice", { kind: "*" })).toHaveLength(3);
      // "session" matches the unlabelled interactive credential.
      expect(await auth.listSessions("alice", { kind: "session" })).toHaveLength(1);
    });

    it("the semantic kind survives refresh rotation (carried in metadata)", async () => {
      const { auth } = makeAuth({ refresh: { ttl: 60_000, rotation: "always" } });
      const r = await auth.issue("alice", { kind: "cli-session" });
      // Rotate — the new pair must keep the family's kind (read off the session,
      // since the kind lives in metadata, not on the request AuthContext).
      await auth.refresh(r.refreshToken!);
      const [s] = await auth.listSessions("alice", { kind: "cli-session" });
      expect(s.kind).toBe("cli-session");
    });

    it("kind is a reserved hint — it does not leak onto the typed payload", async () => {
      const { auth } = makeAuth();
      const r = await auth.issue("alice", { kind: "pat", roles: ["admin"] });
      const ctx = await auth.validate(r.accessToken);
      expect(ctx?.roles).toEqual(["admin"]);
      const rec = ctx as unknown as Record<string, unknown>;
      expect(rec.kind).toBeUndefined();
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
    it("rotates the token but keeps a FIXED session ceiling (expiry never slides)", async () => {
      const { auth, clock } = makeAuth({
        accessTtl: 1000,
        refresh: { ttl: 60_000, rotation: "always" },
      });
      const initial = await auth.issue("alice");
      const ceiling = initial.refreshExpiresAt!;
      clock.advance(10_000);
      const r1 = await auth.refresh(initial.refreshToken!);
      expect(r1.refreshToken).not.toBe(initial.refreshToken);
      // 'always' carries the family's original expiry forward — it must NOT
      // extend to now + ttl the way 'sliding' does.
      expect(r1.refreshExpiresAt).toBe(ceiling);
      clock.advance(10_000);
      const r2 = await auth.refresh(r1.refreshToken!);
      expect(r2.refreshExpiresAt).toBe(ceiling);
    });

    it("benign concurrent refresh within grace re-issues a pair — no theft", async () => {
      // The bug this guards: two tabs present the same just-rotated token at
      // ~the same instant. Within grace the second presentation must succeed,
      // NOT be mistaken for token theft.
      let reuseFired = 0;
      const { auth, clock } = makeAuth({
        accessTtl: 1000,
        refresh: {
          ttl: 60_000,
          rotation: "always",
          rotationGraceMs: 5000,
          onRotationReuse: () => {
            reuseFired++;
          },
        },
      });
      const sibling = await auth.issue("alice");
      const initial = await auth.issue("alice");
      const first = await auth.refresh(initial.refreshToken!);
      clock.advance(10); // second tab, still inside grace
      const second = await auth.refresh(initial.refreshToken!);
      expect(second.accessToken).toBeTruthy();
      expect(second.refreshToken).toBeTruthy();
      expect(second.refreshToken).not.toBe(initial.refreshToken);
      expect(reuseFired).toBe(0);
      // No theft → neither the sibling session nor the freshly-issued tokens die.
      expect(await auth.validate(sibling.accessToken)).not.toBeNull();
      clock.advance(10);
      expect((await auth.refresh(first.refreshToken!)).accessToken).toBeTruthy();
    });

    it("reuse after grace fires theft and revokes ONLY the compromised family (default)", async () => {
      let reuseFired = 0;
      // accessTtl well past the clock advance so the assertion measures
      // revocation, not token expiry.
      const { auth, clock } = makeAuth({
        accessTtl: 60_000,
        refresh: {
          ttl: 600_000,
          rotation: "always",
          rotationGraceMs: 1000,
          onRotationReuse: () => {
            reuseFired++;
          },
        },
      });
      const sibling = await auth.issue("alice");
      const initial = await auth.issue("alice");
      await auth.refresh(initial.refreshToken!);
      clock.advance(2000); // beyond grace
      await expect(auth.refresh(initial.refreshToken!)).rejects.toMatchObject({
        type: "REFRESH_REUSE_DETECTED",
      });
      expect(reuseFired).toBe(1);
      // Default reuseResponse 'session' → the user's OTHER device survives.
      expect(await auth.validate(sibling.accessToken)).not.toBeNull();
    });

    it("reuseResponse 'user' escalates theft to every session", async () => {
      const { auth, clock } = makeAuth({
        accessTtl: 60_000,
        refresh: {
          ttl: 600_000,
          rotation: "always",
          rotationGraceMs: 1000,
          reuseResponse: "user",
        },
      });
      const sibling = await auth.issue("alice");
      const initial = await auth.issue("alice");
      await auth.refresh(initial.refreshToken!);
      clock.advance(2000);
      await expect(auth.refresh(initial.refreshToken!)).rejects.toMatchObject({
        type: "REFRESH_REUSE_DETECTED",
      });
      // 'user' scope revokes the sibling too.
      expect(await auth.validate(sibling.accessToken)).toBeNull();
    });

    it("grace is store-backed: holds across instances sharing one store", async () => {
      // Two AuthCredential instances (think two ECS tasks behind a load
      // balancer) sharing one store. The grace window must hold with NO
      // in-memory state on the instance that sees the replay.
      const clock = new FakeClock();
      const store = new CredentialStoreMemory<MyClaims>({ clock });
      const refresh = { ttl: 60_000, rotation: "always" as const, rotationGraceMs: 5000 };
      const instanceA = new AuthCredential<MyClaims>({ store, clock, accessTtl: 1000, refresh });
      const instanceB = new AuthCredential<MyClaims>({ store, clock, accessTtl: 1000, refresh });
      const initial = await instanceA.issue("alice");
      await instanceA.refresh(initial.refreshToken!); // A rotates
      clock.advance(10);
      // B replays the same token within grace → must succeed (B has no map entry).
      const onB = await instanceB.refresh(initial.refreshToken!);
      expect(onB.accessToken).toBeTruthy();
      // Beyond grace, B treats the same replay as theft.
      clock.advance(10_000);
      await expect(instanceB.refresh(initial.refreshToken!)).rejects.toMatchObject({
        type: "REFRESH_REUSE_DETECTED",
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

    it("an unknown token without instance config is INVALID_TOKEN (no-config redemption exists for per-mint families)", async () => {
      const { auth } = makeAuth();
      await expect(auth.refresh("anything")).rejects.toMatchObject({
        type: "INVALID_TOKEN",
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

  describe("issue: per-mint refresh (IssueOptions.refresh) + no-config redemption", () => {
    it("refresh: false suppresses the refresh mint even when the instance config exists", async () => {
      const { auth, store } = makeAuth({ refresh: { ttl: 60_000 } });
      const issued = await auth.issue("alice", { refresh: false });
      expect(issued.refreshToken).toBeUndefined();
      expect(issued.refreshExpiresAt).toBeUndefined();
      // No orphaned refresh row either.
      const rows = await store.listForUser!("alice");
      expect(rows.every((r) => r.kind !== "refresh")).toBe(true);
    });

    it("refresh: { ttl } mints WITHOUT an instance config, with the per-mint lifetime", async () => {
      const { auth, clock } = makeAuth(); // no instance refresh
      const issued = await auth.issue("alice", { refresh: { ttl: 100_000 } });
      expect(issued.refreshToken).toBeTruthy();
      expect(issued.refreshExpiresAt).toBe(clock.now() + 100_000);
    });

    it("refresh: {} falls back to the instance ttl; without one it is INVALID_CONFIG", async () => {
      const withInstance = makeAuth({ refresh: { ttl: 42_000 } });
      const issued = await withInstance.auth.issue("alice", { refresh: {} });
      expect(issued.refreshExpiresAt).toBe(withInstance.clock.now() + 42_000);

      const { auth } = makeAuth();
      await expect(auth.issue("alice", { refresh: {} })).rejects.toMatchObject({
        type: "INVALID_CONFIG",
      });
    });

    it("a per-mint family keeps its FIXED ceiling even on an instance with 'sliding' rotation (metadata.refreshRotation stamp)", async () => {
      // The demo's shape: browser sessions rotate 'sliding' on the SAME
      // AuthCredential that mints per-mint (authz) refresh families.
      const { auth, clock } = makeAuth({
        refresh: { ttl: 7 * 24 * 60 * 60_000, rotation: "sliding" },
      });
      const grant = await auth.issue("alice", { refresh: { ttl: 100_000 } });
      const ceiling = grant.refreshExpiresAt!;

      clock.advance(10_000);
      const rotated = await auth.refresh(grant.refreshToken!);
      // Fixed ceiling — NOT slid to now + the instance's 7d ttl.
      expect(rotated.refreshExpiresAt).toBe(ceiling);

      // Ordinary sessions on the same instance still slide.
      const session = await auth.issue("bob");
      clock.advance(10_000);
      const sessionRotated = await auth.refresh(session.refreshToken!);
      expect(sessionRotated.refreshExpiresAt).toBe(clock.now() + 7 * 24 * 60 * 60_000);
    });

    it("no-config redemption rotates with a FIXED family ceiling; replay after grace revokes the family", async () => {
      const { auth, clock } = makeAuth(); // no instance refresh config
      const initial = await auth.issue("alice", { refresh: { ttl: 100_000 } });
      const ceiling = initial.refreshExpiresAt!;

      clock.advance(10_000);
      const rotated = await auth.refresh(initial.refreshToken!);
      expect(rotated.refreshToken).toBeTruthy();
      expect(rotated.refreshToken).not.toBe(initial.refreshToken);
      // 'always'-style: the ceiling never slides.
      expect(rotated.refreshExpiresAt).toBe(ceiling);

      // Replay of the already-rotated token beyond the 30s default grace ⇒
      // theft response: the whole family is revoked.
      clock.advance(40_000);
      await expect(auth.refresh(initial.refreshToken!)).rejects.toMatchObject({
        type: "REFRESH_REUSE_DETECTED",
      });
      expect(await auth.validate(rotated.accessToken)).toBeNull();
      await expect(auth.refresh(rotated.refreshToken!)).rejects.toMatchObject({
        type: "INVALID_TOKEN",
      });
    });

    it("guard runs before any rotation: a throwing guard aborts with the family untouched", async () => {
      const { auth, store } = makeAuth();
      const issued = await auth.issue("alice", {
        refresh: { ttl: 100_000 },
        metadata: { authzClientId: "client-1" },
      });

      const seen: Array<{ userId: string; authzClientId?: string }> = [];
      await expect(
        auth.refresh(issued.refreshToken!, {
          guard: (state) => {
            seen.push({ userId: state.userId, authzClientId: state.metadata?.authzClientId });
            throw new Error("wrong client");
          },
        }),
      ).rejects.toThrow("wrong client");
      expect(seen).toEqual([{ userId: "alice", authzClientId: "client-1" }]);

      // Nothing rotated or consumed — the row has no rotatedAt stamp and the
      // token still redeems normally.
      const row = await store.retrieve(issued.refreshToken!);
      expect(row?.rotatedAt).toBeUndefined();
      const rotated = await auth.refresh(issued.refreshToken!, {
        guard: (state) => {
          expect(state.metadata?.authzClientId).toBe("client-1");
        },
      });
      expect(rotated.refreshToken).toBeTruthy();
    });

    it("a per-mint access ttl is stamped on the family and survives refresh (metadata.accessTtl)", async () => {
      const { auth, clock } = makeAuth({ accessTtl: 60_000 });
      const issued = await auth.issue("alice", { ttl: 5_000, refresh: { ttl: 100_000 } });
      expect(issued.accessExpiresAt).toBe(clock.now() + 5_000);

      clock.advance(1_000);
      const rotated = await auth.refresh(issued.refreshToken!);
      // The mint-time ttl, NOT the instance accessTtl.
      expect(rotated.accessExpiresAt).toBe(clock.now() + 5_000);
      const ctx = await auth.validate(rotated.accessToken);
      expect(ctx?.userId).toBe("alice");
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
