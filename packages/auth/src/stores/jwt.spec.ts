import { generateKeyPair } from "jose";
import { beforeEach, describe, expect, it } from "vite-plus/test";
import type { CredentialState } from "../credential/types";
import { AuthError } from "../errors";
import type { Clock } from "../utils/clock";
import { DenylistStoreMemory } from "./denylist-memory";
import { CredentialStoreJwt } from "./jwt";

class FakeClock implements Clock {
  constructor(public time = 1_700_000_000_000) {}
  now(): number {
    return this.time;
  }
  advance(ms: number): void {
    this.time += ms;
  }
}

interface MyClaims {
  role: "admin" | "user";
  scope: string[];
}

function makeState(
  userId: string,
  now: number,
  overrides?: Partial<CredentialState<MyClaims>>,
): CredentialState<MyClaims> {
  return {
    userId,
    issuedAt: now,
    expiresAt: now + 60_000,
    kind: "access",
    ...overrides,
  };
}

const SECRET = "this-is-a-test-secret-of-sufficient-length-1234567890";

describe("CredentialStoreJwt", () => {
  describe("HS256", () => {
    let clock: FakeClock;
    beforeEach(() => {
      clock = new FakeClock();
    });

    it("persists and retrieves state (roundtrip)", async () => {
      const store = new CredentialStoreJwt({ secret: SECRET, clock });
      const state = makeState("alice", clock.now(), {
        claims: { role: "admin", scope: ["read", "write"] },
        metadata: { ip: "1.2.3.4", userAgent: "ua" },
      });
      const token = await store.persist(state);
      expect(typeof token).toBe("string");
      // jose JWT compact form has 3 dot-separated segments.
      expect(token.split(".")).toHaveLength(3);
      const round = await store.retrieve(token);
      expect(round?.userId).toBe("alice");
      expect(round?.kind).toBe("access");
      expect(round?.claims).toEqual({ role: "admin", scope: ["read", "write"] });
      expect(round?.metadata).toEqual({ ip: "1.2.3.4", userAgent: "ua" });
      expect(round?.issuedAt).toBe(state.issuedAt);
      expect(round?.expiresAt).toBe(state.expiresAt);
    });

    it("returns null for an expired token", async () => {
      const store = new CredentialStoreJwt({ secret: SECRET, clock });
      const token = await store.persist(makeState("alice", clock.now()), 1000);
      clock.advance(2000);
      expect(await store.retrieve(token)).toBeNull();
    });

    it("returns null for a token signed with the wrong secret", async () => {
      const a = new CredentialStoreJwt({ secret: SECRET, clock });
      const b = new CredentialStoreJwt({ secret: `${SECRET}-different`, clock });
      const token = await a.persist(makeState("alice", clock.now()));
      expect(await b.retrieve(token)).toBeNull();
    });

    it("returns null for a malformed token", async () => {
      const store = new CredentialStoreJwt({ secret: SECRET, clock });
      expect(await store.retrieve("not.a.jwt")).toBeNull();
      expect(await store.retrieve("garbage")).toBeNull();
    });

    it("revokes via denylist", async () => {
      const denylist = new DenylistStoreMemory({ clock });
      const store = new CredentialStoreJwt({ secret: SECRET, denylist, clock });
      const token = await store.persist(makeState("alice", clock.now()));
      await store.revoke(token);
      expect(await store.retrieve(token)).toBeNull();
    });

    it("revoke without denylist throws STATELESS_OPERATION_UNSUPPORTED", async () => {
      const store = new CredentialStoreJwt({ secret: SECRET, clock });
      const token = await store.persist(makeState("alice", clock.now()));
      try {
        await store.revoke(token);
        expect.fail("expected throw");
      } catch (e) {
        expect(e).toBeInstanceOf(AuthError);
        expect((e as AuthError).type).toBe("STATELESS_OPERATION_UNSUPPORTED");
      }
    });

    it("update with denylist returns a new token and denies the old", async () => {
      const denylist = new DenylistStoreMemory({ clock });
      const store = new CredentialStoreJwt<MyClaims>({ secret: SECRET, denylist, clock });
      const token = await store.persist(makeState("alice", clock.now()));
      const newToken = await store.update(
        token,
        makeState("alice", clock.now(), { claims: { role: "user", scope: ["read"] } }),
      );
      expect(newToken).not.toBe(token);
      expect(await store.retrieve(token)).toBeNull();
      const fresh = await store.retrieve(newToken);
      expect(fresh?.claims?.role).toBe("user");
    });

    it("update without denylist throws", async () => {
      const store = new CredentialStoreJwt({ secret: SECRET, clock });
      const token = await store.persist(makeState("alice", clock.now()));
      try {
        await store.update(token, makeState("alice", clock.now()));
        expect.fail("expected throw");
      } catch (e) {
        expect((e as AuthError).type).toBe("STATELESS_OPERATION_UNSUPPORTED");
      }
    });

    it("revokeAllForUser bumps epoch and rejects tokens minted before it", async () => {
      const store = new CredentialStoreJwt({ secret: SECRET, clock });
      const oldToken = await store.persist(makeState("alice", clock.now()));
      // Tokens minted before the revoke must be rejected after the epoch bump.
      clock.advance(1);
      expect(await store.revokeAllForUser("alice")).toBe(1);
      expect(await store.retrieve(oldToken)).toBeNull();

      // A freshly issued token (iat >= epoch) is accepted.
      clock.advance(1);
      const newToken = await store.persist(makeState("alice", clock.now()));
      expect(await store.retrieve(newToken)).not.toBeNull();
    });

    it("accepts a token whose iatMs equals the epoch (recovery auto-login regression)", async () => {
      // Regression: recovery/invite workflows call `revokeAllForUser` and then
      // immediately mint a fresh token in the same workflow tick. A strict `>`
      // would reject the freshly issued token (`iatMs === epoch`), bouncing
      // the user back to /login. The gate is `>=` so same-ms mint-after-revoke
      // is honored; a token whose iatMs is `epoch - 1` is still rejected.
      const store = new CredentialStoreJwt({ secret: SECRET, clock });
      const stale = await store.persist(makeState("alice", clock.now() - 1));
      expect(await store.revokeAllForUser("alice")).toBe(1);
      const sameMsToken = await store.persist(makeState("alice", clock.now()));
      expect(await store.retrieve(sameMsToken)).not.toBeNull();
      expect(await store.retrieve(stale)).toBeNull();
    });

    it("revokeAllForUser is scoped per-user (other users unaffected)", async () => {
      const store = new CredentialStoreJwt({ secret: SECRET, clock });
      const aliceToken = await store.persist(makeState("alice", clock.now()));
      const bobToken = await store.persist(makeState("bob", clock.now()));
      clock.advance(1);
      await store.revokeAllForUser("alice");
      expect(await store.retrieve(aliceToken)).toBeNull();
      expect(await store.retrieve(bobToken)).not.toBeNull();
    });

    it("consume requires a denylist (otherwise throws)", async () => {
      const store = new CredentialStoreJwt({ secret: SECRET, clock });
      const token = await store.persist(makeState("alice", clock.now()));
      try {
        await store.consume(token);
        expect.fail("expected throw");
      } catch (e) {
        expect((e as AuthError).type).toBe("STATELESS_OPERATION_UNSUPPORTED");
      }
    });

    it("consume with denylist adds jti to the denylist", async () => {
      const denylist = new DenylistStoreMemory({ clock });
      const store = new CredentialStoreJwt({ secret: SECRET, denylist, clock });
      const token = await store.persist(makeState("alice", clock.now()));
      const consumed = await store.consume(token);
      expect(consumed?.userId).toBe("alice");
      // Second consume must fail since jti is denied.
      expect(await store.consume(token)).toBeNull();
      expect(await store.retrieve(token)).toBeNull();
    });

    it("honors iss/aud claims when configured", async () => {
      const store = new CredentialStoreJwt({
        secret: SECRET,
        clock,
        issuer: "aooth.test",
        audience: "api.test",
      });
      const token = await store.persist(makeState("alice", clock.now()));
      expect(await store.retrieve(token)).not.toBeNull();
    });

    it("rejects tokens with mismatched iss/aud", async () => {
      const a = new CredentialStoreJwt({
        secret: SECRET,
        clock,
        issuer: "aooth.test",
        audience: "api.test",
      });
      const b = new CredentialStoreJwt({
        secret: SECRET,
        clock,
        issuer: "different.iss",
        audience: "api.test",
      });
      const token = await a.persist(makeState("alice", clock.now()));
      expect(await b.retrieve(token)).toBeNull();
    });

    it("ttl override on persist is honored when smaller than state.expiresAt", async () => {
      const store = new CredentialStoreJwt({ secret: SECRET, clock });
      const state = makeState("alice", clock.now(), {
        expiresAt: clock.now() + 9_999_000,
      });
      const token = await store.persist(state, 1000);
      const round = await store.retrieve(token);
      // expiresAt is preserved at full ms precision via the state claim
      // (jose's `exp` is second-resolution, but we mirror full ms in `state.expMs`).
      expect(round?.expiresAt).toBe(clock.now() + 1000);
      clock.advance(1500);
      expect(await store.retrieve(token)).toBeNull();
    });

    it("preserves ms precision across persist/retrieve (no second-rounding)", async () => {
      // Pin: previously, retrieve returned `exp * 1000` which truncated to a
      // whole second and disagreed with IssueResult.accessExpiresAt by up to
      // 999ms. Now expMs is mirrored in the state claim.
      const offsetClock = new FakeClock(1_700_000_000_500);
      const store = new CredentialStoreJwt({ secret: SECRET, clock: offsetClock });
      const token = await store.persist(makeState("alice", offsetClock.now()), 60_000);
      const round = await store.retrieve(token);
      expect(round?.issuedAt).toBe(1_700_000_000_500);
      expect(round?.expiresAt).toBe(1_700_000_060_500);
    });

    it("roundtrips parentCredentialId, rotatedAt and kind", async () => {
      const store = new CredentialStoreJwt<MyClaims>({ secret: SECRET, clock });
      const state = makeState("alice", clock.now(), {
        kind: "refresh",
        parentCredentialId: "parent-123",
        rotatedAt: clock.now() - 5000,
      });
      const token = await store.persist(state);
      const round = await store.retrieve(token);
      expect(round?.kind).toBe("refresh");
      expect(round?.parentCredentialId).toBe("parent-123");
      expect(round?.rotatedAt).toBe(state.rotatedAt);
    });
  });

  describe("constructor validation", () => {
    const construct = (opts: ConstructorParameters<typeof CredentialStoreJwt>[0]) => () =>
      new CredentialStoreJwt(opts);

    it("throws INVALID_CONFIG when HS256 has no secret", () => {
      try {
        construct({})();
        expect.fail("expected throw");
      } catch (e) {
        expect(e).toBeInstanceOf(AuthError);
        expect((e as AuthError).type).toBe("INVALID_CONFIG");
      }
    });

    it("throws INVALID_CONFIG when RS256 missing keys", () => {
      try {
        construct({ algorithm: "RS256" })();
        expect.fail("expected throw");
      } catch (e) {
        expect((e as AuthError).type).toBe("INVALID_CONFIG");
      }
    });

    it("throws INVALID_CONFIG when ES256 has only privateKey", async () => {
      const { privateKey } = await generateKeyPair("ES256");
      try {
        construct({ algorithm: "ES256", privateKey })();
        expect.fail("expected throw");
      } catch (e) {
        expect((e as AuthError).type).toBe("INVALID_CONFIG");
      }
    });
  });

  describe("algorithm confusion", () => {
    it("rejects tokens signed with a different HS algorithm than configured", async () => {
      // Pin: jose's default with a Uint8Array key accepts ANY HS* algorithm.
      // The store now restricts verify to the configured `algorithm`, so a
      // token forged by an attacker who knows the secret but switches alg
      // (HS256 -> HS384/HS512) is rejected.
      const clock = new FakeClock();
      const hs256 = new CredentialStoreJwt({ algorithm: "HS256", secret: SECRET, clock });
      const hs512 = new CredentialStoreJwt({ algorithm: "HS512", secret: SECRET, clock });
      const tokenHS512 = await hs512.persist(makeState("alice", clock.now()));
      // The HS256-configured store must reject the HS512-signed token even
      // though the underlying secret is identical.
      expect(await hs256.retrieve(tokenHS512)).toBeNull();
    });
  });

  describe("HS384 / HS512", () => {
    it("HS384 persist + retrieve roundtrip", async () => {
      const clock = new FakeClock();
      const store = new CredentialStoreJwt({ algorithm: "HS384", secret: SECRET, clock });
      const token = await store.persist(makeState("alice", clock.now()));
      expect(await store.retrieve(token)).not.toBeNull();
    });

    it("HS512 persist + retrieve roundtrip", async () => {
      const clock = new FakeClock();
      const store = new CredentialStoreJwt({ algorithm: "HS512", secret: SECRET, clock });
      const token = await store.persist(makeState("alice", clock.now()));
      expect(await store.retrieve(token)).not.toBeNull();
    });
  });

  describe("RS256", () => {
    it("persist + retrieve roundtrip", async () => {
      const { privateKey, publicKey } = await generateKeyPair("RS256");
      const clock = new FakeClock();
      const store = new CredentialStoreJwt<MyClaims>({
        algorithm: "RS256",
        privateKey,
        publicKey,
        clock,
      });
      const token = await store.persist(
        makeState("alice", clock.now(), { claims: { role: "admin", scope: [] } }),
      );
      const round = await store.retrieve(token);
      expect(round?.userId).toBe("alice");
      expect(round?.claims?.role).toBe("admin");
    });
  });

  describe("ES256", () => {
    it("persist + retrieve roundtrip", async () => {
      const { privateKey, publicKey } = await generateKeyPair("ES256");
      const clock = new FakeClock();
      const store = new CredentialStoreJwt({
        algorithm: "ES256",
        privateKey,
        publicKey,
        clock,
      });
      const token = await store.persist(makeState("alice", clock.now()));
      const round = await store.retrieve(token);
      expect(round?.userId).toBe("alice");
    });
  });

  describe("EdDSA", () => {
    it("persist + retrieve roundtrip", async () => {
      const { privateKey, publicKey } = await generateKeyPair("EdDSA");
      const clock = new FakeClock();
      const store = new CredentialStoreJwt({
        algorithm: "EdDSA",
        privateKey,
        publicKey,
        clock,
      });
      const token = await store.persist(makeState("alice", clock.now()));
      const round = await store.retrieve(token);
      expect(round?.userId).toBe("alice");
    });
  });
});
