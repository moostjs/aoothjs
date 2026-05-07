import { beforeEach, describe, expect, it } from "vite-plus/test";
import type { CredentialState } from "../credential/types";
import { AuthError } from "../errors";
import type { Clock } from "../utils/clock";
import { DenylistStoreMemory } from "./denylist-memory";
import { CredentialStoreEncapsulated } from "./encapsulated";

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
  tenant: string;
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

const SECRET = "encapsulated-test-secret-1234567890abcdef";

describe("CredentialStoreEncapsulated", () => {
  let clock: FakeClock;
  beforeEach(() => {
    clock = new FakeClock();
  });

  it("persists and retrieves state (claims + metadata roundtrip)", async () => {
    const store = new CredentialStoreEncapsulated<MyClaims>({ secret: SECRET, clock });
    const state = makeState("alice", clock.now(), {
      claims: { role: "admin", tenant: "acme" },
      metadata: { ip: "10.0.0.1", userAgent: "test" },
    });
    const token = await store.persist(state);
    const round = await store.retrieve(token);
    expect(round?.userId).toBe("alice");
    expect(round?.claims).toEqual({ role: "admin", tenant: "acme" });
    expect(round?.metadata).toEqual({ ip: "10.0.0.1", userAgent: "test" });
    expect(round?.issuedAt).toBe(state.issuedAt);
    expect(round?.expiresAt).toBe(state.expiresAt);
  });

  it("does NOT expose internal jti to callers", async () => {
    const store = new CredentialStoreEncapsulated({ secret: SECRET, clock });
    const token = await store.persist(makeState("alice", clock.now()));
    const round = await store.retrieve(token);
    expect(round && "jti" in round).toBe(false);
  });

  it("returns null for tampered ciphertext", async () => {
    const store = new CredentialStoreEncapsulated({ secret: SECRET, clock });
    const token = await store.persist(makeState("alice", clock.now()));
    const blob = Buffer.from(token, "base64url");
    // Flip a byte deep in the ciphertext (not the IV/tag).
    blob[blob.length - 25] ^= 0x55;
    const tampered = blob.toString("base64url");
    expect(await store.retrieve(tampered)).toBeNull();
  });

  it("returns null for tampered authTag", async () => {
    const store = new CredentialStoreEncapsulated({ secret: SECRET, clock });
    const token = await store.persist(makeState("alice", clock.now()));
    const blob = Buffer.from(token, "base64url");
    blob[blob.length - 1] ^= 0xff;
    const tampered = blob.toString("base64url");
    expect(await store.retrieve(tampered)).toBeNull();
  });

  it("returns null for a truncated token", async () => {
    const store = new CredentialStoreEncapsulated({ secret: SECRET, clock });
    const token = await store.persist(makeState("alice", clock.now()));
    const truncated = Buffer.from(token, "base64url").subarray(0, 8).toString("base64url");
    expect(await store.retrieve(truncated)).toBeNull();
    expect(await store.retrieve("")).toBeNull();
    expect(await store.retrieve("garbage!!!not-base64url")).toBeNull();
  });

  it("returns null when the wrong key is used", async () => {
    const a = new CredentialStoreEncapsulated({ secret: SECRET, clock });
    const b = new CredentialStoreEncapsulated({ secret: `${SECRET}-other`, clock });
    const token = await a.persist(makeState("alice", clock.now()));
    expect(await b.retrieve(token)).toBeNull();
  });

  it("returns null when the state has expired", async () => {
    const store = new CredentialStoreEncapsulated({ secret: SECRET, clock });
    const token = await store.persist(makeState("alice", clock.now()), 1000);
    clock.advance(1500);
    expect(await store.retrieve(token)).toBeNull();
  });

  it("ttl override on persist is honored", async () => {
    const store = new CredentialStoreEncapsulated({ secret: SECRET, clock });
    const state = makeState("alice", clock.now(), { expiresAt: clock.now() + 9_999_000 });
    const token = await store.persist(state, 500);
    const round = await store.retrieve(token);
    expect(round?.expiresAt).toBe(clock.now() + 500);
    clock.advance(600);
    expect(await store.retrieve(token)).toBeNull();
  });

  it("revoke + retrieve via denylist", async () => {
    const denylist = new DenylistStoreMemory({ clock });
    const store = new CredentialStoreEncapsulated({ secret: SECRET, denylist, clock });
    const token = await store.persist(makeState("alice", clock.now()));
    await store.revoke(token);
    expect(await store.retrieve(token)).toBeNull();
  });

  it("consume with denylist denies subsequent retrieval", async () => {
    const denylist = new DenylistStoreMemory({ clock });
    const store = new CredentialStoreEncapsulated({ secret: SECRET, denylist, clock });
    const token = await store.persist(makeState("alice", clock.now()));
    const consumed = await store.consume(token);
    expect(consumed?.userId).toBe("alice");
    expect(await store.consume(token)).toBeNull();
    expect(await store.retrieve(token)).toBeNull();
  });

  it("revoke without denylist throws STATELESS_OPERATION_UNSUPPORTED", async () => {
    const store = new CredentialStoreEncapsulated({ secret: SECRET, clock });
    const token = await store.persist(makeState("alice", clock.now()));
    try {
      await store.revoke(token);
      expect.fail("expected throw");
    } catch (e) {
      expect((e as AuthError).type).toBe("STATELESS_OPERATION_UNSUPPORTED");
    }
  });

  it("update with denylist returns a new token and denies the old", async () => {
    const denylist = new DenylistStoreMemory({ clock });
    const store = new CredentialStoreEncapsulated<MyClaims>({
      secret: SECRET,
      denylist,
      clock,
    });
    const token = await store.persist(
      makeState("alice", clock.now(), { claims: { role: "user", tenant: "acme" } }),
    );
    const newToken = await store.update(
      token,
      makeState("alice", clock.now(), { claims: { role: "admin", tenant: "acme" } }),
    );
    expect(newToken).not.toBe(token);
    expect(await store.retrieve(token)).toBeNull();
    const fresh = await store.retrieve(newToken);
    expect(fresh?.claims?.role).toBe("admin");
  });

  it("update without denylist throws", async () => {
    const store = new CredentialStoreEncapsulated({ secret: SECRET, clock });
    const token = await store.persist(makeState("alice", clock.now()));
    try {
      await store.update(token, makeState("alice", clock.now()));
      expect.fail("expected throw");
    } catch (e) {
      expect((e as AuthError).type).toBe("STATELESS_OPERATION_UNSUPPORTED");
    }
  });

  it("revokeAllForUser is a best-effort no-op (returns 0)", async () => {
    const store = new CredentialStoreEncapsulated({ secret: SECRET, clock });
    // Stateless cannot enumerate; orchestrator's theft-response relies on
    // this returning rather than throwing so the caller still sees the
    // intended REFRESH_REUSE_DETECTED error.
    expect(await store.revokeAllForUser("alice")).toBe(0);
  });

  it("derives different keys for different short string secrets", async () => {
    const a = new CredentialStoreEncapsulated({ secret: "short-a", clock });
    const b = new CredentialStoreEncapsulated({ secret: "short-b", clock });
    const tokenA = await a.persist(makeState("alice", clock.now()));
    expect(await b.retrieve(tokenA)).toBeNull();
    expect(await a.retrieve(tokenA)).not.toBeNull();
  });

  it("supports a 32-byte Buffer secret directly", async () => {
    const raw = Buffer.alloc(32, 0xab);
    const store = new CredentialStoreEncapsulated({ secret: raw, clock });
    const token = await store.persist(makeState("alice", clock.now()));
    expect(await store.retrieve(token)).not.toBeNull();
  });

  it("roundtrips kind, parentCredentialId, rotatedAt", async () => {
    const store = new CredentialStoreEncapsulated<MyClaims>({ secret: SECRET, clock });
    const token = await store.persist(
      makeState("alice", clock.now(), {
        kind: "refresh",
        parentCredentialId: "p-1",
        rotatedAt: clock.now() - 1000,
      }),
    );
    const round = await store.retrieve(token);
    expect(round?.kind).toBe("refresh");
    expect(round?.parentCredentialId).toBe("p-1");
    expect(round?.rotatedAt).toBe(clock.now() - 1000);
  });

  it("roundtrips with strongly typed claims", async () => {
    const store = new CredentialStoreEncapsulated<MyClaims>({ secret: SECRET, clock });
    const token = await store.persist(
      makeState("alice", clock.now(), { claims: { role: "admin", tenant: "acme" } }),
    );
    const round = await store.retrieve(token);
    const role: "admin" | "user" | undefined = round?.claims?.role;
    expect(role).toBe("admin");
    expect(round?.claims?.tenant).toBe("acme");
  });

  it("constructor throws INVALID_CONFIG with no secret", () => {
    const construct = () =>
      // biome-ignore lint/suspicious/noExplicitAny: deliberate misuse
      new CredentialStoreEncapsulated({} as any);
    try {
      construct();
      expect.fail("expected throw");
    } catch (e) {
      expect((e as AuthError).type).toBe("INVALID_CONFIG");
    }
  });
});
