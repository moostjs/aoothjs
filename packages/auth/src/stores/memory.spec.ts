import { describe, expect, it } from "vite-plus/test";
import type { CredentialState } from "../credential/types";
import { type Clock, CredentialStoreMemory } from "./memory";

class FakeClock implements Clock {
  constructor(public time = 1_000_000) {}
  now(): number {
    return this.time;
  }
  advance(ms: number): void {
    this.time += ms;
  }
}

function makeState(userId: string, overrides?: Partial<CredentialState>): CredentialState {
  return {
    userId,
    issuedAt: Date.now(),
    expiresAt: Date.now() + 60_000,
    kind: "access",
    ...overrides,
  };
}

describe("CredentialStoreMemory", () => {
  describe("persist + retrieve", () => {
    it("stores state and returns a UUID token", async () => {
      const store = new CredentialStoreMemory();
      const token = await store.persist(makeState("alice"));
      expect(token).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i);
      const state = await store.retrieve(token);
      expect(state?.userId).toBe("alice");
    });

    it("returns null for unknown token", async () => {
      const store = new CredentialStoreMemory();
      expect(await store.retrieve("nope")).toBeNull();
    });

    it("uses ttl override to compute expiresAt", async () => {
      const clock = new FakeClock(1000);
      const store = new CredentialStoreMemory({ clock });
      const token = await store.persist(makeState("alice", { expiresAt: 9_999_999 }), 500);
      const state = await store.retrieve(token);
      expect(state?.expiresAt).toBe(1500);
    });

    it("returns null and removes entry once expired", async () => {
      const clock = new FakeClock(1000);
      const store = new CredentialStoreMemory({ clock });
      const token = await store.persist(makeState("alice"), 100);
      clock.advance(101);
      expect(await store.retrieve(token)).toBeNull();
      // Subsequent retrieval still null (already cleaned up).
      expect(await store.retrieve(token)).toBeNull();
    });

    it("returns a clone, not a live reference", async () => {
      const store = new CredentialStoreMemory();
      const token = await store.persist(makeState("alice"));
      const a = await store.retrieve(token);
      const b = await store.retrieve(token);
      expect(a).not.toBe(b);
      expect(a).toEqual(b);
    });
  });

  describe("consume", () => {
    it("returns state and removes the token in one call", async () => {
      const store = new CredentialStoreMemory();
      const token = await store.persist(makeState("alice"));
      const consumed = await store.consume(token);
      expect(consumed?.userId).toBe("alice");
      expect(await store.retrieve(token)).toBeNull();
    });

    it("returns null if token not found", async () => {
      const store = new CredentialStoreMemory();
      expect(await store.consume("nope")).toBeNull();
    });
  });

  describe("update", () => {
    it("updates state in place and keeps the same token", async () => {
      const store = new CredentialStoreMemory();
      const token = await store.persist(makeState("alice"));
      const updated = await store.update(token, makeState("alice", { rotatedAt: 5 }));
      expect(updated).toBe(token);
      const state = await store.retrieve(token);
      expect(state?.rotatedAt).toBe(5);
    });

    it("re-indexes when userId changes", async () => {
      const store = new CredentialStoreMemory();
      const token = await store.persist(makeState("alice"));
      await store.update(token, makeState("bob"));
      expect(await store.listForUser("alice")).toHaveLength(0);
      expect(await store.listForUser("bob")).toHaveLength(1);
    });

    it("is a no-op for unknown tokens (does not resurrect revoked entries)", async () => {
      const store = new CredentialStoreMemory();
      const returned = await store.update("does-not-exist", makeState("alice"));
      expect(returned).toBe("does-not-exist");
      expect(await store.retrieve("does-not-exist")).toBeNull();
      expect(await store.listForUser("alice")).toHaveLength(0);
    });
  });

  describe("revoke", () => {
    it("removes a token and updates the user index", async () => {
      const store = new CredentialStoreMemory();
      const token = await store.persist(makeState("alice"));
      await store.revoke(token);
      expect(await store.retrieve(token)).toBeNull();
      expect(await store.listForUser("alice")).toHaveLength(0);
    });

    it("is a no-op for unknown tokens", async () => {
      const store = new CredentialStoreMemory();
      await expect(store.revoke("nope")).resolves.toBeUndefined();
    });
  });

  describe("revokeAllForUser", () => {
    it("removes every token for a user and returns count", async () => {
      const store = new CredentialStoreMemory();
      await store.persist(makeState("alice"));
      await store.persist(makeState("alice"));
      await store.persist(makeState("bob"));
      const count = await store.revokeAllForUser("alice");
      expect(count).toBe(2);
      expect(await store.listForUser("alice")).toHaveLength(0);
      expect(await store.listForUser("bob")).toHaveLength(1);
    });

    it("returns 0 if user has nothing", async () => {
      const store = new CredentialStoreMemory();
      expect(await store.revokeAllForUser("nobody")).toBe(0);
    });
  });

  describe("listForUser", () => {
    it("returns active entries with their tokens", async () => {
      const store = new CredentialStoreMemory();
      const t1 = await store.persist(makeState("alice", { issuedAt: 1 }));
      const t2 = await store.persist(makeState("alice", { issuedAt: 2 }));
      const list = await store.listForUser("alice");
      expect(list.map((e) => e.token).toSorted()).toEqual([t1, t2].toSorted());
    });

    it("filters out expired entries", async () => {
      const clock = new FakeClock(1000);
      const store = new CredentialStoreMemory({ clock });
      await store.persist(makeState("alice"), 100);
      const persistent = await store.persist(makeState("alice"), 10_000);
      clock.advance(101);
      const list = await store.listForUser("alice");
      expect(list).toHaveLength(1);
      expect(list[0].token).toBe(persistent);
    });
  });
});
