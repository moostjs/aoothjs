import { describe, expect, it } from "vite-plus/test";

import { OAuthFlowStoreMemory } from "../oauth/oauth-flow-store";

function makeClock(start = 1_000_000) {
  let now = start;
  return { clock: { now: () => now }, advance: (ms: number) => (now += ms) };
}

const TXN = { provider: "google", verifier: "v-1", nonce: "n-1", redirect: "/app" } as const;

describe("OAuthFlowStoreMemory", () => {
  it("round-trips a stored transaction", async () => {
    const store = new OAuthFlowStoreMemory();
    await store.put("rnd-1", { ...TXN });
    const got = await store.take("rnd-1");
    expect(got).toMatchObject({
      provider: "google",
      verifier: "v-1",
      nonce: "n-1",
      redirect: "/app",
    });
    expect(typeof got?.expiresAt).toBe("number");
  });

  it("is single-use — a second take returns null (replay defense)", async () => {
    const store = new OAuthFlowStoreMemory();
    await store.put("rnd-1", { ...TXN });
    expect(await store.take("rnd-1")).not.toBeNull();
    expect(await store.take("rnd-1")).toBeNull();
  });

  it("returns null for an unknown key", async () => {
    const store = new OAuthFlowStoreMemory();
    expect(await store.take("nope")).toBeNull();
  });

  it("carries the /link userId binding through", async () => {
    const store = new OAuthFlowStoreMemory();
    await store.put("rnd-1", { ...TXN, userId: "user-7" });
    expect((await store.take("rnd-1"))?.userId).toBe("user-7");
  });

  it("expires a transaction past its TTL and drops the key", async () => {
    const { clock, advance } = makeClock();
    const store = new OAuthFlowStoreMemory({ clock, ttlMs: 600_000 });
    await store.put("rnd-1", { ...TXN });
    advance(600_001);
    // Expired → null, even though the key existed (lazy expiry).
    expect(await store.take("rnd-1")).toBeNull();
    // And it was removed, so a second take is also null (no resurrection).
    expect(await store.take("rnd-1")).toBeNull();
  });

  it("honors a transaction within its TTL window", async () => {
    const { clock, advance } = makeClock();
    const store = new OAuthFlowStoreMemory({ clock, ttlMs: 600_000 });
    await store.put("rnd-1", { ...TXN });
    advance(599_999);
    expect(await store.take("rnd-1")).not.toBeNull();
  });

  it("overwrites a prior entry for the same random", async () => {
    const store = new OAuthFlowStoreMemory();
    await store.put("rnd-1", { ...TXN, verifier: "old" });
    await store.put("rnd-1", { ...TXN, verifier: "new" });
    expect((await store.take("rnd-1"))?.verifier).toBe("new");
  });
});
