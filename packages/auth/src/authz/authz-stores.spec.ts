import { describe, expect, it } from "vite-plus/test";

import { AuthCodeStoreMemory } from "./auth-code-store";
import { PendingAuthorizationStoreMemory } from "./pending-authorization-store";

class FakeClock {
  constructor(public t = 1_000_000) {}
  now = (): number => this.t;
  advance(ms: number): void {
    this.t += ms;
  }
}

describe("PendingAuthorizationStoreMemory", () => {
  it("creates, fetches by handle, and deletes", async () => {
    const store = new PendingAuthorizationStoreMemory();
    const { handle, expiresAt } = await store.create({
      redirectUri: "http://127.0.0.1:5000/cb",
      codeChallenge: "chal",
      clientState: "cs",
      tokenPolicy: { kind: "cli-session", ttl: 1000 },
      binding: "bind-secret",
    });
    const row = await store.get(handle);
    expect(row?.redirectUri).toBe("http://127.0.0.1:5000/cb");
    expect(row?.clientState).toBe("cs");
    expect(row?.tokenPolicy).toEqual({ kind: "cli-session", ttl: 1000 });
    expect(row?.binding).toBe("bind-secret");
    // create() surfaces the row's expiry so the caller can size the binding cookie.
    expect(expiresAt).toBe(row?.expiresAt);

    expect(await store.delete(handle)).toBe(true);
    expect(await store.get(handle)).toBeNull();
  });

  it("expires after the ttl", async () => {
    const clock = new FakeClock();
    const store = new PendingAuthorizationStoreMemory({ clock, ttlMs: 1000 });
    const { handle } = await store.create({
      redirectUri: "http://127.0.0.1:5000/cb",
      codeChallenge: "c",
      tokenPolicy: {},
      binding: "b",
    });
    clock.advance(1001);
    expect(await store.get(handle)).toBeNull();
  });

  it("isolates callers from later mutation of the returned row", async () => {
    const store = new PendingAuthorizationStoreMemory();
    const { handle } = await store.create({
      redirectUri: "http://127.0.0.1/cb",
      codeChallenge: "c",
      tokenPolicy: { payload: { tenant: "t1" } },
      binding: "b",
    });
    const a = await store.get(handle);
    (a as { tokenPolicy: { payload?: Record<string, unknown> } }).tokenPolicy.payload!.tenant = "x";
    const b = await store.get(handle);
    expect(b?.tokenPolicy.payload).toEqual({ tenant: "t1" });
  });
});

describe("AuthCodeStoreMemory", () => {
  it("mints and consumes a code once (single-use)", async () => {
    const store = new AuthCodeStoreMemory();
    const { code } = await store.mint({
      userId: "u-1",
      codeChallenge: "chal",
      redirectUri: "http://127.0.0.1:5000/cb",
      tokenPolicy: { kind: "cli-session" },
    });
    const first = await store.consume(code);
    expect(first?.userId).toBe("u-1");
    expect(first?.codeChallenge).toBe("chal");
    // Reuse / back-button replay → miss.
    expect(await store.consume(code)).toBeNull();
  });

  it("a concurrent double-redeem yields the code to exactly one caller", async () => {
    const store = new AuthCodeStoreMemory();
    const { code } = await store.mint({
      userId: "u-1",
      codeChallenge: "c",
      redirectUri: "http://127.0.0.1/cb",
      tokenPolicy: {},
    });
    const [a, b] = await Promise.all([store.consume(code), store.consume(code)]);
    expect([a, b].filter(Boolean)).toHaveLength(1);
  });

  it("an expired code consumes to null", async () => {
    const clock = new FakeClock();
    const store = new AuthCodeStoreMemory({ clock, ttlMs: 60_000 });
    const { code } = await store.mint({
      userId: "u-1",
      codeChallenge: "c",
      redirectUri: "http://127.0.0.1/cb",
      tokenPolicy: {},
    });
    clock.advance(60_001);
    expect(await store.consume(code)).toBeNull();
  });
});
