import { describe, expect, it } from "vite-plus/test";

import type { Clock } from "../utils/clock";
import { DynamicClientStoreMemory, type NewDynamicClient } from "./dynamic-client-store";

function fakeClock(start = 1_000_000): Clock & { advance: (ms: number) => void } {
  let now = start;
  return {
    now: () => now,
    advance: (ms: number) => {
      now += ms;
    },
  };
}

const REC: NewDynamicClient = {
  clientName: "Test Connector",
  redirectUris: ["https://connector.example/cb"],
  tokenEndpointAuthMethod: "none",
  grantTypes: ["authorization_code"],
  responseTypes: ["code"],
  scope: "read",
};

describe("DynamicClientStoreMemory", () => {
  it("create mints a clientId and stamps createdAt; get round-trips the record", async () => {
    const clock = fakeClock();
    const store = new DynamicClientStoreMemory({ clock });
    const created = await store.create(REC);
    expect(created.clientId).toBeTruthy();
    expect(created.createdAt).toBe(clock.now());
    expect(created.lastUsedAt).toBeUndefined();
    const read = await store.get(created.clientId);
    expect(read).toEqual(created);
  });

  it("get isolates callers (mutating a read row does not affect the store)", async () => {
    const store = new DynamicClientStoreMemory();
    const { clientId } = await store.create(REC);
    const read = (await store.get(clientId))!;
    read.redirectUris.push("https://evil.example/cb");
    expect((await store.get(clientId))!.redirectUris).toEqual(REC.redirectUris);
  });

  it("get returns null for an unknown id; delete reports whether a row was removed", async () => {
    const store = new DynamicClientStoreMemory();
    expect(await store.get("nope")).toBeNull();
    const { clientId } = await store.create(REC);
    expect(await store.delete(clientId)).toBe(true);
    expect(await store.delete(clientId)).toBe(false);
    expect(await store.get(clientId)).toBeNull();
  });

  it("count reflects the number of stored registrations", async () => {
    const store = new DynamicClientStoreMemory();
    expect(await store.count()).toBe(0);
    await store.create(REC);
    await store.create(REC);
    expect(await store.count()).toBe(2);
  });

  it("touch stamps lastUsedAt; deleteUnusedBefore removes only never-used rows older than the cutoff", async () => {
    const clock = fakeClock();
    const store = new DynamicClientStoreMemory({ clock });
    const used = await store.create(REC); // old but used → kept
    const stale = await store.create(REC); // old and never used → GC'd
    clock.advance(10_000);
    await store.touch(used.clientId, clock.now());
    expect((await store.get(used.clientId))!.lastUsedAt).toBe(clock.now());
    clock.advance(10_000);
    const fresh = await store.create(REC); // young and never used → kept
    const removed = await store.deleteUnusedBefore(clock.now() - 5_000);
    expect(removed).toBe(1);
    expect(await store.get(stale.clientId)).toBeNull();
    expect(await store.get(used.clientId)).not.toBeNull();
    expect(await store.get(fresh.clientId)).not.toBeNull();
  });
});
