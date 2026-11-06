import { describe, expect, it } from "vite-plus/test";

import { BoundedWfStateStoreMemory } from "../wf-trigger/provider";

// WHY (M2): every magic-link request — for any identifier — persists a pause;
// the default in-memory store must not grow without bound.
describe("the default magic-link store", () => {
  it("keeps at most maxEntries links, dropping the oldest first", async () => {
    const store = new BoundedWfStateStoreMemory(3);
    const state = { schemaId: "s", context: {}, indexes: [] } as never;
    for (const key of ["a", "b", "c", "d"]) await store.set(key, state);
    expect(await store.get("a")).toBeNull();
    for (const key of ["b", "c", "d"]) expect(await store.get(key)).not.toBeNull();
    // a used (consumed) link frees its slot
    await store.getAndDelete("b");
    await store.set("e", state);
    expect(await store.get("c")).not.toBeNull();
    expect(await store.get("e")).not.toBeNull();
  });
});
