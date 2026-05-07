import { describe, expect, it } from "vite-plus/test";
import { type Clock, DenylistStoreMemory } from "./denylist-memory";

class FakeClock implements Clock {
  constructor(public time = 1000) {}
  now(): number {
    return this.time;
  }
  advance(ms: number): void {
    this.time += ms;
  }
}

describe("DenylistStoreMemory", () => {
  it("returns false for unknown jti", async () => {
    const list = new DenylistStoreMemory();
    expect(await list.has("nope")).toBe(false);
  });

  it("returns true for added, unexpired jti", async () => {
    const clock = new FakeClock(1000);
    const list = new DenylistStoreMemory({ clock });
    await list.add("abc", 5000);
    expect(await list.has("abc")).toBe(true);
  });

  it("returns false for expired jti and removes it lazily", async () => {
    const clock = new FakeClock(1000);
    const list = new DenylistStoreMemory({ clock });
    await list.add("abc", 1500);
    clock.advance(600);
    expect(await list.has("abc")).toBe(false);
    // Calling again still returns false; entry was deleted.
    expect(await list.has("abc")).toBe(false);
  });

  it("cleanup removes only expired entries", async () => {
    const clock = new FakeClock(1000);
    const list = new DenylistStoreMemory({ clock });
    await list.add("a", 1500);
    await list.add("b", 5000);
    await list.add("c", 1200);
    clock.advance(600); // now=1600 — a (1500) and c (1200) expired.
    const removed = await list.cleanup();
    expect(removed).toBe(2);
    expect(await list.has("a")).toBe(false);
    expect(await list.has("b")).toBe(true);
    expect(await list.has("c")).toBe(false);
  });

  it("re-adding overwrites the expiry", async () => {
    const clock = new FakeClock(1000);
    const list = new DenylistStoreMemory({ clock });
    await list.add("abc", 1100);
    await list.add("abc", 5000);
    clock.advance(200);
    expect(await list.has("abc")).toBe(true);
  });
});
