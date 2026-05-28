import { describe, expect, it } from "vite-plus/test";

import { ConsentStore } from "../consent.store";

describe("ConsentStore — no-op defaults (Phase 1 plumbing only)", () => {
  it("getPendingConsents returns empty array (no prompts when not overridden)", async () => {
    const store = new ConsentStore();
    const result = await store.getPendingConsents("alice");
    expect(result).toEqual([]);
  });

  it("getPendingConsents accepts undefined username (pre-bind carrier forms)", async () => {
    const store = new ConsentStore();
    const result = await store.getPendingConsents(undefined);
    expect(result).toEqual([]);
  });

  it("save resolves without throwing on no-op default", async () => {
    // WHY: the new `ConsentEvent` shape is `{ id, accepted, version?, at }`.
    // A regression that mistyped any field (kind/optIn left over from
    // pre-Phase-5) would surface as a TS error here — load-bearing
    // structural pin alongside the runtime no-op assertion.
    const store = new ConsentStore();
    await expect(
      store.save("alice", [{ id: "terms", accepted: true, version: "v1", at: Date.now() }]),
    ).resolves.toBeUndefined();
  });

  it("read returns empty array (no history when not overridden)", async () => {
    const store = new ConsentStore();
    const result = await store.read("alice");
    expect(result).toEqual([]);
    // Filter param is `{ id?: string }` post-Phase-5 (was `{ name?: string }`).
    const filtered = await store.read("alice", { id: "terms" });
    expect(filtered).toEqual([]);
  });

  it("recordOtpChannelConsent resolves without throwing on no-op default", async () => {
    const store = new ConsentStore();
    await expect(
      store.recordOtpChannelConsent(
        "alice",
        "email",
        "alice@example.com",
        "By providing your email...",
      ),
    ).resolves.toBeUndefined();
  });
});
