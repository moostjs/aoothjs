/**
 * Unit tests for `DeviceTrustStoreMemory` — the in-process trust-record store
 * backing the "remember this device, skip MFA next time" Phase 4 feature.
 *
 * These tests prove the security invariants the workflow relies on:
 *   - HMAC verification rejects tampered cookies (no second-store lookup).
 *   - `cookie+ip` binding actually compares IPs.
 *   - Expired records are rejected even when the HMAC is otherwise valid.
 *   - `revoke()` removes the record permanently.
 *
 * Without these the workflow's `check-trusted-device` step would let any
 * attacker who steals a cookie skip MFA forever.
 */
import { describe, expect, it } from "vite-plus/test";

import { DeviceTrustStoreMemory } from "../device-trust/index";

describe("DeviceTrustStoreMemory", () => {
  it("constructor throws when secret is empty (fail-loud)", () => {
    expect(() => new DeviceTrustStoreMemory("")).toThrow(/secret is required/);
  });

  it("issue() returns a record whose cookie value is `<token>.<sig>`", () => {
    const store = new DeviceTrustStoreMemory("test-secret");
    const rec = store.issue("alice", undefined, 60_000);
    // token shape: 64-hex (32 bytes) + '.' + 64-hex sha256
    expect(rec.token.includes(".")).toBe(true);
    const [raw, sig] = rec.token.split(".");
    expect(raw).toMatch(/^[a-f0-9]{64}$/);
    expect(sig).toMatch(/^[a-f0-9]{64}$/);
    expect(rec.userId).toBe("alice");
    expect(rec.expiresAt - rec.issuedAt).toBe(60_000);
  });

  it("verify() accepts a freshly issued record for the same user", async () => {
    const store = new DeviceTrustStoreMemory("test-secret");
    const rec = store.issue("alice", undefined, 60_000);
    await store.add(rec);
    expect(await store.verify("alice", rec.token)).toBe(true);
  });

  it("verify() rejects records bound to a different user (HMAC mismatch)", async () => {
    const store = new DeviceTrustStoreMemory("test-secret");
    const rec = store.issue("alice", undefined, 60_000);
    await store.add(rec);
    // The cookie was signed with `alice|<raw>|` payload; calling verify with
    // a different userId rebuilds payload `bob|<raw>|` → different HMAC → reject.
    expect(await store.verify("bob", rec.token)).toBe(false);
  });

  it("verify() rejects tampered cookies (signature mismatch)", async () => {
    const store = new DeviceTrustStoreMemory("test-secret");
    const rec = store.issue("alice", undefined, 60_000);
    await store.add(rec);
    const [raw] = rec.token.split(".");
    // Forge a cookie with a junk signature.
    const fake = `${raw}.${"0".repeat(64)}`;
    expect(await store.verify("alice", fake)).toBe(false);
  });

  it("verify() rejects cookies that were never persisted (no record in store)", async () => {
    const store = new DeviceTrustStoreMemory("test-secret");
    const rec = store.issue("alice", undefined, 60_000);
    // NB: NOT calling store.add(rec) — signature would verify but no record exists.
    expect(await store.verify("alice", rec.token)).toBe(false);
  });

  it("verify() with cookie+ip binding rejects when IP differs", async () => {
    const store = new DeviceTrustStoreMemory("test-secret");
    const rec = store.issue("alice", "10.0.0.1", 60_000);
    await store.add(rec);
    // Same cookie, different IP → reject.
    expect(await store.verify("alice", rec.token, "10.0.0.2")).toBe(false);
    // Same cookie, same IP → accept.
    expect(await store.verify("alice", rec.token, "10.0.0.1")).toBe(true);
  });

  it("verify() rejects records past expiresAt even with valid HMAC", async () => {
    const store = new DeviceTrustStoreMemory("test-secret");
    // Issue with negative TTL so the record is born expired.
    const rec = store.issue("alice", undefined, -1);
    await store.add(rec);
    expect(await store.verify("alice", rec.token)).toBe(false);
  });

  it("revoke() makes a previously valid cookie unusable", async () => {
    const store = new DeviceTrustStoreMemory("test-secret");
    const rec = store.issue("alice", undefined, 60_000);
    await store.add(rec);
    expect(await store.verify("alice", rec.token)).toBe(true);
    await store.revoke("alice", rec.token);
    expect(await store.verify("alice", rec.token)).toBe(false);
  });

  it("revoke() is a no-op when the record does not exist (does not throw)", async () => {
    const store = new DeviceTrustStoreMemory("test-secret");
    await expect(store.revoke("ghost", "nope.sig")).resolves.toBeUndefined();
  });

  it("two records for the same user are stored independently (revoke one keeps other)", async () => {
    const store = new DeviceTrustStoreMemory("test-secret");
    const r1 = store.issue("alice", undefined, 60_000);
    const r2 = store.issue("alice", undefined, 60_000);
    await store.add(r1);
    await store.add(r2);
    await store.revoke("alice", r1.token);
    expect(await store.verify("alice", r1.token)).toBe(false);
    expect(await store.verify("alice", r2.token)).toBe(true);
  });

  it("verify() returns false when token has no separator (malformed)", async () => {
    const store = new DeviceTrustStoreMemory("test-secret");
    expect(await store.verify("alice", "not-a-valid-cookie")).toBe(false);
  });

  it("HMAC depends on the secret — same userId+token verified by a different store is rejected", async () => {
    const storeA = new DeviceTrustStoreMemory("secret-A");
    const storeB = new DeviceTrustStoreMemory("secret-B");
    const rec = storeA.issue("alice", undefined, 60_000);
    await storeB.add(rec);
    // storeB has the record but a different signing key → reject.
    expect(await storeB.verify("alice", rec.token)).toBe(false);
  });
});
