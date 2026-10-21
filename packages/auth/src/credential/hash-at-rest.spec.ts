import { createHash } from "node:crypto";

import { describe, expect, it } from "vite-plus/test";

import { fakeClock } from "../__test__/fake-clock";
import { MockTable } from "../atscript-db/__test__/mock-table";
import { CredentialStoreAtscriptDb } from "../atscript-db/index";
import { AuthError } from "../errors";
import { MockRedis } from "../redis/__test__/mock-redis";
import { CredentialStoreRedis } from "../redis/index";
import type { CredentialStore } from "../stores/store";
import { CredentialStoreJwt } from "../stores/jwt";
import { CredentialStoreMemory } from "../stores/memory";
import { AuthCredential } from "./auth-credential";
import type { CredentialState } from "./types";

// S6 (W10): a store read must not yield a usable token.

const sha256 = (v: string) => createHash("sha256").update(v).digest("hex");

/** Memory store that exposes its rows (key → state) for at-rest assertions. */
class InspectableStore extends CredentialStoreMemory {
  async rows(userId: string): Promise<Array<CredentialState & { token: string }>> {
    return this.listForUser(userId);
  }
}

function setup(hashAtRest: boolean | "migrate" = true, store = new InspectableStore()) {
  const clock = fakeClock();
  const auth = new AuthCredential({
    store,
    accessTtl: 60_000,
    refresh: { ttl: 600_000, rotation: "always", rotationGraceMs: 30_000 },
    tokens: { hashAtRest },
    clock,
  });
  return { auth, store, clock };
}

describe("tokens.hashAtRest", () => {
  it("stores only token hashes — no row key or field equals a live token", async () => {
    const { auth, store } = setup();
    const issued = await auth.issue("u1");
    const rotated = await auth.refresh(issued.refreshToken!);
    const live = [
      issued.accessToken,
      issued.refreshToken!,
      rotated.accessToken,
      rotated.refreshToken,
    ];
    const dump = JSON.stringify(await store.rows("u1"));
    for (const token of live) expect(dump).not.toContain(token);
    expect(dump).toContain(sha256(issued.accessToken));
    // The tokens still work end to end.
    expect((await auth.validate(rotated.accessToken))?.userId).toBe("u1");
  });

  it("re-delivers the (encrypted) successor pair within the grace window", async () => {
    const { auth, store } = setup();
    const issued = await auth.issue("u1");
    const first = await auth.refresh(issued.refreshToken!);
    const rotatedRow = (await store.rows("u1")).find((r) => r.successor);
    expect(rotatedRow?.successor?.refreshToken.startsWith("enc1.")).toBe(true);
    expect(rotatedRow?.parentCredentialId).toBeUndefined();
    const again = await auth.refresh(issued.refreshToken!);
    expect(again.refreshToken).toBe(first.refreshToken);
    expect(again.accessToken).toBe(first.accessToken);
    const child = (await store.rows("u1")).find((r) => r.parentCredentialId);
    expect(child?.parentCredentialId).toBe(sha256(issued.refreshToken!));
  });

  it("revokes, lists and revokes sessions by the hashed rows", async () => {
    const { auth } = setup();
    const a = await auth.issue("u1");
    const b = await auth.issue("u1");
    const ctxA = await auth.validate(a.accessToken);
    expect((await auth.listForUser("u1")).map((c) => c.credentialId)).toContain(ctxA?.credentialId);
    await auth.revoke(b.accessToken);
    expect(await auth.validate(b.accessToken)).toBeNull();
    expect(await auth.revokeOtherSessions("u1", ctxA!.sessionId!)).toBe(1);
    await auth.revokeSession("u1", ctxA!.sessionId!);
    expect(await auth.validate(a.accessToken)).toBeNull();
  });

  it("'migrate' keeps tokens issued before hashing working and re-issues them hashed", async () => {
    const store = new InspectableStore();
    const before = setup(false, store);
    const legacy = await before.auth.issue("u1");
    // `true` would sign everyone out: the legacy rows are keyed by the raw token.
    expect(await setup(true, store).auth.validate(legacy.accessToken)).toBeNull();
    const { auth } = setup("migrate", store);
    expect((await auth.validate(legacy.accessToken))?.userId).toBe("u1");
    const rotated = await auth.refresh(legacy.refreshToken!);
    const rows = await store.rows("u1");
    expect(rows.some((r) => r.token === sha256(rotated.refreshToken!))).toBe(true);
    await auth.revoke(legacy.accessToken);
    expect(await auth.validate(legacy.accessToken)).toBeNull();
  });

  it.each([true, "migrate"] as const)(
    "hashAtRest %s: a row key read from the database is not a usable token",
    async (mode) => {
      const { auth, store } = setup(mode);
      const issued = await auth.issue("victim");
      const keys = (await store.rows("victim")).map((r) => r.token);
      const accessKey = sha256(issued.accessToken);
      const refreshKey = sha256(issued.refreshToken!);
      expect(keys).toEqual(expect.arrayContaining([accessKey, refreshKey]));
      expect(await auth.validate(accessKey)).toBeNull();
      expect(await auth.validate(accessKey.toUpperCase())).toBeNull();
      await expect(auth.refresh(refreshKey)).rejects.toMatchObject({ type: "INVALID_TOKEN" });
      // ...and revoking a row key does not reach the row either.
      await auth.revoke(accessKey);
      expect((await auth.validate(issued.accessToken))?.userId).toBe("victim");
    },
  );

  it("'migrate' looks up only the legacy token shape as-is (isLegacyToken widens it)", async () => {
    const store = new InspectableStore();
    const plain = new AuthCredential({
      store,
      tokens: { generate: () => `legacy_${Math.random().toString(36).slice(2)}x` },
    });
    const old = await plain.issue("u1");
    expect(await setup("migrate", store).auth.validate(old.accessToken)).toBeNull();
    const widened = new AuthCredential({
      store,
      tokens: { hashAtRest: "migrate", isLegacyToken: (t) => t.startsWith("legacy_") },
    });
    expect((await widened.validate(old.accessToken))?.userId).toBe("u1");
  });

  it("'migrate' never looks up a token with whitespace as-is (L3)", async () => {
    // Some databases compare keys ignoring trailing spaces (PAD SPACE collations).
    class PaddedStore extends InspectableStore {
      override retrieve(token: string) {
        return super.retrieve(token.trim());
      }
    }
    const store = new PaddedStore();
    const legacy = await new AuthCredential({ store }).issue("u1");
    const auth = new AuthCredential({
      store,
      tokens: { hashAtRest: "migrate", isLegacyToken: () => true },
    });
    expect((await auth.validate(legacy.accessToken))?.userId).toBe("u1");
    expect(await auth.validate(` ${legacy.accessToken}`)).toBeNull();
    expect(await auth.validate(`${legacy.accessToken}\n`)).toBeNull();
  });

  it("credentialId is the row key under hashAtRest (one hash per validate)", async () => {
    const { auth } = setup();
    const issued = await auth.issue("u1");
    const ctx = await auth.validate(issued.accessToken);
    expect(ctx?.credentialId).toBe(sha256(issued.accessToken));
    expect(ctx?.sessionId).toBeTruthy();
  });

  it("uses tokens.generate and refuses stores that cannot key rows", async () => {
    const { auth } = setup();
    const custom = new AuthCredential({
      store: new CredentialStoreMemory(),
      tokens: { hashAtRest: true, generate: () => `pat_${Math.random().toString(36).slice(2)}` },
    });
    const issued = await custom.issue("u1");
    expect(issued.accessToken.startsWith("pat_")).toBe(true);
    expect((await custom.validate(issued.accessToken))?.userId).toBe("u1");
    expect((await auth.issue("u1")).accessToken).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(
      () =>
        new AuthCredential({
          store: new CredentialStoreJwt({ algorithm: "HS256", secret: "x".repeat(48) }),
          tokens: { hashAtRest: true },
        }),
    ).toThrow(AuthError);
  });

  it.each<[string, () => CredentialStore]>([
    ["redis", () => new CredentialStoreRedis({ redis: new MockRedis() })],
    [
      "atscript-db",
      () => new CredentialStoreAtscriptDb({ table: new MockTable(), metadataField: false }),
    ],
  ])("works on the %s store (persistAs)", async (_name, makeStore) => {
    const auth = new AuthCredential({
      store: makeStore(),
      refresh: { ttl: 600_000, rotation: "always" },
      tokens: { hashAtRest: true },
    });
    const issued = await auth.issue("u1");
    expect((await auth.validate(issued.accessToken))?.userId).toBe("u1");
    const rotated = await auth.refresh(issued.refreshToken!);
    expect((await auth.validate(rotated.accessToken))?.userId).toBe("u1");
    await auth.revoke(rotated.accessToken);
    expect(await auth.validate(rotated.accessToken)).toBeNull();
  });
});
