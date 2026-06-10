import { AtscriptDbTable } from "@atscript/db";
import { BetterSqlite3Driver, SqliteAdapter } from "@atscript/db-sqlite";
import { afterEach, beforeAll, beforeEach, describe, expect, it } from "vite-plus/test";

import type { NewAuthCode } from "../../authz/auth-code-store";
import type { NewPendingAuthorization } from "../../authz/pending-authorization-store";
import type { TokenPolicy } from "../../authz/token-policy";
import {
  AuthCodeStoreAtscriptDb,
  type AuthCodeTable,
  PendingAuthorizationStoreAtscriptDb,
  type PendingAuthorizationTable,
} from "../index";
import { prepareFixtures } from "./test-utils";

// Late-bound compiled fixture classes (populated in beforeAll after prepareFixtures).
/* eslint-disable @typescript-eslint/no-explicit-any */
let AoothPendingAuthorization: any;
let AoothAuthCode: any;
/* eslint-enable @typescript-eslint/no-explicit-any */

/** Mutable fake clock for deterministic expiry without real timers. */
function fakeClock(start = 1_000_000): { now: () => number; advance: (ms: number) => void } {
  let t = start;
  return { now: () => t, advance: (ms) => (t += ms) };
}

// An OPEN payload (arbitrary attenuation keys) — the reason tokenPolicy is stored
// as a JSON string and not a closed `@db.json` column. Must round-trip verbatim.
const POLICY: TokenPolicy = {
  kind: "cli-session",
  ttl: 30 * 86_400_000,
  payload: { assumedRoles: ["admin"], tenant: "t1", nested: { a: 1, b: [true, "x"] } },
};

function newPending(overrides?: Partial<NewPendingAuthorization>): NewPendingAuthorization {
  return {
    redirectUri: "http://127.0.0.1:51789/callback",
    codeChallenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
    tokenPolicy: POLICY,
    clientState: "xyz-state",
    scope: "openid email",
    binding: "binding-secret-xyz",
    ...overrides,
  };
}

function newCode(overrides?: Partial<NewAuthCode>): NewAuthCode {
  return {
    userId: "alice",
    codeChallenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
    redirectUri: "http://127.0.0.1:51789/callback",
    tokenPolicy: POLICY,
    ...overrides,
  };
}

// Intent: the shipped authz `.as` models + the atscript-db adapters work together
// against a real `@atscript/db` table — the JSON-string tokenPolicy round-trips an
// OPEN payload, lazy-GC fires the DELETE, and the auth-code consume is single-use.
describe("authz durable stores — integration against real SQLite", () => {
  // Each table gets its OWN driver/adapter: a directly-constructed
  // `AtscriptDbTable` binds one model per adapter, so the two independent stores
  // use separate in-memory DBs (mirrors the one-table-per-adapter test pattern).
  let pendingDriver: BetterSqlite3Driver;
  let codeDriver: BetterSqlite3Driver;
  let pendingTable: AtscriptDbTable;
  let codeTable: AtscriptDbTable;

  beforeAll(async () => {
    await prepareFixtures();
    const pending = await import("./fixtures/pending-authorization.as");
    const code = await import("./fixtures/auth-code.as");
    AoothPendingAuthorization = pending.AoothPendingAuthorization;
    AoothAuthCode = code.AoothAuthCode;
  });

  beforeEach(async () => {
    pendingDriver = new BetterSqlite3Driver(":memory:");
    pendingTable = new AtscriptDbTable(AoothPendingAuthorization, new SqliteAdapter(pendingDriver));
    codeDriver = new BetterSqlite3Driver(":memory:");
    codeTable = new AtscriptDbTable(AoothAuthCode, new SqliteAdapter(codeDriver));
    for (const t of [pendingTable, codeTable]) {
      await t.ensureTable();
      await t.syncIndexes();
    }
  });

  afterEach(() => {
    pendingDriver.close();
    codeDriver.close();
  });

  function pendingStore(clock?: ReturnType<typeof fakeClock>): PendingAuthorizationStoreAtscriptDb {
    return new PendingAuthorizationStoreAtscriptDb({
      table: pendingTable as unknown as PendingAuthorizationTable,
      ...(clock && { clock }),
    });
  }
  function codeStore(clock?: ReturnType<typeof fakeClock>): AuthCodeStoreAtscriptDb {
    return new AuthCodeStoreAtscriptDb({
      table: codeTable as unknown as AuthCodeTable,
      ...(clock && { clock }),
    });
  }

  describe("PendingAuthorizationStoreAtscriptDb", () => {
    it("create + get round-trips every field incl. the OPEN tokenPolicy payload", async () => {
      const store = pendingStore();
      const { handle } = await store.create(newPending());
      expect(handle).toMatch(/^[0-9a-f-]{36}$/i);
      const got = await store.get(handle);
      expect(got?.redirectUri).toBe("http://127.0.0.1:51789/callback");
      expect(got?.codeChallenge).toBe("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
      expect(got?.clientState).toBe("xyz-state");
      expect(got?.scope).toBe("openid email");
      // The whole point: arbitrary payload keys survive the JSON-string column.
      expect(got?.tokenPolicy).toEqual(POLICY);
      expect(got?.binding).toBe("binding-secret-xyz");
      expect(got?.createdAt).toBeTypeOf("number");
      expect(got?.expiresAt).toBeGreaterThan(got!.createdAt);
    });

    it("round-trips boolean flags + omits absent optionals", async () => {
      const store = pendingStore();
      const { handle } = await store.create(
        newPending({ idToken: true, accessToken: false, audience: "client-123", nonce: "n-1" }),
      );
      const got = await store.get(handle);
      expect(got?.idToken).toBe(true);
      expect(got?.accessToken).toBe(false);
      expect(got?.audience).toBe("client-123");
      expect(got?.nonce).toBe("n-1");
      expect("clientId" in (got ?? {})).toBe(false); // never set → absent, not null
    });

    it("get returns null for an unknown handle", async () => {
      expect(await pendingStore().get("nope")).toBeNull();
    });

    it("get lazily evicts (DELETEs) a past-expiry row", async () => {
      const clock = fakeClock();
      const store = pendingStore(clock);
      const { handle } = await store.create(newPending()); // default 15-min TTL
      clock.advance(15 * 60_000 + 1);
      expect(await store.get(handle)).toBeNull();
      // Probe the table directly — the row is gone, not just hidden.
      expect(await pendingTable.findOne({ filter: { handle } })).toBeNull();
    });

    it("delete reports whether a row was removed", async () => {
      const store = pendingStore();
      const { handle } = await store.create(newPending());
      expect(await store.delete(handle)).toBe(true);
      expect(await store.delete(handle)).toBe(false); // already gone
      expect(await store.get(handle)).toBeNull();
    });
  });

  describe("AuthCodeStoreAtscriptDb", () => {
    it("mint + consume round-trips every field incl. the OPEN tokenPolicy payload", async () => {
      const store = codeStore();
      const { code } = await store.mint(newCode({ scope: "openid", audience: "client-123" }));
      expect(code).toMatch(/^[0-9a-f-]{36}$/i);
      const got = await store.consume(code);
      expect(got?.userId).toBe("alice");
      expect(got?.codeChallenge).toBe("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
      expect(got?.redirectUri).toBe("http://127.0.0.1:51789/callback");
      expect(got?.scope).toBe("openid");
      expect(got?.audience).toBe("client-123");
      expect(got?.tokenPolicy).toEqual(POLICY);
    });

    it("consume is SINGLE-USE — a second redeem of the same code returns null", async () => {
      const store = codeStore();
      const { code } = await store.mint(newCode());
      expect(await store.consume(code)).not.toBeNull();
      expect(await store.consume(code)).toBeNull(); // replay loses
      // And the row is gone from the table.
      expect(await codeTable.findOne({ filter: { code } })).toBeNull();
    });

    it("consume rejects a past-expiry code (and still claims/evicts it)", async () => {
      const clock = fakeClock();
      const store = codeStore(clock);
      const { code } = await store.mint(newCode()); // default 60-s TTL
      clock.advance(60_001);
      expect(await store.consume(code)).toBeNull();
      expect(await codeTable.findOne({ filter: { code } })).toBeNull();
    });

    it("concurrent double-consume yields the code to EXACTLY ONE caller", async () => {
      const store = codeStore();
      const { code } = await store.mint(newCode());
      const results = await Promise.all([store.consume(code), store.consume(code)]);
      const winners = results.filter((r) => r !== null);
      expect(winners).toHaveLength(1);
      expect(winners[0]?.userId).toBe("alice");
    });

    it("consume returns null for an unknown code", async () => {
      expect(await codeStore().consume("nope")).toBeNull();
    });
  });
});
