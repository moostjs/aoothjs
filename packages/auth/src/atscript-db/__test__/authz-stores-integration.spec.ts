import { AtscriptDbTable } from "@atscript/db";
import { BetterSqlite3Driver, SqliteAdapter } from "@atscript/db-sqlite";
import { afterEach, beforeAll, beforeEach, describe, expect, it } from "vite-plus/test";

import type { NewAuthCode } from "../../authz/auth-code-store";
import type { NewDynamicClient } from "../../authz/dynamic-client-store";
import type { NewPendingAuthorization } from "../../authz/pending-authorization-store";
import type { TokenPolicy } from "../../authz/token-policy";
import {
  AuthCodeStoreAtscriptDb,
  type AuthCodeTable,
  DynamicClientStoreAtscriptDb,
  type DynamicClientTable,
  PendingAuthorizationStoreAtscriptDb,
  type PendingAuthorizationTable,
} from "../index";
import { prepareFixtures } from "./test-utils";

// Late-bound compiled fixture classes (populated in beforeAll after prepareFixtures).
/* eslint-disable @typescript-eslint/no-explicit-any */
let AoothPendingAuthorization: any;
let AoothAuthCode: any;
let AoothDynamicClient: any;
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
  let clientDriver: BetterSqlite3Driver;
  let pendingTable: AtscriptDbTable;
  let codeTable: AtscriptDbTable;
  let clientTable: AtscriptDbTable;

  beforeAll(async () => {
    await prepareFixtures();
    const pending = await import("./fixtures/pending-authorization.as");
    const code = await import("./fixtures/auth-code.as");
    const client = await import("./fixtures/dynamic-client.as");
    AoothPendingAuthorization = pending.AoothPendingAuthorization;
    AoothAuthCode = code.AoothAuthCode;
    AoothDynamicClient = client.AoothDynamicClient;
  });

  beforeEach(async () => {
    pendingDriver = new BetterSqlite3Driver(":memory:");
    pendingTable = new AtscriptDbTable(AoothPendingAuthorization, new SqliteAdapter(pendingDriver));
    codeDriver = new BetterSqlite3Driver(":memory:");
    codeTable = new AtscriptDbTable(AoothAuthCode, new SqliteAdapter(codeDriver));
    clientDriver = new BetterSqlite3Driver(":memory:");
    clientTable = new AtscriptDbTable(AoothDynamicClient, new SqliteAdapter(clientDriver));
    for (const t of [pendingTable, codeTable, clientTable]) {
      await t.ensureTable();
      await t.syncIndexes();
    }
  });

  afterEach(() => {
    pendingDriver.close();
    codeDriver.close();
    clientDriver.close();
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
  function clientStore(clock?: ReturnType<typeof fakeClock>): DynamicClientStoreAtscriptDb {
    return new DynamicClientStoreAtscriptDb({
      table: clientTable as unknown as DynamicClientTable,
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

    it("round-trips the consent display name + RFC 8707 resource", async () => {
      const store = pendingStore();
      const { handle } = await store.create(
        newPending({
          clientId: "dyn-1",
          clientName: "Test Connector",
          resource: "https://api.example/mcp",
        }),
      );
      const got = await store.get(handle);
      expect(got?.clientName).toBe("Test Connector");
      expect(got?.resource).toBe("https://api.example/mcp");
      // Absent on a plain row — null from the DB must map back to "absent".
      const { handle: bare } = await store.create(newPending());
      const bareGot = await store.get(bare);
      expect("clientName" in (bareGot ?? {})).toBe(false);
      expect("resource" in (bareGot ?? {})).toBe(false);
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

    it("round-trips the RFC 8707 resource", async () => {
      const store = codeStore();
      const { code } = await store.mint(
        newCode({ clientId: "dyn-1", resource: "https://api.example/mcp" }),
      );
      const got = await store.consume(code);
      expect(got?.clientId).toBe("dyn-1");
      expect(got?.resource).toBe("https://api.example/mcp");
    });
  });

  describe("DynamicClientStoreAtscriptDb", () => {
    function newClient(overrides?: Partial<NewDynamicClient>): NewDynamicClient {
      return {
        clientName: "Test Connector",
        redirectUris: ["https://connector.example/cb", "http://127.0.0.1:33418/cb"],
        tokenEndpointAuthMethod: "none",
        grantTypes: ["authorization_code"],
        responseTypes: ["code"],
        scope: "read write",
        ...overrides,
      };
    }

    it("create + get round-trips every field incl. the JSON-string arrays", async () => {
      const store = clientStore();
      const created = await store.create(newClient());
      expect(created.clientId).toMatch(/^[0-9a-f-]{36}$/i);
      const got = await store.get(created.clientId);
      expect(got).toEqual(created);
      expect(got?.redirectUris).toEqual([
        "https://connector.example/cb",
        "http://127.0.0.1:33418/cb",
      ]);
      expect(got?.grantTypes).toEqual(["authorization_code"]);
      expect(got?.responseTypes).toEqual(["code"]);
      expect("lastUsedAt" in (got ?? {})).toBe(false); // never used → absent, not null
    });

    it("omits absent optionals (clientName / scope)", async () => {
      const store = clientStore();
      const { clientId } = await store.create(
        newClient({ clientName: undefined, scope: undefined }),
      );
      const got = await store.get(clientId);
      expect("clientName" in (got ?? {})).toBe(false);
      expect("scope" in (got ?? {})).toBe(false);
    });

    it("count reflects stored registrations; delete reports removal", async () => {
      const store = clientStore();
      expect(await store.count()).toBe(0);
      const a = await store.create(newClient());
      await store.create(newClient());
      expect(await store.count()).toBe(2);
      expect(await store.delete(a.clientId)).toBe(true);
      expect(await store.delete(a.clientId)).toBe(false);
      expect(await store.count()).toBe(1);
    });

    it("touch stamps lastUsedAt; deleteUnusedBefore GCs only never-used rows older than the cutoff", async () => {
      const clock = fakeClock();
      const store = clientStore(clock);
      const used = await store.create(newClient());
      const stale = await store.create(newClient());
      clock.advance(10_000);
      await store.touch(used.clientId, clock.now());
      expect((await store.get(used.clientId))?.lastUsedAt).toBe(clock.now());
      clock.advance(10_000);
      const fresh = await store.create(newClient());
      const removed = await store.deleteUnusedBefore(clock.now() - 5_000);
      expect(removed).toBe(1);
      expect(await store.get(stale.clientId)).toBeNull();
      expect(await store.get(used.clientId)).not.toBeNull();
      expect(await store.get(fresh.clientId)).not.toBeNull();
      // The GC'd row is gone from the table itself.
      expect(await clientTable.findOne({ filter: { clientId: stale.clientId } })).toBeNull();
    });
  });
});
