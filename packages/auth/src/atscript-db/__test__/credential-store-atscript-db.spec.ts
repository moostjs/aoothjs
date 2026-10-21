import { describe, expect, it } from "vite-plus/test";
import type { CredentialState } from "../../credential/types";
import { AuthError } from "../../errors";
import { CredentialStoreAtscriptDb, getAoothCredentialMetadataSpec } from "../index";
import { MockTable } from "./mock-table";

function makeState(userId: string, overrides?: Partial<CredentialState>): CredentialState {
  return {
    userId,
    issuedAt: Date.now(),
    expiresAt: Date.now() + 60_000,
    kind: "access",
    ...overrides,
  };
}

describe("CredentialStoreAtscriptDb — contract", () => {
  // Intent 1: every CredentialStore method must behave the same as the
  // in-memory store. Without this parity, downstream auth flows would
  // diverge depending on adapter — exactly the bug an interface is meant
  // to prevent.
  describe("persist + retrieve + revoke", () => {
    it("persists a row keyed on a UUID token and retrieves it", async () => {
      const table = new MockTable();
      const store = new CredentialStoreAtscriptDb({ table });
      const token = await store.persist(makeState("alice"));
      expect(token).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i);
      const state = await store.retrieve(token);
      expect(state?.userId).toBe("alice");
    });

    it("retrieve returns null for unknown tokens", async () => {
      const store = new CredentialStoreAtscriptDb({ table: new MockTable() });
      expect(await store.retrieve("nope")).toBeNull();
    });

    it("revoke deletes the row by its primary key", async () => {
      const table = new MockTable();
      const store = new CredentialStoreAtscriptDb({ table });
      const token = await store.persist(makeState("alice"));
      await store.revoke(token);
      expect(await store.retrieve(token)).toBeNull();
      // deleteOne must be called with the token itself (PK on the .as model).
      const last = table.opsOf("deleteOne").at(-1);
      expect(last?.args[0]).toBe(token);
    });

    it("revoke is idempotent on unknown tokens (no throw)", async () => {
      const store = new CredentialStoreAtscriptDb({ table: new MockTable() });
      await expect(store.revoke("nope")).resolves.toBeUndefined();
    });
  });

  describe("consume", () => {
    it("returns the state and deletes the row in one call", async () => {
      const table = new MockTable();
      const store = new CredentialStoreAtscriptDb({ table });
      const token = await store.persist(makeState("alice"));
      const consumed = await store.consume(token);
      expect(consumed?.userId).toBe("alice");
      expect(await store.retrieve(token)).toBeNull();
    });

    it("returns null when the token is not found", async () => {
      const store = new CredentialStoreAtscriptDb({ table: new MockTable() });
      expect(await store.consume("nope")).toBeNull();
    });
  });

  describe("update", () => {
    it("replaces the row in place and returns the same token", async () => {
      const table = new MockTable();
      const store = new CredentialStoreAtscriptDb({ table });
      const token = await store.persist(makeState("alice"));
      // rotatedAt + successor is exactly what the rotation-with-grace path
      // writes onto the old refresh row — both must round-trip.
      const successor = {
        accessToken: "a-2",
        accessExpiresAt: Date.now() + 60_000,
        refreshToken: "r-2",
        refreshExpiresAt: Date.now() + 600_000,
      };
      const returned = await store.update(token, makeState("alice", { rotatedAt: 7, successor }));
      expect(returned).toBe(token);
      const retrieved = await store.retrieve(token);
      expect(retrieved?.rotatedAt).toBe(7);
      expect(retrieved?.successor).toEqual(successor);
    });

    it("is a no-op for unknown tokens (does not insert a resurrected row)", async () => {
      const table = new MockTable();
      const store = new CredentialStoreAtscriptDb({ table });
      const returned = await store.update("ghost", makeState("alice"));
      expect(returned).toBe("ghost");
      expect(await store.retrieve("ghost")).toBeNull();
      expect(table.opsOf("replaceOne")).toHaveLength(0);
    });

    // Intent 9: update with a past-expiry state calls deleteOne, NOT
    // replaceOne. This exists for parity with the Redis adapter's
    // fail-loud rule — a dead row in the table would silently flip to
    // "unknown" on the next retrieve and confuse downstream debugging.
    it("calls deleteOne (revoke) — not replaceOne — when state.expiresAt is past", async () => {
      const table = new MockTable();
      const store = new CredentialStoreAtscriptDb({ table });
      const token = await store.persist(makeState("alice"));
      const replaceCountBefore = table.opsOf("replaceOne").length;
      await store.update(token, makeState("alice", { expiresAt: Date.now() - 1 }));
      // No new replaceOne since the persist.
      expect(table.opsOf("replaceOne")).toHaveLength(replaceCountBefore);
      // The row was deleted by token id.
      const lastDelete = table.opsOf("deleteOne").at(-1);
      expect(lastDelete?.args[0]).toBe(token);
      expect(await store.retrieve(token)).toBeNull();
    });
  });
});

describe("CredentialStoreAtscriptDb — sessionId / lastSeenAt", () => {
  it("round-trips sessionId through persist + retrieve + listForUser", async () => {
    const store = new CredentialStoreAtscriptDb({ table: new MockTable() });
    const token = await store.persist(makeState("alice", { sessionId: "sess-1" }));
    expect((await store.retrieve(token))?.sessionId).toBe("sess-1");
    const [entry] = await store.listForUser("alice");
    expect(entry.sessionId).toBe("sess-1");
  });

  it("touch writes lastSeenAt via replaceOne on an existing token; no-op for unknown", async () => {
    const table = new MockTable();
    const store = new CredentialStoreAtscriptDb({ table });
    const token = await store.persist(makeState("alice"));
    await store.touch(token, 4242);
    expect((await store.retrieve(token))?.lastSeenAt).toBe(4242);
    const replaceCountBefore = table.opsOf("replaceOne").length;
    // Unknown token is a no-op — does not throw, does not write.
    await store.touch("nope", 1);
    expect(table.opsOf("replaceOne")).toHaveLength(replaceCountBefore);
  });

  it("touch with the just-read state patches lastSeenAt via updateOne (no re-read); else falls back", async () => {
    const table = new MockTable();
    const patches: unknown[] = [];
    const patching = Object.assign(table, {
      async updateOne(patch: { token: string; lastSeenAt: number }) {
        patches.push(patch);
        const row = table.rows.get(patch.token);
        if (row) table.rows.set(patch.token, { ...row, lastSeenAt: patch.lastSeenAt });
        return { matchedCount: row ? 1 : 0, modifiedCount: row ? 1 : 0 };
      },
    });
    const store = new CredentialStoreAtscriptDb({ table: patching });
    const token = await store.persist(makeState("alice"));
    const state = (await store.retrieve(token))!;
    const reads = table.opsOf("findOne").length;
    await store.touch(token, 4242, state);
    expect(table.opsOf("findOne")).toHaveLength(reads);
    expect(table.opsOf("replaceOne")).toHaveLength(0);
    expect(patches).toEqual([{ token, lastSeenAt: 4242 }]);
    expect((await store.retrieve(token))?.lastSeenAt).toBe(4242);
    // a gone row is never resurrected
    await store.revoke(token);
    await store.touch(token, 5000, state);
    expect(table.rows.has(token)).toBe(false);
    // an expired state is not stamped
    await store.touch(token, 6000, { ...state, expiresAt: 0 });
    expect(patches).toHaveLength(2);
    // without updateOne on the table: the read-then-replace path
    const plain = new MockTable();
    const s2 = new CredentialStoreAtscriptDb({ table: plain });
    const t2 = await s2.persist(makeState("bob"));
    await s2.touch(t2, 7, (await s2.retrieve(t2))!);
    expect((await s2.retrieve(t2))?.lastSeenAt).toBe(7);
    expect(plain.opsOf("replaceOne")).toHaveLength(1);
  });
});

describe("CredentialStoreAtscriptDb — typed payload + metadata round-trip", () => {
  // Intent: a consumer's typed payload (the flat root fields added to their
  // `extends AoothAuthCredential` model) and metadata persist as real columns.
  // Metadata is CONSUMER-DECLARED — the store maps the envelope's `metadata`
  // through the configured `metadataField` (the consumer's
  // `@aooth.auth.metadata`-annotated column). The adapter must round-trip them
  // byte-for-byte through persist → retrieve; a regression here means
  // per-token data silently drops on the wire.
  it("persists typed payload + metadata and returns them on retrieve", async () => {
    const table = new MockTable<{ scope: string; roles: string[] }>();
    const store = new CredentialStoreAtscriptDb<{ scope: string; roles: string[] }>({
      table,
      metadataField: "metadata",
    });
    const metadata = {
      ip: "10.0.0.1",
      userAgent: "Mozilla/5.0",
      fingerprint: "fp-1",
      label: "iPhone",
    };
    const token = await store.persist({
      userId: "alice",
      issuedAt: Date.now(),
      expiresAt: Date.now() + 60_000,
      kind: "refresh",
      scope: "read:tasks",
      roles: ["admin", "user"],
      metadata,
    });
    const got = await store.retrieve(token);
    expect(got?.scope).toBe("read:tasks");
    expect(got?.roles).toEqual(["admin", "user"]);
    expect(got?.metadata).toEqual(metadata);
  });

  it("does not surface payload/metadata when none were persisted (no synthetic fields)", async () => {
    // Surface contract: omitting a field on persist must NOT synthesize it on
    // retrieve — the adapter returns only the envelope fields actually written.
    const table = new MockTable();
    const store = new CredentialStoreAtscriptDb({ table });
    const token = await store.persist(makeState("alice"));
    const got = await store.retrieve(token);
    expect(got?.metadata).toBeUndefined();
    expect(Object.keys(got ?? {}).toSorted()).toEqual(["expiresAt", "issuedAt", "kind", "userId"]);
  });

  it("update replaces typed payload + metadata wholesale (no merge)", async () => {
    // Adapter contract: update is replace-semantic, not patch-semantic. The
    // refresh-token rotation path relies on this — a stale fingerprint or an
    // old payload value MUST NOT survive a rotation.
    const table = new MockTable<{ scope: string }>();
    const store = new CredentialStoreAtscriptDb<{ scope: string }>({
      table,
      metadataField: "metadata",
    });
    const token = await store.persist({
      userId: "alice",
      issuedAt: Date.now(),
      expiresAt: Date.now() + 60_000,
      scope: "read:tasks",
      metadata: { ip: "10.0.0.1" },
    });
    await store.update(token, {
      userId: "alice",
      issuedAt: Date.now(),
      expiresAt: Date.now() + 120_000,
      scope: "write:tasks",
      metadata: { ip: "10.0.0.2" },
    });
    const got = await store.retrieve(token);
    expect(got?.scope).toBe("write:tasks");
    expect(got?.metadata).toEqual({ ip: "10.0.0.2" });
  });

  it("does NOT persist metadata when no metadataField is configured", async () => {
    // No consumer-declared @aooth.auth.metadata column → the store has no
    // place to put the envelope's metadata. It must drop it silently (the
    // warn happens at boot, in the spec resolver) — not write a phantom
    // column the schema would reject.
    const table = new MockTable();
    const store = new CredentialStoreAtscriptDb({ table });
    const token = await store.persist(makeState("alice", { metadata: { ip: "10.0.0.1" } }));
    const row = table.rows.get(token) as Record<string, unknown> | undefined;
    expect(row?.metadata).toBeUndefined();
    expect((await store.retrieve(token))?.metadata).toBeUndefined();
  });

  it("maps metadata through a consumer-chosen column name without leaking it into the payload", async () => {
    // The consumer's column need not be named "metadata". The store writes the
    // envelope's metadata under the configured name and, on read, maps it BACK
    // onto `state.metadata` — never surfacing the raw column as a typed
    // payload field.
    const table = new MockTable();
    const store = new CredentialStoreAtscriptDb({ table, metadataField: "sessionMeta" });
    const metadata = { ip: "10.0.0.1", label: "iPhone" };
    const token = await store.persist(makeState("alice", { metadata }));
    const row = table.rows.get(token) as Record<string, unknown> | undefined;
    expect(row?.sessionMeta).toEqual(metadata);
    const got = await store.retrieve(token);
    expect(got?.metadata).toEqual(metadata);
    expect((got as Record<string, unknown> | null)?.sessionMeta).toBeUndefined();
  });
});

describe("CredentialStoreAtscriptDb — listForUser", () => {
  // Intent 2: listForUser must yield {...state, token} so UIs can show
  // and manage individual sessions/refresh tokens.
  it("returns active rows with the token attached", async () => {
    const table = new MockTable();
    const store = new CredentialStoreAtscriptDb({ table });
    const t1 = await store.persist(makeState("alice", { issuedAt: 1 }));
    const t2 = await store.persist(makeState("alice", { issuedAt: 2 }));
    const list = await store.listForUser("alice");
    expect(list).toHaveLength(2);
    for (const e of list) {
      expect(e.userId).toBe("alice");
      expect(typeof e.token).toBe("string");
    }
    expect(list.map((e) => e.token).toSorted()).toEqual([t1, t2].toSorted());
  });

  it("returns an empty array when the user has nothing", async () => {
    const store = new CredentialStoreAtscriptDb({ table: new MockTable() });
    expect(await store.listForUser("nobody")).toEqual([]);
  });

  it("filters out expired rows and prunes them in the background", async () => {
    // Lazy GC on read keeps the table tidy without a separate cron — the
    // dead rows would otherwise accumulate forever.
    const table = new MockTable();
    const store = new CredentialStoreAtscriptDb({ table });
    const liveToken = await store.persist(makeState("alice"));
    // Inject a row directly with an expired timestamp.
    await table.insertOne({
      token: "dead-token",
      userId: "alice",
      issuedAt: Date.now() - 10_000,
      expiresAt: Date.now() - 1,
      kind: "access",
    });
    const list = await store.listForUser("alice");
    expect(list.map((e) => e.token)).toEqual([liveToken]);
    expect(table.rows.has("dead-token")).toBe(false);
  });
});

describe("CredentialStoreAtscriptDb — revokeAllForUser", () => {
  // Intent 3 + 5: cascade revoke for a user; other users untouched.
  it("deletes every row for the user and returns the count", async () => {
    const table = new MockTable();
    const store = new CredentialStoreAtscriptDb({ table });
    await store.persist(makeState("alice"));
    await store.persist(makeState("alice"));
    const count = await store.revokeAllForUser("alice");
    expect(count).toBe(2);
    expect(await store.listForUser("alice")).toEqual([]);
  });

  it("returns 0 when the user has nothing", async () => {
    const store = new CredentialStoreAtscriptDb({ table: new MockTable() });
    expect(await store.revokeAllForUser("nobody")).toBe(0);
  });

  it("leaves other users' credentials intact", async () => {
    const table = new MockTable();
    const store = new CredentialStoreAtscriptDb({ table });
    await store.persist(makeState("alice"));
    await store.persist(makeState("alice"));
    const bobToken = await store.persist(makeState("bob"));
    await store.revokeAllForUser("alice");
    const bobList = await store.listForUser("bob");
    expect(bobList).toHaveLength(1);
    expect(bobList[0].token).toBe(bobToken);
  });

  it("uses a single deleteMany call (one round trip)", async () => {
    // The whole point of choosing deleteMany over read-then-deleteOne is
    // performance — if a future refactor regresses this we want to know.
    const table = new MockTable();
    const store = new CredentialStoreAtscriptDb({ table });
    await store.persist(makeState("alice"));
    await store.persist(makeState("alice"));
    const deleteManyBefore = table.opsOf("deleteMany").length;
    await store.revokeAllForUser("alice");
    expect(table.opsOf("deleteMany").length - deleteManyBefore).toBe(1);
  });
});

describe("CredentialStoreAtscriptDb — TTL expiry", () => {
  // Intent 4: retrieve must reject and delete a row whose expiresAt has
  // passed, even if no separate eviction job has run.
  it("retrieve returns null and deletes the row when expiresAt is past", async () => {
    const table = new MockTable();
    const store = new CredentialStoreAtscriptDb({ table });
    const token = await store.persist(makeState("alice"));
    // Push the row into the past in-place to simulate clock-skew / no GC.
    const row = table.rows.get(token);
    if (!row) throw new Error("row missing");
    row.expiresAt = Date.now() - 1;
    expect(await store.retrieve(token)).toBeNull();
    expect(table.rows.has(token)).toBe(false);
  });
});

describe("CredentialStoreAtscriptDb — metadata column resolution (S4)", () => {
  /** Structural stand-in for atscript-db's `table.type`. */
  function modelWith(fields: Record<string, Record<string, unknown>>) {
    return {
      type: {
        kind: "object",
        props: new Map(
          Object.entries(fields).map(([name, md]) => [
            name,
            { metadata: new Map(Object.entries(md)) },
          ]),
        ),
      },
    };
  }
  const annotated = { "aooth.auth.metadata": true, "db.json": true };

  function tableOf(type?: unknown): MockTable {
    const table = new MockTable();
    if (type) Object.assign(table, { type });
    return table;
  }

  it("resolves the @aooth.auth.metadata column from table.type without config", async () => {
    const table = tableOf(modelWith({ token: {}, sessionMeta: annotated }));
    const store = new CredentialStoreAtscriptDb({ table, onWarning: () => {} });
    const metadata = { ip: "10.0.0.1", refreshRotation: "always" as const };
    const token = await store.persist(makeState("alice", { metadata }));
    expect((table.rows.get(token) as Record<string, unknown>).sessionMeta).toEqual(metadata);
    expect((await store.retrieve(token))?.metadata).toEqual(metadata);
  });

  it.each([
    ["no column on the model", { table: tableOf(modelWith({ token: {} })) }],
    ["an explicit metadataField: false", { table: tableOf(), metadataField: false as const }],
  ])("fails closed on per-token restrictions with %s", async (_label, opts) => {
    const store = new CredentialStoreAtscriptDb({ ...opts, onWarning: () => {} });
    for (const metadata of [
      { refreshRotation: "always" as const },
      { accessTtl: 900_000 },
      { credentialKind: "pat" },
      { authzClientId: "cli" },
    ]) {
      const err = await store.persist(makeState("alice", { metadata })).catch((e: unknown) => e);
      expect(err).toBeInstanceOf(AuthError);
      expect((err as AuthError).type).toBe("INVALID_CONFIG");
    }
    expect(opts.table.rows.size).toBe(0);
  });

  it("drops other metadata with a single warning (none when opted out)", async () => {
    const warnings: string[] = [];
    const store = new CredentialStoreAtscriptDb({
      table: tableOf(),
      onWarning: (m) => warnings.push(m),
    });
    await store.persist(makeState("alice", { metadata: { ip: "1.1.1.1" } }));
    await store.persist(makeState("bob", { metadata: { ip: "2.2.2.2" } }));
    expect(warnings).toHaveLength(1);
    const quiet: string[] = [];
    const optedOut = new CredentialStoreAtscriptDb({
      table: tableOf(),
      metadataField: false,
      onWarning: (m) => quiet.push(m),
    });
    await optedOut.persist(makeState("alice", { metadata: { ip: "1.1.1.1" } }));
    expect(quiet).toEqual([]);
  });

  it("discovers the annotated column name-agnostically", () => {
    expect(getAoothCredentialMetadataSpec(modelWith({ token: {}, metadata: annotated }))).toEqual({
      metadataField: "metadata",
      warnings: [],
    });
    expect(
      getAoothCredentialMetadataSpec(modelWith({ sessionMeta: annotated })).metadataField,
    ).toBe("sessionMeta");
  });

  it("no annotated field → undefined without warnings", () => {
    expect(
      getAoothCredentialMetadataSpec(modelWith({ token: {}, grants: { "db.json": true } })),
    ).toEqual({ metadataField: undefined, warnings: [] });
  });

  it("throws on more than one @aooth.auth.metadata field", () => {
    expect(() =>
      getAoothCredentialMetadataSpec(modelWith({ metadata: annotated, altMetadata: annotated })),
    ).toThrow(/multiple @aooth\.auth\.metadata/);
  });

  it("caches per model and tolerates non-object models", () => {
    const model = modelWith({ metadata: annotated });
    expect(getAoothCredentialMetadataSpec(model)).toBe(getAoothCredentialMetadataSpec(model));
    expect(getAoothCredentialMetadataSpec({ type: { kind: "string" } })).toEqual({
      metadataField: undefined,
      warnings: [],
    });
    expect(getAoothCredentialMetadataSpec(null).metadataField).toBeUndefined();
  });

  it("an annotated field without @db.json is not used and warns", () => {
    const spec = getAoothCredentialMetadataSpec(
      modelWith({ meta: { "aooth.auth.metadata": true } }),
    );
    expect(spec.metadataField).toBeUndefined();
    expect(spec.warnings).toHaveLength(1);
    expect(spec.warnings[0]).toMatch(/@aooth\.auth\.metadata/);
    expect(spec.warnings[0]).toMatch(/no @db\.json/);
  });
});
