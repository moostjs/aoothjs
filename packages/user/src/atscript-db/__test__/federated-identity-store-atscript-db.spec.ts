import { randomUUID } from "node:crypto";

import { describe, expect, it } from "vite-plus/test";

import type { FederatedIdentity } from "../../store/federated-identity-store";
import { FederatedIdentityStoreAtscriptDb, type FederatedIdentityTable } from "../index";

/**
 * In-memory `FederatedIdentityTable` double keyed by the surrogate `id` PK.
 * Enforces the compound-unique `(provider, subject)` index by throwing a
 * `{ code: "CONFLICT" }` shape on collision — enough to exercise the adapter's
 * `CONFLICT → ALREADY_EXISTS` mapping without booting `@atscript/db`.
 */
class MockFederatedTable implements FederatedIdentityTable {
  rows = new Map<string, FederatedIdentity>();
  ops: string[] = [];

  async insertOne(row: FederatedIdentity): Promise<{ insertedId: unknown }> {
    this.ops.push("insertOne");
    for (const existing of this.rows.values()) {
      if (existing.provider === row.provider && existing.subject === row.subject) {
        throw Object.assign(new Error("duplicate"), { code: "CONFLICT" });
      }
    }
    const id = row.id || randomUUID();
    this.rows.set(id, { ...row, id });
    return { insertedId: id };
  }

  async findOne(query: { filter: Record<string, unknown> }): Promise<FederatedIdentity | null> {
    this.ops.push("findOne");
    return this.match(query.filter)[0] ?? null;
  }

  async findMany(query: { filter?: Record<string, unknown> }): Promise<FederatedIdentity[]> {
    this.ops.push("findMany");
    return this.match(query.filter ?? {});
  }

  async replaceOne(
    row: FederatedIdentity,
  ): Promise<{ matchedCount: number; modifiedCount: number }> {
    this.ops.push("replaceOne");
    if (!this.rows.has(row.id)) return { matchedCount: 0, modifiedCount: 0 };
    this.rows.set(row.id, { ...row });
    return { matchedCount: 1, modifiedCount: 1 };
  }

  async deleteMany(filter: Record<string, unknown>): Promise<{ deletedCount: number }> {
    this.ops.push("deleteMany");
    const victims = this.match(filter);
    for (const v of victims) this.rows.delete(v.id);
    return { deletedCount: victims.length };
  }

  private match(filter: Record<string, unknown>): FederatedIdentity[] {
    return [...this.rows.values()]
      .filter((row) => {
        const dict = row as unknown as Record<string, unknown>;
        return Object.entries(filter).every(([k, v]) => dict[k] === v);
      })
      .map((row) => structuredClone(row));
  }
}

function makeStore(start = 1_000) {
  let now = start;
  const table = new MockFederatedTable();
  const store = new FederatedIdentityStoreAtscriptDb({ table, clock: () => now });
  return { store, table, advance: (ms: number) => (now += ms) };
}

describe("FederatedIdentityStoreAtscriptDb", () => {
  it("links via insertOne and resolves by (provider, subject)", async () => {
    const { store, table } = makeStore(2_000);
    const linked = await store.link({
      provider: "google",
      subject: "sub-1",
      userId: "u1",
      email: "a@example.com",
    });
    expect(linked.id).toBeTruthy();
    expect(linked.linkedAt).toBe(2_000);
    expect(table.ops).toContain("insertOne");

    const found = await store.find("google", "sub-1");
    expect(found).toMatchObject({ userId: "u1", email: "a@example.com" });
  });

  it("maps a unique-index CONFLICT to ALREADY_EXISTS", async () => {
    const { store } = makeStore();
    await store.link({ provider: "google", subject: "sub-1", userId: "u1" });
    await expect(
      store.link({ provider: "google", subject: "sub-1", userId: "u2" }),
    ).rejects.toMatchObject({ name: "UserAuthError", type: "ALREADY_EXISTS" });
  });

  it("rethrows a non-CONFLICT table error unchanged", async () => {
    const { store, table } = makeStore();
    table.insertOne = async () => {
      throw new Error("disk full");
    };
    await expect(store.link({ provider: "google", subject: "x", userId: "u1" })).rejects.toThrow(
      "disk full",
    );
  });

  it("listForUser scans userId via findMany, ordered by linkedAt", async () => {
    const { store, table, advance } = makeStore(1_000);
    await store.link({ provider: "google", subject: "g", userId: "u1" });
    advance(500);
    await store.link({ provider: "github", subject: "h", userId: "u1" });
    await store.link({ provider: "google", subject: "k", userId: "u2" });

    const list = await store.listForUser("u1");
    expect(list.map((r) => r.provider)).toEqual(["google", "github"]);
    expect(table.ops.filter((o) => o === "findMany")).toHaveLength(1);
  });

  it("unlink deletes by (provider, subject) and reports removal", async () => {
    const { store } = makeStore();
    await store.link({ provider: "google", subject: "g", userId: "u1" });
    expect(await store.unlink("google", "g")).toBe(true);
    expect(await store.unlink("google", "g")).toBe(false);
    expect(await store.find("google", "g")).toBeNull();
  });

  it("touchLogin reads then replaceOne with lastLoginAt + merged profile", async () => {
    const { store, table, advance } = makeStore(1_000);
    await store.link({ provider: "google", subject: "g", userId: "u1", displayName: "Old" });
    advance(2_000);
    await store.touchLogin("google", "g", { displayName: "New" });

    const row = await store.find("google", "g");
    expect(row?.lastLoginAt).toBe(3_000);
    expect(row?.displayName).toBe("New");
    expect(table.ops).toContain("replaceOne");
  });

  it("touchLogin is a no-op (no replaceOne) when the row is absent", async () => {
    const { store, table } = makeStore();
    await store.touchLogin("google", "missing");
    expect(table.ops).not.toContain("replaceOne");
  });

  it("deleteAllForUser removes every row for the user and returns the count", async () => {
    const { store } = makeStore();
    await store.link({ provider: "google", subject: "g", userId: "u1" });
    await store.link({ provider: "github", subject: "h", userId: "u1" });
    await store.link({ provider: "google", subject: "k", userId: "u2" });

    expect(await store.deleteAllForUser("u1")).toBe(2);
    expect(await store.listForUser("u1")).toEqual([]);
    expect((await store.find("google", "k"))?.userId).toBe("u2");
  });
});
