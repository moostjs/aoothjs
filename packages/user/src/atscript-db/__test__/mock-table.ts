import { randomUUID } from "node:crypto";

import type { AuthUserTable, UserCredentialsRow } from "../index";

/**
 * In-memory `AuthUserTable` double — keyed by the stable surrogate `id` (the
 * `@meta.id` PK on the shipped `AoothUserCredentials` model), matching how the
 * adapter writes (`update`/`delete` key on `id`). Exists so the structural
 * surface (`code === "CONFLICT"` conflict detection, no-op short-circuit, etc.)
 * can be exercised without booting `@atscript/db` + SQLite.
 *
 * Filters are matched by ALL keys equal — supports `{ id }`, `{ username }`,
 * and `{ email }` lookups (the adapter's `findById` / `findByHandle` /
 * `findByIdentifier` reads + the `exists` count on `{ username }`).
 *
 * Mirrors the pattern used by `packages/auth/src/atscript-db/__test__/mock-table.ts`.
 */
export class MockTable<TUserCustom extends object = object> implements AuthUserTable<TUserCustom> {
  /** Keyed by the stable surrogate `id`. */
  rows = new Map<string, UserCredentialsRow<TUserCustom>>();
  ops: Array<{ cmd: string; args: unknown[] }> = [];

  async count(query: { filter: Record<string, unknown> }): Promise<number> {
    this.ops.push({ cmd: "count", args: [query] });
    return this.findRow(query.filter) ? 1 : 0;
  }

  async findOne(query: {
    filter: Record<string, unknown>;
  }): Promise<UserCredentialsRow<TUserCustom> | null> {
    this.ops.push({ cmd: "findOne", args: [query] });
    const row = this.findRow(query.filter);
    return row ? { ...row } : null;
  }

  async insertOne(row: Record<string, unknown>): Promise<{ insertedId: unknown }> {
    this.ops.push({ cmd: "insertOne", args: [row] });
    const typed = row as UserCredentialsRow<TUserCustom>;
    const id = (typed.id as string | undefined) ?? randomUUID();
    const username = typed.username;
    // `email` is now a consumer-declared handle field (not on the base
    // `UserCredentials`), so read it structurally. The shipped test fixture
    // (`test-user.as`) still declares the `email_idx` unique index, so the mock
    // mirrors it to keep simulating the DB's unique constraints.
    const email = (typed as Record<string, unknown>).email;
    // Real `@atscript/db` throws a `DbError` on a unique-index collision — but
    // the adapter only looks at `.code`, so a structurally-shaped throw is
    // enough to prove the contract. Mirror the unique columns: `id` (PK),
    // `username`, and `email`.
    for (const existing of this.rows.values()) {
      const existingRec = existing as unknown as Record<string, unknown>;
      if (
        existing.id === id ||
        existing.username === username ||
        (email !== undefined && existingRec.email === email)
      ) {
        throw Object.assign(new Error("duplicate"), { code: "CONFLICT" });
      }
    }
    this.rows.set(id, { ...typed, id });
    return { insertedId: id };
  }

  async updateOne(
    patch: Record<string, unknown>,
  ): Promise<{ matchedCount: number; modifiedCount: number }> {
    this.ops.push({ cmd: "updateOne", args: [patch] });
    const id = patch.id as string;
    const existing = this.rows.get(id);
    if (!existing) return { matchedCount: 0, modifiedCount: 0 };
    this.rows.set(id, { ...existing, ...(patch as Partial<typeof existing>) });
    return { matchedCount: 1, modifiedCount: 1 };
  }

  async deleteMany(filter: Record<string, unknown>): Promise<{ deletedCount: number }> {
    this.ops.push({ cmd: "deleteMany", args: [filter] });
    const row = this.findRow(filter);
    if (!row) return { deletedCount: 0 };
    return { deletedCount: this.rows.delete(row.id) ? 1 : 0 };
  }

  opsOf(cmd: string): Array<{ cmd: string; args: unknown[] }> {
    return this.ops.filter((o) => o.cmd === cmd);
  }

  // ---- internal -----------------------------------------------------------

  /** First row where ALL filter keys equal the row's value. */
  private findRow(filter: Record<string, unknown>): UserCredentialsRow<TUserCustom> | undefined {
    return [...this.rows.values()].find((row) => {
      const dict = row as unknown as Record<string, unknown>;
      return Object.entries(filter).every(([k, v]) => dict[k] === v);
    });
  }
}
