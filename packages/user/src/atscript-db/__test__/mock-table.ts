import type { AuthUserTable, UserCredentialsRow } from "../index";

/**
 * In-memory `AuthUserTable` double — keyed by `username` (matching the unique
 * index on the shipped `AoothUserCredentials` model). Exists so the structural
 * surface (`code === "CONFLICT"` conflict detection, no-op short-circuit, etc.)
 * can be exercised without booting `@atscript/db` + SQLite.
 *
 * Mirrors the pattern used by `packages/auth/src/atscript-db/__test__/mock-table.ts`.
 */
export class MockTable<TUserCustom extends object = object> implements AuthUserTable<TUserCustom> {
  rows = new Map<string, UserCredentialsRow<TUserCustom>>();
  ops: Array<{ cmd: string; args: unknown[] }> = [];

  async count(query: { filter: Record<string, unknown> }): Promise<number> {
    this.ops.push({ cmd: "count", args: [query] });
    const username = query.filter.username as string | undefined;
    if (username !== undefined) return this.rows.has(username) ? 1 : 0;
    return 0;
  }

  async findOne(query: {
    filter: Record<string, unknown>;
  }): Promise<UserCredentialsRow<TUserCustom> | null> {
    this.ops.push({ cmd: "findOne", args: [query] });
    const username = query.filter.username as string | undefined;
    if (username !== undefined) {
      const row = this.rows.get(username);
      return row ? { ...row } : null;
    }
    return null;
  }

  async insertOne(row: Record<string, unknown>): Promise<{ insertedId: unknown }> {
    this.ops.push({ cmd: "insertOne", args: [row] });
    const username = row.username as string;
    if (this.rows.has(username)) {
      // Real `@atscript/db` throws a `DbError` here — but the adapter only
      // looks at `.code`, so a structurally-shaped throw is enough to prove
      // the contract.
      throw Object.assign(new Error("duplicate"), { code: "CONFLICT" });
    }
    this.rows.set(username, { ...(row as UserCredentialsRow<TUserCustom>) });
    return { insertedId: username };
  }

  async updateOne(
    patch: Record<string, unknown>,
  ): Promise<{ matchedCount: number; modifiedCount: number }> {
    this.ops.push({ cmd: "updateOne", args: [patch] });
    const username = patch.username as string;
    if (!this.rows.has(username)) return { matchedCount: 0, modifiedCount: 0 };
    const existing = this.rows.get(username)!;
    this.rows.set(username, { ...existing, ...(patch as Partial<typeof existing>) });
    return { matchedCount: 1, modifiedCount: 1 };
  }

  opsOf(cmd: string): Array<{ cmd: string; args: unknown[] }> {
    return this.ops.filter((o) => o.cmd === cmd);
  }
}
