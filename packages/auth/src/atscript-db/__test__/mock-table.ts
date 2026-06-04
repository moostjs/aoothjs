import type { AuthCredentialRow, AuthCredentialTable } from "../index";

/**
 * In-memory `AuthCredentialTable` double. Backs the rows by their `token`
 * (matching the `.as` model's PK) and supports the small filter vocabulary
 * the adapter actually uses (`{ token }`, `{ userId }`, and the `$in`
 * operator for `{ token: { $in: [...] } }`).
 *
 * All calls are recorded in `ops` so tests can verify, e.g., that `update`
 * calls `deleteOne` when the new state is already expired (parity with the
 * Redis adapter's fail-loud rule).
 */
export class MockTable<TPayload extends object = object> implements AuthCredentialTable<TPayload> {
  rows = new Map<string, AuthCredentialRow<TPayload>>();
  ops: Array<{ cmd: string; args: unknown[] }> = [];

  async insertOne(row: AuthCredentialRow<TPayload>): Promise<{ insertedId: unknown }> {
    this.ops.push({ cmd: "insertOne", args: [row] });
    this.rows.set(row.token, { ...row });
    return { insertedId: row.token };
  }

  async findOne(query: {
    filter: Record<string, unknown>;
  }): Promise<AuthCredentialRow<TPayload> | null> {
    this.ops.push({ cmd: "findOne", args: [query] });
    const token = query.filter.token as string | undefined;
    if (token !== undefined) {
      const row = this.rows.get(token);
      return row ? { ...row } : null;
    }
    return null;
  }

  async findMany(query: {
    filter?: Record<string, unknown>;
    controls?: Record<string, unknown>;
  }): Promise<AuthCredentialRow<TPayload>[]> {
    this.ops.push({ cmd: "findMany", args: [query] });
    const filter = query.filter ?? {};
    return Array.from(this.rows.values())
      .filter((r) => this.matches(r, filter))
      .map((r) => Object.assign({}, r));
  }

  async replaceOne(
    row: AuthCredentialRow<TPayload>,
  ): Promise<{ matchedCount: number; modifiedCount: number }> {
    this.ops.push({ cmd: "replaceOne", args: [row] });
    if (!this.rows.has(row.token)) return { matchedCount: 0, modifiedCount: 0 };
    this.rows.set(row.token, { ...row });
    return { matchedCount: 1, modifiedCount: 1 };
  }

  async deleteOne(idOrPk: unknown): Promise<{ deletedCount: number }> {
    this.ops.push({ cmd: "deleteOne", args: [idOrPk] });
    const token = idOrPk as string;
    return { deletedCount: this.rows.delete(token) ? 1 : 0 };
  }

  async deleteMany(filter: Record<string, unknown>): Promise<{ deletedCount: number }> {
    this.ops.push({ cmd: "deleteMany", args: [filter] });
    let n = 0;
    for (const row of Array.from(this.rows.values())) {
      if (this.matches(row, filter)) {
        this.rows.delete(row.token);
        n++;
      }
    }
    return { deletedCount: n };
  }

  /** Filtered ops by command name. */
  opsOf(cmd: string): Array<{ cmd: string; args: unknown[] }> {
    return this.ops.filter((o) => o.cmd === cmd);
  }

  // ---- internal -----------------------------------------------------------

  private matches(row: AuthCredentialRow<TPayload>, filter: Record<string, unknown>): boolean {
    const rowDict = row as unknown as Record<string, unknown>;
    for (const [k, v] of Object.entries(filter)) {
      if (v && typeof v === "object" && "$in" in (v as Record<string, unknown>)) {
        const values = (v as { $in: unknown[] }).$in;
        if (!values.includes(rowDict[k])) return false;
        continue;
      }
      if (rowDict[k] !== v) return false;
    }
    return true;
  }
}
