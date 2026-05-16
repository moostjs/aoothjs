import { randomUUID } from "node:crypto";
import type { CredentialState } from "../credential/types";
import type { CredentialStore } from "../stores/store";

/**
 * Persisted row shape — mirrors `AoothAuthCredential` from
 * `./auth-credential.as`. Re-declared here as a plain TS interface so
 * consumers can use the adapter without running the atscript build (and so
 * `@aoothjs/auth` doesn't need to depend on `@atscript/typescript` at build
 * time). When you DO wire the `.as` model, the shapes match by construction.
 */
export interface AuthCredentialRow<TClaims extends object = object> {
  token: string;
  userId: string;
  issuedAt: number;
  expiresAt: number;
  kind?: string;
  claims?: TClaims;
  metadata?: {
    ip?: string;
    userAgent?: string;
    fingerprint?: string;
    label?: string;
  };
  parentCredentialId?: string;
  rotatedAt?: number;
}

/**
 * Structural surface of `AtscriptDbTable` covering exactly the methods this
 * adapter calls. Kept loose to avoid pulling `@atscript/db` types into the
 * `@aoothjs/auth` public surface — consumers pass `db.getTable(AoothAuthCredential)`
 * directly and TypeScript matches by-shape.
 */
export interface AuthCredentialTable<TClaims extends object = object> {
  insertOne(row: AuthCredentialRow<TClaims>): Promise<{ insertedId: unknown }>;
  findOne(query: { filter: Record<string, unknown> }): Promise<AuthCredentialRow<TClaims> | null>;
  findMany(query: {
    filter?: Record<string, unknown>;
    controls?: Record<string, unknown>;
  }): Promise<AuthCredentialRow<TClaims>[]>;
  replaceOne(
    row: AuthCredentialRow<TClaims>,
  ): Promise<{ matchedCount: number; modifiedCount: number }>;
  deleteOne(idOrPk: unknown): Promise<{ deletedCount: number }>;
  deleteMany(filter: Record<string, unknown>): Promise<{ deletedCount: number }>;
}

interface CredentialStoreAtscriptDbOptions<TClaims extends object> {
  table: AuthCredentialTable<TClaims>;
}

/**
 * atscript-db-backed `CredentialStore`.
 *
 * - `persist` generates a random UUID token id, inserts a row.
 * - `retrieve` filters by `{ token }` and rejects rows past `expiresAt`,
 *   deleting the dead row opportunistically.
 * - `revokeAllForUser` uses `deleteMany({ userId })` — one round trip.
 * - `listForUser` uses `findMany({ filter: { userId } })` — native.
 *
 * The store assumes the table is keyed on `token` (matches the shipped
 * `.as` model). Custom tables must keep `token` as PK or override the
 * adapter.
 */
export class CredentialStoreAtscriptDb<
  TClaims extends object = object,
> implements CredentialStore<TClaims> {
  private readonly table: AuthCredentialTable<TClaims>;

  constructor(opts: CredentialStoreAtscriptDbOptions<TClaims>) {
    this.table = opts.table;
  }

  async persist(state: CredentialState<TClaims>, ttl?: number): Promise<string> {
    const token = randomUUID();
    const expiresAt = typeof ttl === "number" ? Date.now() + ttl : state.expiresAt;
    const row: AuthCredentialRow<TClaims> = {
      token,
      userId: state.userId,
      issuedAt: state.issuedAt,
      expiresAt,
      kind: state.kind,
      claims: state.claims,
      metadata: state.metadata,
      parentCredentialId: state.parentCredentialId,
      rotatedAt: state.rotatedAt,
    };
    await this.table.insertOne(row);
    return token;
  }

  async retrieve(token: string): Promise<CredentialState<TClaims> | null> {
    const row = await this.table.findOne({ filter: { token } });
    if (!row) return null;
    if (row.expiresAt <= Date.now()) {
      // Lazy GC of an expired row — keeps the table tidy on read.
      await this.table.deleteOne(token).catch(() => {});
      return null;
    }
    return rowToState(row);
  }

  async consume(token: string): Promise<CredentialState<TClaims> | null> {
    const state = await this.retrieve(token);
    if (!state) return null;
    await this.revoke(token);
    return state;
  }

  async update(token: string, state: CredentialState<TClaims>): Promise<string> {
    const existing = await this.table.findOne({ filter: { token } });
    if (!existing) {
      // Mirror the memory/Redis stores: unknown tokens are no-ops.
      return token;
    }
    if (state.expiresAt <= Date.now()) {
      // Parity with the Redis adapter: an update that pushes the credential
      // past expiry is treated as a revoke, not a write of a dead row.
      await this.revoke(token);
      return token;
    }
    const row: AuthCredentialRow<TClaims> = {
      token,
      userId: state.userId,
      issuedAt: state.issuedAt,
      expiresAt: state.expiresAt,
      kind: state.kind,
      claims: state.claims,
      metadata: state.metadata,
      parentCredentialId: state.parentCredentialId,
      rotatedAt: state.rotatedAt,
    };
    await this.table.replaceOne(row);
    return token;
  }

  async revoke(token: string): Promise<void> {
    await this.table.deleteOne(token);
  }

  async revokeAllForUser(userId: string): Promise<number> {
    const result = await this.table.deleteMany({ userId });
    return result.deletedCount;
  }

  async listForUser(userId: string): Promise<Array<CredentialState<TClaims> & { token: string }>> {
    const now = Date.now();
    const rows = await this.table.findMany({ filter: { userId } });
    const out: Array<CredentialState<TClaims> & { token: string }> = [];
    const expired: string[] = [];
    for (const row of rows) {
      if (row.expiresAt <= now) {
        expired.push(row.token);
        continue;
      }
      out.push({ ...rowToState(row), token: row.token });
    }
    if (expired.length > 0) {
      await this.table.deleteMany({ token: { $in: expired } }).catch(() => {});
    }
    return out;
  }
}

function rowToState<TClaims extends object>(
  row: AuthCredentialRow<TClaims>,
): CredentialState<TClaims> {
  const state: CredentialState<TClaims> = {
    userId: row.userId,
    issuedAt: row.issuedAt,
    expiresAt: row.expiresAt,
  };
  if (row.claims !== undefined) state.claims = row.claims;
  if (row.metadata !== undefined) state.metadata = row.metadata;
  if (row.kind === "access" || row.kind === "refresh") state.kind = row.kind;
  if (row.parentCredentialId !== undefined) state.parentCredentialId = row.parentCredentialId;
  if (row.rotatedAt !== undefined) state.rotatedAt = row.rotatedAt;
  return state;
}
