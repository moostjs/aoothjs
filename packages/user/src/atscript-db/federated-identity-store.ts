import { randomUUID } from "node:crypto";

import { UserAuthError } from "../errors";
import {
  FederatedIdentityStore,
  pickDefinedProfile,
  type FederatedIdentity,
  type FederatedProfileSnapshot,
  type NewFederatedIdentity,
} from "../store/federated-identity-store";

/**
 * Structural surface of `AtscriptDbTable` covering exactly the methods this
 * adapter calls — kept loose so `@aooth/user` doesn't pull `@atscript/db` types
 * into its public surface. Consumers pass `db.getTable(AoothFederatedIdentity)`
 * directly and TypeScript matches by-shape. Mirrors `AuthCredentialTable` from
 * `@aooth/auth/atscript-db`.
 */
export interface FederatedIdentityTable {
  insertOne(row: FederatedIdentity): Promise<{ insertedId: unknown }>;
  findOne(query: { filter: Record<string, unknown> }): Promise<FederatedIdentity | null>;
  findMany(query: { filter?: Record<string, unknown> }): Promise<FederatedIdentity[]>;
  replaceOne(row: FederatedIdentity): Promise<{ matchedCount: number; modifiedCount: number }>;
  deleteMany(filter: Record<string, unknown>): Promise<{ deletedCount: number }>;
}

interface DbErrorLike {
  code?: string;
}

function isConflict(err: unknown): boolean {
  return typeof err === "object" && err !== null && (err as DbErrorLike).code === "CONFLICT";
}

interface FederatedIdentityStoreAtscriptDbOptions {
  table: FederatedIdentityTable;
  /** Injectable clock for `linkedAt` / `lastLoginAt`. Defaults to `Date.now`. */
  clock?: () => number;
}

/**
 * `@atscript/db`-backed {@link FederatedIdentityStore}. Pass the resolved table
 * for the `AoothFederatedIdentity` model shipped at
 * `@aooth/user/atscript-db/federated-model`. The compound-unique
 * `(provider, subject)` index makes `find` an O(1) point read and turns a
 * cross-user re-link attempt into a `CONFLICT` (→ `ALREADY_EXISTS`); `userId`
 * is a plain indexed column, so `listForUser` / `deleteAllForUser` scan it
 * natively.
 */
export class FederatedIdentityStoreAtscriptDb extends FederatedIdentityStore {
  private readonly table: FederatedIdentityTable;
  private readonly clock: () => number;

  constructor(opts: FederatedIdentityStoreAtscriptDbOptions) {
    super();
    this.table = opts.table;
    this.clock = opts.clock ?? Date.now;
  }

  async find(provider: string, subject: string): Promise<FederatedIdentity | null> {
    return this.table.findOne({ filter: { provider, subject } });
  }

  async listForUser(userId: string): Promise<FederatedIdentity[]> {
    const rows = await this.table.findMany({ filter: { userId } });
    return rows.toSorted((a, b) => a.linkedAt - b.linkedAt);
  }

  async link(rec: NewFederatedIdentity): Promise<FederatedIdentity> {
    // Mint the PK in-store (mirrors the memory impl + `UserStoreMemory`);
    // `@db.default.uuid` on the model is the fallback for non-store writers.
    const row: FederatedIdentity = {
      id: randomUUID(),
      provider: rec.provider,
      subject: rec.subject,
      userId: rec.userId,
      ...pickDefinedProfile(rec),
      linkedAt: this.clock(),
    };
    try {
      await this.table.insertOne(row);
      return row;
    } catch (e: unknown) {
      if (isConflict(e)) {
        throw new UserAuthError(
          "ALREADY_EXISTS",
          `Provider account "${rec.provider}:${rec.subject}" is already linked`,
        );
      }
      throw e;
    }
  }

  async unlink(provider: string, subject: string): Promise<boolean> {
    const result = await this.table.deleteMany({ provider, subject });
    return result.deletedCount > 0;
  }

  async touchLogin(
    provider: string,
    subject: string,
    profile?: FederatedProfileSnapshot,
  ): Promise<void> {
    const row = await this.table.findOne({ filter: { provider, subject } });
    if (!row) return;
    // replaceOne keeps the adapter portable across engines without a patch op
    // (mirrors `CredentialStoreAtscriptDb.touch`).
    const next: FederatedIdentity = { ...row, lastLoginAt: this.clock() };
    if (profile) Object.assign(next, pickDefinedProfile(profile));
    await this.table.replaceOne(next);
  }

  async deleteAllForUser(userId: string): Promise<number> {
    const result = await this.table.deleteMany({ userId });
    return result.deletedCount;
  }
}
