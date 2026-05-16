import { UserAuthError } from "../errors";
import { UserStore } from "../store/user-store";
import type { UserCredentials, UserStoreUpdate } from "../types";
import { setAtPath } from "../utils";

/**
 * Persisted row shape — `UserCredentials` plus the consumer's custom user
 * fields. The `.as` model shipped at `@aoothjs/user/atscript-db/model.as`
 * (`AoothUserCredentials`) matches by construction; consumers extend it with
 * their own `.as` interface to add custom columns.
 */
export type UserCredentialsRow<TUserCustom extends object = object> = UserCredentials & TUserCustom;

/**
 * Structural surface of `AtscriptDbTable` covering exactly the methods this
 * adapter calls. Kept loose to avoid pulling `@atscript/db` types into the
 * `@aoothjs/user` public surface — consumers pass `db.getTable(AoothUserCredentials)`
 * directly and TypeScript matches by-shape.
 *
 * Mirrors `AuthCredentialTable` from `@aoothjs/auth/atscript-db`.
 */
export interface AuthUserTable<TUserCustom extends object = object> {
  count(query: { filter: Record<string, unknown> }): Promise<number>;
  findOne(query: {
    filter: Record<string, unknown>;
  }): Promise<UserCredentialsRow<TUserCustom> | null>;
  insertOne(row: Record<string, unknown>): Promise<{ insertedId: unknown }>;
  updateOne(
    patch: Record<string, unknown>,
  ): Promise<{ matchedCount: number; modifiedCount: number }>;
}

/**
 * Minimal `@atscript/db` error shape we recognize — the adapter only checks
 * `instanceof` indirectly via the `code` discriminator on a structurally
 * matching error, so we accept anything with a string `code` field. Real
 * `DbError` instances from `@atscript/db` match by shape; tests can throw
 * any object carrying `{ code: 'CONFLICT' }`.
 */
interface DbErrorLike {
  code?: string;
}

function isConflict(err: unknown): boolean {
  return typeof err === "object" && err !== null && (err as DbErrorLike).code === "CONFLICT";
}

interface UsersStoreAtscriptDbOptions<TUserCustom extends object> {
  table: AuthUserTable<TUserCustom>;
}

/**
 * `@atscript/db`-backed `UserStore`. Pass the resolved table for the
 * `AoothUserCredentials` (or a `.as` interface extending it) shipped at the
 * `@aoothjs/user/atscript-db/model.as` subpath.
 */
export class UsersStoreAtscriptDb<
  TUserCustom extends object = object,
> extends UserStore<TUserCustom> {
  protected table: AuthUserTable<TUserCustom>;

  constructor(opts: UsersStoreAtscriptDbOptions<TUserCustom>) {
    super();
    this.table = opts.table;
  }

  async exists(username: string): Promise<boolean> {
    const count = await this.table.count({ filter: { username } });
    return count > 0;
  }

  async findByUsername(username: string): Promise<(UserCredentials & TUserCustom) | null> {
    const result = await this.table.findOne({ filter: { username } });
    return (result as (UserCredentials & TUserCustom) | null) ?? null;
  }

  async create(data: UserCredentials & TUserCustom): Promise<void> {
    try {
      await this.table.insertOne(data as Record<string, unknown>);
    } catch (e: unknown) {
      if (isConflict(e)) {
        throw new UserAuthError("ALREADY_EXISTS", `User "${data.username}" already exists`);
      }
      throw e;
    }
  }

  async update(username: string, update: UserStoreUpdate): Promise<boolean> {
    const patch: Record<string, unknown> = { username };

    if (update.set) {
      Object.assign(patch, update.set);
    }

    if (update.inc) {
      for (const [path, amount] of Object.entries(update.inc)) {
        setAtPath(patch, path, { $inc: amount });
      }
    }

    // If only username was set (no actual changes), no-op
    if (Object.keys(patch).length <= 1) return true;

    const result = await this.table.updateOne(patch);
    return result.matchedCount > 0;
  }
}
