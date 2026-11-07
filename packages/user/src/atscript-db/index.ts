import { UserAuthError } from "../errors";
import { UserStore, type WithCasOptions } from "../store/user-store";
import type { UserCredentials, UserStoreUpdate } from "../types";
import { dropNullFields, setAtPath } from "../utils";

/**
 * Persisted row shape — `UserCredentials` plus the consumer's custom user
 * fields. The `.as` model shipped at `@aooth/user/atscript-db/model.as`
 * (`AoothUserCredentials`) matches by construction; consumers extend it with
 * their own `.as` interface to add custom columns.
 */
export type UserCredentialsRow<TUserCustom extends object = object> = UserCredentials & TUserCustom;

/**
 * Structural surface of `AtscriptDbTable` covering exactly the methods this
 * adapter calls. Kept loose to avoid pulling `@atscript/db` types into the
 * `@aooth/user` public surface — consumers pass `db.getTable(AoothUserCredentials)`
 * directly and TypeScript matches by-shape.
 *
 * Mirrors `AuthCredentialTable` from `@aooth/auth/atscript-db`.
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
  deleteMany(filter: Record<string, unknown>): Promise<{ deletedCount: number }>;
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

/** Optional aooth-owned `account.*` fields (see {@link fromRow}). */
const OPTIONAL_ACCOUNT_FIELDS = [
  "pendingInvitation",
  "invitedBy",
  "inviteNonce",
  "verifiedEmail",
] as const;
/** Optional aooth-owned root fields (see {@link fromRow}). */
const OPTIONAL_ROOT_FIELDS = ["trustedDevices", "seenDevices"] as const;

/**
 * The DB returns an unset optional column as `null` on SQL engines (Mongo
 * omits the key); drop `null` from the optional aooth-owned paths so a row
 * matches the memory store + the `field?` contract — a NULL `inviteNonce` on a
 * pre-0.2 invite must read as absent, not as a different nonce.
 */
function fromRow<R extends UserCredentials>(row: R): R {
  if (row.account) dropNullFields(row.account, OPTIONAL_ACCOUNT_FIELDS);
  dropNullFields(row, OPTIONAL_ROOT_FIELDS);
  return row;
}

interface UsersStoreAtscriptDbOptions<TUserCustom extends object> {
  table: AuthUserTable<TUserCustom>;
  /**
   * Ordered login-handle field names (e.g. email then phone), resolved from the
   * model's `@aooth.user.*` annotations by the wiring layer (`handleFields` of
   * `getAoothUserHandleSpec`). `findByHandle` falls back to a `{ [field]: handle }`
   * lookup for each, in order, after `username`. Omit/empty to disable handle
   * resolution (login by anything but `username` unavailable). The base credential
   * model no longer hardcodes `email` — the field names are whatever the
   * consumer's `.as` model annotates.
   */
  handleFields?: string[];
}

/**
 * `@atscript/db`-backed `UserStore`. Pass the resolved table for the
 * `AoothUserCredentials` (or a `.as` interface extending it) shipped at the
 * `@aooth/user/atscript-db/model.as` subpath. Identity reads use the
 * `@meta.id` PK (`id`) and the unique `username` index, plus any
 * annotation-resolved `handleFields`; writes key on `id`.
 */
export class UsersStoreAtscriptDb<
  TUserCustom extends object = object,
> extends UserStore<TUserCustom> {
  protected table: AuthUserTable<TUserCustom>;
  /** Secondary handle fields tried (in order) by `findByHandle` after `username`. */
  protected readonly handleFields: string[];

  constructor(opts: UsersStoreAtscriptDbOptions<TUserCustom>) {
    super();
    this.table = opts.table;
    this.handleFields = opts.handleFields ?? [];
  }

  async exists(handle: string): Promise<boolean> {
    const count = await this.table.count({ filter: { username: handle } });
    return count > 0;
  }

  /** The one row read every finder goes through — normalized by {@link fromRow}. */
  private async findRow(
    filter: Record<string, unknown>,
  ): Promise<(UserCredentials & TUserCustom) | null> {
    const row = await this.table.findOne({ filter });
    return row && fromRow(row);
  }

  async findById(id: string): Promise<(UserCredentials & TUserCustom) | null> {
    return this.findRow({ id });
  }

  async findByHandle(handle: string): Promise<(UserCredentials & TUserCustom) | null> {
    const byUsername = await this.findRow({ username: handle });
    if (byUsername) return byUsername;
    for (const field of this.handleFields) {
      const byHandle = await this.findRow({ [field]: handle });
      if (byHandle) return byHandle;
    }
    return null;
  }

  async findByIdentifier(value: string): Promise<(UserCredentials & TUserCustom) | null> {
    return (await this.findRow({ id: value })) ?? this.findByHandle(value);
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

  async update(id: string, update: UserStoreUpdate): Promise<boolean> {
    const patch: Record<string, unknown> = { id };

    if (update.set) {
      Object.assign(patch, update.set);
    }

    if (update.inc) {
      for (const [path, amount] of Object.entries(update.inc)) {
        setAtPath(patch, path, { $inc: amount });
      }
    }

    // If only the id was set (no actual changes), no-op.
    if (Object.keys(patch).length <= 1) return true;

    if (update.expectedVersion !== undefined) {
      patch.$cas = { version: update.expectedVersion };
    }

    try {
      const result = await this.table.updateOne(patch);
      return result.matchedCount > 0;
    } catch (e: unknown) {
      // Symmetric with `create`: a unique-index collision — e.g. promoting a
      // confirmed email/phone into its handle column when another account
      // already owns that value — surfaces as a typed `ALREADY_EXISTS` rather
      // than a raw `@atscript/db` `CONFLICT`, so callers (promote-to-handle)
      // can treat it as a best-effort no-op instead of a 500.
      if (isConflict(e)) {
        throw new UserAuthError("ALREADY_EXISTS", "Update conflicts with an existing unique value");
      }
      throw e;
    }
  }

  async delete(id: string, opts?: { expectedVersion?: number }): Promise<boolean> {
    const filter: Record<string, unknown> = { id };
    if (opts?.expectedVersion !== undefined) filter.version = opts.expectedVersion;
    const result = await this.table.deleteMany(filter);
    return result.deletedCount > 0;
  }

  /**
   * Inline retry loop rather than delegating to @atscript/db's
   * `withOptimisticRetry`: that helper expects the mutator to always return a
   * patch object, but our contract lets the mutator return `null` (the
   * race-loser detects nothing to do — used by callers whose mutator opts
   * out of a write after re-reading state). Bridging would need a sentinel
   * exception. The version-bump + $cas atomicity still happen at the
   * atscript-db table layer via the `expectedVersion` we thread through
   * `update()`.
   */
  async withCas(
    id: string,
    mutator: (current: UserCredentials & TUserCustom) => UserStoreUpdate | null,
    opts?: WithCasOptions,
  ): Promise<void> {
    const maxAttempts = opts?.maxAttempts ?? 2;
    for (let attempt = 0; attempt < maxAttempts; attempt++) {
      const current = await this.findById(id);
      if (!current) throw new UserAuthError("NOT_FOUND");
      const patch = mutator(current);
      if (patch === null) return;
      const applied = await this.update(id, {
        ...patch,
        expectedVersion: current.version ?? 0,
      });
      if (applied) return;
    }
    throw new UserAuthError("CAS_EXHAUSTED");
  }
}

export {
  FederatedIdentityStoreAtscriptDb,
  type FederatedIdentityTable,
} from "./federated-identity-store";
