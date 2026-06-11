import { randomUUID } from "node:crypto";
import { credentialPayloadOf } from "../credential/payload";
import type { CredentialState } from "../credential/types";
import type { CredentialStore } from "../stores/store";

// Durable authorization-server stores (AUTH-SERVER.md §4.3) — same atscript-db
// adapter pattern as `CredentialStoreAtscriptDb` below.
export * from "./authz-stores";

/**
 * Persisted row shape — mirrors `AoothAuthCredential` from
 * `./auth-credential.as`. Re-declared here as a plain TS type so consumers can
 * use the adapter without running the atscript build (and so `@aooth/auth`
 * doesn't need to depend on `@atscript/typescript` at build time). When you DO
 * wire the `.as` model, the shapes match by construction.
 *
 * The consumer's typed payload `TPayload` (the root fields they add to their
 * `extends AoothAuthCredential` model) is intersected flat — those become real
 * typed columns, replacing the dropped free-form `claims` blob.
 *
 * There is NO `metadata` envelope column: credential metadata is
 * consumer-declared (a fully-typed `@db.json` field on the extending model,
 * marked `@aooth.auth.metadata`) and mapped dynamically through the
 * `metadataField` option below.
 */
export type AuthCredentialRow<TPayload extends object = object> = {
  token: string;
  userId: string;
  issuedAt: number;
  expiresAt: number;
  kind?: string;
  parentCredentialId?: string;
  rotatedAt?: number;
  sessionId?: string;
  lastSeenAt?: number;
} & TPayload;

/**
 * Structural surface of `AtscriptDbTable` covering exactly the methods this
 * adapter calls. Kept loose to avoid pulling `@atscript/db` types into the
 * `@aooth/auth` public surface — consumers pass `db.getTable(AoothAuthCredential)`
 * directly and TypeScript matches by-shape.
 */
export interface AuthCredentialTable<TPayload extends object = object> {
  insertOne(row: AuthCredentialRow<TPayload>): Promise<{ insertedId: unknown }>;
  findOne(query: { filter: Record<string, unknown> }): Promise<AuthCredentialRow<TPayload> | null>;
  findMany(query: {
    filter?: Record<string, unknown>;
    controls?: Record<string, unknown>;
  }): Promise<AuthCredentialRow<TPayload>[]>;
  replaceOne(
    row: AuthCredentialRow<TPayload>,
  ): Promise<{ matchedCount: number; modifiedCount: number }>;
  deleteOne(idOrPk: unknown): Promise<{ deletedCount: number }>;
  deleteMany(filter: Record<string, unknown>): Promise<{ deletedCount: number }>;
}

interface CredentialStoreAtscriptDbOptions<TPayload extends object> {
  table: AuthCredentialTable<TPayload>;
  /**
   * Name of the consumer's `@aooth.auth.metadata`-annotated column — the
   * fully-typed `@db.json` field declared on their `extends AoothAuthCredential`
   * model that persists the envelope's `metadata`. Resolved at boot by
   * `getAoothCredentialMetadataSpec` (`@aooth/arbac-moost/atscript`) and
   * threaded here as plain config — same pattern as `UserStore.handleFields`.
   * Absent → metadata is not persisted/read by this store.
   */
  metadataField?: string;
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
  TPayload extends object = object,
> implements CredentialStore<TPayload> {
  private readonly table: AuthCredentialTable<TPayload>;
  private readonly metadataField: string | undefined;

  constructor(opts: CredentialStoreAtscriptDbOptions<TPayload>) {
    this.table = opts.table;
    this.metadataField = opts.metadataField;
  }

  async persist(state: CredentialState & TPayload, ttl?: number): Promise<string> {
    const token = randomUUID();
    const expiresAt = typeof ttl === "number" ? Date.now() + ttl : state.expiresAt;
    await this.table.insertOne(stateToRow(state, token, expiresAt, this.metadataField));
    return token;
  }

  async retrieve(token: string): Promise<(CredentialState & TPayload) | null> {
    const row = await this.table.findOne({ filter: { token } });
    if (!row) return null;
    if (row.expiresAt <= Date.now()) {
      // Lazy GC of an expired row — keeps the table tidy on read.
      await this.table.deleteOne(token).catch(() => {});
      return null;
    }
    return rowToState(row, this.metadataField);
  }

  async consume(token: string): Promise<(CredentialState & TPayload) | null> {
    const state = await this.retrieve(token);
    if (!state) return null;
    await this.revoke(token);
    return state;
  }

  async update(token: string, state: CredentialState & TPayload): Promise<string> {
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
    await this.table.replaceOne(stateToRow(state, token, state.expiresAt, this.metadataField));
    return token;
  }

  async revoke(token: string): Promise<void> {
    await this.table.deleteOne(token);
  }

  async touch(token: string, at: number): Promise<void> {
    const row = await this.table.findOne({ filter: { token } });
    if (!row) return;
    if (row.expiresAt <= Date.now()) return;
    // replaceOne keeps the adapter portable across engines without a patch op.
    await this.table.replaceOne({ ...row, lastSeenAt: at });
  }

  async revokeAllForUser(userId: string): Promise<number> {
    const result = await this.table.deleteMany({ userId });
    return result.deletedCount;
  }

  async listForUser(
    userId: string,
  ): Promise<Array<CredentialState & TPayload & { token: string }>> {
    const now = Date.now();
    const rows = await this.table.findMany({ filter: { userId } });
    const out: Array<CredentialState & TPayload & { token: string }> = [];
    const expired: string[] = [];
    for (const row of rows) {
      if (row.expiresAt <= now) {
        expired.push(row.token);
        continue;
      }
      out.push({ ...rowToState(row, this.metadataField), token: row.token });
    }
    if (expired.length > 0) {
      await this.table.deleteMany({ token: { $in: expired } }).catch(() => {});
    }
    return out;
  }
}

/**
 * Build the persisted row from a credential state: typed payload columns first
 * (so an envelope field wins a name clash), then the fixed envelope fields and
 * the resolved `token` + `expiresAt`. Shared by `persist` and `update`, which
 * differ only in the `expiresAt` they resolve.
 *
 * The envelope's `metadata` is written to the consumer's `metadataField`
 * column (a dynamic key the static row type can't carry) — only when the
 * field is configured; otherwise metadata is silently not persisted.
 */
function stateToRow<TPayload extends object>(
  state: CredentialState & TPayload,
  token: string,
  expiresAt: number,
  metadataField: string | undefined,
): AuthCredentialRow<TPayload> {
  const row = {
    ...credentialPayloadOf<TPayload>(state),
    token,
    userId: state.userId,
    issuedAt: state.issuedAt,
    expiresAt,
    kind: state.kind,
    parentCredentialId: state.parentCredentialId,
    rotatedAt: state.rotatedAt,
    sessionId: state.sessionId,
    lastSeenAt: state.lastSeenAt,
  } as AuthCredentialRow<TPayload>;
  if (metadataField !== undefined && state.metadata !== undefined) {
    (row as Record<string, unknown>)[metadataField] = state.metadata;
  }
  return row;
}

/**
 * Inverse of {@link stateToRow}. The consumer's `metadataField` column maps
 * back onto the envelope's `metadata` — and is excluded from the extracted
 * payload (it is envelope data riding under a consumer-chosen name, not a
 * typed payload field).
 */
function rowToState<TPayload extends object>(
  row: AuthCredentialRow<TPayload>,
  metadataField: string | undefined,
): CredentialState & TPayload {
  // Typed payload columns first (excludes envelope keys + `token`); the
  // explicit envelope assignments below win any clash.
  const state: CredentialState = {
    ...credentialPayloadOf<TPayload>(row),
    userId: row.userId,
    issuedAt: row.issuedAt,
    expiresAt: row.expiresAt,
  };
  if (metadataField !== undefined) {
    delete (state as unknown as Record<string, unknown>)[metadataField];
    const metadata = (row as Record<string, unknown>)[metadataField];
    if (metadata !== undefined) state.metadata = metadata as CredentialState["metadata"];
  }
  if (row.kind === "access" || row.kind === "refresh") state.kind = row.kind;
  if (row.parentCredentialId !== undefined) state.parentCredentialId = row.parentCredentialId;
  if (row.rotatedAt !== undefined) state.rotatedAt = row.rotatedAt;
  if (row.sessionId !== undefined) state.sessionId = row.sessionId;
  if (row.lastSeenAt !== undefined) state.lastSeenAt = row.lastSeenAt;
  return state as CredentialState & TPayload;
}
