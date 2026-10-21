import { randomUUID } from "node:crypto";
import { credentialPayloadOf } from "../credential/payload";
import { AuthError } from "../errors";
import type {
  CredentialMetadata,
  CredentialState,
  CredentialSuccessorRef,
} from "../credential/types";
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
  successor?: CredentialSuccessorRef;
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
  /**
   * Optional PK-addressed patch (atscript-db's `updateOne`): lets `touch`
   * stamp `lastSeenAt` without re-reading the row. Never inserts.
   */
  updateOne?(patch: { token: string; lastSeenAt: number }): Promise<unknown>;
  /**
   * The table's annotated model (atscript-db's `table.type`). Read once to
   * find the `@aooth.auth.metadata` column when `metadataField` is not given.
   */
  readonly type?: unknown;
}

interface CredentialStoreAtscriptDbOptions<TPayload extends object> {
  table: AuthCredentialTable<TPayload>;
  /**
   * Column that persists the envelope's `metadata` — the consumer's
   * `@aooth.auth.metadata` + `@db.json` field on their `extends
   * AoothAuthCredential` model. Default: resolved automatically from
   * `table.type` (see {@link getAoothCredentialMetadataSpec}). `false` = no
   * metadata column (explicit opt-out).
   *
   * Without a column the store FAILS CLOSED: persisting a credential whose
   * metadata carries a per-token restriction (`accessTtl`, `refreshRotation`,
   * `rotationGraceMs`, `credentialKind`, `authzClientId`) throws `AuthError('INVALID_CONFIG')` — dropping
   * it would let e.g. a fixed-lifetime token family slide forever. Other
   * metadata (ip, user agent, label…) is dropped with a one-time warning.
   */
  metadataField?: string | false;
  /** Receives configuration warnings. Default: `console.warn`. */
  onWarning?: (message: string) => void;
}

/**
 * Metadata keys that carry per-token authority — losing them on a store
 * without a metadata column would silently widen what the token can do.
 */
export const AUTHORITY_METADATA_KEYS = [
  "accessTtl",
  "refreshRotation",
  "rotationGraceMs",
  "credentialKind",
  "authzClientId",
] as const satisfies readonly (keyof CredentialMetadata)[];

/** Resolved credential-metadata column of a credential model (see {@link getAoothCredentialMetadataSpec}). */
export interface AoothCredentialMetadataSpec {
  /** The `@aooth.auth.metadata` + `@db.json` field, or `undefined`. */
  metadataField: string | undefined;
  /** Non-fatal misconfiguration notes (an annotated field without `@db.json`). */
  warnings: string[];
}

interface StructuralAnnotatedType {
  type?: { kind?: string; props?: Map<string, { metadata?: { get(key: string): unknown } }> };
}

const specCache = new WeakMap<object, AoothCredentialMetadataSpec>();

/**
 * Find the credential-metadata column of a credential model: the field
 * annotated `@aooth.auth.metadata` (registered by `arbacPlugin`) that also
 * carries `@db.json`. An annotated field without `@db.json` resolves to
 * `undefined` with a warning; more than one annotated field throws. Cached
 * per model.
 */
export function getAoothCredentialMetadataSpec(
  credentialType: unknown,
): AoothCredentialMetadataSpec {
  const typed = credentialType as StructuralAnnotatedType | null;
  const cacheable = typed !== null && typeof typed === "object";
  if (cacheable) {
    const cached = specCache.get(typed);
    if (cached) return cached;
  }
  const spec: AoothCredentialMetadataSpec = { metadataField: undefined, warnings: [] };
  const def = typed?.type;
  if (def?.kind === "object" && def.props) {
    const candidates: Array<{ field: string; json: boolean }> = [];
    for (const [field, prop] of def.props) {
      if (prop.metadata?.get("aooth.auth.metadata")) {
        candidates.push({ field, json: Boolean(prop.metadata.get("db.json")) });
      }
    }
    if (candidates.length > 1) {
      throw new Error(
        `getAoothCredentialMetadataSpec: multiple @aooth.auth.metadata fields declared (${candidates
          .map((c) => c.field)
          .join(", ")}) — keep the annotation on exactly one field.`,
      );
    }
    const [only] = candidates;
    if (only?.json) spec.metadataField = only.field;
    else if (only) {
      spec.warnings.push(
        `@aooth.auth.metadata on field "${only.field}" has no @db.json — credential metadata will not be persisted. Add @db.json to the field.`,
      );
    }
  }
  if (cacheable) specCache.set(typed, spec);
  return spec;
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
  private readonly optedOut: boolean;
  private readonly warn: (message: string) => void;
  private warnedDroppedMetadata = false;

  constructor(opts: CredentialStoreAtscriptDbOptions<TPayload>) {
    this.table = opts.table;
    this.warn = opts.onWarning ?? ((message) => console.warn(`[aooth] ${message}`));
    this.optedOut = opts.metadataField === false;
    if (typeof opts.metadataField === "string") {
      this.metadataField = opts.metadataField;
    } else if (!this.optedOut && opts.table.type !== undefined) {
      const spec = getAoothCredentialMetadataSpec(opts.table.type);
      for (const warning of spec.warnings) this.warn(warning);
      this.metadataField = spec.metadataField;
    }
  }

  /**
   * No metadata column: refuse a state whose metadata carries per-token
   * authority (fail closed); drop the rest with a one-time warning.
   */
  private checkMetadata(state: CredentialState): void {
    if (this.metadataField !== undefined || state.metadata === undefined) return;
    const meta = state.metadata as Record<string, unknown>;
    const lost = AUTHORITY_METADATA_KEYS.filter((k) => meta[k] !== undefined);
    if (lost.length > 0) {
      throw new AuthError(
        "INVALID_CONFIG",
        `CredentialStoreAtscriptDb has no metadata column, so this credential's restrictions (${lost.join(
          ", ",
        )}) would be lost. Declare an @aooth.auth.metadata @db.json field on the credential model (or pass metadataField).`,
      );
    }
    if (!this.optedOut && !this.warnedDroppedMetadata) {
      this.warnedDroppedMetadata = true;
      this.warn(
        "CredentialStoreAtscriptDb has no metadata column — credential metadata (ip, user agent, label…) is not persisted. Declare an @aooth.auth.metadata @db.json field on the credential model, or pass metadataField: false to silence this.",
      );
    }
  }

  async persist(state: CredentialState & TPayload, ttl?: number): Promise<string> {
    const token = randomUUID();
    await this.persistAs(token, state, ttl);
    return token;
  }

  async persistAs(id: string, state: CredentialState & TPayload, ttl?: number): Promise<void> {
    this.checkMetadata(state);
    const expiresAt = typeof ttl === "number" ? Date.now() + ttl : state.expiresAt;
    await this.table.insertOne(stateToRow(state, id, expiresAt, this.metadataField));
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
    this.checkMetadata(state);
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

  async touch(token: string, at: number, state?: CredentialState & TPayload): Promise<void> {
    if (state && this.table.updateOne) {
      // The caller just read the row: patch the one column (a missing row
      // matches nothing — never resurrected).
      if (state.expiresAt <= Date.now()) return;
      await this.table.updateOne({ token, lastSeenAt: at });
      return;
    }
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
    successor: state.successor,
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
  if (row.successor !== undefined && row.successor !== null) state.successor = row.successor;
  if (row.sessionId !== undefined) state.sessionId = row.sessionId;
  if (row.lastSeenAt !== undefined) state.lastSeenAt = row.lastSeenAt;
  return state as CredentialState & TPayload;
}
