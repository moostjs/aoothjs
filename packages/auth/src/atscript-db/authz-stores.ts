import { randomUUID } from "node:crypto";

import {
  DEFAULT_PENDING_TTL_MS,
  type NewPendingAuthorization,
  type PendingAuthorization,
  PendingAuthorizationStore,
} from "../authz/pending-authorization-store";
import {
  type AuthCode,
  AuthCodeStore,
  DEFAULT_CODE_TTL_MS,
  type NewAuthCode,
} from "../authz/auth-code-store";
import type { TokenPolicy } from "../authz/token-policy";
import { type Clock, defaultClock } from "../utils/clock";

/**
 * atscript-db-backed durable implementations of the two short-lived
 * authorization-server stores (AUTH-SERVER.md §4.3) — the multi-pod replacement
 * for the in-memory reference impls. They slot under the same DI tokens
 * (`PENDING_AUTHORIZATION_STORE_TOKEN` / `AUTH_CODE_STORE_TOKEN`) so a deployment
 * swaps memory → durable with zero controller change.
 *
 * Row types are re-declared as plain TS (mirroring the `.as` models
 * `AoothPendingAuthorization` / `AoothAuthCode`), so `@aooth/auth` needs no
 * build-time `@atscript/db` dependency. `tokenPolicy` is persisted as a JSON
 * STRING — its `payload` is an open `Record<string, unknown>` that a closed
 * `@db.json` schema would reject — and (de)serialized at this boundary.
 */

// ── PendingAuthorizationStore ───────────────────────────────────────────────

/** Persisted row — mirrors `AoothPendingAuthorization` (`pending-authorization.as`). */
export interface PendingAuthorizationRow {
  handle: string;
  redirectUri: string;
  codeChallenge: string;
  clientId?: string;
  clientState?: string;
  scope?: string;
  nonce?: string;
  idToken?: boolean;
  accessToken?: boolean;
  audience?: string;
  /** `JSON.stringify(TokenPolicy)`. */
  tokenPolicy: string;
  createdAt: number;
  expiresAt: number;
}

/**
 * Structural surface of `AtscriptDbTable` covering exactly the methods this
 * adapter calls — kept loose so `@atscript/db` types stay out of the public
 * surface (consumers pass `db.getTable(AoothPendingAuthorization)` and TS matches
 * by-shape, same seam as `AuthCredentialTable`).
 */
export interface PendingAuthorizationTable {
  insertOne(row: PendingAuthorizationRow): Promise<{ insertedId: unknown }>;
  findOne(query: { filter: Record<string, unknown> }): Promise<PendingAuthorizationRow | null>;
  deleteOne(idOrPk: unknown): Promise<{ deletedCount: number }>;
}

export interface PendingAuthorizationStoreAtscriptDbOptions {
  table: PendingAuthorizationTable;
  /** Injectable clock for deterministic expiry. Defaults to {@link defaultClock}. */
  clock?: Clock;
  /** How long a pending authorization stays valid. Default 15 min. */
  ttlMs?: number;
}

/**
 * Durable {@link PendingAuthorizationStore}. `create` inserts a row keyed by a
 * fresh opaque `handle`; `get` rejects (and lazily evicts) a past-expiry row;
 * `delete` drops it once consumed. PK is `handle`, so reads/deletes are O(1).
 */
export class PendingAuthorizationStoreAtscriptDb extends PendingAuthorizationStore {
  private readonly table: PendingAuthorizationTable;
  private readonly clock: Clock;
  private readonly ttlMs: number;

  constructor(opts: PendingAuthorizationStoreAtscriptDbOptions) {
    super();
    this.table = opts.table;
    this.clock = opts.clock ?? defaultClock;
    this.ttlMs = opts.ttlMs ?? DEFAULT_PENDING_TTL_MS;
  }

  async create(rec: NewPendingAuthorization): Promise<{ handle: string }> {
    const now = this.clock.now();
    const handle = randomUUID();
    await this.table.insertOne({
      handle,
      redirectUri: rec.redirectUri,
      codeChallenge: rec.codeChallenge,
      tokenPolicy: JSON.stringify(rec.tokenPolicy),
      createdAt: now,
      expiresAt: now + this.ttlMs,
      ...(rec.clientId !== undefined && { clientId: rec.clientId }),
      ...(rec.clientState !== undefined && { clientState: rec.clientState }),
      ...(rec.scope !== undefined && { scope: rec.scope }),
      ...(rec.nonce !== undefined && { nonce: rec.nonce }),
      ...(rec.idToken !== undefined && { idToken: rec.idToken }),
      ...(rec.accessToken !== undefined && { accessToken: rec.accessToken }),
      ...(rec.audience !== undefined && { audience: rec.audience }),
    });
    return { handle };
  }

  async get(handle: string): Promise<PendingAuthorization | null> {
    const row = await this.table.findOne({ filter: { handle } });
    if (!row) return null;
    if (row.expiresAt <= this.clock.now()) {
      // Lazy GC of an expired row — keeps the table tidy on read.
      await this.table.deleteOne(handle).catch(() => {});
      return null;
    }
    return rowToPending(row);
  }

  async delete(handle: string): Promise<boolean> {
    const { deletedCount } = await this.table.deleteOne(handle);
    return deletedCount > 0;
  }
}

function rowToPending(row: PendingAuthorizationRow): PendingAuthorization {
  const out: PendingAuthorization = {
    handle: row.handle,
    redirectUri: row.redirectUri,
    codeChallenge: row.codeChallenge,
    tokenPolicy: JSON.parse(row.tokenPolicy) as TokenPolicy,
    createdAt: row.createdAt,
    expiresAt: row.expiresAt,
  };
  // The DB returns an unset optional column as `null`; treat null as absent
  // (omit it) so the shape matches the memory store + the `field?` contract.
  if (row.clientId != null) out.clientId = row.clientId;
  if (row.clientState != null) out.clientState = row.clientState;
  if (row.scope != null) out.scope = row.scope;
  if (row.nonce != null) out.nonce = row.nonce;
  if (row.idToken != null) out.idToken = row.idToken;
  if (row.accessToken != null) out.accessToken = row.accessToken;
  if (row.audience != null) out.audience = row.audience;
  return out;
}

// ── AuthCodeStore ───────────────────────────────────────────────────────────

/** Persisted row — mirrors `AoothAuthCode` (`auth-code.as`). */
export interface AuthCodeRow {
  code: string;
  userId: string;
  codeChallenge: string;
  redirectUri: string;
  clientId?: string;
  scope?: string;
  nonce?: string;
  idToken?: boolean;
  accessToken?: boolean;
  audience?: string;
  /** `JSON.stringify(TokenPolicy)`. */
  tokenPolicy: string;
  expiresAt: number;
}

/** Structural surface of `AtscriptDbTable` for the auth-code adapter. */
export interface AuthCodeTable {
  insertOne(row: AuthCodeRow): Promise<{ insertedId: unknown }>;
  findOne(query: { filter: Record<string, unknown> }): Promise<AuthCodeRow | null>;
  deleteOne(idOrPk: unknown): Promise<{ deletedCount: number }>;
}

export interface AuthCodeStoreAtscriptDbOptions {
  table: AuthCodeTable;
  /** Injectable clock for deterministic expiry. Defaults to {@link defaultClock}. */
  clock?: Clock;
  /** Code lifetime. Default 60 s. */
  ttlMs?: number;
}

/**
 * Durable {@link AuthCodeStore}. `mint` inserts a single-use code; `consume`
 * is an **atomic check-and-delete**: it reads the row, then `deleteOne(code)`
 * — and only the caller whose delete reports `deletedCount === 1` wins the row.
 * Because an auth-code row is immutable once minted, the value read before the
 * delete is exactly what the winner returns; a concurrent double-redeem or a
 * back-button replay loses the race and gets `null`. (The delete is the claim,
 * so no version column is needed — `deleteOne(PK)` is atomic per the DB engine.)
 */
export class AuthCodeStoreAtscriptDb extends AuthCodeStore {
  private readonly table: AuthCodeTable;
  private readonly clock: Clock;
  private readonly ttlMs: number;

  constructor(opts: AuthCodeStoreAtscriptDbOptions) {
    super();
    this.table = opts.table;
    this.clock = opts.clock ?? defaultClock;
    this.ttlMs = opts.ttlMs ?? DEFAULT_CODE_TTL_MS;
  }

  async mint(rec: NewAuthCode): Promise<{ code: string }> {
    const code = randomUUID();
    await this.table.insertOne({
      code,
      userId: rec.userId,
      codeChallenge: rec.codeChallenge,
      redirectUri: rec.redirectUri,
      tokenPolicy: JSON.stringify(rec.tokenPolicy),
      expiresAt: this.clock.now() + this.ttlMs,
      ...(rec.clientId !== undefined && { clientId: rec.clientId }),
      ...(rec.scope !== undefined && { scope: rec.scope }),
      ...(rec.nonce !== undefined && { nonce: rec.nonce }),
      ...(rec.idToken !== undefined && { idToken: rec.idToken }),
      ...(rec.accessToken !== undefined && { accessToken: rec.accessToken }),
      ...(rec.audience !== undefined && { audience: rec.audience }),
    });
    return { code };
  }

  async consume(code: string): Promise<AuthCode | null> {
    const row = await this.table.findOne({ filter: { code } });
    if (!row) return null;
    // Atomic single-use claim — only one concurrent consume gets deletedCount 1.
    const { deletedCount } = await this.table.deleteOne(code);
    if (deletedCount !== 1) return null;
    if (row.expiresAt <= this.clock.now()) return null;
    return rowToAuthCode(row);
  }
}

function rowToAuthCode(row: AuthCodeRow): AuthCode {
  const out: AuthCode = {
    code: row.code,
    userId: row.userId,
    codeChallenge: row.codeChallenge,
    redirectUri: row.redirectUri,
    tokenPolicy: JSON.parse(row.tokenPolicy) as TokenPolicy,
    expiresAt: row.expiresAt,
  };
  if (row.clientId != null) out.clientId = row.clientId;
  if (row.scope != null) out.scope = row.scope;
  if (row.nonce != null) out.nonce = row.nonce;
  if (row.idToken != null) out.idToken = row.idToken;
  if (row.accessToken != null) out.accessToken = row.accessToken;
  if (row.audience != null) out.audience = row.audience;
  return out;
}
