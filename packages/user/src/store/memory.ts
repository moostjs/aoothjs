import { randomUUID } from "node:crypto";

import { UserAuthError } from "../errors";
import type { UserCredentials, UserStoreUpdate } from "../types";
import { UserStore, type WithCasOptions } from "./user-store";
import { deepMerge, incrementAtPath } from "../utils";

export class UserStoreMemory<T extends object = object> extends UserStore<T> {
  /** Keyed by the stable surrogate `id` (the token subject). */
  private store = new Map<string, UserCredentials & T>();

  /**
   * Ordered secondary handle fields (e.g. email then phone) resolved from the
   * model's `@aooth.user.*` annotations by the wiring layer (`handleFields` of
   * `getAoothUserHandleSpec`). Tried by `findByHandle` after `username`, and
   * enforced unique by `create`. Empty when no handles are configured (login by
   * email/phone unavailable).
   */
  private readonly handleFields: string[];

  /**
   * Optional seed. The map is keyed by each record's `id`; a record missing an
   * `id` gets one minted (mirrors the DB `@db.default.uuid`). The seed object's
   * keys are ignored — identity is the record's `id`.
   *
   * `opts.handleFields` names the ordered secondary login handles (mirroring
   * `UsersStoreAtscriptDb`); omit it for username-only resolution.
   */
  constructor(seed?: Record<string, UserCredentials & T>, opts?: { handleFields?: string[] }) {
    super();
    this.handleFields = opts?.handleFields ?? [];
    if (seed) {
      for (const value of Object.values(seed)) {
        const cloned = structuredClone(value);
        if (!cloned.id) cloned.id = randomUUID();
        this.store.set(cloned.id, cloned);
      }
    }
  }

  async exists(handle: string): Promise<boolean> {
    for (const u of this.store.values()) {
      if (u.username === handle) return true;
    }
    return false;
  }

  async findById(id: string): Promise<(UserCredentials & T) | null> {
    const user = this.store.get(id);
    return user ? structuredClone(user) : null;
  }

  async findByHandle(handle: string): Promise<(UserCredentials & T) | null> {
    let byHandle: (UserCredentials & T) | null = null;
    for (const u of this.store.values()) {
      if (u.username === handle) return structuredClone(u);
      if (byHandle === null) {
        const rec = u as Record<string, unknown>;
        for (const field of this.handleFields) {
          const value = rec[field];
          if (value !== undefined && value === handle) {
            byHandle = u;
            break;
          }
        }
      }
    }
    return byHandle ? structuredClone(byHandle) : null;
  }

  async findByIdentifier(value: string): Promise<(UserCredentials & T) | null> {
    const byId = this.store.get(value);
    if (byId) return structuredClone(byId);
    return this.findByHandle(value);
  }

  async create(data: UserCredentials & T): Promise<void> {
    const cloned = structuredClone(data);
    if (!cloned.id) cloned.id = randomUUID();
    for (const u of this.store.values()) {
      if (u.username === cloned.username) {
        throw new UserAuthError("ALREADY_EXISTS", `User "${cloned.username}" already exists`);
      }
    }
    // New row not yet in the store, so there is no self to exclude.
    this.assertHandlesUnique(cloned as Record<string, unknown>);
    // OCC counter is server-managed: seed unconditionally, ignore caller-supplied version.
    cloned.version = 0;
    this.store.set(cloned.id, cloned);
  }

  /**
   * Throw `ALREADY_EXISTS` if any record other than `excludeId` already holds
   * one of `rec`'s handle-column values — the in-memory mirror of the
   * atscript-db store's unique index, so `create` and `update` enforce the same
   * collision contract (which `promote-to-handle` swallows best-effort). Handle
   * values are string columns; a non-string is never a collision.
   */
  private assertHandlesUnique(rec: Record<string, unknown>, excludeId?: string): void {
    for (const field of this.handleFields) {
      const value = rec[field];
      if (typeof value !== "string") continue;
      for (const [otherId, other] of this.store) {
        if (otherId === excludeId) continue;
        if ((other as Record<string, unknown>)[field] === value) {
          throw new UserAuthError("ALREADY_EXISTS", `${field} "${value}" already exists`);
        }
      }
    }
  }

  async update(id: string, update: UserStoreUpdate): Promise<boolean> {
    const user = this.store.get(id);
    if (!user) return false;
    if (update.expectedVersion !== undefined && (user.version ?? 0) !== update.expectedVersion) {
      return false;
    }
    if (update.set) {
      // Enforce handle uniqueness on writes that touch a handle column (mirrors
      // the atscript-db store's unique index) — excluding the record being
      // patched, since re-writing its own value is not a collision.
      this.assertHandlesUnique(update.set as Record<string, unknown>, id);
      deepMerge(user, update.set as Record<string, unknown>);
    }
    if (update.inc) {
      for (const [path, amount] of Object.entries(update.inc)) {
        incrementAtPath(user, path, amount);
      }
    }
    user.version = (user.version ?? 0) + 1;
    return true;
  }

  async delete(id: string): Promise<boolean> {
    return this.store.delete(id);
  }

  async withCas(
    id: string,
    mutator: (current: UserCredentials & T) => UserStoreUpdate | null,
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
