import type { UserCredentials, UserStoreUpdate } from "../types";

export interface WithCasOptions {
  /**
   * Total attempts (1 initial + retries). Default `2` = one retry. Each
   * attempt re-reads the row so the mutator runs against fresh state — that
   * is the whole point of retry under OCC. Bump for high-contention writers
   * (bulk admin scripts); leave at default for normal per-user request flow.
   */
  maxAttempts?: number;
}

/**
 * Storage seam for user credentials, keyed by the stable surrogate **`id`**
 * (the token subject). Reads come in three flavours:
 *
 * - `findById` — strict, by the surrogate id; the canonical identity read used
 *   by authenticated flows that resolve the session subject (`getUserId()`).
 * - `findByHandle` — deterministic LOGIN resolver (`username`, then the
 *   annotation-resolved handle fields — email, then phone — in order).
 * - `findByIdentifier` — permissive internal/admin/recovery lookup (`id`, then
 *   the `findByHandle` chain).
 *
 * Writes (`update`/`delete`/`withCas`) all key on the surrogate `id`.
 */
export abstract class UserStore<T extends object = object> {
  /** True when a user with this login handle (`username`) exists. */
  abstract exists(handle: string): Promise<boolean>;
  /**
   * Strict read by the stable surrogate `id` — the token subject. Authenticated
   * flows resolve the session subject (`useAuth().getUserId()`) through this.
   */
  abstract findById(id: string): Promise<(UserCredentials & T) | null>;
  /**
   * Deterministic LOGIN resolver: matches `username` exactly, then each
   * annotation-resolved handle field (email, then phone) exactly, in that
   * order. Intentionally NOT a permissive `$or` — handle values are all
   * strings, so a permissive match could silently resolve a value that is one
   * user's username and another's email to an arbitrary account. Each handle
   * field is unique-when-present (the `@aooth.user.*` boot contract), so a
   * present value resolves to at most one row.
   */
  abstract findByHandle(handle: string): Promise<(UserCredentials & T) | null>;
  /**
   * Permissive lookup for internal / admin / recovery callers: `id`, then the
   * `findByHandle` chain (`username`, then the resolved handle fields). NOT for
   * the login path — use `findByHandle` there.
   */
  abstract findByIdentifier(value: string): Promise<(UserCredentials & T) | null>;
  abstract create(data: UserCredentials & T): Promise<void>;
  /** Apply a patch to the row identified by the stable `id`. */
  abstract update(id: string, update: UserStoreUpdate): Promise<boolean>;
  /**
   * Hard-delete the row by `id`. Returns `true` when a row was removed, `false`
   * when the id was not found.
   */
  abstract delete(id: string): Promise<boolean>;
  /**
   * Run a read-modify-write cycle under optimistic concurrency, keyed by `id`.
   * Each attempt re-reads (via `findById`), calls `mutator`, and applies the
   * returned patch under CAS (`expectedVersion = current.version`). On CAS miss
   * the cycle repeats up to `opts.maxAttempts`. The mutator MAY return `null`
   * to exit early without writing (race-loser "nothing left to do").
   *
   * Throws `UserAuthError("NOT_FOUND")` when no row matches `id`, or
   * `UserAuthError("CAS_EXHAUSTED")` when retries are saturated. Errors thrown
   * from inside `mutator` propagate immediately without retry.
   */
  abstract withCas(
    id: string,
    mutator: (current: UserCredentials & T) => UserStoreUpdate | null,
    opts?: WithCasOptions,
  ): Promise<void>;
}
