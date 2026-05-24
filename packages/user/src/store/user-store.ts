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

export abstract class UserStore<T extends object = object> {
  abstract exists(username: string): Promise<boolean>;
  abstract findByUsername(username: string): Promise<(UserCredentials & T) | null>;
  abstract create(data: UserCredentials & T): Promise<void>;
  abstract update(username: string, update: UserStoreUpdate): Promise<boolean>;
  /**
   * Hard-delete the row. Returns `true` when a row was removed, `false` when
   * the username was not found. Used by `UserService.deleteUser` (and in turn
   * by the invite workflow's `auth/invite/cancel` step).
   */
  abstract delete(username: string): Promise<boolean>;
  /**
   * Run a read-modify-write cycle under optimistic concurrency. Each attempt
   * fetches the current row, calls `mutator` with it, and applies the returned
   * patch under CAS (`expectedVersion = current.version`). On CAS miss the
   * cycle repeats up to `opts.maxAttempts`. The mutator MAY return `null` to
   * exit early without writing — used for "race-loser detects nothing left to
   * do" paths (e.g. the backup code was already consumed by the winner).
   *
   * Throws `UserAuthError("NOT_FOUND")` when no row matches `username`, or
   * `UserAuthError("CAS_EXHAUSTED")` when retries are saturated. Errors
   * thrown from inside `mutator` propagate immediately without retry.
   */
  abstract withCas(
    username: string,
    mutator: (current: UserCredentials & T) => UserStoreUpdate | null,
    opts?: WithCasOptions,
  ): Promise<void>;
}
