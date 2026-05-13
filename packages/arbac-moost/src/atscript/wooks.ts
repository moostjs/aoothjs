import type { EventContext } from "@wooksjs/event-core";
import { defineWook, key } from "@wooksjs/event-core";

/** Resolves a user record by id. `null` when the user does not exist. */
export type UserRecordFetcher = (userId: string) => Promise<unknown>;

const userRecordKey = key<Promise<unknown> | undefined>("arbac.userRecord");

// Module-level rather than DI so wooks read records without round-tripping
// through controller context. Auto-arbac assumes one user type per process.
let recordFetcher: UserRecordFetcher | undefined;

/** Installed by `setupArbacFromAtscript`. Pass `undefined` to clear (tests). */
export function setUserRecordFetcher(fetcher: UserRecordFetcher | undefined): void {
  recordFetcher = fetcher;
}

interface UserRecordAccess {
  get(userId: string): Promise<unknown>;
}

/**
 * Per-event memoized accessor: first `get(id)` fires the configured
 * fetcher; subsequent calls within the same event reuse the promise.
 * Guarantees one DB read per request across `getRoles` / `getAttrs`.
 */
export const useUserRecord = defineWook((ctx: EventContext): UserRecordAccess => {
  return {
    get(userId: string): Promise<unknown> {
      const cached = ctx.has(userRecordKey) ? ctx.get(userRecordKey) : undefined;
      if (cached !== undefined) return cached;
      if (!recordFetcher) {
        throw new Error(
          "arbac-moost/atscript: no user-record fetcher configured — call setupArbacFromAtscript(moost, ...) before handling requests",
        );
      }
      const promise = recordFetcher(userId);
      ctx.set(userRecordKey, promise);
      return promise;
    },
  };
});
