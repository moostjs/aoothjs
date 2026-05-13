import type { EventContext } from "@wooksjs/event-core";
import { defineWook, key } from "@wooksjs/event-core";

/** Resolves a user record by id. `null` when the user does not exist. */
export type UserRecordFetcher = (userId: string) => Promise<unknown>;

// Cache keyed by userId so a single event that evaluates policy for multiple
// subjects (e.g. an admin handler that checks another user's permissions via
// `ArbacUserProvider.getAttrs(otherId)`) gets correct, isolated records.
const userRecordsKey = key<Map<string, Promise<unknown>> | undefined>("arbac.userRecords");

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
 * Per-event memoized accessor: the first `get(id)` for a given id fires the
 * configured fetcher; subsequent calls for the same id within the same event
 * reuse the in-flight/cached promise. Calls for a different id do NOT collide
 * — each id is cached independently. Guarantees one DB read per
 * (request, userId) pair.
 */
export const useUserRecord = defineWook((ctx: EventContext): UserRecordAccess => {
  return {
    get(userId: string): Promise<unknown> {
      let cache = ctx.has(userRecordsKey) ? ctx.get(userRecordsKey) : undefined;
      if (!cache) {
        cache = new Map<string, Promise<unknown>>();
        ctx.set(userRecordsKey, cache);
      }
      const cached = cache.get(userId);
      if (cached !== undefined) return cached;
      if (!recordFetcher) {
        throw new Error(
          "arbac-moost/atscript: no user-record fetcher configured — call setupArbacFromAtscript(moost, ...) before handling requests",
        );
      }
      const promise = recordFetcher(userId);
      cache.set(userId, promise);
      return promise;
    },
  };
});
