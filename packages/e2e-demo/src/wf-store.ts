import type { AtscriptDbTable } from "@atscript/db";
import { AsWfStore } from "@atscript/moost-wf/store";

import type { AppDb } from "./db";

/**
 * Controllable clock for the durable wf-state store. `AsWfStore` checks every
 * row's `expiresAt` against `clock.now()` on resume, so shifting `offsetMs`
 * forward "fast-forwards" the store past a paused state's TTL without
 * sleeping — test-only (`POST /__test/wf-states/advance-clock`), reset to 0
 * by `POST /__test/reset`. Real time elsewhere (JWTs, pincode expiry, the
 * `expiresAt` stamp itself) is untouched, so only the store's view of "is
 * this paused state expired?" moves.
 */
export interface WfStoreClock {
  offsetMs: number;
  now(): number;
}

export function createWfStoreClock(): WfStoreClock {
  return {
    offsetMs: 0,
    now() {
      return Date.now() + this.offsetMs;
    },
  };
}

export function createWfStore(appDb: AppDb, clock?: WfStoreClock): AsWfStore {
  return new AsWfStore({
    // The `AsWfStoreOptions.table` field is typed as `AtscriptDbTable<any>`
    // because consumer-extended row types (DemoWfState here) don't satisfy
    // `AtscriptDbTable<typeof AsWfStateRecord>` due to invariant generics.
    // The store only touches base columns, so the loose cast is safe.
    // biome-ignore lint/suspicious/noExplicitAny: see comment above
    table: appDb.tables.wfStates,
    clock,
  });
}
