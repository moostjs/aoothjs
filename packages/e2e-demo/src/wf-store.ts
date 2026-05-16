import type { AtscriptDbTable } from "@atscript/db";
import { AsWfStore } from "@atscript/moost-wf/store";

import type { AppDb } from "./db";

export function createWfStore(appDb: AppDb): AsWfStore {
  return new AsWfStore({
    // The `AsWfStoreOptions.table` field is typed as `AtscriptDbTable<any>`
    // because consumer-extended row types (DemoWfState here) don't satisfy
    // `AtscriptDbTable<typeof AsWfStateRecord>` due to invariant generics.
    // The store only touches base columns, so the loose cast is safe.
    // biome-ignore lint/suspicious/noExplicitAny: see comment above
    table: appDb.tables.wfStates as unknown as AtscriptDbTable<any>,
  });
}
