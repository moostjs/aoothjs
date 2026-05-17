import { ArbacResource, AsArbacDbController } from "@aooth/arbac-moost";
import type { AtscriptDbTable } from "@atscript/db";
import { TableController } from "@atscript/moost-db";

import type { AuditEntry } from "../models/audit.as";
import type { DbControllerCtor } from "./_helpers";

export function makeAuditController(
  table: AtscriptDbTable<typeof AuditEntry>,
): DbControllerCtor<typeof AuditEntry> {
  @TableController(table)
  @ArbacResource("audit")
  class AuditController extends AsArbacDbController<typeof AuditEntry> {}
  return AuditController as unknown as DbControllerCtor<typeof AuditEntry>;
}
