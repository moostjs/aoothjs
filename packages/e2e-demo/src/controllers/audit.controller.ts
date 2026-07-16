import { ArbacResource, AsArbacDbController } from "@aooth/arbac-moost";
import { TableController } from "@atscript/moost-db";

import { AuditEntry } from "../models/audit.as";

@TableController(AuditEntry)
@ArbacResource("audit")
export class AuditController extends AsArbacDbController<typeof AuditEntry> {}
