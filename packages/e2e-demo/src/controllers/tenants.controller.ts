import { ArbacResource, AsArbacDbController } from "@aooth/arbac-moost";
import type { AtscriptDbTable } from "@atscript/db";
import { TableController } from "@atscript/moost-db";

import type { Tenant } from "../models/tenant.as";
import type { DbControllerCtor } from "./_helpers";

export function makeTenantsController(
  table: AtscriptDbTable<typeof Tenant>,
): DbControllerCtor<typeof Tenant> {
  @TableController(table)
  @ArbacResource("tenants")
  class TenantsController extends AsArbacDbController<typeof Tenant> {}
  return TenantsController as unknown as DbControllerCtor<typeof Tenant>;
}
