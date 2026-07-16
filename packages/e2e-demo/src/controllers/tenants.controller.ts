import { ArbacResource, AsArbacDbController } from "@aooth/arbac-moost";
import { TableController } from "@atscript/moost-db";

import { Tenant } from "../models/tenant.as";

@TableController(Tenant)
@ArbacResource("tenants")
export class TenantsController extends AsArbacDbController<typeof Tenant> {}
