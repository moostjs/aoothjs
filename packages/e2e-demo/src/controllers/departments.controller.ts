import { ArbacResource, AsArbacDbController } from "@aooth/arbac-moost";
import type { AtscriptDbTable } from "@atscript/db";
import { TableController } from "@atscript/moost-db";

import type { Department } from "../models/department.as";
import type { DbControllerCtor } from "./_helpers";

export function makeDepartmentsController(
  table: AtscriptDbTable<typeof Department>,
): DbControllerCtor<typeof Department> {
  @TableController(table)
  @ArbacResource("departments")
  class DepartmentsController extends AsArbacDbController<typeof Department> {}
  return DepartmentsController as unknown as DbControllerCtor<typeof Department>;
}
