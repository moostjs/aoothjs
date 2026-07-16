import { ArbacResource, AsArbacDbController } from "@aooth/arbac-moost";
import { TableController } from "@atscript/moost-db";

import { Department } from "../models/department.as";

@TableController(Department)
@ArbacResource("departments")
export class DepartmentsController extends AsArbacDbController<typeof Department> {}
