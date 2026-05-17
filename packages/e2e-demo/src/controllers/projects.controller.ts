import { ArbacResource, AsArbacDbController } from "@aooth/arbac-moost";
import type { AtscriptDbTable } from "@atscript/db";
import { TableController } from "@atscript/moost-db";

import type { Project } from "../models/project.as";
import type { DbControllerCtor } from "./_helpers";

export function makeProjectsController(
  table: AtscriptDbTable<typeof Project>,
): DbControllerCtor<typeof Project> {
  @TableController(table)
  @ArbacResource("projects")
  class ProjectsController extends AsArbacDbController<typeof Project> {}
  return ProjectsController as unknown as DbControllerCtor<typeof Project>;
}
