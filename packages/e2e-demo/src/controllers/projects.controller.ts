import { ArbacResource, AsArbacDbController } from "@aooth/arbac-moost";
import { TableController } from "@atscript/moost-db";

import { Project } from "../models/project.as";

@TableController(Project)
@ArbacResource("projects")
export class ProjectsController extends AsArbacDbController<typeof Project> {}
