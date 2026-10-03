import { ArbacResource, AsArbacDbController } from "@aooth/arbac-moost";
import { DbActionsFrom, ReadableController } from "@atscript/moost-db";

import { TaskDict } from "../models/task-dict.as";
import { TasksController } from "./tasks.controller";

// Regression surface: a @db.view bound through the WRITABLE ARBAC controller
// chain. moost-db's `.table` getter throws for view-bound controllers, so
// every read-side override in AsArbacDbController must stay on `.readable` —
// `/meta`, `hasField`, and the write-scope pre-check all 500'd here before
// the fix. Write routes exist but fail loudly via the `.table` guard, which
// is the intended moost-db contract for views.
//
// It also lists the tasks' own row actions on its rows (`@DbActionsFrom`):
// each verdict, form and execution belongs to TasksController — evaluated
// under the caller's grants on `tasks`, never this view's.
@ReadableController(TaskDict)
@ArbacResource("task-dict")
@DbActionsFrom(() => TasksController, { actions: ["markDone", "markDoneMany"] })
export class TaskDictController extends AsArbacDbController<typeof TaskDict> {}
