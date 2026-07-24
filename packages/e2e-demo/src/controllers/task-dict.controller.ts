import { ArbacResource, AsArbacDbController } from "@aooth/arbac-moost";
import { ReadableController } from "@atscript/moost-db";

import { TaskDict } from "../models/task-dict.as";

// Regression surface: a @db.view bound through the WRITABLE ARBAC controller
// chain. moost-db's `.table` getter throws for view-bound controllers, so
// every read-side override in AsArbacDbController must stay on `.readable` —
// `/meta`, `hasField`, and the write-scope pre-check all 500'd here before
// the fix. Write routes exist but fail loudly via the `.table` guard, which
// is the intended moost-db contract for views.
@ReadableController(TaskDict)
@ArbacResource("task-dict")
export class TaskDictController extends AsArbacDbController<typeof TaskDict> {}
