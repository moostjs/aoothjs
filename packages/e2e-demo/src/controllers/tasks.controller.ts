import { ArbacResource, AsArbacDbController, useArbacDbScope } from "@aooth/arbac-moost";
import {
  DbAction,
  DbActionID,
  DbActionIDs,
  DbActionRow,
  InputForm,
  TableController,
  perRow,
} from "@atscript/moost-db";
import { HttpError, Post } from "@moostjs/event-http";

import { AssignTaskForm, NewTaskForm, Task } from "../models/task.as";
import { assertWritten } from "./_helpers";

type Ack = { ok: true; message: string };

@TableController(Task)
@ArbacResource("tasks")
export class TasksController extends AsArbacDbController<typeof Task> {
  private async patchOne(
    id: string,
    patch: Record<string, unknown>,
    message: string,
  ): Promise<Ack> {
    const scope = await useArbacDbScope<typeof Task>();
    const r = await this.table.updateMany(scope.filter({ id }), {
      ...patch,
      updatedAt: Date.now(),
    });
    assertWritten(r);
    return { ok: true, message };
  }

  @Post("actions/new")
  @DbAction<typeof Task>("new", {
    label: "New task",
    icon: "i-as-plus",
    intent: "primary",
    requiredFields: [],
  })
  async newTask(@InputForm(NewTaskForm) form: NewTaskForm): Promise<Ack & { insertedId: string }> {
    const scope = await useArbacDbScope<typeof Task>();
    // NewTaskForm is a class instance; only its data fields are persisted, methods are unused.
    // oxlint-disable-next-line no-misused-spread
    const row: Record<string, unknown> = { ...form, ...scope.set(), status: "open" };
    // The CRUD endpoints' write enforcement inside the insert's transaction —
    // notably `checkRefs`: the form's `projectId` must name a project the
    // caller can read (`set` pins the task's tenant, not its project's).
    const r = await this.table.insertOne(row, scope.writeOptions(this.table));
    const insertedId: unknown = r.insertedId;
    if (typeof insertedId !== "string") {
      throw new HttpError(500, "Insert succeeded but no insertedId returned");
    }
    return { ok: true, message: "Task created", insertedId };
  }

  @Post("actions/markDone")
  @DbAction<typeof Task, ["status"]>("markDone", {
    label: "Mark done",
    icon: "i-as-check",
    intent: "positive",
    requiredFields: ["status"],
    disabled: perRow((t) => t.status === "done"),
  })
  markDone(
    @DbActionID() id: { id: string },
    @DbActionRow() _row: Pick<Task, "id" | "status">,
  ): Promise<Ack> {
    return this.patchOne(id.id, { status: "done" }, "Task marked done");
  }

  // Bulk variant: selected rows, or every row matching the table's current
  // query (`{ query }` body — a query target, under the caller's read ∧
  // action scope). Rows already done are skipped, not refused.
  @Post("actions/markDoneMany")
  @DbAction<typeof Task, ["status"]>("markDoneMany", {
    label: "Mark selected done",
    icon: "i-as-check",
    intent: "positive",
    requiredFields: ["status"],
    disabled: perRow((t) => t.status === "done"),
    onDisabledRows: "skip",
    queryTarget: { maxRows: 500, batchSize: 50 },
  })
  async markDoneMany(@DbActionIDs() ids: Array<{ id: string }>): Promise<Ack & { count: number }> {
    const scope = await useArbacDbScope<typeof Task>();
    const r = await this.table.updateMany(scope.filter({ id: { $in: ids.map((i) => i.id) } }), {
      status: "done",
      updatedAt: Date.now(),
    });
    const count = r.matchedCount ?? 0;
    return { ok: true, message: `${count} task(s) marked done`, count };
  }

  @Post("actions/markInProgress")
  @DbAction<typeof Task, ["status"]>("markInProgress", {
    label: "Start",
    icon: "i-as-play",
    intent: "warning",
    requiredFields: ["status"],
    disabled: perRow((t) => t.status !== "open"),
  })
  markInProgress(
    @DbActionID() id: { id: string },
    @DbActionRow() _row: Pick<Task, "id" | "status">,
  ): Promise<Ack> {
    return this.patchOne(id.id, { status: "in_progress" }, "Task in progress");
  }

  @Post("actions/archive")
  @DbAction<typeof Task, ["status"]>("archive", {
    label: "Archive",
    icon: "i-as-archive",
    intent: "secondary",
    requiredFields: ["status"],
    disabled: perRow((t) => t.status === "done"),
  })
  archive(
    @DbActionID() id: { id: string },
    @DbActionRow() _row: Pick<Task, "id" | "status">,
  ): Promise<Ack> {
    return this.patchOne(id.id, { status: "done" }, "Task archived");
  }

  @Post("actions/assign")
  @DbAction<typeof Task>("assign", {
    label: "Assign",
    icon: "i-as-user",
    intent: "primary",
    requiredFields: [],
  })
  assign(
    @DbActionID() id: { id: string },
    @InputForm(AssignTaskForm) form: AssignTaskForm,
  ): Promise<Ack> {
    return this.patchOne(id.id, { assigneeUsername: form.assigneeUsername }, "Task assigned");
  }

  @Post("actions/delete")
  @DbAction<typeof Task>("delete", {
    label: "Delete",
    icon: "i-as-trash",
    intent: "negative",
    promptText: ["Delete this task?", "Delete $N tasks?"],
    requiredFields: [],
  })
  async deleteTask(@DbActionID() id: { id: string }): Promise<Ack> {
    const scope = await useArbacDbScope<typeof Task>();
    const r = await this.table.deleteMany(scope.filter({ id: id.id }));
    assertWritten(r);
    return { ok: true, message: "Task deleted" };
  }
}
