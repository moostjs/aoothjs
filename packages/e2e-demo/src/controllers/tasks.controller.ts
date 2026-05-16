import { ArbacResource, AsArbacDbController } from "@aoothjs/arbac-moost";
import type { AtscriptDbTable } from "@atscript/db";
import {
  DbAction,
  DbActionID,
  DbActionRow,
  InputForm,
  TableController,
  perRow,
} from "@atscript/moost-db";
import { HttpError, Post } from "@moostjs/event-http";

import { AssignTaskForm, NewTaskForm, type Task } from "../models/task.as";
import { type DbControllerCtor, assertWritten, scopedFilter, scopedSet } from "./_helpers";

type Ack = { ok: true; message: string };

export function makeTasksController(
  table: AtscriptDbTable<typeof Task>,
): DbControllerCtor<typeof Task> {
  @TableController(table)
  @ArbacResource("tasks")
  class TasksController extends AsArbacDbController<typeof Task> {
    private async patchOne(
      id: string,
      patch: Record<string, unknown>,
      message: string,
    ): Promise<Ack> {
      const r = await this.table.updateMany(scopedFilter({ id }), {
        ...patch,
        updatedAt: Date.now(),
      } as never);
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
    async newTask(
      @InputForm(NewTaskForm) form: NewTaskForm,
    ): Promise<Ack & { insertedId: string }> {
      // NewTaskForm is a class instance; only its data fields are persisted, methods are unused.
      // oxlint-disable-next-line no-misused-spread
      const r = await this.table.insertOne({ ...form, ...scopedSet(), status: "open" } as never);
      const insertedId = (r as { insertedId: unknown }).insertedId;
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
      const r = await this.table.deleteMany(scopedFilter({ id: id.id }));
      assertWritten(r);
      return { ok: true, message: "Task deleted" };
    }
  }
  return TasksController as unknown as DbControllerCtor<typeof Task>;
}
