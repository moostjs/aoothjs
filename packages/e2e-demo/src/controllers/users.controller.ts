import { ArbacResource, AsArbacDbController } from "@aooth/arbac-moost";
import type { AtscriptDbTable } from "@atscript/db";
import { DbAction, DbActionID, InputForm, TableController } from "@atscript/moost-db";
import { Post } from "@moostjs/event-http";

import { AssignRolesForm, type DemoUser, LockForm } from "../models/user.as";
import { type DbControllerCtor, assertWritten, scopedFilter } from "./_helpers";

type Ack = { ok: true; message: string };

export function makeUsersController(
  table: AtscriptDbTable<typeof DemoUser>,
): DbControllerCtor<typeof DemoUser> {
  @TableController(table)
  @ArbacResource("users")
  class UsersController extends AsArbacDbController<typeof DemoUser> {
    private async patchOne(
      id: string,
      patch: Record<string, unknown>,
      message: string,
    ): Promise<Ack> {
      const r = await this.table.updateMany(scopedFilter({ id }), patch as never);
      assertWritten(r);
      return { ok: true, message };
    }

    @Post("actions/assignRoles")
    @DbAction<typeof DemoUser>("assignRoles", {
      label: "Assign roles",
      icon: "i-as-shield",
      intent: "primary",
      requiredFields: [],
    })
    assignRoles(
      @DbActionID() id: { id: string },
      @InputForm(AssignRolesForm) form: AssignRolesForm,
    ): Promise<Ack> {
      return this.patchOne(id.id, { roles: form.roles }, "Roles assigned");
    }

    @Post("actions/lock")
    @DbAction<typeof DemoUser>("lock", {
      label: "Lock account",
      icon: "i-as-lock",
      intent: "negative",
      requiredFields: [],
    })
    lock(@DbActionID() id: { id: string }, @InputForm(LockForm) form: LockForm): Promise<Ack> {
      const lockEnds = form.durationMs ? Date.now() + form.durationMs : 0;
      return this.patchOne(
        id.id,
        {
          "account.locked": true,
          "account.lockReason": form.reason,
          "account.lockEnds": lockEnds,
        },
        "Account locked",
      );
    }

    @Post("actions/unlock")
    @DbAction<typeof DemoUser>("unlock", {
      label: "Unlock account",
      icon: "i-as-unlock",
      intent: "positive",
      requiredFields: [],
    })
    unlock(@DbActionID() id: { id: string }): Promise<Ack> {
      return this.patchOne(
        id.id,
        {
          "account.locked": false,
          "account.lockReason": "",
          "account.lockEnds": 0,
          "account.failedLoginAttempts": 0,
        },
        "Account unlocked",
      );
    }
  }
  return UsersController as unknown as DbControllerCtor<typeof DemoUser>;
}
