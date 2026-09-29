import { ArbacResource, AsArbacDbController, useArbac, useArbacDbScope } from "@aooth/arbac-moost";
import { DbAction, DbActionID, InputForm, TableController } from "@atscript/moost-db";
import { HttpError, Post } from "@moostjs/event-http";

import { AssignRolesForm, DemoUser, LockForm } from "../models/user.as";
import { allRoles, ASSIGN_ANY_ROLE_ACTION, TENANT_ASSIGNABLE_ROLES } from "../roles";
import { assertWritten } from "./_helpers";

const KNOWN_ROLES: ReadonlySet<string> = new Set(allRoles.map((r) => r.id));

type Ack = { ok: true; message: string };

@TableController(DemoUser)
@ArbacResource("users")
export class UsersController extends AsArbacDbController<typeof DemoUser> {
  private async patchOne(
    id: string,
    patch: Record<string, unknown>,
    message: string,
  ): Promise<Ack> {
    const scope = await useArbacDbScope<typeof DemoUser>();
    const r = await this.table.updateMany(scope.filter({ id }), patch);
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
  async assignRoles(
    @DbActionID() id: { id: string },
    @InputForm(AssignRolesForm) form: AssignRolesForm,
  ): Promise<Ack> {
    await assertAssignableRoles(form.roles);
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

/**
 * Server-side limit on `assignRoles`: an unknown role is a 400; a role
 * outside {@link TENANT_ASSIGNABLE_ROLES} (e.g. `superadmin`) is a 403 unless
 * the caller holds the privileged `users/assignAnyRole` ARBAC action.
 */
async function assertAssignableRoles(roles: readonly string[]): Promise<void> {
  const unknown = roles.find((r) => !KNOWN_ROLES.has(r));
  if (unknown !== undefined) throw new HttpError(400, `Unknown role "${unknown}"`);
  const restricted = roles.find((r) => !TENANT_ASSIGNABLE_ROLES.includes(r));
  if (restricted === undefined) return;
  const { allowed } = await useArbac().evaluate({
    resource: "users",
    action: ASSIGN_ANY_ROLE_ACTION,
  });
  if (!allowed) {
    throw new HttpError(403, `Role "${restricted}" cannot be assigned by your role`);
  }
}
