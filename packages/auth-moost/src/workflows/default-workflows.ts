/**
 * Empty-opts subclasses moost can DI-register directly. The base workflows'
 * first ctor arg is an opts POJO (no provider), which moost won't inject.
 * To override opts or hooks, extend the base class instead.
 */
import { AuthCredential } from "@aooth/auth";
import { UserService } from "@aooth/user";
import { Controller, Inherit } from "moost";

import { InviteWorkflow } from "./invite.workflow";
import { LoginWorkflow } from "./login.workflow";
import { RecoveryWorkflow } from "./recovery.workflow";

@Inherit()
@Controller()
export class DefaultLoginWorkflow extends LoginWorkflow {
  constructor(users: UserService, auth: AuthCredential) {
    super({}, users, auth);
  }
}

@Inherit()
@Controller()
export class DefaultInviteWorkflow extends InviteWorkflow {
  constructor(users: UserService, auth: AuthCredential) {
    super({}, users, auth);
  }
}

@Inherit()
@Controller()
export class DefaultRecoveryWorkflow extends RecoveryWorkflow {
  constructor(users: UserService, auth: AuthCredential) {
    super({}, users, auth);
  }
}
