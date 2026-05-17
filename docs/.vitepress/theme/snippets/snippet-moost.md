```ts:no-line-numbers
import {
  AuthController,
  authGuardInterceptor,
  Public,
  UserId,
  LoginWorkflow,
  type LoginWorkflowOpts,
  type DeliverPayload,
} from "@aooth/auth-moost";
import {
  ArbacAuthorize,
  ArbacResource,
  ArbacAction,
  arbacAuthorizeInterceptor,
} from "@aooth/arbac-moost";
import type { AuthCredential } from "@aooth/auth";
import type { UserService } from "@aooth/user";
import { Controller, Inherit, Injectable } from "moost";
import { Get } from "@moostjs/event-http";

app.applyGlobalInterceptors(authGuardInterceptor());
app.applyGlobalInterceptors(arbacAuthorizeInterceptor);
app.registerControllers(AuthController, MyLoginWorkflow, ReportsController);

@Controller("reports")
@ArbacResource("reports")
class ReportsController {
  @Get(":id")
  @ArbacAction("read")
  @ArbacAuthorize()
  async read(@UserId() userId: string) {
    return { userId };
  }
}

@Inherit() @Injectable("FOR_EVENT") @Controller()
class MyLoginWorkflow extends LoginWorkflow {
  // Subclasses MUST re-declare the ctor — TS emits fresh design-paramtypes per class.
  constructor(opts: LoginWorkflowOpts, users: UserService, auth: AuthCredential) {
    super(opts, users, auth);
  }

  protected override async deliver(payload: DeliverPayload) {
    if (payload.channel === "email") await emailSender.send(payload);
  }
}
```
