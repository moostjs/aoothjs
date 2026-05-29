```ts:no-line-numbers
import {
  AuthController,
  authGuardInterceptor,
  Public,
  UserId,
  AuthWorkflow,
  ConsentStore,
  type AuthDeliveryPayload,
} from "@aooth/auth-moost";
import {
  ArbacAuthorize,
  ArbacResource,
  ArbacAction,
  arbacAuthorizeInterceptor,
} from "@aooth/arbac-moost";
import type { AuthCredential } from "@aooth/auth";
import type { UserService } from "@aooth/user";
import { Controller, Inherit, createReplaceRegistry } from "moost";
import { Get } from "@moostjs/event-http";

app.applyGlobalInterceptors(authGuardInterceptor());
app.applyGlobalInterceptors(arbacAuthorizeInterceptor);
app.setReplaceRegistry(createReplaceRegistry([AuthWorkflow, MyAuth]));
app.registerControllers(AuthController, MyAuth, ReportsController);

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

@Inherit() @Controller() // one class, three @Workflow schemas
class MyAuth extends AuthWorkflow {
  // Subclasses MUST re-declare the 4-arg ctor — TS emits fresh design-paramtypes per class.
  constructor(users: UserService, auth: AuthCredential, consents: ConsentStore) {
    super({ totpIssuer: "Acme" }, users, auth, consents);
  }

  protected override async deliver(payload: AuthDeliveryPayload) {
    if (payload.channel === "email") await emailSender.send(payload);
  }
}
```
