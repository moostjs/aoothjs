import { ArbacAction, ArbacResource } from "@aooth/arbac-moost";
import { Public, useAuth } from "@aooth/auth-moost";
import { Get } from "@moostjs/event-http";
import { Controller } from "moost";

@Controller()
export class HealthController {
  @Get("health")
  @Public()
  health(): { ok: true } {
    return { ok: true };
  }

  @Get("health/protected")
  protectedRoute(): { user: string } {
    return { user: useAuth().getUserId() };
  }

  @Get("health/admin-only")
  @ArbacResource("health")
  @ArbacAction("admin")
  adminOnly(): { ok: true; user: string } {
    return { ok: true, user: useAuth().getUserId() };
  }
}
