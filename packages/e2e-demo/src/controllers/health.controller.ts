import { ArbacAction, ArbacPublic, ArbacResource } from "@aoothjs/arbac-moost"
import { Public, useAuth } from "@aoothjs/auth-moost"
import { Get } from "@moostjs/event-http"
import { Controller } from "moost"

@Controller()
export class HealthController {
  @Get("health")
  @Public()
  @ArbacPublic()
  health(): { ok: true } {
    return { ok: true }
  }

  @Get("health/protected")
  @ArbacPublic()
  protectedRoute(): { user: string } {
    return { user: useAuth().getCurrentUserId() }
  }

  @Get("health/admin-only")
  @ArbacResource("health")
  @ArbacAction("admin")
  adminOnly(): { ok: true; user: string } {
    return { ok: true, user: useAuth().getCurrentUserId() }
  }
}
