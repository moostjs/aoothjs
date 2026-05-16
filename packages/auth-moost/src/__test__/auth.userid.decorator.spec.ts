import { Get } from "@moostjs/event-http";
import { Controller } from "moost";
import { beforeEach, describe, expect, it } from "vite-plus/test";

import { UserId } from "../auth.decorator";
import { prepareControllerApp } from "./controller-utils";

// ISSUE-5 / ISSUE-6: pins the `@UserId()` parameter decorator end-to-end. The
// decorator is a one-line `Resolve(() => useAuth().getUserId())` — but the
// "wires" are non-trivial: it depends on moost's Resolve param infra, the
// auth.composables slot key, and the guard interceptor populating that slot
// before the handler runs. A unit test of the decorator factory would prove
// only that the closure exists; it would not catch a regression in any of
// those collaborators. So the test boots the full Moost+MoostHttp stack used
// by every other controller spec and asserts the observable contract: an
// authenticated request reaches the handler with the right id; an
// unauthenticated request never reaches the handler (the guard interrupts at
// 401). The negative case is delegated to `auth.composables.spec.ts` (proves
// `getUserId()` throws HttpError(401)) — re-testing it through the decorator
// would only re-prove `useAuth().getUserId()` and add no new signal.
@Controller("probe")
class UserIdProbeController {
  // Mirrors the documented usage pattern from `auth.decorator.ts`:
  //   getId(@UserId() userId: string): string { return userId; }
  // The handler returns the id verbatim so the test can assert the exact
  // value the decorator resolved (not just "some string").
  @Get("id")
  getId(@UserId() userId: string): string {
    return userId;
  }
}

describe("@UserId() parameter decorator (ISSUE-5)", () => {
  let app: Awaited<ReturnType<typeof prepareControllerApp>>;
  let accessToken: string;

  beforeEach(async () => {
    // The probe controller must be registered BEFORE `moost.init()` —
    // post-init registration silently no-ops on the HTTP adapter (route
    // table is frozen at boot). `extraControllers` is the supported hook.
    app = await prepareControllerApp({ extraControllers: [UserIdProbeController] });
    await app.users.createUser("alice", "Password123");
    await app.users.activateAccount("alice");
    // `/auth/login` was dropped (AUTH-MOOST-5) — mint a token directly through
    // the AuthCredential so the test stays focused on the decorator, not the
    // login flow (covered by workflow specs).
    const issue = await app.auth.issue("alice");
    accessToken = issue.accessToken;
  });

  it("injects the authenticated user's id into the handler parameter", async () => {
    // The full chain under test:
    //   bearer header
    //     → authGuardInterceptor writes AuthContext to the event slot
    //       → @UserId() → Resolve(() => useAuth().getUserId())
    //         → reads the slot, returns "alice"
    //           → handler returns "alice"
    // A regression in any link breaks this assertion. The literal "alice"
    // (not just "any string") is load-bearing — it proves the decorator
    // resolves the *current* event's user id, not a hard-coded default.
    const res = await app.request("/probe/id", {
      headers: { authorization: `Bearer ${accessToken}` },
    });
    expect(res.status).toBe(200);
    expect(res.body).toBe("alice");
  });

  it("returns 401 on an anonymous request (guard interrupts before @UserId runs)", async () => {
    // The guard is what produces this 401 — the probe controller is NOT
    // `@Public()`, so `authGuardInterceptor` rejects the request before the
    // handler is even constructed. This test pins the guard-before-resolve
    // ordering: if the guard were ever moved AFTER param resolution, the
    // @UserId() resolver would itself throw HttpError(401) (via
    // `useAuth().getUserId()`) and the status would still be 401 — but the
    // body and headers would differ. We assert only the status because that
    // is the externally-observable contract. The guard-vs-resolver path is
    // verified separately in `auth.composables.spec.ts` (`getUserId throws
    // HttpError(401)`).
    const res = await app.request("/probe/id", {});
    expect(res.status).toBe(401);
  });
});
