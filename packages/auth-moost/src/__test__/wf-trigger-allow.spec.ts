import { describe, expect, it } from "vite-plus/test";

import { Post } from "@moostjs/event-http";
import { Controller, Inherit } from "moost";

import { Public } from "../auth.decorator";
import { AuthController } from "../auth.controller";
import { WfTrigger } from "../wf-trigger/decorator";
import { prepareFlowApp } from "./flow-utils";

// F42 / S2: a trigger's `allow` list governs RESUME too — a state token minted
// for one workflow must never run on a route that does not allow it — and
// `allow: []` denies every workflow (an omitted `allow` stays unrestricted).

async function loginWfs(app: Awaited<ReturnType<typeof prepareFlowApp>>): Promise<string> {
  const start = await app.start("auth/login/flow");
  expect(start.status).toBe(201);
  return start.body.wfs as string;
}

describe("F42: @WfTrigger allow list on resume", () => {
  it("refuses a login state token on the guarded /auth/change-password route", async () => {
    const app = await prepareFlowApp();
    const victim = await app.seedUser("victim", "Password123!");
    const attacker = await app.seedUser("attacker", "Password123!");
    const { accessToken } = await app.auth.issue(attacker);
    const wfs = await loginWfs(app);

    const res = await app.post(
      "/auth/change-password",
      { wfs, input: { formData: { username: "victim", password: "wrong-guess" } } },
      { authorization: `Bearer ${accessToken}` },
    );
    expect(res.status).toBe(403);
    // The login step never ran: no failed attempt was recorded on the victim.
    expect((await app.users.getUser(victim)).account.failedLoginAttempts).toBe(0);

    // The refused token was not consumed — it still resumes on its own route.
    const own = await app.submit(wfs, {
      formData: { username: "victim", password: "Password123!" },
    });
    expect(own.status).toBe(201);
    expect(own.body.inputRequired?.context?.errors).toBeUndefined();
  });

  it("refuses a change-password state token on the public /auth/trigger route", async () => {
    const app = await prepareFlowApp();
    const user = await app.seedUser("alice", "Password123!");
    const { accessToken } = await app.auth.issue(user);
    const start = await app.post(
      "/auth/change-password",
      { wfid: "auth/change-password/flow" },
      { authorization: `Bearer ${accessToken}` },
    );
    expect(start.status).toBe(201);
    const res = await app.submit(start.body.wfs, {});
    expect(res.status).toBe(403);
  });

  it("matches ids with or without a leading slash", async () => {
    @Inherit()
    @Controller("auth")
    class SlashController extends AuthController {
      @Post("trigger")
      @Public()
      @WfTrigger({ allow: ["/auth/login/flow"] })
      override triggerWf(): void {}
    }
    const app = await prepareFlowApp({ controllerClass: SlashController });
    const wfs = await loginWfs(app);
    const res = await app.submit(wfs);
    expect(res.status).toBe(201);
  });

  it("allow: [] denies every workflow; an omitted allow is unrestricted", async () => {
    @Inherit()
    @Controller("auth")
    class LockedController extends AuthController {
      @Post("trigger")
      @Public()
      @WfTrigger({ allow: [] })
      override triggerWf(): void {}

      @Post("open")
      @Public()
      @WfTrigger()
      open(): void {}
    }
    const app = await prepareFlowApp({ controllerClass: LockedController });
    const denied = await app.start("auth/login/flow");
    expect(denied.status).toBe(403);
    const open = await app.post("/auth/open", { wfid: "auth/login/flow" });
    expect(open.status).toBe(201);
    const resumedOnLocked = await app.submit(open.body.wfs, {});
    expect(resumedOnLocked.status).toBe(403);
  });
});
