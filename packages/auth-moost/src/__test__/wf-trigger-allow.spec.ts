import { afterEach, describe, expect, it, vi } from "vite-plus/test";

import { Post } from "@moostjs/event-http";
import { Controller, Inherit } from "moost";

import { Public } from "../auth.decorator";
import { AuthController } from "../auth.controller";
import { WfTrigger } from "../wf-trigger/decorator";
import { WfTriggerProvider } from "../wf-trigger/provider";
import { pauseOnForcedPasswordChange, prepareFlowApp, setPasswordInput } from "./flow-utils";

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

  it("a refused DURABLE state token is not consumed either", async () => {
    // Store-backed tokens are single-use, so a refusal that consumed one would
    // burn the link; the check runs before `consumeEntry()` as well.
    const app = await prepareFlowApp();
    const wfs = await pauseOnForcedPasswordChange(app, "victim");
    const attacker = await app.seedUser("attacker", "Password123!");
    const { accessToken } = await app.auth.issue(attacker);

    const res = await app.post(
      "/auth/change-password",
      { wfs, input: {} },
      { authorization: `Bearer ${accessToken}` },
    );
    expect(res.status).toBe(403);
    expect((await app.submit(wfs, setPasswordInput)).status).toBe(201);
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

describe("@WfTrigger on an @Inherit() override replaces the base trigger", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("the override's allow is the only list checked — narrowing and widening", async () => {
    @Inherit()
    @Controller("auth")
    class NarrowController extends AuthController {
      @Post("trigger")
      @Public()
      @WfTrigger({ allow: ["auth/login/flow"] })
      override triggerWf(): void {}
    }
    const narrow = await prepareFlowApp({ controllerClass: NarrowController });
    expect((await narrow.start("auth/login/flow")).status).toBe(201);
    expect((await narrow.start("auth/recovery/flow")).status).toBe(403);

    @Inherit()
    @Controller("auth")
    class WideController extends AuthController {
      @Post("trigger")
      @Public()
      @WfTrigger({ allow: ["auth/login/flow", "auth/change-password/flow"] })
      override triggerWf(): void {}
    }
    const wide = await prepareFlowApp({ controllerClass: WideController });
    const handle = vi.spyOn(WfTriggerProvider.prototype, "handle");
    // Outside the base list, inside the override's: the base never refuses it.
    const user = await wide.seedUser("alice", "Password123!");
    const { accessToken } = await wide.auth.issue(user);
    const started = await wide.start("auth/change-password/flow", {
      authorization: `Bearer ${accessToken}`,
    });
    expect(started.status).toBe(201);
    expect(handle).toHaveBeenCalledTimes(1);
  });

  it("the trigger runs once per request, even when the reply is undefined", async () => {
    @Inherit()
    @Controller("auth")
    class SilentController extends AuthController {
      @Post("trigger")
      @Public()
      @WfTrigger({ allow: ["auth/login/flow"], renderEnvelope: () => undefined })
      override triggerWf(): void {}
    }
    const app = await prepareFlowApp({ controllerClass: SilentController });
    const handle = vi.spyOn(WfTriggerProvider.prototype, "handle");
    await app.start("auth/login/flow");
    expect(handle).toHaveBeenCalledTimes(1);
    expect(handle.mock.calls[0][0]?.allow).toEqual(["auth/login/flow"]);
  });

  it("a subclass that does not override the handler keeps the base trigger, once", async () => {
    @Inherit()
    @Controller("auth")
    class Untouched extends AuthController {}
    const app = await prepareFlowApp({ controllerClass: Untouched });
    const handle = vi.spyOn(WfTriggerProvider.prototype, "handle");
    expect((await app.start("auth/login/flow")).status).toBe(201);
    expect((await app.start("auth/change-password/flow")).status).toBe(403);
    expect(handle).toHaveBeenCalledTimes(2);
  });

  it("@Inherit(false) on a re-decorated override: only its own trigger, once", async () => {
    @Inherit()
    @Controller("auth")
    class OptedOut extends AuthController {
      @Inherit(false)
      @Post("trigger")
      @Public()
      @WfTrigger({ allow: ["auth/login/flow"], renderEnvelope: () => undefined })
      override triggerWf(): void {}
    }
    const app = await prepareFlowApp({ controllerClass: OptedOut });
    expect((await app.start("auth/recovery/flow")).status).toBe(403);
    const handle = vi.spyOn(WfTriggerProvider.prototype, "handle");
    await app.start("auth/login/flow");
    expect(handle).toHaveBeenCalledTimes(1);
    expect(handle.mock.calls[0][0]?.allow).toEqual(["auth/login/flow"]);
  });

  it("two @WfTrigger on one method run one trigger — the top one's options", async () => {
    // No base class: moost's own dedupe only runs when merging inherited metadata.
    @Controller("auth")
    class Doubled {
      @Post("trigger")
      @Public()
      @WfTrigger({ allow: ["auth/login/flow"], renderEnvelope: () => undefined })
      @WfTrigger({ allow: ["auth/recovery/flow"], renderEnvelope: () => undefined })
      triggerWf(): void {}
    }
    const app = await prepareFlowApp({
      controllerClass: Doubled as unknown as typeof AuthController,
    });
    const handle = vi.spyOn(WfTriggerProvider.prototype, "handle");
    await app.start("auth/login/flow");
    expect(handle).toHaveBeenCalledTimes(1);
    expect(handle.mock.calls[0][0]?.allow).toEqual(["auth/login/flow"]);
  });

  it("an override without its own @WfTrigger keeps the base options", async () => {
    @Inherit()
    @Controller("auth")
    class PlainOverride extends AuthController {
      override triggerWf(): void {}
    }
    const app = await prepareFlowApp({ controllerClass: PlainOverride });
    expect((await app.start("auth/login/flow")).status).toBe(201);
    expect((await app.start("auth/change-password/flow")).status).toBe(403);
  });
});
