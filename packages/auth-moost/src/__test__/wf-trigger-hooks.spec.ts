import { describe, expect, it, vi } from "vite-plus/test";

import { Post } from "@moostjs/event-http";
import { Controller, Inherit } from "moost";

import { Public } from "../auth.decorator";
import { AuthController, DEFAULT_AUTH_WORKFLOWS } from "../auth.controller";
import { WfTrigger } from "../wf-trigger/decorator";
import type { WfTriggerHooks } from "../wf-trigger/provider";
import {
  pauseOnForcedPasswordChange,
  prepareFlowApp,
  type PreparedFlowApp,
  setPasswordInput,
} from "./flow-utils";

// The workflow-trigger hooks of wooks' trigger (`around`, `beforePersist`,
// `renderEnvelope`, `restoreOnError`) reach the trigger from
// `WfTriggerProvider.triggerHooks()` (app-wide) and `@WfTrigger(...)` (per route).

const PASSWORD = "Password123!";
const NEW_PASSWORD = "NewPassword456!";

/** Hooks that record every call, in order, into `calls`. */
function recordingHooks(calls: unknown[][]): WfTriggerHooks {
  return {
    around: async (run) => {
      calls.push(["around:enter"]);
      try {
        return await run();
      } finally {
        calls.push(["around:exit"]);
      }
    },
    beforePersist: (state, pause) => {
      calls.push(["beforePersist", state.schemaId, pause.outlet]);
    },
    renderEnvelope: (envelope, info) => {
      calls.push(["renderEnvelope", info.phase, info.schemaId]);
      return { ...(envelope as object), rendered: info.phase };
    },
  };
}

describe("WfTriggerProvider.triggerHooks()", () => {
  it("runs around → beforePersist → renderEnvelope on a paused start, around wrapping it all", async () => {
    const calls: unknown[][] = [];
    const app = await prepareFlowApp({ triggerHooks: recordingHooks(calls) });
    const res = await app.start("auth/login/flow");
    expect(res.status).toBe(201);
    expect(calls).toEqual([
      ["around:enter"],
      ["beforePersist", "/auth/login/flow", "http"],
      ["renderEnvelope", "paused", "/auth/login/flow"],
      ["around:exit"],
    ]);
    // The rendered envelope is the response; the state token is added after rendering.
    expect(res.body.rendered).toBe("paused");
    expect(res.body.inputRequired).toBeDefined();
    expect(res.body.wfs).toBeTypeOf("string");
  });

  it("beforePersist gets the paused state and pause request; throwing aborts the pause", async () => {
    const seen: { state?: unknown; pause?: unknown } = {};
    const app = await prepareFlowApp({
      triggerHooks: {
        beforePersist: (state, pause) => {
          seen.state = state;
          seen.pause = pause;
          throw new Error("context too large");
        },
      },
    });
    const res = await app.start("auth/login/flow");
    expect(res.status).toBe(500);
    expect(res.body.wfs).toBeUndefined();
    expect(seen.state).toMatchObject({ schemaId: "/auth/login/flow", meta: { outlet: "http" } });
    expect(seen.pause).toMatchObject({ outlet: "http" });
  });

  it("renderEnvelope also maps the finished value", async () => {
    const calls: unknown[][] = [];
    const app = await prepareFlowApp({ triggerHooks: recordingHooks(calls) });
    await app.seedUser("alice", PASSWORD);
    const started = await app.start("auth/login/flow");
    const paused = await app.submit(started.body.wfs, {
      formData: { username: "alice", password: PASSWORD },
    });
    // The optional MFA enrolment offer follows a password sign-in; skip it.
    calls.length = 0;
    const done = await app.submit(paused.body.wfs, { action: "skip" });
    expect(done.status).toBe(201);
    expect(done.body.finished).toBe(true);
    expect(done.body.rendered).toBe("finished");
    expect(calls).toEqual([
      ["around:enter"],
      ["renderEnvelope", "finished", "/auth/login/flow"],
      ["around:exit"],
    ]);
  });

  it("around can wrap the run in its own scope (e.g. a transaction) and sees its outcome", async () => {
    const outcomes: string[] = [];
    const app = await prepareFlowApp({
      triggerHooks: {
        around: async (run) => {
          try {
            const value = await run();
            outcomes.push("commit");
            return value;
          } catch (error) {
            outcomes.push("rollback");
            throw error;
          }
        },
      },
    });
    expect((await app.start("auth/login/flow")).status).toBe(201);
    // A refused resume (unknown token) fails inside `around`.
    expect((await app.submit("encapsulated.not-a-token")).status).toBeGreaterThanOrEqual(400);
    expect(outcomes).toEqual(["commit", "rollback"]);
  });
});

describe("triggerHooks() filtering", () => {
  it("passes only the hook options; other trigger config returned by mistake is ignored", async () => {
    const app = await prepareFlowApp({
      triggerHooks: {
        // Not hooks: trigger config that would change which flows run.
        block: ["auth/login/flow"],
        wfidName: "flow",
      } as WfTriggerHooks,
    });
    const res = await app.start("auth/login/flow");
    expect(res.status).toBe(201);
    expect(res.body.inputRequired).toBeDefined();
    expect(res.body.wfs).toBeTypeOf("string");
  });
});

describe("@WfTrigger(...) hooks", () => {
  it("a route's hook replaces the provider's hook of the same name; the others still apply", async () => {
    const calls: unknown[][] = [];
    @Inherit()
    @Controller("auth")
    class RenderingController extends AuthController {
      @Post("trigger")
      @Public()
      @WfTrigger({
        allow: [...DEFAULT_AUTH_WORKFLOWS],
        renderEnvelope: (envelope) => ({ ...(envelope as object), rendered: "route" }),
      })
      override triggerWf(): void {}
    }
    const app = await prepareFlowApp({
      controllerClass: RenderingController,
      triggerHooks: recordingHooks(calls),
    });
    const res = await app.start("auth/login/flow");
    expect(res.status).toBe(201);
    expect(res.body.rendered).toBe("route");
    expect(calls).toEqual([
      ["around:enter"],
      ["beforePersist", "/auth/login/flow", "http"],
      ["around:exit"],
    ]);
  });
});

/**
 * Sign in with an initial password: the run moves to the durable store and
 * pauses on the set-password form. Returns that form's single-use token.
 */
/** Make `setPassword` throw once (the submit answers 500), then re-submit the same token. */
async function failOnceThenRetry(
  app: PreparedFlowApp,
  wfs: string,
  error = new Error("store unavailable"),
) {
  const spy = vi.spyOn(app.users, "setPassword").mockRejectedValueOnce(error);
  expect((await app.submit(wfs, setPasswordInput)).status).toBe(500);
  spy.mockRestore();
  return app.submit(wfs, setPasswordInput);
}

describe("restoreOnError", () => {
  it("off (default): a step that throws burns the durable token", async () => {
    const app = await prepareFlowApp();
    const wfs = await pauseOnForcedPasswordChange(app);
    expect((await failOnceThenRetry(app, wfs)).status).toBe(410);
  });

  it("on: the token survives a throwing step and the retry continues the flow", async () => {
    const app = await prepareFlowApp({ triggerHooks: { restoreOnError: true } });
    const wfs = await pauseOnForcedPasswordChange(app);
    const retried = await failOnceThenRetry(app, wfs);
    expect(retried.status).toBe(201);
    // Past the set-password form: the next pause is the optional MFA offer.
    expect(retried.body.inputRequired?.payload?.id).toBe("EnrollPickMethodForm");
  });

  it("on, per route: enabled only by the route's @WfTrigger option", async () => {
    @Inherit()
    @Controller("auth")
    class RestoringController extends AuthController {
      @Post("trigger")
      @Public()
      @WfTrigger({ allow: [...DEFAULT_AUTH_WORKFLOWS], restoreOnError: true })
      override triggerWf(): void {}
    }
    const app = await prepareFlowApp({ controllerClass: RestoringController });
    const wfs = await pauseOnForcedPasswordChange(app);
    expect((await failOnceThenRetry(app, wfs)).status).toBe(201);
  });

  it("a predicate restores only the errors it accepts", async () => {
    const app = await prepareFlowApp({
      triggerHooks: { restoreOnError: (error) => (error as Error).message === "transient" },
    });
    const wfs = await pauseOnForcedPasswordChange(app);
    expect((await failOnceThenRetry(app, wfs, new Error("fatal"))).status).toBe(410);
  });
});

describe("a replayed password form never changes the password twice", () => {
  it("restoreOnError: a set-password token restored after a later failure is refused", async () => {
    let armed = false;
    const app = await prepareFlowApp({
      triggerHooks: {
        restoreOnError: true,
        // Fails the pause AFTER set-password stored the new password (the
        // next pause is never persisted, so the consumed token is restored).
        beforePersist: () => {
          if (!armed) return;
          armed = false;
          throw new Error("transient");
        },
      },
    });
    const wfs = await pauseOnForcedPasswordChange(app);
    const userId = (await app.users.findByHandle("alice"))!.id;
    armed = true;
    expect((await app.submit(wfs, setPasswordInput)).status).toBe(500);
    expect(await app.users.verifyPassword(userId, NEW_PASSWORD)).toBe(true);

    const replay = await app.submit(wfs, {
      formData: { newPassword: "Another789!x", confirmPassword: "Another789!x", consents: [] },
    });
    expect(replay.status).toBe(410);
    expect(replay.body).toMatchObject({ code: "PASSWORD_CHANGED_SIGN_IN_AGAIN" });
    expect(await app.users.verifyPassword(userId, NEW_PASSWORD)).toBe(true);
  });

  it("change-password: re-submitting the (encapsulated) form token after the change is refused", async () => {
    const app = await prepareFlowApp();
    const userId = await app.seedUser("bob", PASSWORD);
    const { accessToken } = await app.auth.issue(userId);
    const headers = { authorization: `Bearer ${accessToken}` };
    const started = await app.post(
      "/auth/change-password",
      { wfid: "auth/change-password/flow" },
      headers,
    );
    const wfs = started.body.wfs as string;
    const submit = (current: string, next: string) =>
      app.post(
        "/auth/change-password",
        {
          wfs,
          input: {
            formData: { currentPassword: current, newPassword: next, confirmPassword: next },
          },
        },
        headers,
      );
    expect((await submit(PASSWORD, NEW_PASSWORD)).body.finished).toBe(true);
    const { accessToken: fresh } = await app.auth.issue(userId);
    headers.authorization = `Bearer ${fresh}`;
    const replay = await submit(NEW_PASSWORD, "Another789!x");
    expect(replay.status).toBe(410);
    expect(await app.users.verifyPassword(userId, NEW_PASSWORD)).toBe(true);
  });
});

describe("an account deleted while its password form is open", () => {
  it("set-password: the submit answers the form error, not a 500", async () => {
    const app = await prepareFlowApp();
    const wfs = await pauseOnForcedPasswordChange(app);
    await app.users.deleteUser((await app.users.findByHandle("alice"))!.id);
    const res = await app.submit(wfs, setPasswordInput);
    expect(res.status, JSON.stringify(res.body).slice(0, 300)).toBe(201);
    expect(res.body.inputRequired?.context?.errors?.newPassword).toBeDefined();
  });

  it("change-password: the submit answers the form error, not a 500", async () => {
    const app = await prepareFlowApp();
    const userId = await app.seedUser("bob", PASSWORD);
    const { accessToken } = await app.auth.issue(userId);
    const headers = { authorization: `Bearer ${accessToken}` };
    const started = await app.post(
      "/auth/change-password",
      { wfid: "auth/change-password/flow" },
      headers,
    );
    await app.users.deleteUser(userId);
    const res = await app.post(
      "/auth/change-password",
      {
        wfs: started.body.wfs,
        input: {
          formData: {
            currentPassword: PASSWORD,
            newPassword: NEW_PASSWORD,
            confirmPassword: NEW_PASSWORD,
          },
        },
      },
      headers,
    );
    expect(res.status, JSON.stringify(res.body).slice(0, 300)).toBe(201);
    expect(res.body.inputRequired?.context?.errors?.newPassword).toBeDefined();
  });
});
