import { Post } from "@moostjs/event-http";
import { Step, Workflow, WorkflowSchema } from "@moostjs/event-wf";
import { Controller, Inherit } from "moost";
import { describe, expect, it } from "vite-plus/test";

import { AuthController } from "../auth.controller";
import { Public } from "../auth.decorator";
import { WfTrigger } from "../wf-trigger/decorator";
import { completeAccept, prepareFlowApp, type PreparedFlowApp } from "./flow-utils";

// The wooks trigger judges `allow` / `resumeOnly` / `block` on the REGISTERED flow a
// request resolves to; aooth keeps its own refusal contract (403
// `AOOTH_WORKFLOW_NOT_ALLOWED`).

const NOT_ALLOWED = { code: "AOOTH_WORKFLOW_NOT_ALLOWED" };

/** A refused resume: its own code, a placeholder-free message and no params (it never names the flow). */
function expectResumeRefused(res: { status: number; body: any }) {
  expect(res.status).toBe(403);
  expect(res.body).toMatchObject({
    code: "AOOTH_WORKFLOW_RESUME_NOT_ALLOWED",
    message: "Workflow is not allowed",
  });
  expect(res.body).not.toHaveProperty("params");
}

describe("@WfTrigger resumeOnly", () => {
  @Inherit()
  @Controller("auth")
  class InviteSplit extends AuthController {
    /** Public: resumes the invitee's link, never starts the invite flow. */
    @Post("trigger")
    @Public()
    @WfTrigger({ allow: ["auth/login/flow"], resumeOnly: ["auth/invite/start"] })
    override triggerWf(): void {}

    /** The issuing side (the test stands in for an authorised admin). */
    @Post("admin")
    @Public()
    @WfTrigger({ allow: ["auth/invite/start"] })
    admin(): void {}
  }

  async function issue(app: PreparedFlowApp, email: string): Promise<string> {
    const start = await app.post("/auth/admin", { wfid: "auth/invite/start" });
    expect(start.status).toBe(201);
    const sent = await app.post("/auth/admin", {
      wfs: start.body.wfs,
      input: { formData: { email, roles: [] } },
    });
    expect(sent.status, JSON.stringify(sent.body)).toBeLessThan(300);
    return app.emails[0].token;
  }

  it("refuses a start (403 AOOTH_WORKFLOW_NOT_ALLOWED) and admits the resume of the issued link", async () => {
    const app = await prepareFlowApp({
      controllerClass: InviteSplit,
      workflowOpts: { autoLoginOnInvite: false },
    });
    const token = await issue(app, "i@x.test");

    const refused = await app.start("auth/invite/start");
    expect(refused.status).toBe(403);
    expect(refused.body).toMatchObject({
      ...NOT_ALLOWED,
      params: { workflow: "auth/invite/start" },
    });

    const opened = await app.submit(token);
    expect(opened.status, JSON.stringify(opened.body)).toBe(201);
    expect(opened.body.inputRequired?.payload?.id).toBe("SetPasswordForm");
    await completeAccept(app, opened.body.wfs);
  });

  it("a start is refused even when allow lists the flow too; the other routes are unaffected", async () => {
    const app = await prepareFlowApp({
      controllerClass: Inherited({
        allow: ["auth/login/flow", "auth/invite/start"],
        resumeOnly: ["/auth/invite/start"],
      }),
    });
    const refused = await app.start("auth/invite/start");
    expect(refused.status).toBe(403);
    expect(refused.body).toMatchObject(NOT_ALLOWED);
    expect((await app.start("auth/login/flow")).status).toBe(201);
  });

  it("a resume needs no allow entry; a trigger without resumeOnly refuses the link and leaves it usable", async () => {
    @Inherit()
    @Controller("auth")
    class WithPlain extends InviteSplit {
      @Post("plain")
      @Public()
      @WfTrigger({ allow: ["auth/login/flow"] })
      plain(): void {}
    }
    const app = await prepareFlowApp({
      controllerClass: WithPlain,
      workflowOpts: { autoLoginOnInvite: false },
    });
    const token = await issue(app, "j@x.test");
    expectResumeRefused(await app.post("/auth/plain", { wfs: token, input: {} }));
    // Refused before it was consumed: the resumeOnly route still opens it.
    expect((await app.submit(token)).status).toBe(201);
  });
});

describe("@WfTrigger block", () => {
  it("wins over allow and resumeOnly, on start and on resume", async () => {
    @Inherit()
    @Controller("auth")
    class Open extends AuthController {
      @Post("open")
      @Public()
      @WfTrigger()
      open(): void {}
    }
    @Inherit()
    @Controller("auth")
    class Blocking extends Open {
      @Post("trigger")
      @Public()
      @WfTrigger({
        allow: ["auth/login/flow", "auth/recovery/flow"],
        resumeOnly: ["auth/signup/flow"],
        block: ["auth/recovery/flow", "auth/signup/flow"],
      })
      override triggerWf(): void {}
    }
    const app = await prepareFlowApp({ controllerClass: Blocking });
    const recovery = await app.start("auth/recovery/flow");
    expect(recovery.status).toBe(403);
    expect(recovery.body).toMatchObject(NOT_ALLOWED);
    expect((await app.start("auth/signup/flow")).status).toBe(403);
    expect((await app.start("auth/login/flow")).status).toBe(201);

    // A blocked flow's token minted elsewhere is refused on resume too.
    const minted = await app.post("/auth/open", { wfid: "auth/recovery/flow" });
    expect(minted.status).toBe(201);
    expectResumeRefused(await app.submit(minted.body.wfs, {}));
  });
});

describe("@WfTrigger judges the resolved flow, not the request's spelling", () => {
  it("a start resolved through onNotFound is judged on the flow it runs", async () => {
    const app = await prepareFlowApp({
      wfOptions: { onNotFound: () => ({ id: "auth/recovery/flow" }) },
      controllerClass: Inherited({ allow: ["auth/login/flow", "ghost/flow"] }),
    });
    // `ghost/flow` is listed but registers nothing: onNotFound would run recovery.
    const ghost = await app.start("ghost/flow");
    expect(ghost.status).toBe(403);
    expect(ghost.body).toMatchObject(NOT_ALLOWED);
    // ...and a flow only onNotFound can reach is refused the same way.
    expect((await app.start("anything/else")).status).toBe(403);
    expect((await app.start("auth/login/flow")).status).toBe(201);
  });

  it("a start caught by a parametric route is judged on that route", async () => {
    const ran: string[] = [];
    @Controller()
    class Shadow {
      @Workflow("auth/:kind/flow")
      @WorkflowSchema([{ id: "shadow-step" }])
      shadow(): void {}

      @Step("shadow-step")
      step(): void {
        ran.push("shadow");
      }
    }
    const listed = await prepareFlowApp({
      extraControllers: [Shadow],
      controllerClass: Inherited({ allow: ["auth/login/flow", "auth/ghost/flow"] }),
    });
    // `auth/ghost/flow` is listed, but the flow that runs is `/auth/:kind/flow`.
    const ghost = await listed.start("auth/ghost/flow");
    expect(ghost.status).toBe(403);
    expect(ghost.body).toMatchObject(NOT_ALLOWED);
    expect(ran).toEqual([]);
    expect((await listed.start("auth/login/flow")).status).toBe(201);

    // Listing the route's own id admits what it catches.
    const admitting = await prepareFlowApp({
      extraControllers: [Shadow],
      controllerClass: Inherited({ allow: ["auth/:kind/flow"] }),
    });
    expect((await admitting.start("auth/ghost/flow")).status).toBe(201);
    expect(ran).toEqual(["shadow"]);
  });

  it("allow lists an id that registers nothing: 403 like an unlisted id, never a 404", async () => {
    const app = await prepareFlowApp({
      controllerClass: Inherited({ allow: ["auth/login/flow", "ghost/flow"] }),
    });
    for (const wfid of ["ghost/flow", "unlisted/flow"]) {
      const res = await app.start(wfid);
      expect(res.status).toBe(403);
      expect(res.body).toMatchObject({ ...NOT_ALLOWED, params: { workflow: wfid } });
    }
  });

  it("allow set: a registered-but-unlisted id and an unregistered id answer identically (no oracle)", async () => {
    const app = await prepareFlowApp({
      controllerClass: Inherited({ allow: ["auth/login/flow"] }),
    });
    // `auth/recovery/flow` registers a flow (the engine answers WF_FORBIDDEN);
    // `nope/flow` registers nothing (the engine answers WF_NOT_FOUND). A caller
    // must not be able to tell the two apart.
    const registered = await app.start("auth/recovery/flow");
    const unregistered = await app.start("nope/flow");
    expect(registered.status).toBe(403);
    expect(unregistered.status).toBe(registered.status);
    expect(registered.body).toMatchObject({
      ...NOT_ALLOWED,
      params: { workflow: "auth/recovery/flow" },
    });
    const normalise = (body: any, workflow: string) => ({
      ...body,
      params: { workflow: "<wf>" },
      message: String(body.message).replace(workflow, "<wf>"),
    });
    expect(normalise(unregistered.body, "nope/flow")).toEqual(
      normalise(registered.body, "auth/recovery/flow"),
    );
  });

  it("a user's around sees the mapped refusal codes", async () => {
    const seen: string[] = [];
    const app = await prepareFlowApp({
      controllerClass: Inherited({
        allow: ["auth/login/flow"],
        around: async (run) => {
          try {
            return await run();
          } catch (error) {
            seen.push((error as { body: { code: string } }).body.code);
            throw error;
          }
        },
      }),
    });
    await app.start("auth/recovery/flow");
    const minted = await app.start("auth/login/flow");
    expect(minted.status).toBe(201);
    expect(seen).toEqual(["AOOTH_WORKFLOW_NOT_ALLOWED"]);
  });

  it("without allow, an unresolvable id is not an AOOTH_WORKFLOW_NOT_ALLOWED", async () => {
    const app = await prepareFlowApp({
      controllerClass: Inherited({ block: ["auth/recovery/flow"] }),
    });
    const res = await app.start("auth/no-such/flow");
    expect(res.status).toBe(404);
    expect(res.body.code).not.toBe("AOOTH_WORKFLOW_NOT_ALLOWED");
  });
});

function Inherited(opts: Parameters<typeof WfTrigger>[0]): typeof AuthController {
  @Inherit()
  @Controller("auth")
  class Route extends AuthController {
    @Post("trigger")
    @Public()
    @WfTrigger(opts)
    override triggerWf(): void {}
  }
  return Route;
}
