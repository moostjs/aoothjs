import { ArbacAction, ArbacPublic, ArbacResource } from "@aoothjs/arbac-moost"
import { createAuthEmailOutlet, MoostAuthWorkflowConfig, Public } from "@aoothjs/auth-moost"
import { createAsHttpOutlet, handleAsOutletRequest } from "@atscript/moost-wf"
import { Body, Post } from "@moostjs/event-http"
import { HandleStateStrategy, MoostWf, type WfOutletTriggerDeps } from "@moostjs/event-wf"
import type { AsWfStore } from "@atscript/moost-wf/store"
import { current } from "@wooksjs/event-core"
import { Controller, useControllerContext } from "moost"

export const WF_PUBLIC_ALLOW = ["auth.login", "auth.recovery", "project.handover"] as const
export const WF_ADMIN_ALLOW = ["auth.invite"] as const

interface WfBody {
  wfid?: string
  wfs?: string
  input?: unknown
  action?: string
}

export type WfTriggerControllerCtor = new (...args: never[]) => {
  public(body: WfBody): Promise<unknown>
  admin(body: WfBody): Promise<unknown>
}

export function makeWfTriggerController(wfStateStore: AsWfStore): WfTriggerControllerCtor {
  const handleStrategy = new HandleStateStrategy({ store: wfStateStore })
  const httpOutlet = createAsHttpOutlet()
  const tokenWire = {
    read: ["body", "query"] as ("body" | "query" | "cookie")[],
    write: "body" as const,
    name: "wfs",
  }

  async function makeDeps(): Promise<WfOutletTriggerDeps> {
    const wf = await useControllerContext().instantiate(MoostWf)
    const wfApp = wf.getWfApp()
    return {
      start: (schemaId, context, opts) =>
        wfApp.start(schemaId, context as never, {
          input: opts?.input,
          eventContext: (opts?.eventContext ?? current()) as never,
        }),
      resume: (state, opts) =>
        wfApp.resume(state as { schemaId: string; indexes: number[]; context: never }, {
          input: opts?.input,
          eventContext: (opts?.eventContext ?? current()) as never,
        }),
    }
  }

  async function trigger(allow: readonly string[]): Promise<unknown> {
    const cfg = await useControllerContext().instantiate(MoostAuthWorkflowConfig)
    return handleAsOutletRequest(
      {
        allow: [...allow],
        state: handleStrategy,
        outlets: [httpOutlet, createAuthEmailOutlet(cfg)],
        token: tokenWire,
      },
      await makeDeps(),
    )
  }

  @Controller("wf")
  class WfTriggerController {
    @Post("public")
    @Public()
    @ArbacPublic()
    public(@Body() _body: WfBody): Promise<unknown> {
      return trigger(WF_PUBLIC_ALLOW)
    }

    @Post("admin")
    @ArbacResource("auth")
    @ArbacAction("admin.invite")
    admin(@Body() _body: WfBody): Promise<unknown> {
      return trigger(WF_ADMIN_ALLOW)
    }
  }

  return WfTriggerController as unknown as WfTriggerControllerCtor
}
