import { createAsHttpOutlet, handleAsOutletRequest } from "@atscript/moost-wf";
import {
  HandleStateStrategy,
  MoostWf,
  type WfOutlet,
  type WfOutletTokenConfig,
  type WfOutletTriggerDeps,
  type WfStateStrategy,
  WfStateStoreMemory,
} from "@moostjs/event-wf";
import { current } from "@wooksjs/event-core";
import { Injectable } from "moost";

/**
 * DI singleton owning the workflow-trigger wiring: state persistence, outlets,
 * and token wire. Consumers subclass to swap the state store, add outlets
 * (email, SMS, ...), or override `handle()` for per-request dispatch logic.
 *
 * Defaults are intentionally minimal: in-memory state + HTTP outlet only.
 * Production deployments swap in a persistent `WfStateStore` and any outlets
 * they need by extending this class and re-binding via `setReplaceRegistry`.
 *
 * Uses `handleAsOutletRequest` (not `MoostWf.handleOutlet`) because the atscript
 * wrapper restores the `finished: true` marker that `<AsWfForm>` keys off — the
 * bare wooks request handler strips it during `useWfFinished()` unwrap.
 */
@Injectable()
export class WfTriggerProvider {
  protected state: WfStateStrategy = new HandleStateStrategy({ store: new WfStateStoreMemory() });
  protected outlets: WfOutlet[] = [createAsHttpOutlet()];
  protected token: WfOutletTokenConfig = {
    read: ["body", "query", "cookie"],
    write: "body",
    name: "wfs",
  };

  constructor(protected readonly wf: MoostWf) {}

  async handle(opts: { allow?: string[]; token?: WfOutletTokenConfig } = {}): Promise<unknown> {
    const wfApp = this.wf.getWfApp();
    const deps: WfOutletTriggerDeps = {
      start: (schemaId, context, o) =>
        wfApp.start(schemaId, context as never, {
          input: o?.input,
          eventContext: (o?.eventContext ?? current()) as never,
        }),
      resume: (state, o) =>
        wfApp.resume(state as { schemaId: string; indexes: number[]; context: never }, {
          input: o?.input,
          eventContext: (o?.eventContext ?? current()) as never,
        }),
    };
    return handleAsOutletRequest(
      {
        ...(opts.allow && { allow: opts.allow }),
        state: this.state,
        outlets: this.outlets,
        token: opts.token ?? this.token,
      },
      deps,
    );
  }
}
