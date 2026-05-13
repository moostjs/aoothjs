import { formInputInterceptor } from "@atscript/moost-wf";
import { createProvideRegistry, type Moost } from "moost";

import { type AuthWorkflowsOptions, MoostAuthWorkflowConfig } from "./workflow-config";
import { InviteWorkflow, LoginWorkflow, RecoveryWorkflow } from "./workflows/index";

/**
 * One-call configuration for the workflow half of `@aoothjs/auth-moost`.
 *
 * - Validates options, registers {@link MoostAuthWorkflowConfig} as a DI
 *   singleton, and applies the global `formInputInterceptor()` so workflow
 *   steps decorated with `@FormInput()` pause correctly.
 * - Conditionally registers the three workflow controllers gated on
 *   `opts.workflows.{login,recovery,invite}` (all default to `true`).
 *
 * Pairs with `setupAuthMoost()` (REST endpoints + guard); both are independent.
 *
 * Call exactly once per Moost instance — `applyGlobalInterceptors` and
 * `registerControllers` append.
 */
export function setupAuthWorkflows(moost: Moost, opts: AuthWorkflowsOptions): void {
  const config = new MoostAuthWorkflowConfig();
  config.configure(opts);

  moost.setProvideRegistry(createProvideRegistry([MoostAuthWorkflowConfig, () => config]));
  moost.applyGlobalInterceptors(formInputInterceptor());

  const { workflows } = config.config;
  const wfControllers = [
    workflows.login && LoginWorkflow,
    workflows.recovery && RecoveryWorkflow,
    workflows.invite && InviteWorkflow,
  ].filter(Boolean) as Array<new () => object>;
  if (wfControllers.length > 0) {
    moost.registerControllers(...wfControllers);
  }
}
