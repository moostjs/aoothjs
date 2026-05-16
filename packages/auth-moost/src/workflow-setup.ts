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
 * Pairs with the REST endpoints + guard wiring (DI providers + global
 * `authGuardInterceptor` + `AuthController`); both halves are independent.
 *
 * Call exactly once per Moost instance — `applyGlobalInterceptors` and
 * `registerControllers` append.
 *
 * SECURITY — invite workflow exposure. Enabling the `invite` workflow only
 * registers the class with the WF adapter; it does NOT mount any HTTP
 * trigger. The trigger is the consumer's responsibility (see
 * {@link createAuthEmailOutlet} for the recommended two-trigger split).
 * If you do NOT have an admin/RBAC story yet, pass
 * `workflows: { invite: false }` to keep the schema unregistered as
 * defence-in-depth against accidentally including `'auth.invite'` in a
 * public trigger's `allow:` list.
 */
export function setupAuthWorkflows(moost: Moost, opts: AuthWorkflowsOptions): void {
  const config = new MoostAuthWorkflowConfig();
  config.configure(opts);

  moost.setProvideRegistry(createProvideRegistry([MoostAuthWorkflowConfig, () => config]));
  moost.applyGlobalInterceptors(formInputInterceptor());

  const { workflows } = config.config;
  const wfControllers: Array<new () => object> = [];
  if (workflows.login) wfControllers.push(LoginWorkflow);
  if (workflows.recovery) wfControllers.push(RecoveryWorkflow);
  if (workflows.invite) wfControllers.push(InviteWorkflow);
  if (wfControllers.length > 0) {
    moost.registerControllers(...wfControllers);
  }
}
