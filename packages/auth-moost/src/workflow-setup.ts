import { formInputInterceptor } from "@atscript/moost-wf";
import { createProvideRegistry, type Moost } from "moost";

import {
  EmailIdentifierForm,
  InviteForm,
  LoginCredentialsForm,
  MfaCodeForm,
  SetPasswordForm,
} from "./atscript/index";
import {
  type AuthWorkflowFormsOverrides,
  type AuthWorkflowsOptions,
  MoostAuthWorkflowConfig,
} from "./workflow-config";

/**
 * One-call configuration for the workflow half of `@aoothjs/auth-moost`.
 *
 * Validates options, registers {@link MoostAuthWorkflowConfig} as a DI
 * singleton, and applies the global `formInputInterceptor()` so workflow
 * steps decorated with `@FormInput()` pause correctly. Pairs with
 * `setupAuthMoost()` (REST endpoints + guard); both are independent.
 *
 * Call exactly once per Moost instance — `applyGlobalInterceptors` appends.
 * The login / recovery / invite workflow controllers themselves are
 * registered by Phase 6.5b.
 */
export function setupAuthWorkflows(moost: Moost, opts: AuthWorkflowsOptions): void {
  const defaults: Required<AuthWorkflowFormsOverrides> = {
    loginCredentials: LoginCredentialsForm,
    mfaCode: MfaCodeForm,
    emailIdentifier: EmailIdentifierForm,
    setPassword: SetPasswordForm,
    invite: InviteForm,
  };

  const config = new MoostAuthWorkflowConfig();
  config.configure(opts, defaults);

  moost.setProvideRegistry(createProvideRegistry([MoostAuthWorkflowConfig, () => config]));
  moost.applyGlobalInterceptors(formInputInterceptor());

  // TODO(6.5b): register the login / recovery / invite workflow controllers
  // here (gated on config.config.workflows.{login,recovery,invite}).
}
