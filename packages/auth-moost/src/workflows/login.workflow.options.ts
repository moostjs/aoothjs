/**
 * `LoginWorkflowOpts` — infrastructure-only nested-pojo configuration for
 * `LoginWorkflow`.
 *
 * Post-`AuthOpts` reshape: cross-workflow infrastructure (pincode timers/length,
 * magic-link TTL, TOTP issuer, login URL) moved off this opts shape and onto
 * the shared `AuthOpts` DI provider — see `auth.opts.ts`. What remains here is
 * login-specific infrastructure only: the `deviceTrust` cookie binding and the
 * form-schema replacement map. Policy still lives on the `resolveXxx(ctx)`
 * getter surface on `LoginWorkflow`.
 */
import type { TAtscriptAnnotatedType } from "@atscript/typescript/utils";

import {
  AskEmailForm,
  AskPhoneForm,
  BackupCodeForm,
  ConcurrencyLimitForm,
  EnrollAddressForm,
  EnrollConfirmForm,
  EnrollPickMethodForm,
  LoginCredentialsForm,
  MfaCodeForm,
  PersonaSelectForm,
  PincodeForm,
  ProfileCompleteForm,
  Select2faForm,
  SetPasswordForm,
  TenantSelectForm,
} from "../atscript/models/forms.as";

export type LoginRedirect = "referer" | "home" | false | null;

export type { MfaTransport } from "./auth-workflow.base";

export interface SsoProvider {
  id: string;
  label: string;
  url: string;
}

export interface ConcurrencyLimitOptions {
  max: number;
  onLimit: "reject" | "kickPrompt";
}

export interface LoginWorkflowOpts {
  deviceTrust?: {
    cookieName?: string;
    ttlMs?: number;
    bindsTo?: "cookie" | "cookie+ip";
  };
  /**
   * Replaceable form schemas. Each field defaults to the corresponding
   * `.as` form shipped under `@aooth/auth-moost/atscript/models`; supply a
   * subset to override only the forms you want to swap.
   */
  forms?: {
    askEmail?: TAtscriptAnnotatedType;
    askPhone?: TAtscriptAnnotatedType;
    backupCode?: TAtscriptAnnotatedType;
    concurrencyLimit?: TAtscriptAnnotatedType;
    enrollAddress?: TAtscriptAnnotatedType;
    enrollConfirm?: TAtscriptAnnotatedType;
    enrollPickMethod?: TAtscriptAnnotatedType;
    loginCredentials?: TAtscriptAnnotatedType;
    mfaCode?: TAtscriptAnnotatedType;
    personaSelect?: TAtscriptAnnotatedType;
    pincode?: TAtscriptAnnotatedType;
    profileComplete?: TAtscriptAnnotatedType;
    select2fa?: TAtscriptAnnotatedType;
    setPassword?: TAtscriptAnnotatedType;
    tenantSelect?: TAtscriptAnnotatedType;
  };
}

/**
 * Fully-resolved view used by the workflow at runtime — every nested group is
 * always populated by `mergeLoginOpts`, so step bodies can read
 * `this.opts.<group>.<flag>` directly without optional chaining.
 */
export interface ResolvedLoginWorkflowOpts {
  deviceTrust: {
    cookieName: string;
    ttlMs: number;
    bindsTo: "cookie" | "cookie+ip";
  };
  forms: {
    askEmail: TAtscriptAnnotatedType;
    askPhone: TAtscriptAnnotatedType;
    backupCode: TAtscriptAnnotatedType;
    concurrencyLimit: TAtscriptAnnotatedType;
    enrollAddress: TAtscriptAnnotatedType;
    enrollConfirm: TAtscriptAnnotatedType;
    enrollPickMethod: TAtscriptAnnotatedType;
    loginCredentials: TAtscriptAnnotatedType;
    mfaCode: TAtscriptAnnotatedType;
    personaSelect: TAtscriptAnnotatedType;
    pincode: TAtscriptAnnotatedType;
    profileComplete: TAtscriptAnnotatedType;
    select2fa: TAtscriptAnnotatedType;
    setPassword: TAtscriptAnnotatedType;
    tenantSelect: TAtscriptAnnotatedType;
  };
}

/**
 * Deep-merge defaults with the user-supplied nested pojo. Each group has its
 * own `{ ...defaults, ...input }` line — small enough that pulling in lodash
 * would be silly.
 */
export function mergeLoginOpts(opts: LoginWorkflowOpts = {}): ResolvedLoginWorkflowOpts {
  return {
    deviceTrust: {
      cookieName: "aooth_trusted_device",
      ttlMs: 24 * 60 * 60_000,
      bindsTo: "cookie",
      ...opts.deviceTrust,
    },
    forms: {
      askEmail: AskEmailForm as unknown as TAtscriptAnnotatedType,
      askPhone: AskPhoneForm as unknown as TAtscriptAnnotatedType,
      backupCode: BackupCodeForm as unknown as TAtscriptAnnotatedType,
      concurrencyLimit: ConcurrencyLimitForm as unknown as TAtscriptAnnotatedType,
      enrollAddress: EnrollAddressForm as unknown as TAtscriptAnnotatedType,
      enrollConfirm: EnrollConfirmForm as unknown as TAtscriptAnnotatedType,
      enrollPickMethod: EnrollPickMethodForm as unknown as TAtscriptAnnotatedType,
      loginCredentials: LoginCredentialsForm as unknown as TAtscriptAnnotatedType,
      mfaCode: MfaCodeForm as unknown as TAtscriptAnnotatedType,
      personaSelect: PersonaSelectForm as unknown as TAtscriptAnnotatedType,
      pincode: PincodeForm as unknown as TAtscriptAnnotatedType,
      profileComplete: ProfileCompleteForm as unknown as TAtscriptAnnotatedType,
      select2fa: Select2faForm as unknown as TAtscriptAnnotatedType,
      setPassword: SetPasswordForm as unknown as TAtscriptAnnotatedType,
      tenantSelect: TenantSelectForm as unknown as TAtscriptAnnotatedType,
      ...opts.forms,
    },
  };
}
