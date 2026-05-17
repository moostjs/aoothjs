/**
 * `LoginWorkflowOpts` — nested-pojo configuration for `LoginWorkflow`.
 *
 * Phase 2 of the workflow OOP-reshape (see TASKS.md): the options class +
 * callbacks have been replaced by a nested-object pojo passed as the first
 * ctor arg, plus protected methods on `LoginWorkflow` that consumers override
 * via subclassing. Defaults are applied by `mergeLoginOpts(opts)` so step
 * bodies + schema conditions can read `ctx.opts.<group>.<flag>` without `?.`.
 */
import type { TAtscriptAnnotatedType } from "@atscript/typescript/utils";

import {
  AskEmailForm,
  AskPhoneForm,
  BackupCodeForm,
  ConcurrencyLimitForm,
  ConsentMarketingForm,
  LoginCredentialsForm,
  MfaCodeForm,
  PersonaSelectForm,
  PincodeForm,
  ProfileCompleteForm,
  Select2faForm,
  SetPasswordForm,
  TenantSelectForm,
  TermsAcceptForm,
} from "../atscript/models/forms.as.js";

export const DEFAULT_MFA_CODE_TTL_MS = 5 * 60 * 1000;

export type LoginRedirect = "referer" | "home" | false | null;

export type MfaTransport = "sms" | "email" | "totp";

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
  alternateCredentials?: {
    forgotPassword?: boolean;
    signup?: boolean;
    magicLink?: boolean;
    magicLinkSkipsMfa?: boolean;
    magicLinkTtlMs?: number;
    ssoProviders?: SsoProvider[];
    recoveryUrl?: string;
    signupUrl?: string;
    embedRecovery?: boolean;
  };
  guards?: {
    emailVerifiedRequired?: boolean;
    passwordExpiry?: boolean;
    passwordInitial?: boolean;
  };
  enrollment?: {
    ensureEmail?: boolean;
    ensurePhone?: boolean;
  };
  mfa?: {
    enabled?: boolean;
    transports?: MfaTransport[];
    backupCodes?: boolean;
    enrollRequired?: boolean;
    pincodeTtlMs?: number;
    pincodeResendTimeoutMs?: number;
    /** Numeric length of the server-generated OTP for SMS/email pincodes. */
    pincodeLength?: number;
  };
  deviceTrust?: {
    enabled?: boolean;
    optIn?: boolean;
    cookieName?: string;
    ttlMs?: number;
    skipsMfa?: boolean;
    bindsTo?: "cookie" | "cookie+ip";
  };
  acceptance?: {
    termsVersion?: string;
    profileCompleteRequired?: boolean;
    consentMarketing?: boolean;
  };
  multiContext?: {
    tenantSelect?: boolean;
    personaSelect?: boolean;
  };
  sessionPolicy?: {
    concurrencyLimit?: ConcurrencyLimitOptions;
  };
  finalize?: {
    auditLogin?: boolean;
    notifyNewDevice?: boolean;
    redirect?: LoginRedirect;
  };
  /**
   * Replaceable form schemas. Each field defaults to the corresponding
   * `.as` form shipped under `@aoothjs/auth-moost/atscript/models`; supply a
   * subset to override only the forms you want to swap.
   */
  forms?: {
    askEmail?: TAtscriptAnnotatedType;
    askPhone?: TAtscriptAnnotatedType;
    backupCode?: TAtscriptAnnotatedType;
    concurrencyLimit?: TAtscriptAnnotatedType;
    consentMarketing?: TAtscriptAnnotatedType;
    loginCredentials?: TAtscriptAnnotatedType;
    mfaCode?: TAtscriptAnnotatedType;
    personaSelect?: TAtscriptAnnotatedType;
    pincode?: TAtscriptAnnotatedType;
    profileComplete?: TAtscriptAnnotatedType;
    select2fa?: TAtscriptAnnotatedType;
    setPassword?: TAtscriptAnnotatedType;
    tenantSelect?: TAtscriptAnnotatedType;
    termsAccept?: TAtscriptAnnotatedType;
  };
}

/**
 * Fully-resolved view used by the workflow at runtime — every nested group is
 * always populated by `mergeLoginOpts`, so schema conditions can read
 * `ctx.opts.<group>.<flag>` directly without optional chaining.
 *
 * Fields without sensible defaults (e.g. `termsVersion`, `concurrencyLimit`)
 * stay optional inside their group.
 */
export interface ResolvedLoginWorkflowOpts {
  alternateCredentials: {
    forgotPassword: boolean;
    signup: boolean;
    magicLink: boolean;
    magicLinkSkipsMfa: boolean;
    magicLinkTtlMs: number;
    ssoProviders: SsoProvider[];
    recoveryUrl: string;
    signupUrl: string;
    embedRecovery: boolean;
  };
  guards: {
    emailVerifiedRequired: boolean;
    passwordExpiry: boolean;
    passwordInitial: boolean;
  };
  enrollment: {
    ensureEmail: boolean;
    ensurePhone: boolean;
  };
  mfa: {
    enabled: boolean;
    transports: MfaTransport[];
    backupCodes: boolean;
    enrollRequired: boolean;
    pincodeTtlMs: number;
    pincodeResendTimeoutMs: number;
    pincodeLength: number;
  };
  deviceTrust: {
    enabled: boolean;
    optIn: boolean;
    cookieName: string;
    ttlMs: number;
    skipsMfa: boolean;
    bindsTo: "cookie" | "cookie+ip";
  };
  acceptance: {
    termsVersion?: string;
    profileCompleteRequired: boolean;
    consentMarketing: boolean;
  };
  multiContext: {
    tenantSelect: boolean;
    personaSelect: boolean;
  };
  sessionPolicy: {
    concurrencyLimit?: ConcurrencyLimitOptions;
  };
  finalize: {
    auditLogin: boolean;
    notifyNewDevice: boolean;
    redirect: LoginRedirect;
  };
  forms: {
    askEmail: TAtscriptAnnotatedType;
    askPhone: TAtscriptAnnotatedType;
    backupCode: TAtscriptAnnotatedType;
    concurrencyLimit: TAtscriptAnnotatedType;
    consentMarketing: TAtscriptAnnotatedType;
    loginCredentials: TAtscriptAnnotatedType;
    mfaCode: TAtscriptAnnotatedType;
    personaSelect: TAtscriptAnnotatedType;
    pincode: TAtscriptAnnotatedType;
    profileComplete: TAtscriptAnnotatedType;
    select2fa: TAtscriptAnnotatedType;
    setPassword: TAtscriptAnnotatedType;
    tenantSelect: TAtscriptAnnotatedType;
    termsAccept: TAtscriptAnnotatedType;
  };
}

/**
 * Deep-merge defaults with the user-supplied nested pojo. Each group has its
 * own `{ ...defaults, ...input }` line — small enough that pulling in lodash
 * would be silly.
 */
export function mergeLoginOpts(opts: LoginWorkflowOpts = {}): ResolvedLoginWorkflowOpts {
  return {
    alternateCredentials: {
      forgotPassword: true,
      signup: false,
      magicLink: false,
      magicLinkSkipsMfa: false,
      magicLinkTtlMs: 30 * 60_000,
      ssoProviders: [],
      recoveryUrl: "/recover",
      signupUrl: "/signup",
      embedRecovery: false,
      ...opts.alternateCredentials,
    },
    guards: {
      emailVerifiedRequired: false,
      passwordExpiry: true,
      passwordInitial: true,
      ...opts.guards,
    },
    enrollment: {
      ensureEmail: false,
      ensurePhone: false,
      ...opts.enrollment,
    },
    mfa: {
      enabled: true,
      transports: ["sms", "email", "totp"],
      backupCodes: true,
      enrollRequired: false,
      pincodeTtlMs: DEFAULT_MFA_CODE_TTL_MS,
      pincodeResendTimeoutMs: 60_000,
      pincodeLength: 6,
      ...opts.mfa,
    },
    deviceTrust: {
      enabled: false,
      optIn: true,
      cookieName: "aooth_trusted_device",
      ttlMs: 24 * 60 * 60_000,
      skipsMfa: true,
      bindsTo: "cookie",
      ...opts.deviceTrust,
    },
    acceptance: {
      profileCompleteRequired: false,
      consentMarketing: false,
      ...opts.acceptance,
    },
    multiContext: {
      tenantSelect: false,
      personaSelect: false,
      ...opts.multiContext,
    },
    sessionPolicy: {
      ...opts.sessionPolicy,
    },
    finalize: {
      auditLogin: true,
      notifyNewDevice: false,
      // SPA-friendly default; server-rendered apps opt in via redirect: "referer"
      redirect: false,
      ...opts.finalize,
    },
    forms: {
      askEmail: AskEmailForm as unknown as TAtscriptAnnotatedType,
      askPhone: AskPhoneForm as unknown as TAtscriptAnnotatedType,
      backupCode: BackupCodeForm as unknown as TAtscriptAnnotatedType,
      concurrencyLimit: ConcurrencyLimitForm as unknown as TAtscriptAnnotatedType,
      consentMarketing: ConsentMarketingForm as unknown as TAtscriptAnnotatedType,
      loginCredentials: LoginCredentialsForm as unknown as TAtscriptAnnotatedType,
      mfaCode: MfaCodeForm as unknown as TAtscriptAnnotatedType,
      personaSelect: PersonaSelectForm as unknown as TAtscriptAnnotatedType,
      pincode: PincodeForm as unknown as TAtscriptAnnotatedType,
      profileComplete: ProfileCompleteForm as unknown as TAtscriptAnnotatedType,
      select2fa: Select2faForm as unknown as TAtscriptAnnotatedType,
      setPassword: SetPasswordForm as unknown as TAtscriptAnnotatedType,
      tenantSelect: TenantSelectForm as unknown as TAtscriptAnnotatedType,
      termsAccept: TermsAcceptForm as unknown as TAtscriptAnnotatedType,
      ...opts.forms,
    },
  };
}
