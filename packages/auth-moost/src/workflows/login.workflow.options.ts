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

import { ProfileCompleteForm } from "../atscript/models/forms.as.js";

export const DEFAULT_MFA_CODE_TTL_MS = 5 * 60 * 1000;

export type LoginRedirect = "referer" | "home";

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
    /** Replaceable profile-completion form. Falls back to the default first/last name shape. */
    profileCompleteForm?: TAtscriptAnnotatedType;
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
}

/**
 * Fully-resolved view used by the workflow at runtime — every nested group is
 * always populated by `mergeLoginOpts`, so schema conditions can read
 * `ctx.opts.<group>.<flag>` directly without optional chaining.
 *
 * Fields without sensible defaults (e.g. `termsVersion`, `concurrencyLimit`,
 * `profileCompleteForm`) stay optional inside their group.
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
    profileCompleteForm: TAtscriptAnnotatedType;
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
      profileCompleteForm: ProfileCompleteForm as unknown as TAtscriptAnnotatedType,
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
      redirect: "referer",
      ...opts.finalize,
    },
  };
}
