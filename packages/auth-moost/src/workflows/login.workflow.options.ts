/**
 * Full shape per `WF_LOGIN.md` §"LoginWorkflowOptions — full shape".
 *
 * Defaults give a sane out-of-the-box login flow (password → optional MFA →
 * issue tokens → redirect). Consumers turn on advanced features (channel
 * enrollment, device trust, MFA enroll-required, terms acceptance, tenant /
 * persona selection, risk step-up, etc.) by replacing this provider entry —
 * no subclassing required for the common cases.
 */
import type { TAtscriptAnnotatedType } from "@atscript/typescript/utils";
import { Injectable } from "moost";

import { ProfileCompleteForm } from "../atscript/models/forms.as.js";

import type { LoginWfCtx } from "./login.workflow";

export const DEFAULT_MFA_CODE_TTL_MS = 5 * 60 * 1000;

export type LoginRedirect = "referer" | "home" | ((ctx: LoginWfCtx) => string);

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

@Injectable()
export class LoginWorkflowOptions {
  // ── Phase 1: alt actions on the credentials form ────────────────────────
  forgotPasswordAction = true;
  signupAction = false;
  magicLinkAction = false;
  ssoActions: SsoProvider[] = [];
  /** When true, successful magic-link verify bypasses Phase 4 (MFA). */
  magicLinkSkipsMfa = false;
  magicLinkTtlMs = 30 * 60_000;
  recoveryUrl = "/recover";
  /**
   * Builds the redirect URL the `forgotPassword` alt-action navigates to.
   * Receives whatever the user typed into the username field so the recovery
   * page can pre-fill it. When undefined, defaults to
   * `${recoveryUrl}?username=${encodeURIComponent(username ?? '')}`.
   */
  recoveryUrlBuilder?: (username?: string) => string;
  signupUrl = "/signup";
  /** Advanced: inline recovery in the login flow rather than redirecting. */
  embedRecovery = false;

  // ── Phase 2: account-state guards ──────────────────────────────────────
  emailVerifiedRequired = false;
  passwordExpiryGuard = true;
  passwordInitialGuard = true;

  // ── Phase 3: channel-enrollment loops ──────────────────────────────────
  ensureEmail = false;
  ensurePhone = false;

  // ── Phase 4: MFA challenge ─────────────────────────────────────────────
  mfaEnabled = true;
  mfaTransports: MfaTransport[] = ["sms", "email", "totp"];
  mfaBackupCodes = true;
  mfaEnrollRequired = false;
  pincodeTtlMs = 5 * 60_000;
  pincodeResendTimeoutMs = 60_000;
  /** Numeric length of the server-generated OTP for SMS/email pincodes. */
  pincodeLength = 6;

  // Device trust — "remember this device, skip OTP/MFA next time"
  deviceTrust = false;
  deviceTrustOptIn = true;
  deviceTrustCookieName = "aooth_trusted_device";
  deviceTrustTtlMs = 24 * 60 * 60_000;
  deviceTrustSkipsMfa = true;
  deviceTrustBindsTo: "cookie" | "cookie+ip" = "cookie";

  // ── Phase 6: acceptance / onboarding ──────────────────────────────────
  termsAcceptVersion?: string;
  profileCompleteRequired = false;
  /**
   * Replaceable profile-completion form. Defaults to the minimal first/last
   * name shape shipped in `forms.as`. Consumers replace via opts override.
   */
  profileCompleteForm: TAtscriptAnnotatedType =
    ProfileCompleteForm as unknown as TAtscriptAnnotatedType;
  /**
   * Inspected by the `profile-complete` step to decide which fields are
   * missing. Defaults to the keys of `profileCompleteForm`; consumers
   * override to read missing-ness from a tenant policy / user record shape.
   */
  profileMissingFields?: (ctx: LoginWfCtx) => Promise<string[]> | string[];
  /**
   * Persists the profile-complete payload onto the user record. Defaults to
   * a no-op (the workflow only records that the form was submitted). For a
   * real flow, override to write into your user store.
   */
  profileApply?: (username: string, payload: Record<string, unknown>) => Promise<void> | void;
  consentMarketing = false;
  /** Persists the marketing consent decision. Defaults to no-op. */
  consentMarketingApply?: (username: string, optIn: boolean) => Promise<void> | void;

  // ── Phase 7: tenant / persona ─────────────────────────────────────────
  tenantSelect = false;
  /** Resolves the user's available tenants. Required when `tenantSelect: true`. */
  loadTenants?: (
    username: string,
  ) => Promise<Array<{ id: string; name: string }>> | Array<{ id: string; name: string }>;
  personaSelect = false;
  loadPersonas?: (
    username: string,
  ) => Promise<Array<{ id: string; label: string }>> | Array<{ id: string; label: string }>;

  // ── Phase 8: session policy ───────────────────────────────────────────
  concurrencyLimit?: ConcurrencyLimitOptions;
  /** Counts currently-active sessions for `concurrencyLimit`. */
  countActiveSessions?: (username: string) => Promise<number> | number;
  /** Implements the "log out other sessions" branch of `concurrencyLimit`. */
  logoutOtherSessions?: (username: string) => Promise<void> | void;
  /**
   * Risk-step-up: when the callback returns `require: true`, the workflow
   * forces an additional MFA pincode challenge before issuing tokens.
   */
  riskStepUp?: (ctx: LoginWfCtx) => Promise<{ require: boolean; reason?: string }>;
  /**
   * JSON-safe projection of `!!riskStepUp` populated by `snapshotOpts` at
   * workflow start — schema `condition`/`while` predicates read from
   * `ctx.opts` (the snapshot, which strips callbacks) so they need a boolean
   * stand-in. Consumers do not set this directly.
   */
  riskStepUpEnabled?: boolean;

  // ── Phase 9: finalize ─────────────────────────────────────────────────
  auditLogin = true;
  notifyNewDevice = false;
  /**
   * Final-step redirect target. `'referer'` reads `Referer` from the request
   * (falls back to `/`); `'home'` always uses `/`; a function receives the
   * full ctx and returns the URL.
   */
  redirect: LoginRedirect = "referer";

  constructor(opts: Partial<LoginWorkflowOptions> = {}) {
    Object.assign(this, opts);
  }
}
