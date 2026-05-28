/**
 * Unified `AuthWorkflow` — single concrete class with three `@Workflow`
 * methods (`loginFlow`, `inviteFlow`, `recoveryFlow`) replacing the prior
 * `LoginWorkflow` / `InviteWorkflow` / `RecoveryWorkflow` trio plus their
 * abstract `AuthWorkflowBase` parent. Each step is implemented exactly once;
 * the three `@WorkflowSchema` arrays reference step IDs by string so the same
 * `@Step` body can be reached from multiple flows.
 *
 * Design: see `packages/auth-moost/UNIFICATION.md`.
 *
 * **Step 3 (skeleton)** — this file currently:
 *   - Declares the class with its constructor + DI providers.
 *   - Provides all 17 `protected resolveXxx(ctx)` defaults (extracted from the
 *     existing three workflows).
 *   - Provides all 66 `@Step` methods as stubs returning `undefined`.
 *   - Provides the three `@Workflow` methods with their final
 *     `@WorkflowSchema` arrays (copied verbatim from §9 of the design doc).
 *
 * Step bodies are filled in steps 4-6. Until then this class type-checks and
 * is registerable as a Moost controller, but running any of its `@Workflow`
 * schemas would no-op every step.
 */
import { AuthCredential } from "@aooth/auth";
import { UserService } from "@aooth/user";
import type { TAtscriptAnnotatedType } from "@atscript/typescript/utils";
import { Step, Workflow, WorkflowParam, WorkflowSchema } from "@moostjs/event-wf";
import { Controller, Inherit, Param } from "moost";

import { AuthOpts } from "../auth.opts";
import { ConsentStore } from "../consent.store";
import { Public } from "../auth.decorator";
import type { AuthWfCtx, AuthWfAltCredsPolicy } from "./auth-workflow.ctx";
import type { AuthWorkflowOpts, ResolvedAuthWorkflowOpts } from "./auth-workflow.opts";
import {
  consentsPersistTailSchema,
  mfaLoopSchema,
  passwordPhaseSchema,
  pincodeSendCheckPair,
} from "./auth-workflow.schemas";

/**
 * Unified outbound-dispatch payload. Customers override `deliver(payload)` on
 * the `AuthWorkflow` subclass to route by `kind` (per-purpose templates) and
 * `channel` (email vs SMS). Replaces the prior workflow-specific deliver
 * payloads which carried slightly different field sets per call site.
 */
export type AuthDeliveryPayload =
  | {
      kind: "mfa-pincode";
      channel: "sms" | "email";
      recipient: string;
      code: string;
      expiresInMs: number;
    }
  | {
      kind: "recovery-pincode";
      channel: "email";
      recipient: string;
      code: string;
      expiresInMs: number;
    }
  | {
      kind: "enroll-pincode";
      channel: "sms" | "email";
      recipient: string;
      code: string;
      expiresInMs: number;
    }
  | {
      kind: "invite-link";
      channel: "email";
      recipient: string;
      url: string;
      expiresInMs: number;
    }
  | {
      kind: "new-device-notice";
      channel: "email";
      recipient: string;
      deviceLabel?: string;
      loginAt: number;
    };

/**
 * Minimal opts-merge for the skeleton. Populates the two `autoLogin*`
 * booleans + the device-trust cookie defaults so schema condition functions
 * (`!this.opts.autoLoginOnInvite`, etc.) read deterministic values. The
 * `forms` map is intentionally NOT defaulted here — the real form-schema
 * defaults are wired in step 4 alongside the step body merges. Stub @Step
 * bodies never traverse `this.opts.forms`, so the cast is safe for P1 step 3.
 */
function mergeAuthWorkflowOpts(opts: AuthWorkflowOpts): ResolvedAuthWorkflowOpts {
  return {
    autoLoginOnInvite: opts.autoLoginOnInvite ?? true,
    autoLoginOnRecover: opts.autoLoginOnRecover ?? false,
    deviceTrust: {
      cookieName: "aooth_trusted_device",
      ttlMs: 24 * 60 * 60_000,
      bindsTo: "cookie",
      ...opts.deviceTrust,
    },
    forms: (opts.forms ?? {}) as ResolvedAuthWorkflowOpts["forms"],
  };
}

@Inherit()
@Controller()
export class AuthWorkflow {
  protected readonly opts: ResolvedAuthWorkflowOpts;
  protected readonly users: UserService;
  protected readonly auth: AuthCredential;
  protected readonly authOpts: AuthOpts;
  protected readonly consentStore: ConsentStore;

  constructor(
    opts: AuthWorkflowOpts,
    users: UserService,
    auth: AuthCredential,
    authOpts: AuthOpts,
    consentStore: ConsentStore,
  ) {
    this.opts = mergeAuthWorkflowOpts(opts);
    this.users = users;
    this.auth = auth;
    this.authOpts = authOpts;
    this.consentStore = consentStore;
  }

  // ── Protected extension surface ─────────────────────────────────────────

  /**
   * Unified outbound dispatch hook. Default is a no-op — customers override
   * to wire email / SMS senders, magic-link emitters, new-device notices.
   * Stays sync-friendly per CLAUDE.md: the default `void` return preserves
   * the engine's sync fast path; async customer overrides are accepted via
   * the union return type.
   */
  protected deliver(_payload: AuthDeliveryPayload): void | Promise<void> {
    return undefined;
  }

  // ── Resolved policy surface (override on subclass to customize) ─────────

  /**
   * Resolve the profile-completion policy. Reached from login.flow only.
   * Default-false matches the prior `LoginWorkflow` behaviour.
   */
  protected resolveProfile(
    _ctx: AuthWfCtx,
  ): { required: boolean } | Promise<{ required: boolean }> {
    return { required: false };
  }

  /**
   * Resolve the alternate-credentials policy (forgot-password / signup /
   * magic-link / SSO providers + their URLs). Reached from login.flow.
   */
  protected resolveAlternateCredentials(
    _ctx: AuthWfCtx,
  ):
    | NonNullable<AuthWfCtx["alternateCredentials"]>
    | Promise<NonNullable<AuthWfCtx["alternateCredentials"]>> {
    return {
      forgotPassword: true,
      signup: false,
      magicLink: false,
      magicLinkSkipsMfa: false,
      ssoProviders: [],
      recoveryUrl: "/recover",
      signupUrl: "/signup",
      embedRecovery: false,
    };
  }

  /**
   * Resolve the device-trust policy. Infrastructure (cookieName / ttlMs /
   * bindsTo) lives on `this.opts.deviceTrust`. Reached from login.flow.
   */
  protected resolveDeviceTrust(
    _ctx: AuthWfCtx,
  ): NonNullable<AuthWfCtx["deviceTrust"]> | Promise<NonNullable<AuthWfCtx["deviceTrust"]>> {
    return {
      enabled: false,
      optIn: true,
      skipsMfa: true,
    };
  }

  /**
   * Resolve the channel-enrolment policy (ensureEmail / ensurePhone).
   * Reached from login.flow.
   */
  protected resolveEnrollment(
    _ctx: AuthWfCtx,
  ): NonNullable<AuthWfCtx["enrollment"]> | Promise<NonNullable<AuthWfCtx["enrollment"]>> {
    return {
      ensureEmail: false,
      ensurePhone: false,
    };
  }

  /**
   * Resolve the finalize policy. Reached from login.flow. `auditLogin` is
   * dropped from the shape per §2 — audit moved out of the workflow layer.
   */
  protected resolveFinalize(
    _ctx: AuthWfCtx,
  ): NonNullable<AuthWfCtx["finalize"]> | Promise<NonNullable<AuthWfCtx["finalize"]>> {
    return {
      notifyNewDevice: false,
      redirect: false,
    };
  }

  /**
   * Resolve the login-time guards policy (passwordInitial / passwordExpiry /
   * emailVerifiedRequired). Reached from login.flow.
   */
  protected resolveGuards(
    _ctx: AuthWfCtx,
  ): NonNullable<AuthWfCtx["guards"]> | Promise<NonNullable<AuthWfCtx["guards"]>> {
    return {
      passwordInitial: true,
      passwordExpiry: true,
      emailVerifiedRequired: false,
    };
  }

  /**
   * Resolve the session-policy (concurrency limit). Reached from login.flow.
   */
  protected resolveSessionPolicy(
    _ctx: AuthWfCtx,
  ): NonNullable<AuthWfCtx["sessionPolicy"]> | Promise<NonNullable<AuthWfCtx["sessionPolicy"]>> {
    return {};
  }

  /**
   * Resolve the unified MFA policy. Replaces login's hardcoded defaults +
   * invite's `{ issuer }` resolver. Issuer is sourced from
   * `this.authOpts.totpIssuer` so per-app TOTP labels remain a single knob.
   * Reached from login.flow + invite.start.
   */
  protected resolveMfaPolicy(
    _ctx: AuthWfCtx,
  ): NonNullable<AuthWfCtx["mfaPolicy"]> | Promise<NonNullable<AuthWfCtx["mfaPolicy"]>> {
    return {
      mode: "optional",
      availableTransports: ["sms", "email", "totp"],
      issuer: this.authOpts.totpIssuer,
    };
  }

  /**
   * Resolve the channel-OTP disclosure copy rendered beneath the email/phone
   * input on `AskEmailForm` / `AskPhoneForm`. Reached from login.flow Phase 3.
   * Default returns a TCPA / PECR / CASL / GDPR-safe English paragraph that is
   * GENERIC per channel (no target templated in — the user hasn't submitted
   * yet at ask-time).
   */
  protected resolveOtpDisclosure(
    _ctx: AuthWfCtx,
    channel: "email" | "phone",
  ): string | Promise<string> {
    return channel === "phone"
      ? "By providing your phone number, you consent to receive one-time security codes from us via SMS. Message and data rates may apply."
      : "By providing your email address, you consent to receive one-time security codes from us via email. Standard email delivery may apply.";
  }

  /**
   * Resolve whether to require an additional MFA round (risk step-up).
   * Default never requires an extra factor.
   */
  protected async resolveRiskStepUp(
    _ctx: AuthWfCtx,
  ): Promise<{ require: boolean; reason?: string }> {
    return { require: false };
  }

  /**
   * Resolve the recovery URL targeted by the `forgotPassword` alt-action on
   * login's credentials form. Receives whatever the user typed into the
   * username field so the recovery page can pre-fill it.
   *
   * Sync return type only — the caller (`credentials` @Step alt-action
   * handler) uses the URL inline.
   */
  protected resolveRecoveryUrl(username: string | undefined, alt: AuthWfAltCredsPolicy): string {
    return `${alt.recoveryUrl}?username=${encodeURIComponent(username ?? "")}`;
  }

  /**
   * Resolve the admin-form policy (whether to collect roles on the invite
   * admin form). Reached from invite.start admin phase.
   */
  protected resolveAdminForm(
    _ctx: AuthWfCtx,
  ): NonNullable<AuthWfCtx["adminForm"]> | Promise<NonNullable<AuthWfCtx["adminForm"]>> {
    return { collectRoles: true };
  }

  /**
   * Resolve the invite accept-tail policy. Reached from invite.start accept
   * phase. `loginUrl` defaults to `this.authOpts.loginUrl`. Note: today's
   * `freshLoginRequired` field is GONE — the auto-login choice is the static
   * `AuthWorkflowOpts.autoLoginOnInvite` boolean (per §2 decision).
   */
  protected resolveAccept(
    _ctx: AuthWfCtx,
  ): NonNullable<AuthWfCtx["accept"]> | Promise<NonNullable<AuthWfCtx["accept"]>> {
    return {
      alreadyAcceptedRedirectUrl: this.authOpts.loginUrl,
      loginUrl: this.authOpts.loginUrl,
      showConfirmation: true,
      confirmationMessage: "Your account has been created.",
    };
  }

  /**
   * Resolve the recovery post-reset policy. Reached from recovery.flow.
   * `freshLoginRequired` REMOVED — the auto-login choice is the static
   * `AuthWorkflowOpts.autoLoginOnRecover` boolean (per §2 decision).
   */
  protected resolvePostReset(
    _ctx: AuthWfCtx,
  ): NonNullable<AuthWfCtx["postReset"]> | Promise<NonNullable<AuthWfCtx["postReset"]>> {
    return {
      // safe to default-on since CredentialStoreJwt.passesEpoch uses >=
      revokeAllSessions: true,
      loginUrl: this.authOpts.loginUrl,
    };
  }

  /**
   * Resolve the recovery alt-actions policy (whether `backToLogin` is offered
   * on the recovery forms). Renamed from the prior `resolveAltActions` to
   * disambiguate from login's `resolveAlternateCredentials` (different
   * concept). Reached from recovery.flow.
   */
  protected resolveRecoveryAltActions(
    _ctx: AuthWfCtx,
  ):
    | NonNullable<AuthWfCtx["recoveryAltActions"]>
    | Promise<NonNullable<AuthWfCtx["recoveryAltActions"]>> {
    return { backToLogin: true };
  }

  // ── Pincode variation seams (override points for unified pincode-send/check) ──
  //
  // Defaults discriminate by ctx-slot presence (`ctx.mfa?.method` set → MFA
  // flavor, else → recovery). Customers override these to redirect form choice
  // / target / channel without touching the unified `pincode-send` / `pincode-check`
  // step bodies.

  /**
   * Pick the form to render for the unified pincode pair. Default routes to
   * `opts.forms.pincode` (MFA alt-actions) when `ctx.mfa?.method` is set;
   * otherwise `opts.forms.recoveryPincode` (recovery alt-actions).
   */
  protected resolvePincodeForm(ctx: AuthWfCtx): TAtscriptAnnotatedType {
    return ctx.mfa?.method ? this.opts.forms.pincode : this.opts.forms.recoveryPincode;
  }

  /**
   * Pick the raw recipient + channel for pincode delivery. Default sources
   * the address from the user's enrolled MFA method (when `ctx.mfa.method` is
   * set) or from `ctx.email` (recovery path).
   */
  protected resolvePincodeTarget(ctx: AuthWfCtx): { address: string; channel: "sms" | "email" } {
    if (ctx.mfa?.method && ctx.mfa.method !== "totp") {
      // TODO P1 step 4: read raw method address via users.getUser; placeholder uses masked.
      const m = ctx.mfa.enrolledMethods?.find((mm) => mm.kind === ctx.mfa!.method);
      return { address: m?.masked ?? "", channel: ctx.mfa.method };
    }
    return { address: ctx.email ?? "", channel: "email" };
  }

  /**
   * Route a form alt-action click to a canonical outcome. Default returns
   * `undefined` (customer overrides per form / per flow).
   */
  protected resolvePincodeAltAction(
    _ctx: AuthWfCtx,
    _action: string,
  ): "resend" | "exit" | "useDifferentMethod" | undefined {
    return undefined;
  }

  // ── @Step stubs (66 — bodies filled in steps 4-6) ───────────────────────
  //
  // Each stub returns `undefined` and takes the ctx via `@WorkflowParam("context")`.
  // `@Public()` is applied per §6 — every step that the wf engine can land on
  // under anonymous auth carries `@Public()`. Invite admin-phase steps + admin
  // helper steps (admin-form, infer-roles, build-user-extras, create-user)
  // are NOT `@Public()` — arbac evaluates them on the admin's first-pass.

  // ── Init + entry (4) ──

  @Step("init-login")
  @Public()
  initLogin(@WorkflowParam("context") _ctx: AuthWfCtx): void {
    return undefined;
  }

  @Step("init-invite-admin")
  initInviteAdmin(@WorkflowParam("context") _ctx: AuthWfCtx): void {
    return undefined;
  }

  @Step("init-invite-accept")
  @Public()
  initInviteAccept(@WorkflowParam("context") _ctx: AuthWfCtx): void {
    return undefined;
  }

  @Step("init-recovery")
  @Public()
  initRecovery(@WorkflowParam("context") _ctx: AuthWfCtx): void {
    return undefined;
  }

  // ── Authentication entry (2) ──

  @Step("credentials")
  @Public()
  credentials(@WorkflowParam("context") _ctx: AuthWfCtx): void {
    return undefined;
  }

  @Step("request")
  @Public()
  request(@WorkflowParam("context") _ctx: AuthWfCtx): void {
    return undefined;
  }

  // ── Prepare-* policy steps (16) ──

  @Step("prepare-semantic-flags")
  @Public()
  prepareSemanticFlags(@WorkflowParam("context") _ctx: AuthWfCtx): void {
    return undefined;
  }

  @Step("prepare-profile")
  @Public()
  prepareProfile(@WorkflowParam("context") _ctx: AuthWfCtx): void {
    return undefined;
  }

  @Step("prepare-consents")
  @Public()
  prepareConsents(@WorkflowParam("context") _ctx: AuthWfCtx): void {
    return undefined;
  }

  @Step("prepare-alternate-credentials")
  @Public()
  prepareAlternateCredentials(@WorkflowParam("context") _ctx: AuthWfCtx): void {
    return undefined;
  }

  @Step("prepare-device-trust")
  @Public()
  prepareDeviceTrust(@WorkflowParam("context") _ctx: AuthWfCtx): void {
    return undefined;
  }

  @Step("prepare-enrollment")
  @Public()
  prepareEnrollment(@WorkflowParam("context") _ctx: AuthWfCtx): void {
    return undefined;
  }

  @Step("prepare-finalize")
  @Public()
  prepareFinalize(@WorkflowParam("context") _ctx: AuthWfCtx): void {
    return undefined;
  }

  @Step("prepare-guards")
  @Public()
  prepareGuards(@WorkflowParam("context") _ctx: AuthWfCtx): void {
    return undefined;
  }

  @Step("prepare-session-policy")
  @Public()
  prepareSessionPolicy(@WorkflowParam("context") _ctx: AuthWfCtx): void {
    return undefined;
  }

  @Step("prepare-mfa")
  @Public()
  prepareMfa(@WorkflowParam("context") _ctx: AuthWfCtx): void {
    return undefined;
  }

  @Step("prepare-admin-form")
  prepareAdminForm(@WorkflowParam("context") _ctx: AuthWfCtx): void {
    return undefined;
  }

  @Step("prepare-available-roles")
  prepareAvailableRoles(@WorkflowParam("context") _ctx: AuthWfCtx): void {
    return undefined;
  }

  @Step("prepare-accept")
  @Public()
  prepareAccept(@WorkflowParam("context") _ctx: AuthWfCtx): void {
    return undefined;
  }

  @Step("prepare-password-rules")
  @Public()
  preparePasswordRules(@WorkflowParam("context") _ctx: AuthWfCtx): void {
    return undefined;
  }

  @Step("prepare-post-reset")
  @Public()
  preparePostReset(@WorkflowParam("context") _ctx: AuthWfCtx): void {
    return undefined;
  }

  @Step("prepare-recovery-alt-actions")
  @Public()
  prepareRecoveryAltActions(@WorkflowParam("context") _ctx: AuthWfCtx): void {
    return undefined;
  }

  // ── Invite admin phase (5; arbac-evaluated except `send-email`) ──

  @Step("admin-form")
  adminForm(@WorkflowParam("context") _ctx: AuthWfCtx): void {
    return undefined;
  }

  @Step("infer-roles")
  inferRoles(@WorkflowParam("context") _ctx: AuthWfCtx): void {
    return undefined;
  }

  @Step("build-user-extras")
  buildUserExtras(@WorkflowParam("context") _ctx: AuthWfCtx): void {
    return undefined;
  }

  @Step("create-user")
  createUser(@WorkflowParam("context") _ctx: AuthWfCtx): void {
    return undefined;
  }

  @Step("send-email")
  @Public()
  sendInviteEmail(@WorkflowParam("context") _ctx: AuthWfCtx): void {
    return undefined;
  }

  // ── Invite accept-tail (5) ──

  @Step("check-pending-invitation")
  @Public()
  checkPendingInvitation(@WorkflowParam("context") _ctx: AuthWfCtx): void {
    return undefined;
  }

  @Step("idempotent-redirect")
  @Public()
  idempotentRedirect(@WorkflowParam("context") _ctx: AuthWfCtx): void {
    return undefined;
  }

  @Step("unset-pending-invitation")
  @Public()
  unsetPendingInvitation(@WorkflowParam("context") _ctx: AuthWfCtx): void {
    return undefined;
  }

  @Step("activate-user")
  @Public()
  activateUser(@WorkflowParam("context") _ctx: AuthWfCtx): void {
    return undefined;
  }

  @Step("confirmation")
  @Public()
  confirmation(@WorkflowParam("context") _ctx: AuthWfCtx): void {
    return undefined;
  }

  // ── Password (1) — collapsed across all three flows ──

  @Step("create-password-form")
  @Public()
  createPasswordForm(@WorkflowParam("context") _ctx: AuthWfCtx): void {
    return undefined;
  }

  // ── Channel enrolment (2) — login only, parameterized by :channel ──

  @Step("ask/:channel(email|phone)")
  @Public()
  askChannel(
    @WorkflowParam("context") _ctx: AuthWfCtx,
    @Param("channel") _channel: "email" | "phone",
  ): void {
    return undefined;
  }

  @Step("verify/:channel(email|phone)")
  @Public()
  verifyChannel(
    @WorkflowParam("context") _ctx: AuthWfCtx,
    @Param("channel") _channel: "email" | "phone",
  ): void {
    return undefined;
  }

  // ── MFA loop (11; shared login + invite, plus recovery's reuse of pincode pair) ──

  @Step("check-trusted-device")
  @Public()
  checkTrustedDevice(@WorkflowParam("context") _ctx: AuthWfCtx): void {
    return undefined;
  }

  @Step("load-enrolled-mfa-methods")
  @Public()
  loadEnrolledMfaMethods(@WorkflowParam("context") _ctx: AuthWfCtx): void {
    return undefined;
  }

  @Step("select-mfa-method")
  @Public()
  selectMfaMethod(@WorkflowParam("context") _ctx: AuthWfCtx): void {
    return undefined;
  }

  @Step("select-2fa")
  @Public()
  select2fa(@WorkflowParam("context") _ctx: AuthWfCtx): void {
    return undefined;
  }

  @Step("pincode-send")
  @Public()
  pincodeSend(@WorkflowParam("context") _ctx: AuthWfCtx): void {
    return undefined;
  }

  @Step("pincode-check")
  @Public()
  pincodeCheck(@WorkflowParam("context") _ctx: AuthWfCtx): void {
    return undefined;
  }

  @Step("totp-check")
  @Public()
  totpCheck(@WorkflowParam("context") _ctx: AuthWfCtx): void {
    return undefined;
  }

  @Step("enroll-pick-method")
  @Public()
  enrollPickMethod(@WorkflowParam("context") _ctx: AuthWfCtx): void {
    return undefined;
  }

  @Step("enroll-address")
  @Public()
  enrollAddress(@WorkflowParam("context") _ctx: AuthWfCtx): void {
    return undefined;
  }

  @Step("enroll-confirm")
  @Public()
  enrollConfirm(@WorkflowParam("context") _ctx: AuthWfCtx): void {
    return undefined;
  }

  @Step("risk-step-up")
  @Public()
  riskStepUp(@WorkflowParam("context") _ctx: AuthWfCtx): void {
    return undefined;
  }

  // ── Login post-MFA tail (5) ──

  @Step("device-trust")
  @Public()
  deviceTrust(@WorkflowParam("context") _ctx: AuthWfCtx): void {
    return undefined;
  }

  @Step("profile-complete")
  @Public()
  profileComplete(@WorkflowParam("context") _ctx: AuthWfCtx): void {
    return undefined;
  }

  @Step("terms-bump-prompt")
  @Public()
  termsBumpPrompt(@WorkflowParam("context") _ctx: AuthWfCtx): void {
    return undefined;
  }

  @Step("load-active-sessions")
  @Public()
  loadActiveSessions(@WorkflowParam("context") _ctx: AuthWfCtx): void {
    return undefined;
  }

  @Step("concurrency-limit")
  @Public()
  concurrencyLimit(@WorkflowParam("context") _ctx: AuthWfCtx): void {
    return undefined;
  }

  // ── Invite accept-tail profile (2) ──

  @Step("collect-profile")
  @Public()
  collectProfile(@WorkflowParam("context") _ctx: AuthWfCtx): void {
    return undefined;
  }

  @Step("apply-profile")
  @Public()
  applyProfile(@WorkflowParam("context") _ctx: AuthWfCtx): void {
    return undefined;
  }

  // ── Extra-step (1) — login + invite, gated on isFirstLogin ──

  @Step("extra-step")
  @Public()
  extraStep(@WorkflowParam("context") _ctx: AuthWfCtx): void {
    return undefined;
  }

  // ── Consents persistence (1) — all three ──

  @Step("persist-consents")
  @Public()
  persistConsents(@WorkflowParam("context") _ctx: AuthWfCtx): void {
    return undefined;
  }

  // ── Recovery (1) ──

  @Step("revoke-sessions")
  @Public()
  revokeSessions(@WorkflowParam("context") _ctx: AuthWfCtx): void {
    return undefined;
  }

  // ── Finalize (5) ──

  @Step("issue")
  @Public()
  issue(@WorkflowParam("context") _ctx: AuthWfCtx): void {
    return undefined;
  }

  @Step("notify-new-device")
  @Public()
  notifyNewDevice(@WorkflowParam("context") _ctx: AuthWfCtx): void {
    return undefined;
  }

  @Step("redirect")
  @Public()
  redirect(@WorkflowParam("context") _ctx: AuthWfCtx): void {
    return undefined;
  }

  @Step("finalize-fresh-login")
  @Public()
  finalizeFreshLogin(@WorkflowParam("context") _ctx: AuthWfCtx): void {
    return undefined;
  }

  @Step("finalize-auto-login")
  @Public()
  finalizeAutoLogin(@WorkflowParam("context") _ctx: AuthWfCtx): void {
    return undefined;
  }

  // ── Alt-cred stubs (5; login-only, all condition: false placeholders) ──

  @Step("magic-link-request")
  @Public()
  magicLinkRequest(@WorkflowParam("context") _ctx: AuthWfCtx): void {
    return undefined;
  }

  @Step("magic-link-send")
  @Public()
  magicLinkSend(@WorkflowParam("context") _ctx: AuthWfCtx): void {
    return undefined;
  }

  @Step("magic-link-verified")
  @Public()
  magicLinkVerified(@WorkflowParam("context") _ctx: AuthWfCtx): void {
    return undefined;
  }

  @Step("passkey")
  @Public()
  passkey(@WorkflowParam("context") _ctx: AuthWfCtx): void {
    return undefined;
  }

  @Step("sso-callback")
  @Public()
  ssoCallback(@WorkflowParam("context") _ctx: AuthWfCtx): void {
    return undefined;
  }

  // ── @Workflow methods (3) — schemas copied verbatim from UNIFICATION.md §9 ──

  /**
   * login.flow — `wfid = '<controller-prefix>/auth/login/flow'` once wired.
   * `@Public()` on the body because the wf adapter dispatches the flow body
   * on every `start()` / `resume()` call (anonymous login).
   */
  @Workflow("flow")
  @Public()
  @WorkflowSchema<AuthWfCtx>([
    { id: "init-login" },
    { id: "credentials" },
    { break: (ctx) => !ctx.username },

    // Resolve all policy groups
    { id: "prepare-profile" },
    { id: "prepare-consents" },
    { id: "prepare-alternate-credentials" },
    { id: "prepare-device-trust" },
    { id: "prepare-enrollment" },
    { id: "prepare-finalize" },
    { id: "prepare-guards" },
    { id: "prepare-session-policy" },

    // Semantic flags AFTER prepare-guards so it can read ctx.guards.* + ctx.isPasswordInitial/Expired
    // (which credentials sets inline). Idempotent on re-entry.
    { id: "prepare-semantic-flags" },

    // Alt-cred stub registration (always condition: false; consumer overrides)
    {
      condition: () => false,
      steps: [
        { id: "magic-link-request" },
        { id: "magic-link-send" },
        { id: "magic-link-verified" },
        { id: "passkey" },
        { id: "sso-callback" },
      ],
    },

    // Forced channel enrolment
    {
      id: "ask/email",
      condition: (ctx) =>
        (!!ctx.enrollment?.ensureEmail || !!ctx.guards?.emailVerifiedRequired) && !ctx.email,
    },
    {
      id: "verify/email",
      condition: (ctx) =>
        (!!ctx.enrollment?.ensureEmail || !!ctx.guards?.emailVerifiedRequired) &&
        !!ctx.email &&
        !ctx.channel?.emailConfirmed,
    },
    {
      id: "ask/phone",
      condition: (ctx) => !!ctx.enrollment?.ensurePhone && !ctx.channel?.phone,
    },
    {
      id: "verify/phone",
      condition: (ctx) =>
        !!ctx.enrollment?.ensurePhone && !!ctx.channel?.phone && !ctx.channel?.phoneConfirmed,
    },

    // MFA loop (shared)
    ...mfaLoopSchema,

    // Post-MFA device-trust
    {
      id: "device-trust",
      condition: (ctx) =>
        !!ctx.deviceTrust?.enabled &&
        !!ctx.otp?.verified &&
        !!ctx.trust?.newDevice &&
        (!ctx.deviceTrust?.optIn || !!ctx.trust?.rememberDevice),
    },

    // Forced password change (shared) — uses semantic flag
    ...passwordPhaseSchema,
    { break: (ctx) => !!ctx.aborted },

    // Profile + extra-step
    {
      id: "profile-complete",
      condition: (ctx) =>
        !!ctx.profileCompleteRequired &&
        !ctx.completion?.profileApplied &&
        (ctx.profileMissingFields?.length ?? 0) > 0,
    },
    { id: "extra-step", condition: (ctx) => !!ctx.isFirstLogin },
    {
      id: "terms-bump-prompt",
      condition: (ctx) =>
        (ctx.consents?.pending?.length ?? 0) > 0 &&
        !ctx.consents?.decidedAt &&
        !ctx.consents?.persisted,
    },

    ...consentsPersistTailSchema,

    // Session policy
    {
      condition: (ctx) => !!ctx.sessionPolicy?.concurrencyLimit,
      steps: [
        { id: "load-active-sessions" },
        {
          id: "concurrency-limit",
          condition: (ctx) =>
            (ctx.session?.activeSessions ?? 0) >= ctx.sessionPolicy!.concurrencyLimit!.max,
        },
      ],
    },
    { break: (ctx) => !!ctx.aborted },

    // Finalize (login-specific tail)
    { id: "issue", condition: (ctx) => !ctx.completion?.tokensIssued },
    {
      condition: (ctx) => !!ctx.completion?.tokensIssued,
      steps: [
        {
          id: "notify-new-device",
          condition: (ctx) =>
            !ctx.isFirstLogin && !!ctx.finalize?.notifyNewDevice && !!ctx.trust?.newDevice,
        },
        { id: "redirect" },
      ],
    },
  ])
  loginFlow(): void {}

  /**
   * invite.start — admin-phase + anonymous magic-link accept-tail. Admin
   * steps are arbac-evaluated (no `@Public()` on them); accept-tail steps are
   * all `@Public()` (anonymous resume). The body itself is `@Public()` so the
   * wf adapter can dispatch start/resume on anonymous magic-link clicks.
   */
  @Workflow("start")
  @Public()
  @WorkflowSchema<AuthWfCtx>([
    // ── Phase A: admin invites (arbac-protected) ──
    { id: "init-invite-admin" },
    { id: "prepare-admin-form" },
    { id: "prepare-available-roles", condition: (ctx) => !!ctx.adminForm?.collectRoles },
    { id: "admin-form", condition: (ctx) => !ctx.email },
    { id: "infer-roles", condition: (ctx) => !!ctx.email },
    {
      id: "build-user-extras",
      condition: (ctx) => !!(ctx.email && !ctx.username && !ctx.admin?.userExtras),
    },
    {
      id: "create-user",
      condition: (ctx) => !!(ctx.email && !ctx.username && !!ctx.admin?.userExtras),
    },
    { id: "send-email", condition: (ctx) => !!ctx.username },

    // ── Phase B: anonymous magic-link resume (all public) ──
    {
      condition: (ctx) => !!ctx.admin?.linkSent,
      steps: [
        { id: "init-invite-accept" }, // sets isFirstLogin=true, newPasswordRequired=true
        { id: "prepare-accept" },
        { id: "check-pending-invitation" },
        { id: "idempotent-redirect", condition: (ctx) => !!ctx.accept?.alreadyAccepted },
        { id: "prepare-consents" },
        { id: "prepare-semantic-flags" }, // idempotent re-write

        // Forced password change (shared) — invite always satisfies newPasswordRequired
        ...passwordPhaseSchema,

        // MFA loop (shared) — invite users have zero enrolled methods so the enrol trio fires
        ...mfaLoopSchema,

        // Profile (invite-specific 2-step pattern)
        {
          id: "collect-profile",
          condition: (ctx) =>
            !!ctx.accept?.profileFormPresent &&
            !ctx.accept?.profile &&
            !!ctx.completion?.passwordCompleted,
        },
        {
          id: "apply-profile",
          condition: (ctx) =>
            !!ctx.accept?.profileFormPresent &&
            !!ctx.accept?.profile &&
            !ctx.completion?.profileApplied &&
            !!ctx.completion?.passwordCompleted,
        },

        { id: "extra-step" }, // always fires for invite (isFirstLogin=true)

        ...consentsPersistTailSchema,

        {
          id: "unset-pending-invitation",
          condition: (ctx) =>
            !!ctx.completion?.passwordCompleted && !ctx.completion?.pendingInvitationCleared,
        },
        {
          id: "activate-user",
          condition: (ctx) =>
            !!ctx.completion?.pendingInvitationCleared && !ctx.completion?.activated,
        },
        {
          id: "confirmation",
          condition: (ctx) =>
            !!ctx.completion?.activated &&
            !!ctx.accept?.showConfirmation &&
            !ctx.completion?.confirmationShown,
        },

        // Finalize (invite tail — gated by ctx.autoLogin, mirrored from
        // `opts.autoLoginOnInvite` by init-invite-admin / init-invite-accept).
        {
          id: "finalize-fresh-login",
          condition: (ctx) => !!ctx.completion?.activated && !ctx.autoLogin,
        },
        {
          id: "finalize-auto-login",
          condition: (ctx) =>
            !!ctx.completion?.activated && !!ctx.autoLogin && !ctx.completion?.tokensIssued,
        },
      ],
    },
  ])
  inviteFlow(): void {}

  /**
   * recovery.flow — OTP-via-email reset. `@Public()` on the body because
   * anonymous users start recovery.
   */
  @Workflow("flow")
  @Public()
  @WorkflowSchema<AuthWfCtx>([
    { id: "init-recovery" },
    { id: "request" },
    { break: (ctx) => !ctx.username },

    { id: "prepare-post-reset" },
    { id: "prepare-recovery-alt-actions" },
    { id: "prepare-consents" },
    { id: "prepare-semantic-flags" }, // sets ctx.password.changeReason = "reset"

    // OTP-via-email loop — spreads the shared pincode pair (same step pair as login MFA).
    // Step bodies inspect `ctx.mfa?.method` (unset here → recovery context) and pick
    // `opts.forms.recoveryPincode` with recovery alt-actions.
    {
      while: (ctx) => !ctx.otp?.verified && !ctx.aborted,
      steps: pincodeSendCheckPair,
    },
    { break: (ctx) => !!ctx.aborted },

    // Password reset — gating differs from passwordPhaseSchema (no `newPasswordRequired` flag;
    // gated directly on OTP verification).
    {
      condition: (ctx) => !!ctx.otp?.verified,
      steps: [{ id: "prepare-password-rules" }, { id: "create-password-form" }],
    },
    { break: (ctx) => !!ctx.aborted },

    // Post-reset tail (recovery-specific)
    {
      condition: (ctx) => !!ctx.completion?.passwordCompleted,
      steps: [
        { id: "revoke-sessions", condition: (ctx) => !!ctx.postReset?.revokeAllSessions },
        ...consentsPersistTailSchema,
        // Finalize (recovery tail — gated by ctx.autoLogin, mirrored from
        // `opts.autoLoginOnRecover` by init-recovery).
        {
          id: "finalize-fresh-login",
          condition: (ctx) => !ctx.autoLogin,
        },
        {
          id: "finalize-auto-login",
          condition: (ctx) => !!ctx.autoLogin && !ctx.completion?.tokensIssued,
        },
        // Note: notify-new-device is NOT fired here in this pass — see §13.
      ],
    },
  ])
  recoveryFlow(): void {}
}
