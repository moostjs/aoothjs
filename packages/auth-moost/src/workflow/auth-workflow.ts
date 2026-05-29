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
import {
  generateTotpSecret,
  generateTotpUri,
  maskEmail,
  maskPhone,
  type MfaMethodInfo,
  type TrustedDeviceRecord,
  UserAuthError,
  type UserCredentials,
  UserService,
} from "@aooth/user";
import {
  abortWf,
  finishWf,
  type FinishWfOpts,
  useAtscriptWf,
  type WfFinished,
} from "@atscript/moost-wf";
import type { TAtscriptAnnotatedType } from "@atscript/typescript/utils";
import { HttpError } from "@moostjs/event-http";
import {
  outletEmail,
  Step,
  StepRetriableError,
  StepTTL,
  useWfFinished,
  useWfState,
  Workflow,
  WorkflowParam,
  WorkflowSchema,
} from "@moostjs/event-wf";
import { current } from "@wooksjs/event-core";
import { useCookies, useHeaders, useRequest, useResponse, useUrlParams } from "@wooksjs/event-http";
import { ArbacAction, ArbacResource } from "@aooth/arbac-moost";
import { Controller, Inherit, Param } from "moost";

import { useAuth } from "../auth.composables";
import { ConsentStore } from "../consent.store";
import { Public } from "../auth.decorator";
import type {
  AuthWfCtx,
  AuthWfAltCredsPolicy,
  AuthWfPublicState,
  ConsentDescriptorLike,
  MfaSummary,
  MfaTransport,
} from "./auth-workflow.ctx";
import type { AuthWorkflowOpts, ResolvedAuthWorkflowOpts } from "./auth-workflow.opts";
import {
  AskEmailForm,
  AskPhoneForm,
  ConcurrencyLimitForm,
  EmailIdentifierForm,
  EnrollAddressForm,
  EnrollConfirmForm,
  EnrollPickMethodForm,
  InviteForm,
  LoginCredentialsForm,
  MfaCodeForm,
  PincodeForm,
  Select2faForm,
  SetPasswordForm,
  TermsBumpForm,
} from "../atscript/models/forms.as";
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
 * Default form schemas — the bundled `forms.as` models the workflow's
 * `useAtscriptWf()` callers resolve to. Consumers can override any field
 * via `opts.forms.<field>` to ship their own atscript-annotated subclass
 * (typically `extends` the bundled one to add `meta` / `ui` annotations).
 *
 * Recovery's `recoveryPincode` defaults to the shared `PincodeForm`; an
 * app that wants a recovery-specific OTP form overrides this slot.
 */
const DEFAULT_FORMS: ResolvedAuthWorkflowOpts["forms"] = {
  loginCredentials: LoginCredentialsForm,
  invite: InviteForm,
  recoveryEmailIdentifier: EmailIdentifierForm,
  askEmail: AskEmailForm,
  askPhone: AskPhoneForm,
  enrollPickMethod: EnrollPickMethodForm,
  enrollAddress: EnrollAddressForm,
  enrollConfirm: EnrollConfirmForm,
  select2fa: Select2faForm,
  mfaCode: MfaCodeForm,
  pincode: PincodeForm,
  setPassword: SetPasswordForm,
  termsBump: TermsBumpForm,
  concurrencyLimit: ConcurrencyLimitForm,
  recoveryPincode: PincodeForm,
};

function mergeAuthWorkflowOpts(opts: Partial<AuthWorkflowOpts>): ResolvedAuthWorkflowOpts {
  return {
    autoLoginOnInvite: opts.autoLoginOnInvite ?? true,
    autoLoginOnRecover: opts.autoLoginOnRecover ?? false,
    mfa: {
      pincodeLength: opts.mfa?.pincodeLength ?? 6,
      pincodeTtlMs: opts.mfa?.pincodeTtlMs ?? 5 * 60 * 1000,
      pincodeResendTimeoutMs: opts.mfa?.pincodeResendTimeoutMs ?? 60_000,
    },
    recoveryStateTtlMs: opts.recoveryStateTtlMs ?? 60 * 60 * 1000,
    loginUrl: opts.loginUrl ?? "/login",
    totpIssuer: opts.totpIssuer ?? "aooth",
    deviceTrust: {
      cookieName: "aooth_trusted_device",
      ttlMs: 24 * 60 * 60_000,
      bindsTo: "cookie",
      ...opts.deviceTrust,
    },
    forms: { ...DEFAULT_FORMS, ...opts.forms },
  };
}

/**
 * Top-level `UserCredentials` keys that workflow-collected profile payloads
 * MUST NEVER carry through to persistence. The server sets these out-of-band
 * (admin-supplied `ctx.admin?.roles`, password-set step, account activation,
 * MFA enrolment elsewhere). If the consumer's `.as` profile form mistakenly
 * declares one — or an attacker submits one as an extra field — the strip
 * applied at the workflow step blocks shadowing.
 */
export const RESERVED_USER_KEYS: ReadonlySet<string> = new Set<string>([
  "roles",
  "version",
  "id",
  "username",
  "account",
  "password",
  "passwordHistory",
  "mfa",
  "trustedDevices",
  "pendingInvitation",
]);

/**
 * Return a shallow copy of `profile` with `RESERVED_USER_KEYS` removed.
 * Does not mutate the input.
 */
export function stripReservedUserKeys(profile: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const key of Object.keys(profile)) {
    if (!RESERVED_USER_KEYS.has(key)) out[key] = profile[key];
  }
  return out;
}

/** Trim + de-duplicate role identifiers submitted via the admin invite form. */
export function parseInviteRoles(input?: string[]): string[] {
  if (!Array.isArray(input)) return [];
  const seen = new Set<string>();
  for (const v of input) {
    const trimmed = typeof v === "string" ? v.trim() : "";
    if (trimmed) seen.add(trimmed);
  }
  return [...seen];
}

/**
 * Single source of truth for the "this invite was already accepted" finish
 * envelope. Used by both `idempotent-redirect` (in-workflow) and by
 * `AuthController.invitePostRedemption` (side route reached when the wf
 * state store has evicted the finished row and re-resume hits 410).
 *
 * Secondary "Request a new invite" option is gated on
 * `alreadyAcceptedRedirectUrl` being non-empty — mirrors how the resolver
 * defaults it, but lets consumers blank it to suppress the secondary button.
 */
export function buildInviteAlreadyAcceptedEnvelope(opts: {
  loginUrl: string;
  alreadyAcceptedRedirectUrl: string;
}): FinishWfOpts {
  const altUrl = opts.alreadyAcceptedRedirectUrl;
  return {
    message: { level: "info", text: "This invite was already accepted." },
    next: {
      trigger: "manual",
      primary: {
        label: "Go to sign-in",
        action: { type: "redirect", target: opts.loginUrl, reason: "already-accepted" },
      },
      ...(altUrl && {
        options: [
          {
            label: "Request a new invite",
            action: { type: "redirect", target: altUrl, reason: "request-new-invite" },
          },
        ],
      }),
    },
  };
}

/**
 * Sentinel returned by alt-action handlers that have already short-circuited
 * the step (via `finishWf(...)`). The step body returns `undefined` after
 * seeing this so the schema advances without running form validation against
 * the alt-action payload (which lacks the form's required fields).
 */
const ALT_HANDLED: unique symbol = Symbol("ALT_HANDLED");
type AltHandled = typeof ALT_HANDLED;

/**
 * Workflow-state TTL for the invite `send-email` step — caps how long a
 * pending invite remains resumable from the magic link. 7 days matches the
 * industry-standard invite-link window (Slack/GitHub/Atlassian). Override by
 * re-decorating the step in a subclass.
 */
const INVITE_LINK_TTL_MS = 7 * 24 * 60 * 60 * 1000;

/**
 * Read a single field from the raw wf input envelope without validating
 * against any form schema. Used by alt-action handlers that carry a payload
 * field outside the current step's form (e.g. the typed `username` read on a
 * `forgotPassword` click before the password is filled in).
 */
function getInputField(name: string): string | undefined {
  return useWfState().input<{ formData?: Record<string, string> }>()?.formData?.[name];
}

/**
 * Reads the `?username=` query parameter when the workflow is triggered (e.g.
 * via the login workflow's `forgotPassword` alt-action). Returns undefined
 * outside of an HTTP event context (unit tests that hand-roll the wf
 * runtime). Used purely for recovery's email-form pre-fill.
 */
function readUsernameQueryParam(): string | undefined {
  try {
    const { params } = useUrlParams(current());
    const raw = params().get("username");
    return raw ?? undefined;
  } catch {
    return undefined;
  }
}

/**
 * Subset-copy of `src` keyed by `keys`, omitting any key whose value is
 * `undefined`. Returns `undefined` when no key carries a value — keeps
 * `populatePublic` from emitting empty subgroups like `{ mfa: {} }` that
 * would clutter the wire context.
 */
function pickDefined<T extends object, K extends keyof T>(
  src: T,
  keys: readonly K[],
): Pick<T, K> | undefined {
  const out: Partial<Pick<T, K>> = {};
  let any = false;
  for (const k of keys) {
    const v = src[k];
    if (v !== undefined) {
      out[k] = v;
      any = true;
    }
  }
  return any ? (out as Pick<T, K>) : undefined;
}

@Inherit()
@Controller()
export class AuthWorkflow {
  protected readonly opts: ResolvedAuthWorkflowOpts;
  protected readonly users: UserService;
  protected readonly auth: AuthCredential;
  protected readonly consentStore: ConsentStore;

  constructor(
    opts: Partial<AuthWorkflowOpts>,
    users: UserService,
    auth: AuthCredential,
    consentStore: ConsentStore,
  ) {
    this.opts = mergeAuthWorkflowOpts(opts);
    this.users = users;
    this.auth = auth;
    this.consentStore = consentStore;
  }

  // ── Protected extension surface ─────────────────────────────────────────

  /**
   * Unified outbound dispatch hook for direct synchronous deliveries
   * (MFA / recovery / enrollment pincodes, new-device notices). NOT used for
   * resume-token flows — the invite magic link is emitted via the wf engine's
   * `outletEmail()` primitive (pause-and-resume), since the resume URL is
   * minted by the engine AFTER the step yields and is not knowable here.
   * Default is a no-op — customer overrides wire concrete senders. Stays
   * sync-friendly: the default `void` preserves the engine's sync fast path.
   */
  protected deliver(_payload: AuthDeliveryPayload): void | Promise<void> {
    return undefined;
  }

  /**
   * Return the list of selectable role identifiers for the admin invite form.
   * Mirrors the prior `InviteWorkflow.getAvailableRoles()` consumer hook —
   * `undefined` (default) means no whitelist is enforced. Read by
   * `prepareAvailableRoles`.
   */
  protected getAvailableRoles(): Promise<string[] | undefined> | string[] | undefined {
    return undefined;
  }

  /**
   * Build the extras dict merged into the freshly-created user row by the
   * `create-user` step. Default: `{}`. Override to populate e.g. a
   * required `tenantId` from request context.
   */
  protected prepareUser(_input: {
    email: string;
    roles: string[];
    invitedBy?: string;
  }): Promise<Record<string, unknown>> | Record<string, unknown> {
    return {};
  }

  /**
   * Derive roles server-side from the admin-form payload (e.g. AD lookup).
   * Result is set-unioned with admin-supplied roles by `infer-roles`.
   * Default: `[]`.
   */
  protected inferAdminRoles(_input: { email: string }): Promise<string[]> | string[] {
    return [];
  }

  /**
   * Override the structural duplicate rule for `admin-form`. Default: any
   * existing row → `'reject'`; nothing → `'allow'`. Multi-tenant apps that
   * allow re-inviting the same email into a different tenant override.
   */
  protected duplicateInviteCheck(input: {
    email: string;
    existingUser: UserCredentials | null;
  }): Promise<"allow" | "reject"> | "allow" | "reject" {
    return input.existingUser ? "reject" : "allow";
  }

  /**
   * Implements the "log out other sessions" branch of `sessionPolicy.concurrencyLimit`.
   * Default: no-op. Consumers override to revoke sessions in their auth store.
   */
  protected async logoutOtherSessions(_username: string): Promise<void> {
    // No-op default.
  }

  /**
   * Return the number of active (non-revoked, non-expired) sessions for the
   * user. Default: returns `0` (no enforcement). Override with a real count.
   */
  protected async loadActiveSessionsCount(_username: string): Promise<number> {
    return 0;
  }

  /**
   * Resolves the post-login redirect URL. Default reads `finalize.redirect`:
   * `false` / `null` → no redirect; `'home'` → `/`; `'referer'` → request
   * `Referer` header (undefined when absent).
   */
  protected resolveRedirect(ctx: AuthWfCtx): string | undefined {
    const r = ctx.finalize?.redirect;
    if (!r) return undefined;
    if (r === "home") return "/";
    if (r === "referer") {
      const { referer, referrer } = useHeaders(current());
      const ref = referer ?? referrer;
      const first = Array.isArray(ref) ? ref[0] : ref;
      return typeof first === "string" && first.length > 0 ? first : undefined;
    }
    return undefined;
  }

  // ── Resolved policy surface (override on subclass to customize) ─────────

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
   * `this.opts.totpIssuer` so per-app TOTP labels remain a single knob.
   * Reached from login.flow + invite.start.
   */
  protected resolveMfaPolicy(
    _ctx: AuthWfCtx,
  ): NonNullable<AuthWfCtx["mfaPolicy"]> | Promise<NonNullable<AuthWfCtx["mfaPolicy"]>> {
    return {
      mode: "optional",
      availableTransports: ["sms", "email", "totp"],
      issuer: this.opts.totpIssuer,
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
   * phase. `loginUrl` defaults to `this.opts.loginUrl`. Note: today's
   * `freshLoginRequired` field is GONE — the auto-login choice is the static
   * `AuthWorkflowOpts.autoLoginOnInvite` boolean (per §2 decision).
   */
  protected resolveAccept(
    _ctx: AuthWfCtx,
  ): NonNullable<AuthWfCtx["accept"]> | Promise<NonNullable<AuthWfCtx["accept"]>> {
    return {
      alreadyAcceptedRedirectUrl: this.opts.loginUrl,
      loginUrl: this.opts.loginUrl,
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
      loginUrl: this.opts.loginUrl,
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
   * set) or from `ctx.email` (recovery path). Loads the user to read the raw
   * method `value` — the `ctx.mfa.enrolledMethods` summary carries only the
   * MASKED form, which is for display, never for delivery.
   */
  protected resolvePincodeTarget(
    ctx: AuthWfCtx,
  ):
    | { address: string; channel: "sms" | "email" }
    | Promise<{ address: string; channel: "sms" | "email" }> {
    if (ctx.mfa?.method && ctx.mfa.method !== "totp") {
      const channel = ctx.mfa.method;
      const summary = ctx.mfa.enrolledMethods?.find((mm) => mm.kind === channel);
      if (!ctx.username) throw new HttpError(500, "Workflow state corrupted: missing username");
      return this.users.getUser(ctx.username).then((user) => {
        const methodName = summary?.methodName ?? channel;
        const method = user.mfa.methods.find((m) => m.name === methodName && m.confirmed);
        if (!method) throw new HttpError(500, "MFA method no longer present");
        return { address: method.value, channel };
      });
    }
    return { address: ctx.email ?? "", channel: "email" };
  }

  /**
   * Route a form alt-action click to a canonical outcome. Defaults match the
   * action ids the bundled `PincodeForm` declares; customers override per
   * form when adding new actions or remapping the canonical ones.
   */
  protected resolvePincodeAltAction(
    _ctx: AuthWfCtx,
    action: string,
  ): "resend" | "exit" | "useDifferentMethod" | undefined {
    if (action === "resend") return "resend";
    if (action === "useDifferentMethod") return "useDifferentMethod";
    if (action === "backToLogin") return "exit";
    return undefined;
  }

  // ── Private helpers (ported from AuthWorkflowBase) ──────────────────────

  /**
   * Asserts `ctx.username` is populated. Throws `HttpError(500)` on miss;
   * narrows `username` to `string` for the caller. Ported from
   * `AuthWorkflowBase` since the unified class no longer extends it.
   */
  protected requireUsername<T extends { username?: string }>(
    ctx: T,
  ): asserts ctx is T & { username: string } {
    if (!ctx.username) throw new HttpError(500, "Workflow state corrupted: missing username");
  }

  /**
   * Project the internal ctx state onto `ctx.public` — the ONLY top-level
   * key whitelisted on form schemas (via `@wf.context.pass 'public'`).
   * Mirrors `AuthWfPublicState` field-for-field; intentionally drops
   * internal-only fields (`pincode.channelCooldowns`, `mfa.saveAsDefault` /
   * `mfa.current` / `mfa.ignoreDefault`, `trust.deviceTrustToken`,
   * `channel.phone` / `channel.emailConfirmed`, `mfaEnroll.address`, …)
   * so they cannot leak to the wire.
   *
   * Called via `throwPublic` immediately before every `requireInput`-style
   * pause so the FE always reads a fresh projection of the post-step ctx.
   */
  protected populatePublic(ctx: AuthWfCtx): void {
    // wf state-token serialization rejects `undefined` (only string / number
    // / boolean / null / array / object are allowed — same constraint that
    // `ctx.foo = undefined` hits at state save time). `pickDefined` below
    // copies only the keys that are actually set so we never emit an
    // explicit `{ field: undefined }` for an unset field.
    const pub: AuthWfPublicState = {};
    if (ctx.consents) {
      const sub = pickDefined(ctx.consents, ["pending", "decidedAt"] as const);
      if (sub) pub.consents = sub as AuthWfPublicState["consents"];
    }
    if (ctx.altActions) {
      const sub = pickDefined(ctx.altActions, ["forgotPassword", "signup", "magicLink"] as const);
      if (sub) pub.altActions = sub as AuthWfPublicState["altActions"];
    }
    if (ctx.mfa) {
      const sub = pickDefined(ctx.mfa, ["method", "methodCount", "enrolledMethods"] as const);
      if (sub) pub.mfa = sub as AuthWfPublicState["mfa"];
    }
    if (ctx.pincode) {
      const sub = pickDefined(ctx.pincode, ["sentTo", "codeLength", "resendAllowedAt"] as const);
      if (sub) pub.pincode = sub as AuthWfPublicState["pincode"];
    }
    if (ctx.trust) {
      const sub = pickDefined(ctx.trust, ["optIn"] as const);
      if (sub) pub.trust = sub as AuthWfPublicState["trust"];
    }
    if (ctx.password) {
      const sub = pickDefined(ctx.password, ["heading", "intro", "policies"] as const);
      if (sub) pub.password = sub as AuthWfPublicState["password"];
    }
    if (ctx.admin) {
      const sub = pickDefined(ctx.admin, ["availableRoles"] as const);
      if (sub) pub.admin = sub as AuthWfPublicState["admin"];
    }
    if (ctx.channel) {
      const sub = pickDefined(ctx.channel, ["otpDisclosure"] as const);
      if (sub) pub.channel = sub as AuthWfPublicState["channel"];
    }
    if (ctx.mfaEnroll) {
      const sub = pickDefined(ctx.mfaEnroll, [
        "method",
        "mode",
        "availableTransports",
        "secret",
        "uri",
      ] as const);
      if (sub) pub.mfaEnroll = sub as AuthWfPublicState["mfaEnroll"];
    }
    if (ctx.defaults) {
      const sub = pickDefined(ctx.defaults, ["email"] as const);
      if (sub) pub.defaults = sub as AuthWfPublicState["defaults"];
    }
    if (ctx.newPasswordRequired !== undefined) {
      pub.newPasswordRequired = ctx.newPasswordRequired;
    }
    ctx.public = pub;
  }

  /**
   * Wrap `wf.requireInput(opts)` so `ctx.public` is freshly projected
   * before the pause throws. Every `throw wf.requireInput(...)` in the
   * codebase routes through this so no pause can ship a stale public
   * surface (and no contributor can accidentally skip the projection).
   */
  protected throwPublic<T>(
    ctx: AuthWfCtx,
    wf: { requireInput(opts?: T): unknown },
    opts?: T,
  ): unknown {
    this.populatePublic(ctx);
    return wf.requireInput(opts);
  }

  /**
   * Drop-in wrapper around `useAtscriptWf(type)` that projects `ctx.public`
   * BEFORE returning the form handle. Steps that pause implicitly — via
   * `wf.resolveInput()` throwing on missing input or `wf.resolveAction()`
   * throwing on an unknown action — bypass `throwPublic`, so without this
   * wrapper the implicit-pause path would ship a stale (or missing)
   * `ctx.public`. Every `useAtscriptWf(...)` call in the workflow routes
   * through this so both pause flavors snapshot the same fresh projection.
   */
  protected useAtscriptWfPublic(
    ctx: AuthWfCtx,
    type: Parameters<typeof useAtscriptWf>[0],
  ): ReturnType<typeof useAtscriptWf> {
    this.populatePublic(ctx);
    return useAtscriptWf(type);
  }

  /** Translate `CAS_EXHAUSTED` UserAuthError to 409 Conflict (OCC contract). */
  protected async withStoreErrorTranslation<T>(op: () => Promise<T>): Promise<T> {
    try {
      return await op();
    } catch (err) {
      if (err instanceof UserAuthError && err.type === "CAS_EXHAUSTED") {
        throw new HttpError(409, err.message);
      }
      throw err;
    }
  }

  /** Mint a numeric pincode + stash it onto ctx. Returns the plain code. */
  protected mintPin(
    ctx: { pin?: string; pinExpire?: number },
    length: number,
    ttlMs: number,
  ): string {
    let code = "";
    for (let i = 0; i < length; i++) code += Math.floor(Math.random() * 10).toString();
    ctx.pin = code;
    ctx.pinExpire = Date.now() + ttlMs;
    return code;
  }

  /** Verify a submitted pincode against ctx.pin. Returns error map or null. */
  protected verifyPin(
    ctx: { pin?: string; pinExpire?: number },
    submitted: string | undefined,
  ): { code: string } | null {
    if (!ctx.pin || !ctx.pinExpire || Date.now() > ctx.pinExpire) return { code: "Code expired" };
    if (submitted !== ctx.pin) return { code: "Invalid code" };
    return null;
  }

  /**
   * Validate + stash inline-consent fields submitted on a carrier form.
   * SECURITY: silently drops unknown ids (audit-grade defense — see base
   * class docstring).
   *
   * Does NOT persist — persistence is deferred to `persist-consents` at the
   * workflow tail, AFTER channel/identity verification. Staging the decision
   * here (without persisting) lets downstream carrier forms hide the consent
   * block via `decidedAt` while the wf engine still owns the rollback
   * boundary: if the user abandons before the verification step succeeds,
   * the consent record never lands in the durable store.
   */
  protected processInlineConsent(
    ctx: AuthWfCtx,
    input: { consents?: string[] },
    wf: {
      requireInput(opts?: { errors?: Record<string, string>; formMessage?: string }): unknown;
    },
  ): void {
    if (ctx.consents?.decidedAt !== undefined) return;
    const pending: ConsentDescriptorLike[] = ctx.consents?.pending ?? [];
    if (pending.length === 0) return;
    const validIds = new Set(pending.map((p) => p.id));
    const submitted = new Set<string>();
    for (const id of input.consents ?? []) {
      if (validIds.has(id)) submitted.add(id);
    }
    for (const p of pending) {
      if (p.required && !submitted.has(p.id)) {
        throw this.throwPublic(ctx, wf, { errors: { consents: p.required } });
      }
    }
    const group = (ctx.consents ??= {});
    group.accepted = [...submitted];
    group.decidedAt = Date.now();
  }

  /**
   * Mask a raw address for UI display. The masked string is for
   * `ctx.pincode.sentTo`; the raw value is what gets passed to `deliver`.
   */
  protected maskAddress(address: string, channel: "sms" | "email"): string {
    return channel === "email" ? maskEmail(address) : maskPhone(address);
  }

  /** Narrow `MfaMethod.name` to the canonical MfaTransport union. */
  protected mfaKindOf(methodName: string): MfaTransport | null {
    if (methodName === "sms" || methodName === "email" || methodName === "totp") return methodName;
    return null;
  }

  /**
   * Send an enrolment pincode and stamp `ctx.pincode.sentTo` with the masked
   * recipient. Shared by `enrollAddress` (initial dispatch) and the resend
   * path inside `enrollConfirm`.
   */
  protected async sendEnrollPincode(ctx: AuthWfCtx, address: string, code: string): Promise<void> {
    const pincode = (ctx.pincode ??= {});
    const channel = ctx.mfaEnroll?.method === "email" ? "email" : "sms";
    pincode.sentTo = this.maskAddress(address, channel);
    await this.deliver({
      kind: "enroll-pincode",
      channel,
      recipient: address,
      code,
      expiresInMs: this.opts.mfa.pincodeTtlMs,
    });
  }

  /**
   * Cleanup any partially-persisted enrolment state (unconfirmed method row +
   * ctx scratch). Called when the user picks `skip` or `useDifferentMethod`
   * mid-flow on `enrollConfirm`, where the unconfirmed method has already
   * been written via `addMfaMethod` (in `enrollPickMethod` for totp /
   * `enrollAddress` for sms+email).
   */
  protected async cleanupEnrollment(ctx: AuthWfCtx, username: string): Promise<void> {
    const m = ctx.mfaEnroll;
    if (m) {
      if (m.method) {
        await this.withStoreErrorTranslation(() => this.users.removeMfaMethod(username, m.method!));
      }
      delete m.method;
      delete m.address;
      delete m.secret;
      delete m.uri;
    }
    delete ctx.pin;
    delete ctx.pinExpire;
    if (ctx.pincode) delete ctx.pincode.sentTo;
  }

  /**
   * Load a user row by username, returning null on NOT_FOUND. Used by invite
   * admin-phase steps (duplicate check) and accept-tail (pending-invitation
   * gate).
   */
  private async loadUserOrNull(username: string): Promise<UserCredentials | null> {
    try {
      return await this.users.getUser(username);
    } catch (err) {
      if (err instanceof UserAuthError && err.type === "NOT_FOUND") return null;
      throw err;
    }
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
  @ArbacResource("auth.invite")
  @ArbacAction("start")
  initInviteAdmin(@WorkflowParam("context") ctx: AuthWfCtx): void {
    ctx.autoLogin = this.opts.autoLoginOnInvite;
    return undefined;
  }

  @Step("init-invite-accept")
  @Public()
  initInviteAccept(@WorkflowParam("context") ctx: AuthWfCtx): void {
    // Invite-accept is always first-login with a forced initial password.
    ctx.isFirstLogin = true;
    ctx.newPasswordRequired = true;
    ctx.autoLogin = this.opts.autoLoginOnInvite;
    (ctx.password ??= {}).changeReason = "initial";
    return undefined;
  }

  @Step("init-recovery")
  @Public()
  initRecovery(@WorkflowParam("context") ctx: AuthWfCtx): void {
    ctx.autoLogin = this.opts.autoLoginOnRecover;
    return undefined;
  }

  // ── Authentication entry (2) ──

  @Step("credentials")
  @Public()
  async credentials(@WorkflowParam("context") ctx: AuthWfCtx): Promise<unknown> {
    // Runs BEFORE the `!ctx.username` gate / prepare-* steps, so we inline
    // the alt-cred + guards resolvers we need (idempotent vs. later prepare-*).
    const altResult = this.resolveAlternateCredentials(ctx);
    const alt = altResult instanceof Promise ? await altResult : altResult;
    ctx.alternateCredentials = alt;
    const guardsResult = this.resolveGuards(ctx);
    ctx.guards = guardsResult instanceof Promise ? await guardsResult : guardsResult;
    // Mirror alt-credentials config into ctx so the form can hide each alt-action
    // button when its feature is disabled (`@ui.form.fn.hidden`).
    const altActions = (ctx.altActions ??= {});
    altActions.forgotPassword = alt.forgotPassword;
    altActions.signup = alt.signup;
    altActions.magicLink = alt.magicLink;
    const wf = this.useAtscriptWfPublic(ctx, this.opts.forms.loginCredentials);

    // Alt-action routing — handled BEFORE the form-input pause so the user
    // can hit "Forgot password?" without filling in the form at all. SSO
    // provider ids (from `alt.ssoProviders[].id`) must be declared as phantom
    // `ui.action` fields on the consumer's custom `LoginCredentialsForm`.
    const action = wf.resolveAction();
    if (action) {
      const typedUsername = getInputField("username");
      const handled = this.handleCredentialsAlt(action, typedUsername, alt);
      if (handled === ALT_HANDLED) return undefined;
    }

    const input = wf.resolveInput() as { username: string; password: string };

    try {
      const result = await this.users.login(input.username, input.password);
      ctx.username = result.user.username;
      // Phase 2 inline guards — set top-level `isPasswordInitial`/`isPasswordExpired`
      // so `prepare-semantic-flags` (which runs later) can read them as a fallback.
      if (ctx.guards?.passwordInitial && result.user.password.isInitial) {
        ctx.isPasswordInitial = true;
      }
      if (ctx.guards?.passwordExpiry && this.users.isPasswordExpired(result.user)) {
        ctx.isPasswordExpired = true;
      }
      if (ctx.isPasswordInitial) {
        (ctx.password ??= {}).changeReason = "initial";
      } else if (ctx.isPasswordExpired) {
        (ctx.password ??= {}).changeReason = "expired";
      }
      // Sync existing channel state so `ensureEmail`/`ensurePhone` skip
      // when the user already has a confirmed channel.
      const email = result.user.mfa.methods.find((m) => m.name === "email" && m.confirmed);
      if (email) {
        ctx.email = email.value;
        (ctx.channel ??= {}).emailConfirmed = true;
      }
      const phone = result.user.mfa.methods.find((m) => m.name === "sms" && m.confirmed);
      if (phone) {
        const channel = (ctx.channel ??= {});
        channel.phone = phone.value;
        channel.phoneConfirmed = true;
      }
    } catch (err) {
      if (err instanceof UserAuthError) {
        if (err.type === "LOCKED") {
          throw this.throwPublic(ctx, wf, {
            formMessage: "Account locked, please try again later",
          });
        }
        throw this.throwPublic(ctx, wf, { formMessage: "Invalid credentials" });
      }
      throw err;
    }
    return undefined;
  }

  /**
   * Route a credentials alt-action click (forgotPassword / signup / magicLink
   * / sso-<id>) to a `finishWf` redirect envelope. Returns `ALT_HANDLED` when
   * the caller should short-circuit without running form validation.
   */
  private handleCredentialsAlt(
    action: string,
    typedUsername: string | undefined,
    alt: AuthWfAltCredsPolicy,
  ): AltHandled | undefined {
    if (action === "forgotPassword" && alt.forgotPassword) {
      const url = this.resolveRecoveryUrl(typedUsername, alt);
      finishWf({
        next: {
          trigger: "immediate",
          action: { type: "redirect", target: url, reason: "forgot-password" },
        },
      });
      return ALT_HANDLED;
    }
    if (action === "signup" && alt.signup) {
      finishWf({
        next: {
          trigger: "immediate",
          action: { type: "redirect", target: alt.signupUrl, reason: "signup" },
        },
      });
      return ALT_HANDLED;
    }
    if (action === "magicLink" && alt.magicLink) {
      throw new HttpError(501, "Magic-link login path not implemented in this version");
    }
    const sso = alt.ssoProviders.find((p) => p.id === action);
    if (sso) {
      finishWf({
        next: {
          trigger: "immediate",
          action: { type: "redirect", target: sso.url, reason: `sso-${sso.id}` },
        },
      });
      return ALT_HANDLED;
    }
    return undefined;
  }

  @Step("request")
  @Public()
  async request(@WorkflowParam("context") ctx: AuthWfCtx): Promise<unknown> {
    // Runs BEFORE the `!ctx.username` gate / prepare-* steps; inline the
    // alt-actions resolver (idempotent vs. later `prepare-recovery-alt-actions`).
    const altResult = this.resolveRecoveryAltActions(ctx);
    const alt = altResult instanceof Promise ? await altResult : altResult;
    ctx.recoveryAltActions = alt;

    const emailWf = this.useAtscriptWfPublic(ctx, this.opts.forms.recoveryEmailIdentifier);
    const action = emailWf.resolveAction();
    if (action === "backToLogin" && alt.backToLogin) {
      // postReset not yet resolved — inline (idempotent vs. `prepare-post-reset`).
      const postResetResult = this.resolvePostReset(ctx);
      ctx.postReset = postResetResult instanceof Promise ? await postResetResult : postResetResult;
      this.abortRecoveryToLogin(ctx);
      return undefined;
    }

    // First entry: read `?username=` from the resume URL (carried from
    // login's `forgotPassword` alt-action) to pre-fill the form.
    const rawFormData = useWfState().input<{ formData?: unknown }>()?.formData;
    if (rawFormData === undefined) {
      const prefilled = readUsernameQueryParam();
      if (prefilled) ctx.defaults = { email: prefilled };
      throw this.throwPublic(ctx, emailWf);
    }

    const input = emailWf.resolveInput() as { email: string };
    const email = input.email;
    ctx.email = email;

    let username: string | undefined;
    try {
      const userId = await this.emailToUserId(email);
      if (userId) {
        const user = await this.users.getUser(userId);
        username = user.username;
      }
    } catch (err) {
      if (!(err instanceof UserAuthError) || err.type !== "NOT_FOUND") throw err;
    }

    if (!username) {
      // Anti-enumeration: same generic response. Downstream skips via `ctx.username` gate.
      this.finishGenericRecovery();
      return undefined;
    }

    ctx.username = username;
    return undefined;
  }

  /**
   * Resolves the recovery-step `email` input to the canonical username.
   * Default: returns the email unchanged. Apps with separate username/email
   * MUST override; return `null` when no user matches.
   */
  protected async emailToUserId(email: string): Promise<string | null> {
    return email;
  }

  /** Anti-enumeration generic finish envelope used when recovery's `request` step receives an unknown email. */
  private finishGenericRecovery(): void {
    finishWf({
      data: { sent: true },
      message: { level: "info", text: "If an account exists, you will receive instructions." },
    });
  }

  /**
   * Stamp `recoveryStateTtlMs` on a paused-state error so the wf engine's
   * persisted-state strategy expires the state at that timestamp. Use at
   * recovery-side `requireInput` throws (recovery-only steps) or wrap a
   * shared-step `resolveInput()` throw inside a `ctx.postReset` guard.
   */
  protected stampRecoveryExpiry<E extends { expires?: number }>(err: E): E {
    err.expires = Date.now() + this.opts.recoveryStateTtlMs;
    return err;
  }

  /** Emit the recovery "backToLogin" abort envelope and stamp `ctx.aborted`. */
  private abortRecoveryToLogin(ctx: AuthWfCtx): void {
    finishWf({
      next: {
        trigger: "immediate",
        action: {
          type: "redirect",
          target: ctx.postReset!.loginUrl!,
          reason: "user-cancelled",
        },
      },
    });
    ctx.aborted = true;
  }

  // ── Prepare-* policy steps (16) ──

  /**
   * Canonical writer of `ctx.password.changeReason` + `isFirstLogin` /
   * `newPasswordRequired`. Discriminates by ctx-slot presence (§10):
   * `ctx.accept` → invite-accept; `ctx.postReset` → recovery; otherwise login.
   * Idempotent on re-entry.
   */
  @Step("prepare-semantic-flags")
  @Public()
  prepareSemanticFlags(@WorkflowParam("context") ctx: AuthWfCtx): undefined | Promise<undefined> {
    if (ctx.accept) {
      ctx.isFirstLogin = true;
      ctx.newPasswordRequired = true;
      (ctx.password ??= {}).changeReason = "initial";
      return undefined;
    }
    if (ctx.postReset) {
      (ctx.password ??= {}).changeReason = "reset";
      return undefined;
    }
    // `guards.<flag>` is the feature gate ("the check is enabled"); the
    // per-user determination lives in `ctx.isPasswordInitial` /
    // `ctx.isPasswordExpired` (set by the `credentials` step from the
    // user's stored `password.isInitial` / `lastChanged`). Read the
    // computed flags here so users whose password is current skip the
    // password form even when the guard is on.
    ctx.newPasswordRequired = !!ctx.isPasswordInitial || !!ctx.isPasswordExpired;
    const reason = (ctx.password ??= {});
    if (ctx.isPasswordInitial) reason.changeReason = "initial";
    else if (ctx.isPasswordExpired) reason.changeReason = "expired";
    else delete reason.changeReason;
    if (!ctx.username) {
      ctx.isFirstLogin = false;
      return undefined;
    }
    return this.users.getUser(ctx.username).then(
      (user) => {
        ctx.isFirstLogin = !user?.account?.lastLogin;
        return undefined;
      },
      (err) => {
        if (err instanceof UserAuthError && err.type === "NOT_FOUND") {
          ctx.isFirstLogin = false;
          return undefined;
        }
        throw err;
      },
    );
  }

  @Step("prepare-consents")
  @Public()
  prepareConsents(@WorkflowParam("context") ctx: AuthWfCtx): undefined | Promise<undefined> {
    if (!ctx.username) return undefined;
    const result = this.consentStore.getPendingConsents(ctx.username);
    if (result instanceof Promise) {
      return result.then((resolved) => {
        (ctx.consents ??= {}).pending = resolved;
        return undefined;
      });
    }
    (ctx.consents ??= {}).pending = result;
    return undefined;
  }

  @Step("prepare-alternate-credentials")
  @Public()
  prepareAlternateCredentials(
    @WorkflowParam("context") ctx: AuthWfCtx,
  ): undefined | Promise<undefined> {
    const result = this.resolveAlternateCredentials(ctx);
    if (result instanceof Promise) {
      return result.then((resolved) => {
        ctx.alternateCredentials = resolved;
        return undefined;
      });
    }
    ctx.alternateCredentials = result;
    return undefined;
  }

  @Step("prepare-device-trust")
  @Public()
  prepareDeviceTrust(@WorkflowParam("context") ctx: AuthWfCtx): undefined | Promise<undefined> {
    const result = this.resolveDeviceTrust(ctx);
    if (result instanceof Promise) {
      return result.then((resolved) => {
        ctx.deviceTrust = resolved;
        return undefined;
      });
    }
    ctx.deviceTrust = result;
    return undefined;
  }

  @Step("prepare-enrollment")
  @Public()
  prepareEnrollment(@WorkflowParam("context") ctx: AuthWfCtx): undefined | Promise<undefined> {
    const result = this.resolveEnrollment(ctx);
    if (result instanceof Promise) {
      return result.then((resolved) => {
        ctx.enrollment = resolved;
        return undefined;
      });
    }
    ctx.enrollment = result;
    return undefined;
  }

  @Step("prepare-finalize")
  @Public()
  prepareFinalize(@WorkflowParam("context") ctx: AuthWfCtx): undefined | Promise<undefined> {
    const result = this.resolveFinalize(ctx);
    if (result instanceof Promise) {
      return result.then((resolved) => {
        ctx.finalize = resolved;
        return undefined;
      });
    }
    ctx.finalize = result;
    return undefined;
  }

  @Step("prepare-guards")
  @Public()
  prepareGuards(@WorkflowParam("context") ctx: AuthWfCtx): undefined | Promise<undefined> {
    const result = this.resolveGuards(ctx);
    if (result instanceof Promise) {
      return result.then((resolved) => {
        ctx.guards = resolved;
        return undefined;
      });
    }
    ctx.guards = result;
    return undefined;
  }

  @Step("prepare-session-policy")
  @Public()
  prepareSessionPolicy(@WorkflowParam("context") ctx: AuthWfCtx): undefined | Promise<undefined> {
    const result = this.resolveSessionPolicy(ctx);
    if (result instanceof Promise) {
      return result.then((resolved) => {
        ctx.sessionPolicy = resolved;
        return undefined;
      });
    }
    ctx.sessionPolicy = result;
    return undefined;
  }

  /**
   * Merges login's `prepare-mfa-setup` + invite's `prepare-mfa` + `setup-mfa`.
   * Writes `ctx.mfaPolicy`; with `ctx.username` bound, pre-picks
   * `ctx.mfa.current` from the user's `defaultMethod` (challenge branch);
   * with zero confirmed methods and a single available transport, pre-picks
   * `ctx.mfaEnroll.method` (enrol branch). `enrolledMethods` is NOT written
   * here — `load-enrolled-mfa-methods` owns that masking. Idempotent.
   */
  @Step("prepare-mfa")
  @Public()
  prepareMfa(@WorkflowParam("context") ctx: AuthWfCtx): undefined | Promise<undefined> {
    const policyResult = this.resolveMfaPolicy(ctx);
    const applyPolicy = (
      policy: NonNullable<AuthWfCtx["mfaPolicy"]>,
    ): undefined | Promise<undefined> => {
      ctx.mfaPolicy = policy;
      const transports = policy.availableTransports;
      const autoPickEnroll = (): void => {
        if (transports.length === 1 && !ctx.mfaEnroll?.method) {
          (ctx.mfaEnroll ??= {}).method = transports[0];
        }
      };
      if (!ctx.username) {
        autoPickEnroll();
        return undefined;
      }
      return this.users.getUser(ctx.username).then(
        (user) => {
          const allowed = new Set(transports);
          const confirmed = (user?.mfa?.methods ?? []).filter(
            (m) => m.confirmed && allowed.has(m.name as MfaTransport),
          );
          if (confirmed.length > 0 && user?.mfa?.defaultMethod) {
            const def = user.mfa.defaultMethod as MfaTransport;
            if (allowed.has(def) && confirmed.some((m) => m.name === def)) {
              (ctx.mfa ??= {}).current = def;
            }
          }
          if (confirmed.length === 0) autoPickEnroll();
          return undefined;
        },
        (err) => {
          if (err instanceof UserAuthError && err.type === "NOT_FOUND") return undefined;
          throw err;
        },
      );
    };
    if (policyResult instanceof Promise) {
      return policyResult.then(applyPolicy);
    }
    return applyPolicy(policyResult);
  }

  @Step("prepare-admin-form")
  @ArbacResource("auth.invite")
  @ArbacAction("start")
  prepareAdminForm(@WorkflowParam("context") ctx: AuthWfCtx): undefined | Promise<undefined> {
    const result = this.resolveAdminForm(ctx);
    if (result instanceof Promise) {
      return result.then((resolved) => {
        ctx.adminForm = resolved;
        return undefined;
      });
    }
    ctx.adminForm = result;
    return undefined;
  }

  @Step("prepare-available-roles")
  @ArbacResource("auth.invite")
  @ArbacAction("start")
  async prepareAvailableRoles(@WorkflowParam("context") ctx: AuthWfCtx): Promise<undefined> {
    const roles = await this.getAvailableRoles();
    if (roles) (ctx.admin ??= {}).availableRoles = roles;
    return undefined;
  }

  /**
   * Merges policy from `resolveAccept` into `ctx.accept` (rather than
   * overwriting) so any state stamped by later steps (`alreadyAccepted`)
   * survives.
   */
  @Step("prepare-accept")
  @Public()
  prepareAccept(@WorkflowParam("context") ctx: AuthWfCtx): undefined | Promise<undefined> {
    const result = this.resolveAccept(ctx);
    if (result instanceof Promise) {
      return result.then((resolved) => {
        Object.assign((ctx.accept ??= {}), resolved);
        return undefined;
      });
    }
    Object.assign((ctx.accept ??= {}), result);
    return undefined;
  }

  @Step("prepare-password-rules")
  @Public()
  preparePasswordRules(@WorkflowParam("context") ctx: AuthWfCtx): undefined | Promise<undefined> {
    const policies = this.users.getTransferablePolicies();
    (ctx.password ??= {}).policies = policies;
    return undefined;
  }

  @Step("prepare-post-reset")
  @Public()
  preparePostReset(@WorkflowParam("context") ctx: AuthWfCtx): undefined | Promise<undefined> {
    const result = this.resolvePostReset(ctx);
    if (result instanceof Promise) {
      return result.then((resolved) => {
        ctx.postReset = resolved;
        return undefined;
      });
    }
    ctx.postReset = result;
    return undefined;
  }

  @Step("prepare-recovery-alt-actions")
  @Public()
  prepareRecoveryAltActions(
    @WorkflowParam("context") ctx: AuthWfCtx,
  ): undefined | Promise<undefined> {
    const result = this.resolveRecoveryAltActions(ctx);
    if (result instanceof Promise) {
      return result.then((resolved) => {
        ctx.recoveryAltActions = resolved;
        return undefined;
      });
    }
    ctx.recoveryAltActions = result;
    return undefined;
  }

  // ── Invite admin phase (5; arbac-evaluated except `send-email`) ──

  /**
   * Admin-side invite form. Pauses for `InviteForm`; binds `ctx.email` +
   * `ctx.admin.roles`. Server-side enforces the `availableRoles` whitelist
   * (populated by `prepare-available-roles`). Calls `duplicateInviteCheck`
   * to decide whether to reject duplicates.
   */
  @Step("admin-form")
  @ArbacResource("auth.invite")
  @ArbacAction("start")
  async adminForm(@WorkflowParam("context") ctx: AuthWfCtx): Promise<unknown> {
    const wf = this.useAtscriptWfPublic(ctx, this.opts.forms.invite);
    const input = wf.resolveInput() as {
      email: string;
      roles: string[];
    };
    const email = input.email;
    const parsed = parseInviteRoles(input.roles);
    if (Array.isArray(ctx.admin?.availableRoles)) {
      const allowed = new Set(ctx.admin.availableRoles);
      const bad = parsed.find((r) => !allowed.has(r));
      if (bad !== undefined) {
        throw this.throwPublic(ctx, wf, { errors: { roles: "Invalid role" } });
      }
    }
    const existing = await this.loadUserOrNull(email);
    const action = await this.duplicateInviteCheck({ email, existingUser: existing });
    if (action === "reject") {
      if (existing?.account?.pendingInvitation) {
        throw this.throwPublic(ctx, wf, { errors: { email: "Invite already pending" } });
      }
      if (existing) throw this.throwPublic(ctx, wf, { errors: { email: "User already exists" } });
      throw this.throwPublic(ctx, wf, { errors: { email: "Duplicate invite rejected" } });
    }
    ctx.email = email;
    if (parsed.length > 0) (ctx.admin ??= {}).roles = parsed;
    return undefined;
  }

  /**
   * Map admin-provided role labels to canonical IDs via `inferAdminRoles`
   * hook, set-unioning with admin-supplied roles.
   */
  @Step("infer-roles")
  @ArbacResource("auth.invite")
  @ArbacAction("start")
  async inferRoles(@WorkflowParam("context") ctx: AuthWfCtx): Promise<undefined> {
    if (!ctx.email) return undefined;
    const inferred = await this.inferAdminRoles({ email: ctx.email });
    if (inferred.length === 0) return undefined;
    const admin = (ctx.admin ??= {});
    const merged = new Set<string>([...(admin.roles ?? []), ...inferred]);
    admin.roles = Array.from(merged);
    return undefined;
  }

  /**
   * Build the extras dict that `create-user` merges into the new user row.
   * Calls `prepareUser({email, roles, invitedBy})` and writes the result onto
   * `ctx.admin.userExtras`.
   */
  @Step("build-user-extras")
  @ArbacResource("auth.invite")
  @ArbacAction("start")
  async buildUserExtras(@WorkflowParam("context") ctx: AuthWfCtx): Promise<undefined> {
    if (!ctx.email) throw new HttpError(500, "Workflow state corrupted: missing email");
    const invitedBy = useAuth().getAuthContext()?.userId;
    const preparedInput = {
      email: ctx.email,
      roles: ctx.admin?.roles ?? [],
      ...(invitedBy && { invitedBy }),
    };
    const extras = await this.prepareUser(preparedInput);
    (ctx.admin ??= {}).userExtras = extras;
    return undefined;
  }

  /**
   * Create the user row from `ctx.admin.userExtras` (plus the admin-supplied
   * `ctx.admin.roles`), then stamp `pendingInvitation = true` via a follow-up
   * deep-merge update so `createUser`-applied account defaults survive.
   */
  @Step("create-user")
  @ArbacResource("auth.invite")
  @ArbacAction("start")
  async createUser(@WorkflowParam("context") ctx: AuthWfCtx): Promise<undefined> {
    if (!ctx.email) throw new HttpError(500, "Workflow state corrupted: missing email");
    const adminRoles = ctx.admin?.roles;
    const fields: Record<string, unknown> = {
      ...ctx.admin?.userExtras,
      ...(adminRoles && adminRoles.length > 0 && { roles: adminRoles }),
    };
    try {
      await this.users.createUser(ctx.email, undefined, fields);
    } catch (err) {
      if (err instanceof UserAuthError && err.type === "ALREADY_EXISTS") {
        throw new HttpError(409, "User already exists");
      }
      throw err;
    }
    await this.users.update(ctx.email, {
      account: { pendingInvitation: true },
    } as Partial<UserCredentials>);
    ctx.username = ctx.email;
    return undefined;
  }

  /**
   * Issue magic-link token and dispatch the invite email via `outletEmail` —
   * the wf engine pauses, the email-outlet trigger mints the resume URL, and
   * the click-through re-enters at this step's level. NOT routed through the
   * `deliver()` hook because that hook is for direct dispatches where the
   * payload is fully known at call-time; the magic-link URL exists only after
   * the pause. Public so the engine can re-enter on the anonymous resume.
   *
   * Outlet-pause idempotency via `admin.emailDispatched`: on the invitee's
   * magic-link resume, the engine re-executes this step body (a paused step's
   * cursor stays AT the step until the body returns a non-`inputRequired`
   * value). Returning the outletEmail envelope again would dispatch another
   * email + re-pause; the flag short-circuits the resume so the cursor
   * advances into the Phase B accept-tail. This is the engine-documented
   * step-layer idempotency pattern for outlet pauses with side effects
   * (`@wooksjs/event-wf` resume semantics — the cursor advances on a
   * successful step but a re-invocation of the same step body must guard
   * its own non-idempotent work).
   */
  @Step("send-email")
  @StepTTL(INVITE_LINK_TTL_MS)
  @Public()
  sendInviteEmail(@WorkflowParam("context") ctx: AuthWfCtx): unknown {
    const admin = (ctx.admin ??= {});
    if (admin.emailDispatched) return undefined;
    admin.emailDispatched = true;
    return outletEmail(ctx.email as string, "invite.magicLink", {
      username: ctx.username,
      ...(ctx.username && { userId: ctx.username }),
      ...(admin.roles && { roles: admin.roles }),
    });
  }

  // ── Invite accept-tail (5) ──

  /**
   * Check whether the invite was already accepted. Sets
   * `ctx.accept.alreadyAccepted` when the user's pending-invitation marker is
   * cleared.
   */
  @Step("check-pending-invitation")
  @Public()
  async checkPendingInvitation(@WorkflowParam("context") ctx: AuthWfCtx): Promise<undefined> {
    if (!ctx.username) {
      throw new HttpError(500, "Workflow state corrupted: missing username at accept");
    }
    const existing = await this.loadUserOrNull(ctx.username);
    if (!existing) {
      throw new HttpError(410, "This invite has been cancelled");
    }
    if (!existing.account?.pendingInvitation) {
      (ctx.accept ??= {}).alreadyAccepted = true;
    }
    return undefined;
  }

  /**
   * Emit the "this invite was already accepted" finish envelope and short-
   * circuit the rest of the accept tail.
   */
  @Step("idempotent-redirect")
  @Public()
  idempotentRedirect(@WorkflowParam("context") ctx: AuthWfCtx): undefined {
    finishWf(
      buildInviteAlreadyAcceptedEnvelope({
        loginUrl: ctx.accept!.loginUrl!,
        alreadyAcceptedRedirectUrl: ctx.accept!.alreadyAcceptedRedirectUrl!,
      }),
    );
    return undefined;
  }

  /**
   * Clear the user's `pendingInvitation` marker after successful password set.
   */
  @Step("unset-pending-invitation")
  @Public()
  async unsetPendingInvitation(@WorkflowParam("context") ctx: AuthWfCtx): Promise<undefined> {
    this.requireUsername(ctx);
    await this.users.update(ctx.username, {
      account: { pendingInvitation: false },
    } as Partial<UserCredentials>);
    return undefined;
  }

  /** Activate the invited user account (flips the account status flag). */
  @Step("activate-user")
  @Public()
  async activateUser(@WorkflowParam("context") ctx: AuthWfCtx): Promise<undefined> {
    this.requireUsername(ctx);
    await this.users.activateAccount(ctx.username);
    return undefined;
  }

  /**
   * Emit the success-confirmation envelope. The downstream `finalize-auto-
   * login` step preserves this `message` so the SPA paints the configured
   * confirmation text alongside the tokens (WF-INVITE-020).
   */
  @Step("confirmation")
  @Public()
  confirmation(@WorkflowParam("context") ctx: AuthWfCtx): undefined {
    finishWf({
      data: { confirmed: true },
      message: { level: "success", text: ctx.accept!.confirmationMessage! },
    });
    return undefined;
  }

  // ── Password (1) — collapsed across all three flows ──

  /**
   * Unified password-set step body — merges login Phase 5 + invite accept-tail
   * + recovery set-password. Stages copy via `ctx.password.changeReason`
   * (`initial` / `expired` / `reset`), pauses for `SetPasswordForm`, validates
   * match, calls `users.setPassword`, processes inline consents, and clears
   * the per-user `isPasswordInitial` / `isPasswordExpired` flags.
   */
  @Step("create-password-form")
  @Public()
  async createPasswordForm(@WorkflowParam("context") ctx: AuthWfCtx): Promise<unknown> {
    this.requireUsername(ctx);
    // Stage context-aware copy BEFORE the pause so the inputRequired envelope
    // carries the rendered heading/intro alongside the form schema.
    const password = (ctx.password ??= {});
    if (password.changeReason === "expired") {
      password.heading = "Your password has expired";
      password.intro = "Choose a new password to continue. The previous one is no longer valid.";
    } else if (password.changeReason === "reset") {
      password.heading = "Reset your password";
      password.intro = "Choose a new password for your account.";
    } else if (ctx.accept) {
      password.heading = "Welcome — set your password";
      password.intro = "Choose a password to activate your account.";
    } else {
      password.heading = "Set your initial password";
      password.intro = "Your account was created without a password. Choose one to continue.";
    }
    const wf = this.useAtscriptWfPublic(ctx, this.opts.forms.setPassword);
    let input: { newPassword: string; confirmPassword: string; consents?: string[] };
    try {
      input = wf.resolveInput() as typeof input;
    } catch (err) {
      if (ctx.postReset && err instanceof StepRetriableError) throw this.stampRecoveryExpiry(err);
      throw err;
    }
    if (input.newPassword !== input.confirmPassword) {
      throw this.throwPublic(ctx, wf, { errors: { confirmPassword: "Passwords do not match" } });
    }
    try {
      await this.users.setPassword(ctx.username, input.newPassword);
    } catch (err) {
      if (err instanceof UserAuthError) {
        throw this.throwPublic(ctx, wf, { errors: { newPassword: err.message } });
      }
      throw err;
    }
    this.processInlineConsent(ctx, input, wf);
    ctx.isPasswordInitial = false;
    ctx.isPasswordExpired = false;
    // Clear the forced-change flag now that the user has set a fresh
    // password — without this, downstream forms keep seeing the gate as
    // active. Notably `PincodeForm.rememberDevice` is hidden while
    // `newPasswordRequired` is true, so an MFA pause that follows
    // set-password would silently lose the trust-prompt UX.
    ctx.newPasswordRequired = false;
    // `delete` (not `= undefined`) — wf state-token persistence rejects
    // explicit undefined.
    delete password.changeReason;
    delete password.heading;
    delete password.intro;
    return undefined;
  }

  // ── Channel enrolment (2) — login only, parameterized by :channel ──

  @Step("ask/:channel(email|phone)")
  @Public()
  async askChannel(
    @WorkflowParam("context") ctx: AuthWfCtx,
    @Param("channel") channel: "email" | "phone",
  ): Promise<unknown> {
    this.requireUsername(ctx);
    const isEmail = channel === "email";
    // Stage the disclosure BEFORE the pause — `useAtscriptWf` snapshots ctx
    // at the throw site so `@wf.context.pass 'channel'` rides on the carrier
    // descriptor (rendered adjacent to the email/phone input → submission =
    // implied consent). Forwarded to `recordOtpChannelConsent` at verify-time.
    const disclosure = await this.resolveOtpDisclosure(ctx, channel);
    (ctx.channel ??= {}).otpDisclosure = disclosure;
    const askWf = this.useAtscriptWfPublic(
      ctx,
      isEmail ? this.opts.forms.askEmail : this.opts.forms.askPhone,
    );
    const input = askWf.resolveInput() as {
      email?: string;
      phone?: string;
      consents?: string[];
    };
    this.processInlineConsent(ctx, input, askWf);
    const value = (isEmail ? input.email : input.phone) as string;
    const methodName = isEmail ? "email" : "sms";
    const username = ctx.username;
    await this.withStoreErrorTranslation(() =>
      this.users.addMfaMethod(username, { name: methodName, value, confirmed: false }),
    );
    if (isEmail) ctx.email = value;
    else {
      (ctx.channel ??= {}).phone = value;
    }
    const code = this.mintPin(ctx, this.opts.mfa.pincodeLength, this.opts.mfa.pincodeTtlMs);
    await this.deliver({
      kind: "enroll-pincode",
      channel: isEmail ? "email" : "sms",
      recipient: value,
      code,
      expiresInMs: this.opts.mfa.pincodeTtlMs,
    });
    // Arm the resend cooldown — `verifyChannel` reads `resendAllowedAt` to
    // gate the user's "Resend code" click on the PincodeForm. Mirrors the
    // `pincode-send` step's pattern so both pincode surfaces use the same
    // cooldown contract. `sentTo` rides alongside so the PincodeForm's
    // transportHint can render "Code sent to <masked>" — without it the
    // login-enrollment branch falls through to the generic
    // "Enter your verification code." copy.
    const pincode = (ctx.pincode ??= {});
    pincode.resendAllowedAt = Date.now() + this.opts.mfa.pincodeResendTimeoutMs;
    pincode.sentTo = this.maskAddress(value, isEmail ? "email" : "sms");
    const pincodeWf = this.useAtscriptWfPublic(ctx, this.opts.forms.pincode);
    throw this.throwPublic(ctx, pincodeWf);
  }

  @Step("verify/:channel(email|phone)")
  @Public()
  async verifyChannel(
    @WorkflowParam("context") ctx: AuthWfCtx,
    @Param("channel") channel: "email" | "phone",
  ): Promise<unknown> {
    this.requireUsername(ctx);
    const isEmail = channel === "email";
    const pincodeWf = this.useAtscriptWfPublic(ctx, this.opts.forms.pincode);
    // Handle alt-action clicks BEFORE input parsing — the user may click
    // "Resend code" without ever filling in `code`, so a naive
    // `resolveInput()` would fail validation on a missing required field.
    // Resend is the only meaningful alt-action on the enrollment pincode
    // surface (no method-switching here — one channel per enroll loop, and
    // `backToLogin` is hidden in non-recovery contexts via @ui.form.fn.hidden).
    const action = pincodeWf.resolveAction();
    if (action && this.resolvePincodeAltAction(ctx, action) === "resend") {
      // SERVER-SIDE cooldown enforcement (defence in depth — UI also gates).
      // Banner (`formMessage`) rather than per-field error: the user clicked
      // the resend action, not the code input, so an inline error on `code`
      // would be misattributed. `ctx.pincode.resendAllowedAt` rides the
      // `@wf.context.pass 'pincode'` whitelist so custom action components
      // can render a progress bar / countdown without re-deriving the value.
      if (ctx.pincode?.resendAllowedAt && ctx.pincode.resendAllowedAt > Date.now()) {
        const remainingSec = Math.ceil((ctx.pincode.resendAllowedAt - Date.now()) / 1000);
        throw this.throwPublic(ctx, pincodeWf, {
          formMessage: `Please wait ${remainingSec}s before requesting a new code.`,
        });
      }
      const recipient = (isEmail ? ctx.email : ctx.channel?.phone) as string;
      const code = this.mintPin(ctx, this.opts.mfa.pincodeLength, this.opts.mfa.pincodeTtlMs);
      await this.deliver({
        kind: "enroll-pincode",
        channel: isEmail ? "email" : "sms",
        recipient,
        code,
        expiresInMs: this.opts.mfa.pincodeTtlMs,
      });
      const pincode = (ctx.pincode ??= {});
      pincode.resendAllowedAt = Date.now() + this.opts.mfa.pincodeResendTimeoutMs;
      pincode.sentTo = this.maskAddress(recipient, isEmail ? "email" : "sms");
      throw this.throwPublic(ctx, pincodeWf);
    }
    const input = pincodeWf.resolveInput() as { code: string };
    const pinErr = this.verifyPin(ctx, input.code);
    if (pinErr) throw this.throwPublic(ctx, pincodeWf, { errors: pinErr });
    await this.withStoreErrorTranslation(() =>
      this.users.confirmMfaMethod(ctx.username, isEmail ? "email" : "sms"),
    );
    const channelState = (ctx.channel ??= {});
    if (isEmail) channelState.emailConfirmed = true;
    else channelState.phoneConfirmed = true;
    // Record the OTP-channel disclosure AFTER channel ownership is confirmed.
    if (channelState.otpDisclosure) {
      const channelArg: "email" | "sms" = isEmail ? "email" : "sms";
      const target = (isEmail ? ctx.email : channelState.phone) as string;
      await this.consentStore.recordOtpChannelConsent(
        ctx.username,
        channelArg,
        target,
        channelState.otpDisclosure,
      );
    }
    delete ctx.pin;
    delete ctx.pinExpire;
    // Channel-enrollment cooldown is local to the ask/verify pair. Clearing
    // `resendAllowedAt` + `sentTo` here keeps the enrolment cooldown from
    // surfacing on the first MFA-challenge PincodeForm pause when nothing
    // has been sent yet. `channelCooldowns` is MFA-challenge-only (set by
    // `pincode-send` when `ctx.mfa?.method` is bound) so enrollment never
    // touches it — nothing to clear here.
    if (ctx.pincode) {
      delete ctx.pincode.resendAllowedAt;
      delete ctx.pincode.sentTo;
    }
    return undefined;
  }

  // ── MFA loop (11; shared login + invite, plus recovery's reuse of pincode pair) ──

  /**
   * Read the device-trust cookie; if it matches a valid record, set
   * `ctx.otp.verified = true` to skip the MFA loop. Otherwise stamp
   * `ctx.trust.newDevice = true` to drive the post-MFA notify gate.
   */
  @Step("check-trusted-device")
  @Public()
  async checkTrustedDevice(@WorkflowParam("context") ctx: AuthWfCtx): Promise<undefined> {
    if (!ctx.username) return undefined;
    const cookieValue = useCookies(current()).getCookie(this.opts.deviceTrust.cookieName);
    const trust = (ctx.trust ??= {});
    if (!cookieValue) {
      trust.newDevice = true;
      return undefined;
    }
    const ip = this.opts.deviceTrust.bindsTo === "cookie+ip" ? this.resolveClientIp() : undefined;
    const ok = await this.users.verifyTrustedDevice(ctx.username, cookieValue, ip);
    if (ok) {
      (ctx.otp ??= {}).verified = true;
      trust.deviceTrustToken = cookieValue;
    } else {
      trust.newDevice = true;
    }
    return undefined;
  }

  /**
   * Resolve the client IP from the active HTTP request, swallowing the case
   * where there is no HTTP context (unit tests that hand-roll the wf runtime).
   * Ported from `AuthWorkflowBase`.
   */
  protected resolveClientIp(): string | undefined {
    try {
      return useRequest().getIp() || undefined;
    } catch {
      return undefined;
    }
  }

  /**
   * Load + summarise the user's enrolled MFA methods (filtered against
   * `ctx.mfaPolicy.availableTransports`) and mirror form-gating flags
   * (`mfa.methodCount`, `trust.optIn`) onto ctx. Pure data-load.
   */
  @Step("load-enrolled-mfa-methods")
  @Public()
  async loadEnrolledMfaMethods(@WorkflowParam("context") ctx: AuthWfCtx): Promise<undefined> {
    if (!ctx.username) return undefined;
    const user = await this.users.getUser(ctx.username);
    const mfa = (ctx.mfa ??= {});
    const allowed = new Set(ctx.mfaPolicy?.availableTransports ?? []);
    const methods = this.users.getAvailableMfaMethods(user.mfa);
    const summary: MfaSummary[] = methods
      .filter((m: MfaMethodInfo) => {
        const kind = this.mfaKindOf(m.name);
        return kind !== null && allowed.has(kind);
      })
      .map((m: MfaMethodInfo) => {
        const kind = this.mfaKindOf(m.name) as "sms" | "email" | "totp";
        return {
          kind,
          methodName: m.name,
          masked: m.masked,
          isDefault: m.isDefault,
        };
      });
    mfa.enrolledMethods = summary;
    mfa.methodCount = summary.length;
    const trustOptIn = !!(ctx.deviceTrust?.enabled && ctx.deviceTrust?.optIn);
    (ctx.trust ??= {}).optIn = trustOptIn;
    return undefined;
  }

  /**
   * Pick which MFA method to use from `ctx.mfa.enrolledMethods`. Decision-only,
   * no IO. Honors `ctx.mfa.current` (pre-selected by `prepare-mfa` from the
   * user's `defaultMethod`), auto-picks when only one method is enrolled,
   * falls back to the `isDefault` method. Gated on `!ctx.mfa.ignoreDefault`.
   */
  @Step("select-mfa-method")
  @Public()
  selectMfaMethod(@WorkflowParam("context") ctx: AuthWfCtx): undefined | Promise<undefined> {
    const mfa = (ctx.mfa ??= {});
    const summary = mfa.enrolledMethods ?? [];
    if (!mfa.ignoreDefault && mfa.current && summary.some((m) => m.kind === mfa.current)) {
      mfa.method = mfa.current;
      return undefined;
    }
    if (summary.length === 0) return undefined;
    if (summary.length === 1) {
      mfa.method = summary[0].kind;
      return undefined;
    }
    if (!mfa.ignoreDefault) {
      const def = summary.find((m) => m.isDefault);
      if (def) mfa.method = def.kind;
    }
    return undefined;
  }

  /** Pauses for `Select2faForm`; binds `ctx.mfa.method` from input. */
  @Step("select-2fa")
  @Public()
  async select2fa(@WorkflowParam("context") ctx: AuthWfCtx): Promise<unknown> {
    const wf = this.useAtscriptWfPublic(ctx, this.opts.forms.select2fa);
    const input = wf.resolveInput() as { methodName: string; saveAsDefault?: boolean };
    const mfa = (ctx.mfa ??= {});
    const picked = (mfa.enrolledMethods ?? []).find((m) => m.methodName === input.methodName);
    if (!picked) {
      throw this.throwPublic(ctx, wf, { errors: { methodName: "Unknown MFA method" } });
    }
    if (picked.kind === "sms" || picked.kind === "email") {
      // PER-CHANNEL cooldown — survives `useDifferentMethod` so a user
      // can't bypass SMS rate-limiting by ping-ponging SMS → Email → SMS.
      // (`resendAllowedAt` mirrors only the CURRENT channel and is cleared
      // on method-switch so the new-channel UX isn't gated for the wrong
      // reason; `channelCooldowns` is the source of truth.)
      const cooldownUntil = ctx.pincode?.channelCooldowns?.[picked.kind];
      if (cooldownUntil && Date.now() < cooldownUntil) {
        const waitSec = Math.ceil((cooldownUntil - Date.now()) / 1000);
        const channel = picked.kind === "sms" ? "SMS" : "email";
        // Banner — the user clicked a method radio + Submit, not a `methodName`
        // input. Inline errors on a radio group are misattributed UX.
        throw this.throwPublic(ctx, wf, {
          formMessage: `Please wait ${waitSec}s before requesting another ${channel} code`,
        });
      }
    }
    mfa.method = picked.kind;
    mfa.saveAsDefault = Boolean(input.saveAsDefault);
    if (mfa.saveAsDefault && ctx.username) {
      await this.users.setDefaultMfaMethod(ctx.username, picked.methodName);
    }
    return undefined;
  }

  /**
   * Unified MFA pincode send. Used by login MFA SMS/email challenge and
   * recovery OTP. Form/target picked via `resolvePincodeForm` /
   * `resolvePincodeTarget` (which discriminate on `ctx.mfa?.method` presence).
   */
  @Step("pincode-send")
  @Public()
  async pincodeSend(@WorkflowParam("context") ctx: AuthWfCtx): Promise<unknown> {
    const targetResult = this.resolvePincodeTarget(ctx);
    const target = targetResult instanceof Promise ? await targetResult : targetResult;
    const code = this.mintPin(ctx, this.opts.mfa.pincodeLength, this.opts.mfa.pincodeTtlMs);
    // Branched on `kind` discriminator: `AuthDeliveryPayload` pins
    // `recovery-pincode` to `channel: "email"` (a recovery target is always
    // email per `resolvePincodeTarget`'s recovery branch).
    if (ctx.mfa?.method) {
      await this.deliver({
        kind: "mfa-pincode",
        channel: target.channel,
        recipient: target.address,
        code,
        expiresInMs: this.opts.mfa.pincodeTtlMs,
      });
    } else {
      await this.deliver({
        kind: "recovery-pincode",
        channel: "email",
        recipient: target.address,
        code,
        expiresInMs: this.opts.mfa.pincodeTtlMs,
      });
    }
    const pincode = (ctx.pincode ??= {});
    pincode.sentTo = this.maskAddress(target.address, target.channel);
    pincode.codeLength = this.opts.mfa.pincodeLength;
    const cooldownAt = Date.now() + this.opts.mfa.pincodeResendTimeoutMs;
    pincode.resendAllowedAt = cooldownAt;
    // Per-channel cooldown lives alongside `resendAllowedAt` so the gate
    // survives a `useDifferentMethod` clear (see `pincode-check` +
    // `select-2fa`). Only MFA-challenge sends are tracked here — recovery
    // is single-channel (email-only) so per-channel persistence is moot.
    if (ctx.mfa?.method && (target.channel === "sms" || target.channel === "email")) {
      (pincode.channelCooldowns ??= {})[target.channel] = cooldownAt;
    }
    return undefined;
  }

  /**
   * Unified MFA pincode check. Used by login MFA SMS/email challenge and
   * recovery OTP. Alt-actions routed via `resolvePincodeAltAction` — the
   * default returns `undefined` (customers override per form).
   */
  @Step("pincode-check")
  @Public()
  async pincodeCheck(@WorkflowParam("context") ctx: AuthWfCtx): Promise<unknown> {
    const wf = this.useAtscriptWfPublic(ctx, this.resolvePincodeForm(ctx));
    const action = wf.resolveAction();
    if (action) {
      const outcome = this.resolvePincodeAltAction(ctx, action);
      if (outcome === "resend") {
        // SERVER-SIDE cooldown enforcement — banner-form, see the matching
        // raise in `verify-channel` for the rationale (resend is an action
        // click, not a `code` input error).
        if (ctx.pincode?.resendAllowedAt && ctx.pincode.resendAllowedAt > Date.now()) {
          const remainingSec = Math.ceil((ctx.pincode.resendAllowedAt - Date.now()) / 1000);
          throw this.throwPublic(ctx, wf, {
            formMessage: `Please wait ${remainingSec}s before requesting a new code.`,
          });
        }
        delete ctx.pin;
        delete ctx.pinExpire;
        return undefined;
      }
      if (outcome === "exit") {
        ctx.aborted = true;
        return undefined;
      }
      if (outcome === "useDifferentMethod") {
        if (ctx.mfa) {
          ctx.mfa.ignoreDefault = true;
          delete ctx.mfa.method;
        }
        delete ctx.pin;
        delete ctx.pinExpire;
        // Method-switching MUST clear the CURRENT-channel resend cooldown —
        // the next channel is a fresh send, not a re-send for the channel
        // the user just walked away from. Without this delete, the user
        // gets "Please wait Ns…" on the new channel for the WRONG reason
        // (see select-2fa cooldown gate). Mirrors `verifyChannel`'s
        // post-success cleanup.
        //
        // `channelCooldowns` is NOT cleared here — that's the per-channel
        // ledger that survives method-switches so ping-ponging (SMS →
        // Email → SMS → …) cannot bypass per-channel rate limiting.
        // `select-2fa` + `pincode-send` consult that ledger on the next
        // attempt.
        if (ctx.pincode) delete ctx.pincode.resendAllowedAt;
        return undefined;
      }
    }
    let input: { code: string; rememberDevice?: boolean };
    try {
      input = wf.resolveInput() as typeof input;
    } catch (err) {
      if (ctx.postReset && err instanceof StepRetriableError) throw this.stampRecoveryExpiry(err);
      throw err;
    }
    const pinErr = this.verifyPin(ctx, input.code);
    if (pinErr) throw this.throwPublic(ctx, wf, { errors: pinErr });
    (ctx.otp ??= {}).verified = true;
    // Re-arm risk step-up so it re-evaluates after this verification.
    (ctx.session ??= {}).riskStepUpEvaluated = false;
    if (ctx.deviceTrust?.enabled && ctx.deviceTrust?.optIn) {
      (ctx.trust ??= {}).rememberDevice = Boolean(input.rememberDevice);
    }
    delete ctx.pin;
    delete ctx.pinExpire;
    return undefined;
  }

  /**
   * TOTP MFA challenge step body. Verifies a TOTP code via `users.verifyMfa`
   * (lockout-aware); sets `ctx.otp.verified = true` on success. Replaces
   * login's prior `mfa-totp` step.
   */
  @Step("totp-check")
  @Public()
  async totpCheck(@WorkflowParam("context") ctx: AuthWfCtx): Promise<unknown> {
    const wf = this.useAtscriptWfPublic(ctx, this.opts.forms.mfaCode);
    const action = wf.resolveAction();
    if (action === "useDifferentMethod") {
      const mfa = (ctx.mfa ??= {});
      mfa.ignoreDefault = true;
      delete mfa.method;
      return undefined;
    }
    const input = wf.resolveInput() as { code: string; rememberDevice?: boolean };
    this.requireUsername(ctx);
    try {
      await this.users.verifyMfa(ctx.username, input.code);
      (ctx.otp ??= {}).verified = true;
      (ctx.session ??= {}).riskStepUpEvaluated = false;
      if (ctx.deviceTrust?.enabled && ctx.deviceTrust?.optIn) {
        (ctx.trust ??= {}).rememberDevice = Boolean(input.rememberDevice);
      }
    } catch (err) {
      if (err instanceof UserAuthError) {
        if (err.type === "LOCKED") {
          throw this.throwPublic(ctx, wf, {
            formMessage: "Account locked, please try again later",
          });
        }
        if (err.type === "INACTIVE") {
          throw this.throwPublic(ctx, wf, { errors: { code: "Invalid code" } });
        }
        if (err.type === "MFA_NOT_CONFIGURED") {
          throw new HttpError(400, "No TOTP MFA configured");
        }
        if (err.type === "MFA_INVALID") {
          if (err.details?.lockEnds !== undefined) {
            throw this.throwPublic(ctx, wf, {
              formMessage: "Account locked, please try again later",
            });
          }
          throw this.throwPublic(ctx, wf, { errors: { code: "Invalid code" } });
        }
        if (err.type === "CAS_EXHAUSTED") throw new HttpError(409, err.message);
      }
      throw err;
    }
    return undefined;
  }

  /**
   * Unified MFA-enrol phase 1 (pick method). Auto-picks a single transport,
   * otherwise pauses for `EnrollPickMethodForm`. When TOTP is picked, the
   * secret is idempotently provisioned in the same step body. Handles
   * `skip` in `'optional'` mode.
   */
  @Step("enroll-pick-method")
  @Public()
  enrollPickMethod(@WorkflowParam("context") ctx: AuthWfCtx): undefined | Promise<undefined> {
    this.requireUsername(ctx);
    const username = ctx.username;
    const transports = ctx.mfaPolicy?.availableTransports ?? [];
    const mode = ctx.mfaPolicy?.mode === "required" ? "required" : "optional";
    const m = (ctx.mfaEnroll ??= {});
    m.mode = mode;
    if (!m.availableTransports) m.availableTransports = [...transports];

    // 0-transport guard.
    if (transports.length === 0) {
      if (mode === "optional") {
        m.done = true;
        (ctx.otp ??= {}).verified = true;
        return undefined;
      }
      throw new HttpError(
        500,
        "MFA enrollment is required but no transports are configured. " +
          "Override `resolveMfaPolicy` to provide at least one transport, or set `mode` to 'disabled'.",
      );
    }

    // Auto-pick when only one transport; otherwise pause for picker form.
    if (transports.length === 1) {
      m.method = transports[0];
    } else {
      const wf = this.useAtscriptWfPublic(ctx, this.opts.forms.enrollPickMethod);
      if (mode === "optional" && wf.resolveAction() === "skip") {
        m.done = true;
        (ctx.otp ??= {}).verified = true;
        return undefined;
      }
      const input = wf.resolveInput() as { method: string };
      const picked = input.method as MfaTransport;
      if (!m.availableTransports.includes(picked)) {
        throw this.throwPublic(ctx, wf, { errors: { method: "Unknown method" } });
      }
      m.method = picked;
    }

    // Idempotent TOTP secret provisioning.
    if (m.method === "totp" && !m.secret) {
      const issuer = ctx.mfaPolicy?.issuer ?? this.opts.totpIssuer;
      const secret = generateTotpSecret();
      const uri = generateTotpUri(secret, issuer, username);
      return this.withStoreErrorTranslation(() =>
        this.users.addMfaMethod(username, {
          name: "totp",
          value: secret,
          confirmed: false,
        }),
      ).then(() => {
        m.secret = secret;
        m.uri = uri;
        return undefined;
      });
    }

    return undefined;
  }

  /**
   * Unified MFA-enrol phase 2 (collect sms/email address + send pincode).
   * Not invoked for totp. Handles `skip` / `useDifferentMethod`.
   */
  @Step("enroll-address")
  @Public()
  async enrollAddress(@WorkflowParam("context") ctx: AuthWfCtx): Promise<undefined> {
    this.requireUsername(ctx);
    const username = ctx.username;
    const m = (ctx.mfaEnroll ??= {});
    const mode = m.mode ?? "optional";
    const wf = this.useAtscriptWfPublic(ctx, this.opts.forms.enrollAddress);
    const action = wf.resolveAction();
    if (mode === "optional" && action === "skip") {
      m.done = true;
      (ctx.otp ??= {}).verified = true;
      return undefined;
    }
    if (action === "useDifferentMethod") {
      delete m.method;
      return undefined;
    }
    const input = wf.resolveInput() as { address: string };
    const methodName = m.method as MfaTransport;
    await this.withStoreErrorTranslation(() =>
      this.users.addMfaMethod(username, {
        name: methodName,
        value: input.address,
        confirmed: false,
      }),
    );
    m.address = input.address;
    const code = this.mintPin(ctx, this.opts.mfa.pincodeLength, this.opts.mfa.pincodeTtlMs);
    (ctx.pincode ??= {}).resendAllowedAt = Date.now() + this.opts.mfa.pincodeResendTimeoutMs;
    await this.sendEnrollPincode(ctx, input.address, code);
    return undefined;
  }

  /**
   * Unified MFA-enrol phase 3 (verify pincode/TOTP, mark confirmed). On
   * success sets `ctx.mfaEnroll.done = true` AND `ctx.otp.verified = true`
   * (the loop-exit signal — enrol-confirm verifies an OTP, so the unified
   * `otp.verified` flag fires alongside the MFA-specific `mfaEnroll.done`).
   */
  @Step("enroll-confirm")
  @Public()
  async enrollConfirm(@WorkflowParam("context") ctx: AuthWfCtx): Promise<undefined> {
    this.requireUsername(ctx);
    const username = ctx.username;
    const m = (ctx.mfaEnroll ??= {});

    // Idempotent TOTP provisioning at top of confirm — covers the
    // single-transport auto-pick path (`prepare-mfa` may pre-pick totp
    // without going through `enrollPickMethod`).
    if (m.method === "totp" && !m.secret) {
      const issuer = ctx.mfaPolicy?.issuer ?? this.opts.totpIssuer;
      const secret = generateTotpSecret();
      const uri = generateTotpUri(secret, issuer, username);
      await this.withStoreErrorTranslation(() =>
        this.users.addMfaMethod(username, { name: "totp", value: secret, confirmed: false }),
      );
      m.secret = secret;
      m.uri = uri;
    }
    const wf = this.useAtscriptWfPublic(ctx, this.opts.forms.enrollConfirm);
    const mode = m.mode ?? "optional";
    const action = wf.resolveAction();
    if (mode === "optional" && action === "skip") {
      await this.cleanupEnrollment(ctx, username);
      m.done = true;
      (ctx.otp ??= {}).verified = true;
      return undefined;
    }
    if (action === "useDifferentMethod") {
      await this.cleanupEnrollment(ctx, username);
      return undefined;
    }
    if (action === "resend") {
      if (m.method === "totp") {
        throw this.throwPublic(ctx, wf, { formMessage: "Resend is not applicable for TOTP" });
      }
      const cooldown = ctx.pincode?.resendAllowedAt;
      if (cooldown && Date.now() < cooldown) {
        const waitSec = Math.ceil((cooldown - Date.now()) / 1000);
        throw this.throwPublic(ctx, wf, {
          formMessage: `Please wait ${waitSec}s before requesting another code`,
        });
      }
      const code = this.mintPin(ctx, this.opts.mfa.pincodeLength, this.opts.mfa.pincodeTtlMs);
      (ctx.pincode ??= {}).resendAllowedAt = Date.now() + this.opts.mfa.pincodeResendTimeoutMs;
      await this.sendEnrollPincode(ctx, m.address as string, code);
      return undefined;
    }
    const input = wf.resolveInput() as { code: string };
    if (m.method === "totp") {
      try {
        await this.users.verifyTotpSetupCode(username, input.code);
      } catch (err) {
        if (err instanceof UserAuthError && err.type === "MFA_INVALID") {
          throw this.throwPublic(ctx, wf, { errors: { code: "Invalid code" } });
        }
        throw err;
      }
    } else {
      const pinErr = this.verifyPin(ctx, input.code);
      if (pinErr) throw this.throwPublic(ctx, wf, { errors: pinErr });
    }
    const methodName = m.method as MfaTransport;
    await this.withStoreErrorTranslation(() => this.users.confirmMfaMethod(username, methodName));
    await this.users.setDefaultMfaMethod(username, methodName);
    m.done = true;
    (ctx.otp ??= {}).verified = true;
    delete ctx.pin;
    delete ctx.pinExpire;
    return undefined;
  }

  /**
   * Risk step-up: re-evaluate whether to require another MFA round. Default
   * `resolveRiskStepUp` returns `{require: false}`. When `require: true`,
   * clear `ctx.otp.verified` to re-arm the loop.
   */
  @Step("risk-step-up")
  @Public()
  async riskStepUp(@WorkflowParam("context") ctx: AuthWfCtx): Promise<undefined> {
    const session = (ctx.session ??= {});
    session.riskStepUpEvaluated = true;
    const res = await this.resolveRiskStepUp(ctx);
    if (res.require) {
      const reason = res.reason ?? "additional verification required";
      session.riskStepUpReason = reason;
      if (ctx.otp) delete ctx.otp.verified;
      delete ctx.pin;
      delete ctx.pinExpire;
    } else {
      delete session.riskStepUpReason;
    }
    return undefined;
  }

  // ── Login post-MFA tail (5) ──

  /**
   * Mint a device-trust record + cookie value. Default: delegates to
   * `UserService.issueTrustedDevice` — produces an HMAC-signed token bound to
   * `username` (+ `ip` when `bindsTo === 'cookie+ip'`).
   */
  protected async issueTrustedDevice(
    username: string,
    ip: string | undefined,
    ttlMs: number,
  ): Promise<TrustedDeviceRecord> {
    return this.users.issueTrustedDevice(username, {
      ttlMs,
      ...(ip !== undefined && { ip }),
    });
  }

  /**
   * Persist the trusted-device record onto the user store. Default: appends
   * onto the `trustedDevices` array.
   */
  protected async storeTrustedDevice(username: string, record: TrustedDeviceRecord): Promise<void> {
    await this.withStoreErrorTranslation(() => this.users.addTrustedDevice(username, record));
  }

  /**
   * Post-MFA device-trust issuance. SECURITY: must bail when
   * `ctx.newPasswordRequired` is true — issuing a trusted-device token before
   * the user has set their own password would let an admin-set temporary
   * credential establish persistent device trust (defence-in-depth on top of
   * the MFA-form `hidden` expression on `rememberDevice`).
   */
  @Step("device-trust")
  @Public()
  async deviceTrust(@WorkflowParam("context") ctx: AuthWfCtx): Promise<undefined> {
    if (ctx.newPasswordRequired) return undefined;
    if (!ctx.username) return undefined;
    const ip = this.opts.deviceTrust.bindsTo === "cookie+ip" ? this.resolveClientIp() : undefined;
    const record = await this.issueTrustedDevice(ctx.username, ip, this.opts.deviceTrust.ttlMs);
    await this.storeTrustedDevice(ctx.username, record);
    (ctx.trust ??= {}).deviceTrustToken = record.token;
    useResponse(current()).setCookie(
      this.opts.deviceTrust.cookieName,
      record.token,
      useAuth().cookieAttrs({ maxAge: this.opts.deviceTrust.ttlMs / 1000 }),
    );
    return undefined;
  }

  /**
   * Standalone terms-bump prompt for returning users whose accepted terms
   * version is stale and no carrier form ran. Delegates to
   * `processInlineConsent` for validation + ctx writes.
   */
  @Step("terms-bump-prompt")
  @Public()
  termsBumpPrompt(@WorkflowParam("context") ctx: AuthWfCtx): undefined {
    const wf = this.useAtscriptWfPublic(ctx, this.opts.forms.termsBump);
    const input = wf.resolveInput() as { consents?: string[] };
    this.processInlineConsent(ctx, input, wf);
    return undefined;
  }

  /**
   * Load the user's active session count for the concurrency-limit gate.
   * Pure data-load — calls the overridable `loadActiveSessionsCount` hook.
   */
  @Step("load-active-sessions")
  @Public()
  async loadActiveSessions(@WorkflowParam("context") ctx: AuthWfCtx): Promise<undefined> {
    if (!ctx.username) return undefined;
    const n = await this.loadActiveSessionsCount(ctx.username);
    (ctx.session ??= {}).activeSessions = n;
    return undefined;
  }

  /**
   * Concurrency-limit gate — pauses for `ConcurrencyLimitForm`. `reject` mode
   * blocks the login outright; `kickPrompt` mode lets the user cancel (sets
   * `ctx.aborted`) or kick all other sessions.
   */
  @Step("concurrency-limit")
  @Public()
  async concurrencyLimit(@WorkflowParam("context") ctx: AuthWfCtx): Promise<unknown> {
    const cfg = ctx.sessionPolicy?.concurrencyLimit;
    if (!cfg) return undefined;
    const wf = this.useAtscriptWfPublic(ctx, this.opts.forms.concurrencyLimit);
    if (cfg.onLimit === "reject") {
      throw this.throwPublic(ctx, wf, { formMessage: "Session limit reached" });
    }
    const action = wf.resolveAction();
    if (action === "cancel") {
      abortWf("sessionLimit", {
        message: { level: "warn", text: "Concurrent session limit reached." },
      });
      ctx.aborted = true;
      return undefined;
    }
    if (action === "logoutOthers" && ctx.username) {
      await this.logoutOtherSessions(ctx.username);
      return undefined;
    }
    throw this.throwPublic(ctx, wf);
  }

  // ── Extra-step (1) — login + invite, gated on isFirstLogin ──

  /**
   * Consumer extension point — override in your subclass to inject extra
   * accept-tail logic (input pauses, alt actions, persistence). Default:
   * no-op.
   */
  @Step("extra-step")
  @Public()
  extraStep(@WorkflowParam("context") _ctx: AuthWfCtx): undefined {
    return undefined;
  }

  // ── Consents persistence (1) — all three ──

  /**
   * Batched consent persistence — fans one `ConsentEvent` per pending
   * descriptor out to the `ConsentStore.save` DI provider.
   */
  @Step("persist-consents")
  @Public()
  async persistConsents(@WorkflowParam("context") ctx: AuthWfCtx): Promise<undefined> {
    this.requireUsername(ctx);
    const group = ctx.consents ?? {};
    const pending = group.pending ?? [];
    if (pending.length === 0) return undefined;
    const accepted = new Set(group.accepted ?? []);
    const at = group.decidedAt ?? Date.now();
    const events = pending.map((p) => {
      const evt: { id: string; accepted: boolean; at: number; version?: string } = {
        id: p.id,
        accepted: accepted.has(p.id),
        at,
      };
      if (p.version !== undefined) evt.version = p.version;
      return evt;
    });
    await this.consentStore.save(ctx.username, events);
    return undefined;
  }

  // ── Recovery (1) ──

  /**
   * Revoke all the user's existing sessions via `auth.revokeAllForUser`.
   * Gated upstream by `ctx.postReset.revokeAllSessions`.
   */
  @Step("revoke-sessions")
  @Public()
  async revokeSessions(@WorkflowParam("context") ctx: AuthWfCtx): Promise<undefined> {
    if (!ctx.username) return undefined;
    await this.auth.revokeAllForUser(ctx.username);
    return undefined;
  }

  // ── Finalize (5) ──

  /**
   * Issue access + refresh tokens via `auth.issue`. Stashes the login
   * response envelope on `useWfFinished` so downstream `redirect` can
   * override with a redirect envelope while preserving the cookies.
   */
  @Step("issue")
  @Public()
  async issue(@WorkflowParam("context") ctx: AuthWfCtx): Promise<void> {
    this.requireUsername(ctx);
    const issue = await this.auth.issue(ctx.username);
    const auth = useAuth();
    const envelope: WfFinished = {
      finished: true,
      data: auth.buildLoginResponse(ctx.username, issue),
    };
    useWfFinished().set({
      type: "data",
      value: envelope,
      cookies: auth.buildFinishedCookies(issue),
    });
  }

  /**
   * Notify the user of a login from a new device via the unified `deliver`
   * hook. Gated upstream by
   * `!ctx.isFirstLogin && !!ctx.finalize.notifyNewDevice && !!ctx.trust.newDevice`.
   */
  @Step("notify-new-device")
  @Public()
  async notifyNewDevice(@WorkflowParam("context") ctx: AuthWfCtx): Promise<undefined> {
    if (!ctx.email) return undefined;
    await this.deliver({
      kind: "new-device-notice",
      channel: "email",
      recipient: ctx.email,
      loginAt: Date.now(),
    });
    return undefined;
  }

  /**
   * Set `ctx.completion.redirectUrl` from `resolveRedirect`. When set,
   * overrides `issue`'s data envelope with an immediate-redirect envelope
   * (cookies from `issue` are preserved).
   */
  @Step("redirect")
  @Public()
  redirect(@WorkflowParam("context") ctx: AuthWfCtx): undefined {
    const url = this.resolveRedirect(ctx);
    if (!url) return undefined;
    const existing = useWfFinished().get();
    const envelope: WfFinished = {
      finished: true,
      next: {
        trigger: "immediate",
        action: { type: "redirect", target: url, reason: "finalize-redirect" },
      },
    };
    useWfFinished().set({
      type: "data",
      value: envelope,
      ...(existing?.cookies && { cookies: existing.cookies }),
    });
    (ctx.completion ??= {}).redirectUrl = url;
    return undefined;
  }

  /**
   * Fresh-login finalize — invite + recovery. Emits a finish envelope that
   * redirects the user to `loginUrl`. Invite uses an immediate redirect;
   * recovery uses an auto countdown so the user reads the "Password updated"
   * confirmation first. Discriminated by ctx-slot presence
   * (`ctx.postReset` → recovery; otherwise invite).
   */
  @Step("finalize-fresh-login")
  @Public()
  finalizeFreshLogin(@WorkflowParam("context") ctx: AuthWfCtx): undefined {
    const target = ctx.postReset?.loginUrl ?? ctx.accept!.loginUrl!;
    if (ctx.postReset) {
      finishWf({
        message: { level: "success", text: "Password updated. Redirecting to sign-in…" },
        next: {
          trigger: "auto",
          timeoutMs: 5000,
          action: { type: "redirect", target, reason: "reset-success" },
          skipButton: { label: "Go now" },
        },
      });
    } else {
      finishWf({
        next: {
          trigger: "immediate",
          action: { type: "redirect", target, reason: "fresh-login-required" },
        },
      });
    }
    (ctx.completion ??= {}).redirectUrl = target;
    return undefined;
  }

  /**
   * Auto-login finalize — invite + recovery. Issues access + refresh tokens
   * and stashes the login response envelope on `useWfFinished`. Invite
   * preserves any `message` set by an earlier terminal (`confirmation`) so
   * the SPA paints the confirmation text alongside the tokens (WF-INVITE-020).
   */
  @Step("finalize-auto-login")
  @Public()
  async finalizeAutoLogin(@WorkflowParam("context") ctx: AuthWfCtx): Promise<undefined> {
    this.requireUsername(ctx);
    const issue = await this.auth.issue(ctx.username);
    const auth = useAuth();
    const previousMessage = (useWfFinished().get()?.value as WfFinished | undefined)?.message;
    const envelope: WfFinished = {
      finished: true,
      data: auth.buildLoginResponse(ctx.username, issue),
      ...(previousMessage && { message: previousMessage }),
    };
    useWfFinished().set({
      type: "data",
      value: envelope,
      cookies: auth.buildFinishedCookies(issue),
    });
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
  @Workflow("auth/login/flow")
  @Public()
  @WorkflowSchema<AuthWfCtx>([
    { id: "init-login" },
    { id: "credentials" },
    { break: (ctx) => !ctx.username },

    // Resolve all policy groups
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

    // Forced password change (shared) — runs BEFORE channel enrolment + MFA
    // setup so the rest of the flow operates against a real authenticated
    // password (a passwordInitial / passwordExpired user shouldn't be
    // enrolling MFA factors against a placeholder credential). Mirrors the
    // invite-accept schema ordering. `create-password-form` also clears
    // `ctx.newPasswordRequired` on success so the downstream PincodeForm
    // pause shows the `rememberDevice` checkbox normally.
    ...passwordPhaseSchema,
    { break: (ctx) => !!ctx.aborted },

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

    // Extra-step
    { id: "extra-step", condition: (ctx) => !!ctx.isFirstLogin },
    {
      id: "terms-bump-prompt",
      condition: (ctx) => (ctx.consents?.pending?.length ?? 0) > 0 && !ctx.consents?.decidedAt,
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
    { id: "issue" },
    {
      id: "notify-new-device",
      condition: (ctx) =>
        !ctx.isFirstLogin && !!ctx.finalize?.notifyNewDevice && !!ctx.trust?.newDevice,
    },
    { id: "redirect" },
  ])
  loginFlow(): void {}

  /**
   * invite.start — admin-phase + anonymous magic-link accept-tail. Admin
   * steps are arbac-evaluated (no `@Public()` on them); accept-tail steps are
   * all `@Public()` (anonymous resume). The body itself is `@Public()` so the
   * wf adapter can dispatch start/resume on anonymous magic-link clicks.
   */
  @Workflow("auth/invite/start")
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
      condition: (ctx) => !!ctx.username,
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

        { id: "extra-step" }, // always fires for invite (isFirstLogin=true)

        ...consentsPersistTailSchema,

        { id: "unset-pending-invitation" },
        { id: "activate-user" },
        { id: "confirmation", condition: (ctx) => !!ctx.accept?.showConfirmation },

        // Finalize (invite tail — gated by ctx.autoLogin, mirrored from
        // `opts.autoLoginOnInvite` by init-invite-admin / init-invite-accept).
        { id: "finalize-fresh-login", condition: (ctx) => !ctx.autoLogin },
        { id: "finalize-auto-login", condition: (ctx) => !!ctx.autoLogin },
      ],
    },
  ])
  inviteFlow(): void {}

  /**
   * recovery.flow — OTP-via-email reset. `@Public()` on the body because
   * anonymous users start recovery.
   */
  @Workflow("auth/recovery/flow")
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

    // Post-reset tail (recovery-specific) — sequential after the password
    // subflow above; cursor advancement past the `{ break: !!ctx.aborted }`
    // gate already guarantees the password form completed.
    { id: "revoke-sessions", condition: (ctx) => !!ctx.postReset?.revokeAllSessions },
    ...consentsPersistTailSchema,
    // Finalize (recovery tail — gated by ctx.autoLogin, mirrored from
    // `opts.autoLoginOnRecover` by init-recovery).
    { id: "finalize-fresh-login", condition: (ctx) => !ctx.autoLogin },
    { id: "finalize-auto-login", condition: (ctx) => !!ctx.autoLogin },
    // Note: notify-new-device is NOT fired here in this pass — see §13.
  ])
  recoveryFlow(): void {}
}
