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
import {
  AuthCredential,
  type CredentialMetadata,
  type RateLimitStore,
  RateLimitStoreMemory,
} from "@aooth/auth";
import type { NormalizedProfile } from "@aooth/idp";
import {
  type FederatedProfileSnapshot,
  generateMfaCode,
  generateTotpSecret,
  generateTotpUri,
  maskEmail,
  maskPhone,
  type MfaMethod,
  type MfaMethodInfo,
  pickDefinedProfile,
  SEEN_DEVICES_DEFAULT_CAP,
  type TrustedDeviceRecord,
  UserAuthError,
  type UserCredentials,
  UserService,
  verifyTotpCode,
} from "@aooth/user";
import { finishWf, type FinishWfOpts, useAtscriptWf, type WfFinished } from "@atscript/moost-wf";
import type { TAtscriptAnnotatedType } from "@atscript/typescript/utils";
import { HttpError } from "@moostjs/event-http";
import {
  outlet,
  outletEmail,
  Step,
  StepRetriableError,
  StepTTL,
  swapStrategy,
  useWfFinished,
  useWfState,
  Workflow,
  WorkflowParam,
  WorkflowSchema,
} from "@moostjs/event-wf";
import { createHash, createHmac, randomBytes } from "node:crypto";

import { current, tryGetCurrent } from "@wooksjs/event-core";
import { useCookies, useHeaders, useResponse, useUrlParams } from "@wooksjs/event-http";
import { ArbacAction, ArbacResource, useArbac } from "@aooth/arbac-moost";
import { Controller, Inherit, Param, useControllerContext, useLogger } from "moost";

import { useAuth } from "../auth.composables";
import { aoothHttpError, codedHttpError } from "../http-messages";
import { ConsentStore } from "../consent.store";
import { Public } from "../auth.decorator";
import { buildOAuthAuthorizeRequest, OAUTH_TTL_SEC } from "../oauth/oauth-authorize";
import { AUTHZ_BINDING_COOKIE, authzBindingCookieAttrs } from "../authz/authz-binding";
import { authzRedirectUrl } from "../authz/authz-redirect";
import { OAUTH_CSRF_COOKIE, oauthCsrfCookieAttrs, safeEqual } from "../oauth/oauth-csrf";
import { resolveOAuthRedirect } from "../oauth/oauth-redirect";
import { AuthorizeRuntime } from "../authz/authorize-runtime";
import { OAuthRuntime } from "../oauth/oauth-runtime";
import {
  translatePolicyTexts,
  userAuthErrorField,
  userAuthErrorText,
  userAuthErrorToHttp,
} from "../user-errors";
import type {
  AuthWfCtx,
  AuthWfAltCredsPolicy,
  AuthWfPasswordUiState,
  AuthWfPublicState,
  AuthWfRecoveryDeliveryMode,
  AuthzReauthPolicy,
  ConsentDescriptorLike,
  MfaSummary,
  MfaTransport,
} from "./auth-workflow.ctx";
import type { AuthWorkflowOpts, ResolvedAuthWorkflowOpts } from "./auth-workflow.opts";
import { markPublicProjection } from "./public-projection";
import {
  AOOTH_MESSAGES,
  type AoothMessageCode,
  type AoothMessageParams,
  type AoothMessages,
  currentLocale,
  resolveAoothMessage,
} from "./auth-messages";
import { INVITE_OUTLET, setPendingInviteLink } from "./invite-outlet";
import { MAGIC_LINK_OUTLET, MAGIC_LINK_STRATEGY } from "./magic-link-outlet";
import { defaultPincodeKey, pincodeKeySlot } from "./pincode-key";
import { enforceRateLimit, requestClientIp } from "../rate-limit/interceptor";
import { SEND_RATE_LIMIT, SEND_USER_RATE_LIMIT } from "../rate-limit/registry";
import {
  AskEmailForm,
  AskPhoneForm,
  AuthorizeConsentForm,
  ChangePasswordForm,
  ConcurrencyLimitForm,
  EmailIdentifierForm,
  EnrollAddressForm,
  EnrollConfirmForm,
  EnrollPickMethodForm,
  EnrollTotpQrForm,
  InviteChooseUsernameForm,
  InviteForm,
  LoginCredentialsForm,
  MagicLinkConfirmForm,
  MagicLinkRequestForm,
  ManageMfaForm,
  MfaCodeForm,
  PasswordReauthForm,
  PincodeForm,
  ProveControlForm,
  ProveControlOtpForm,
  RecoveryModeSelectForm,
  RemoveMfaConfirmForm,
  Select2faForm,
  SetPasswordForm,
  SignupForm,
  StepUpConfirmForm,
  TermsBumpForm,
} from "../atscript/models/forms.as";
import {
  consentsPersistTailSchema,
  enrollTrioSteps,
  mfaLoopSchema,
  mfaStepUpLoop,
  passwordPhaseSchema,
  pincodeSendCheckPair,
} from "./auth-workflow.schemas";

/**
 * The set-password screen's copy ({@link AuthWorkflow.resolveSetPasswordCopy}):
 * your own `heading` / `intro` text (shown as is), or message codes rendered
 * through `msg()` in each request's language. Text wins over a code.
 */
export type SetPasswordCopy = Pick<AuthWfPasswordUiState, SetPasswordCopyKey>;

type SetPasswordCopyKey = "heading" | "intro" | "headingCode" | "introCode";
const SET_PASSWORD_COPY_KEYS: readonly SetPasswordCopyKey[] = [
  "heading",
  "intro",
  "headingCode",
  "introCode",
];

/**
 * Unified outbound-dispatch payload. Customers override `deliver(payload)` on
 * the `AuthWorkflow` subclass to route by `kind` (per-purpose templates) and
 * `channel` (email vs SMS). Replaces the prior workflow-specific deliver
 * payloads which carried slightly different field sets per call site.
 */
export type AuthDeliveryPayload = AuthDeliveryPayloadOf & {
  /**
   * The locale of the request the delivery is sent from (moost
   * `useLocale()`), for a localized message. Absent when the request has none.
   */
  locale?: string;
};

/** The {@link AuthDeliveryPayload} variants, by `kind`. */
type AuthDeliveryPayloadOf =
  | {
      kind: "mfa-pincode";
      channel: "sms" | "email";
      recipient: string;
      code: string;
      expiresInMs: number;
    }
  | {
      kind: "recovery-pincode";
      channel: "sms" | "email";
      recipient: string;
      code: string;
      expiresInMs: number;
    }
  | {
      kind: "signup-pincode";
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
    }
  /**
   * Consumer-triggered security notice (e.g. impossible-travel detected by a
   * `resolveRiskStepUp` override) — routed through the same `deliver()` as
   * every other notice. `reason` is the machine-readable trigger
   * (e.g. `"impossible-travel"`); `context` is free-form template data
   * (distances, cities). NEVER auto-sent by the base class — only a consumer
   * call to `sendSecurityAlert` emits it.
   */
  | {
      kind: "security-alert";
      channel: "email";
      recipient: string;
      reason: string;
      loginAt: number;
      context?: Record<string, unknown>;
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
  enrollTotpQr: EnrollTotpQrForm,
  enrollConfirm: EnrollConfirmForm,
  manageMfa: ManageMfaForm,
  removeMfaConfirm: RemoveMfaConfirmForm,
  passwordReauth: PasswordReauthForm,
  stepUpConfirm: StepUpConfirmForm,
  select2fa: Select2faForm,
  mfaCode: MfaCodeForm,
  pincode: PincodeForm,
  setPassword: SetPasswordForm,
  changePassword: ChangePasswordForm,
  inviteChooseUsername: InviteChooseUsernameForm,
  proveControl: ProveControlForm,
  proveControlOtp: ProveControlOtpForm,
  termsBump: TermsBumpForm,
  concurrencyLimit: ConcurrencyLimitForm,
  recoveryPincode: PincodeForm,
  recoveryModeSelect: RecoveryModeSelectForm,
  magicLinkRequest: MagicLinkRequestForm,
  magicLinkConfirm: MagicLinkConfirmForm,
  signup: SignupForm,
  authzConsent: AuthorizeConsentForm,
};

/**
 * Process-wide warn-once latches (module level: `AuthWorkflow` may be
 * event-scoped, and a per-instance flag would warn on every request).
 */
const warnedOnce = { openInviteWhitelist: false, crossIssuerReuse: false };

/** What `pincode-check` compares a recovery code against when there is no account: matches no code. */
const NO_CODE = "\u0000";

/** Default name of the cookie that binds a sign-in link to its browser (opt-in). */
const MAGIC_LINK_BROWSER_COOKIE = "aooth_magic_link";

/** The id an unknown identifier's recovery reads, so its lookups match a known one's. */
const UNKNOWN_ACCOUNT_ID = "00000000-0000-4000-8000-000000000000";

/** Key prefixes of a code's attempt counter and single-use marker (in `lockoutShadowStore`). */
const PIN_ATTEMPT_PREFIX = "code-attempts:";
const PIN_SPENT_PREFIX = "code-spent:";

/** Key prefixes of a code destination's resend cooldown and failed-code budget. */
const CODE_SEND_PREFIX = "code-send:";
const CODE_FAIL_PREFIX = "code-fail:";

/** Key prefix of a magic link's resend cooldown. */
const MAGIC_LINK_SEND_PREFIX = "magic-link:";

/** SHA-256 of `value`, base64url — fixed-size store keys and binding hashes. */
function sha256url(value: string): string {
  return createHash("sha256").update(value).digest("base64url");
}

/** How long a code's counters outlive the code. */
const PIN_COUNTER_GRACE_MS = 60_000;

/** Where a one-time code in flight lives (top-level ctx, or a pending federated link). */
type PinState = { pinNonce?: string; pinDigest?: string; pinExpire?: number };

/** Sliding lifetime of a shadow failure counter (and of a shadow "permanent" lock). */
const SHADOW_TTL_MS = 30 * 24 * 60 * 60_000;

/** Key prefix of an active shadow lock (kept longest by the default store). */
const SHADOW_LOCK_PREFIX = "shadow-lock:";

/** Cap of the default (process-wide, in-memory) shadow-lockout store. */
const SHADOW_STORE_MAX_ENTRIES = 50_000;

/**
 * Keys a flood of fresh failure counters must not push out of the default
 * store: ACTIVE shadow locks (evicting one would unmask exactly the handles an
 * attacker is probing), and the code and magic-link counters (evicting one
 * would restore a code's attempt budget, or lift a resend wait).
 */
const EVICT_LAST_PREFIXES = [
  SHADOW_LOCK_PREFIX,
  PIN_ATTEMPT_PREFIX,
  PIN_SPENT_PREFIX,
  CODE_SEND_PREFIX,
  CODE_FAIL_PREFIX,
  MAGIC_LINK_SEND_PREFIX,
];

/** Internal: a memory `lockoutShadowStore` as the default one is built (bounded, protected keys evicted last). */
export function createShadowStore(maxEntries = SHADOW_STORE_MAX_ENTRIES): RateLimitStoreMemory {
  return new RateLimitStoreMemory({
    maxEntries,
    evictLast: (key) => EVICT_LAST_PREFIXES.some((prefix) => key.startsWith(prefix)),
  });
}

// One process-wide shadow-lockout store: `AuthWorkflow` may be event-scoped,
// and a per-instance memory store would forget every failure between requests.
let sharedShadowStore: RateLimitStore | undefined;
function defaultShadowStore(): RateLimitStore {
  return (sharedShadowStore ??= createShadowStore());
}

function mergeAuthWorkflowOpts(opts: Partial<AuthWorkflowOpts>): ResolvedAuthWorkflowOpts {
  // Merge deviceTrust FIRST — the recognition cookie name is derived from the
  // MERGED trust cookie name (`<trustCookie>_seen`), so a consumer renaming
  // the trust cookie gets a matching recognition name without a second knob.
  const deviceTrust = {
    cookieName: "aooth_trusted_device",
    ttlMs: 24 * 60 * 60_000,
    bindsTo: "cookie" as const,
    ...opts.deviceTrust,
  };
  return {
    autoLoginOnInvite: opts.autoLoginOnInvite ?? true,
    autoLoginOnRecover: opts.autoLoginOnRecover ?? false,
    invitableRoles: opts.invitableRoles ?? [],
    allowAnyInviteRole: opts.allowAnyInviteRole ?? false,
    inviteDelivery: opts.inviteDelivery ?? "outlet-email",
    ...(opts.inviteLinkUrl && { inviteLinkUrl: opts.inviteLinkUrl }),
    inviteUsername: opts.inviteUsername ?? "email",
    ...(opts.messages !== undefined && { messages: opts.messages }),
    lockoutDisclosure: opts.lockoutDisclosure ?? "uniform",
    lockoutShadowStore: opts.lockoutShadowStore ?? defaultShadowStore(),
    mfa: {
      pincodeLength: opts.mfa?.pincodeLength ?? 6,
      pincodeTtlMs: opts.mfa?.pincodeTtlMs ?? 5 * 60 * 1000,
      pincodeResendTimeoutMs: opts.mfa?.pincodeResendTimeoutMs ?? 60_000,
      pincodeMaxAttempts: opts.mfa?.pincodeMaxAttempts ?? 5,
      pincodeMaxFailures: opts.mfa?.pincodeMaxFailures ?? 10,
      pincodeFailureWindowMs: opts.mfa?.pincodeFailureWindowMs ?? 60 * 60_000,
      pincodeMaxFailuresGlobal: opts.mfa?.pincodeMaxFailuresGlobal ?? 100,
      pincodeMaxSendsGlobal: opts.mfa?.pincodeMaxSendsGlobal ?? 10,
    },
    recoveryStateTtlMs: opts.recoveryStateTtlMs ?? 60 * 60 * 1000,
    magicLinkTtlMs: opts.magicLinkTtlMs ?? 15 * 60 * 1000,
    loginUrl: opts.loginUrl ?? "/login",
    totpIssuer: opts.totpIssuer ?? "aooth",
    deviceTrust,
    deviceRecognition: {
      cookieName: opts.deviceRecognition?.cookieName ?? `${deviceTrust.cookieName}_seen`,
      ttlMs: opts.deviceRecognition?.ttlMs ?? 180 * 24 * 60 * 60_000,
      maxDevices: opts.deviceRecognition?.maxDevices ?? SEEN_DEVICES_DEFAULT_CAP,
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
  "seenDevices",
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

// Ordered match→label tables for `humanizeUserAgent` — first hit wins, so
// order matters: Edge ships a `Chrome/` token (check `Edg` first) and Chrome
// ships `Safari/` (check Chrome before Safari); Android UAs carry a `Linux`
// token and iOS UAs a `Mac OS X` token (check the mobile platforms first).
const UA_BROWSERS: readonly (readonly [token: string, label: string])[] = [
  ["Edg", "Edge"],
  ["Chrome", "Chrome"],
  ["Firefox", "Firefox"],
  ["Safari", "Safari"],
];
const UA_OSES: readonly (readonly [pattern: RegExp, label: string])[] = [
  [/iPhone|iPad|iPod/, "iOS"],
  [/Android/, "Android"],
  [/Mac OS X|Macintosh/, "macOS"],
  [/Windows/, "Windows"],
  [/Linux/, "Linux"],
];

/**
 * Best-effort "Browser on OS" label from a raw User-Agent string — feeds the
 * `name` field of `seenDevices` records so a device list reads "Chrome on
 * Windows" instead of a token. Deliberately tiny (no UA-parser dependency);
 * detection order lives in the `UA_BROWSERS` / `UA_OSES` tables above.
 * Returns just the browser or just the OS when only one side is detected;
 * `undefined` for empty / fully unrecognized input.
 */
export function humanizeUserAgent(ua: string | undefined): string | undefined {
  if (!ua) return undefined;
  const browser = UA_BROWSERS.find(([token]) => ua.includes(token))?.[1];
  const os = UA_OSES.find(([pattern]) => pattern.test(ua))?.[1];
  if (browser && os) return `${browser} on ${os}`;
  return browser ?? os;
}

/**
 * Great-circle distance in kilometres between two coordinates (haversine,
 * WGS84 mean radius 6371 km) — for impossible-travel thresholds against
 * per-session geo metadata captured via `resolveIssueMetadata`. Pure and
 * dependency-free; aooth ships no geo resolution or default thresholds —
 * feeding coordinates in (and deciding what distance is "impossible") is
 * consumer policy.
 */
const toRad = (deg: number): number => (deg * Math.PI) / 180;

export function haversineKm(
  a: { lat: number; lon: number },
  b: { lat: number; lon: number },
): number {
  const R = 6371; // WGS84 mean radius, km
  const dLat = toRad(b.lat - a.lat);
  const dLon = toRad(b.lon - a.lon);
  const h =
    Math.sin(dLat / 2) ** 2 +
    Math.cos(toRad(a.lat)) * Math.cos(toRad(b.lat)) * Math.sin(dLon / 2) ** 2;
  return 2 * R * Math.asin(Math.sqrt(h));
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
  /** Text overrides (see `AuthWorkflowOpts.messages`). */
  messages?: AoothMessages;
}): FinishWfOpts {
  const altUrl = opts.alreadyAcceptedRedirectUrl;
  const msg = (code: AoothMessageCode) => resolveAoothMessage(code, {}, opts.messages);
  return {
    message: { level: "info", text: msg("INVITE_ALREADY_ACCEPTED") },
    next: {
      trigger: "manual",
      primary: {
        label: msg("GO_TO_SIGN_IN"),
        action: { type: "redirect", target: opts.loginUrl, reason: "already-accepted" },
      },
      ...(altUrl && {
        options: [
          {
            label: msg("REQUEST_NEW_INVITE"),
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

/** One canonical form of a chosen username: Unicode NFKC, surrounding whitespace trimmed. */
function normalizeUsername(raw: unknown): string {
  return String(raw).normalize("NFKC").trim();
}

/** Loose email shape — `account.verifiedEmail` is only recorded for a value that looks like one. */
const EMAIL_SHAPE = /^[^@\s]+@[^@\s]+\.[^@\s]+$/;

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

/** The message code of each MFA method's label. */
const MFA_METHOD_LABEL_CODES = {
  totp: "MFA_METHOD_TOTP",
  email: "MFA_METHOD_EMAIL",
  sms: "MFA_METHOD_SMS",
} as const satisfies Record<MfaTransport, AoothMessageCode>;

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

/**
 * Thrown by `recoveryPincodeTarget`'s registered (M2) branch when the confirmed
 * recovery method that `request`'s guard saw has VANISHED before send time
 * (deleted between the two row loads — the request→send TOCTOU). `pincode-send`
 * catches it and degrades to the ghost OTP run instead of surfacing a
 * distinguishable 500, so a known account can never become
 * distinguishable from an unknown one on a resend. Recovery-only; the MFA
 * challenge branch keeps its own `HttpError(500)` (that path is post-password,
 * so enumeration is moot there).
 */
class RecoveryMethodUnavailableError extends Error {}

@Inherit()
@Controller()
export class AuthWorkflow {
  protected readonly opts: ResolvedAuthWorkflowOpts;
  protected readonly users: UserService;
  protected readonly auth: AuthCredential;
  protected readonly consentStore: ConsentStore;

  /** The invite context every invite hook receives: issuer, app context, extra form fields. */
  private inviteHookInput(ctx: AuthWfCtx): {
    invitedBy?: string;
    app?: Record<string, unknown>;
    form?: Record<string, unknown>;
  } {
    const admin = ctx.admin;
    return {
      ...(admin?.invitedBy && { invitedBy: admin.invitedBy }),
      ...(admin?.app && { app: admin.app }),
      ...(admin?.form && { form: admin.form }),
    };
  }

  /** Warn once per process when a `'reuse'` re-invite crosses issuers. */
  private warnCrossIssuerReuse(): void {
    if (warnedOnce.crossIssuerReuse) return;
    warnedOnce.crossIssuerReuse = true;
    useLogger("aooth:auth", current()).warn(
      "A re-invite ('reuse') took over a pending invite issued by another user — its " +
        "roles and extras were replaced and the earlier link no longer works. Override " +
        "`duplicateInviteCheck()` (it receives `invitedBy`, `app` and `pending`) to refuse it.",
    );
  }

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
   * Resolve a user-facing text by code (`AOOTH_MESSAGES`): `opts.messages`
   * first, then moost's translator in the request's locale, then the English
   * template. Every form error, banner, finish message and button label the
   * workflow produces goes through here — override for full control.
   */
  protected msg(code: AoothMessageCode, params?: AoothMessageParams): string {
    return resolveAoothMessage(code, params, this.opts.messages);
  }

  /**
   * An `HttpError` whose body carries the message `code` and `params` next to
   * its (resolved) text, so an error-body translator can translate it by code.
   */
  protected httpError(
    status: 400 | 409 | 410,
    code: AoothMessageCode,
    params?: AoothMessageParams,
  ): HttpError {
    return codedHttpError(status, code, this.msg(code, params), params);
  }

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

  /** {@link deliver} with the request's locale stamped on the payload. */
  private dispatch(payload: AuthDeliveryPayload): void | Promise<void> {
    const locale = currentLocale();
    return this.deliver(locale === undefined ? payload : { ...payload, locale });
  }

  /**
   * The blessed one-call alert path for risk overrides — emit a
   * `security-alert` delivery (e.g. from an impossible-travel
   * `resolveRiskStepUp` override). Recipient comes from `ctx.notice.email`,
   * the proven-first correspondence chain seeded by `credentials` /
   * `seedChannelState` and refreshed by `verify/email`. No recipient →
   * SILENT no-op (a user with no provable inbox simply can't be alerted —
   * mirrors `notifyNewDevice`'s posture). Never called by the base class.
   */
  protected async sendSecurityAlert(
    ctx: AuthWfCtx,
    reason: string,
    context?: Record<string, unknown>,
  ): Promise<void> {
    const recipient = ctx.notice?.email;
    if (!recipient) return;
    await this.dispatch({
      kind: "security-alert",
      channel: "email",
      recipient,
      reason,
      loginAt: Date.now(),
      ...(context && { context }),
    });
  }

  // ── Lifecycle hooks ───────────────────────────────────────────────────────
  // Overridable side-effect seams fired at a SINGLE uniform point per event
  // (provision a tenant, send a welcome email, push analytics, sync an external
  // directory, …). All default to a no-op and are maybe-async (`void |
  // Promise<void>`) so the engine keeps its sync fast path when unimplemented.
  // They are AWAITED and a throw PROPAGATES — i.e. a failing hook aborts the
  // flow; wrap your own body in try/catch for best-effort behaviour. Each
  // receives the live `AuthWfCtx` (subject + all resolved flow state). The
  // firing points are the schema's `after-*` steps and the flow-exclusive
  // finish terminals — never call these directly.

  /**
   * A user just authenticated and a session is being established — interactive
   * login, federated (SSO) login, OR invite/signup/recovery auto-login. Fired
   * from the single `record-login` funnel, AFTER `account.lastLogin` is stamped
   * and BEFORE the session/code is delivered, so a throw aborts the login
   * atomically (no half-issued session). `ctx.subject` is set; read
   * `ctx.isFirstLogin` to distinguish the very first sign-in, `ctx.oauth` for
   * federated context. Does NOT fire for the no-session "fresh-login" finalize
   * (where the user is redirected to sign in separately).
   */
  protected afterLogin(_ctx: AuthWfCtx): void | Promise<void> {
    return undefined;
  }

  /**
   * An invitee finished accepting their invite — account activated — whether or
   * not the flow auto-logged-them-in. Fires once, before the finalize terminal.
   * (An auto-login invite ALSO fires {@link afterLogin}.)
   */
  protected afterInvitationAccepted(_ctx: AuthWfCtx): void | Promise<void> {
    return undefined;
  }

  /**
   * A self-signup account was created + activated (post password-set, post
   * activate). Fires once, before the auto-login finalize. (Signup always
   * auto-logins, so {@link afterLogin} fires too.)
   */
  protected afterSignup(_ctx: AuthWfCtx): void | Promise<void> {
    return undefined;
  }

  /**
   * A recovery password reset completed. Fires once even when an `admin-only`
   * lock survived the reset (the password DID change) — so it runs ahead of the
   * still-locked guard. An auto-login recovery ALSO fires {@link afterLogin}.
   */
  protected afterPasswordReset(_ctx: AuthWfCtx): void | Promise<void> {
    return undefined;
  }

  /**
   * An already-authenticated user changed their own password (change-password
   * flow). NOT a login — the session is rotated, not established — so
   * {@link afterLogin} does NOT fire.
   */
  protected afterPasswordChanged(_ctx: AuthWfCtx): void | Promise<void> {
    return undefined;
  }

  /**
   * A user added, changed, or removed an MFA factor (add-mfa flow). NOT fired
   * on a cancel / nothing-to-do finish. The user KEEPS their session (no
   * re-issue), so {@link afterLogin} does NOT fire.
   */
  protected afterMfaChanged(_ctx: AuthWfCtx): void | Promise<void> {
    return undefined;
  }

  /**
   * Selectable role ids for the admin invite form — ALSO enforced server-side
   * (`admin-form` rejects any submitted role outside this set). Read by
   * `prepareAvailableRoles`. Mirrors the prior `InviteWorkflow.getAvailableRoles()`
   * consumer hook.
   *
   * Default behaviour is driven by {@link AuthWorkflowOpts.invitableRoles}:
   * - **configured** → that universe intersected with the CURRENT inviter's
   *   ARBAC grants (`auth.invite` / `assign:<role>`), so an inviter can only
   *   delegate roles they may themselves assign. If ARBAC is unreachable the
   *   universe is returned verbatim — still a CLOSED whitelist, never fail-open.
   * - **unset** → `undefined`, preserving the legacy "no whitelist" behaviour;
   *   `prepareAvailableRoles` warns once unless
   *   {@link AuthWorkflowOpts.allowAnyInviteRole} acknowledges it.
   *
   * Override for fully custom sourcing — the override then owns the gate
   * outright (no warning fires; `invitableRoles` is consulted only if the
   * override reads it).
   */
  protected getAvailableRoles(): Promise<string[] | undefined> | string[] | undefined {
    const universe = this.opts.invitableRoles;
    if (universe.length === 0) return undefined;
    return this.filterInvitableRolesByArbac(universe);
  }

  /**
   * Intersect a role universe with the current inviter's ARBAC grants — keep
   * only roles they hold `auth.invite` / `assign:<role>` for. Falls back to the
   * universe verbatim when ARBAC is unreachable (no event context / not wired),
   * which keeps the whitelist CLOSED rather than failing open.
   */
  protected async filterInvitableRolesByArbac(universe: string[]): Promise<string[]> {
    try {
      const arbac = useArbac();
      const verdicts = await Promise.all(
        universe.map((role) =>
          arbac.evaluate({ resource: "auth.invite", action: `assign:${role}` }),
        ),
      );
      return universe.filter((_, i) => verdicts[i].allowed);
    } catch {
      return [...universe];
    }
  }

  /**
   * True when the admin invite form would assign roles with NO server-side
   * whitelist in effect: `invitableRoles` unset, `getAvailableRoles` not
   * overridden, and the open default not acknowledged via `allowAnyInviteRole`.
   * Drives the one-time `prepare-available-roles` warning.
   */
  protected inviteWhitelistIsOpen(): boolean {
    return (
      !this.opts.allowAnyInviteRole &&
      this.opts.invitableRoles.length === 0 &&
      this.getAvailableRoles === AuthWorkflow.prototype.getAvailableRoles
    );
  }

  /**
   * Build the extras dict merged into the freshly-created user row. Runs for
   * EVERY new-account path: password-signup and invite-accept merge it at
   * `createUser` time (the `create-user` step), and a first-time federated
   * login applies it from `sso-callback` (post-create `users.update`). Default:
   * `{}`. Override to populate e.g. a required `tenantId` from request context.
   *
   * `email` is optional: a federated profile can carry no email, so overrides
   * must tolerate `email === undefined`.
   */
  protected prepareUser(_input: {
    email?: string;
    roles: string[];
    invitedBy?: string;
    /** Invite only: the app context from {@link resolveInviteContext}. */
    app?: Record<string, unknown>;
    /** Invite only: admin-form fields beyond `email` / `roles`. */
    form?: Record<string, unknown>;
  }): Promise<Record<string, unknown>> | Record<string, unknown> {
    return {};
  }

  /**
   * Derive roles server-side from the admin-form payload (e.g. AD lookup).
   * Result is set-unioned with admin-supplied roles by `infer-roles`.
   * Default: `[]`.
   */
  protected inferAdminRoles(_input: {
    email: string;
    invitedBy?: string;
    app?: Record<string, unknown>;
    form?: Record<string, unknown>;
  }): Promise<string[]> | string[] {
    return [];
  }

  /**
   * App context of an invite, resolved once when the issue phase starts
   * (`init-invite-admin`) from the trigger's START input (`{ wfid, input: {
   * formData } }` — the `startFormData` argument) and the session. Return
   * e.g. `{ tenantId }`; the value is kept server-side as `ctx.admin.app` and
   * handed to `prepareUser`, `inferAdminRoles` and `duplicateInviteCheck`.
   * Throw an `HttpError` to refuse the invite (e.g. the issuer may not invite
   * into that tenant). Default: `undefined` (no app context).
   */
  protected resolveInviteContext(
    _ctx: AuthWfCtx,
    _startFormData: Record<string, unknown> | undefined,
  ): Record<string, unknown> | undefined | Promise<Record<string, unknown> | undefined> {
    return undefined;
  }

  /**
   * Override the structural duplicate rule for `admin-form`. Default: a row
   * still parked on `account.pendingInvitation` → `'reuse'` (re-invite:
   * `create-user` refreshes the existing record in place and `send-email`
   * mints a fresh magic link — see `createUser`); any other existing row →
   * `'reject'`; nothing → `'allow'`.
   *
   * Multi-tenant apps that allow re-inviting the same email into a different
   * tenant override to `'allow'`. Apps that want the strict legacy behavior
   * ("Invite already pending" error on a duplicate invite of a pending user)
   * return `'reject'` for pending rows. Compare `invitedBy` / `app` with
   * `pending` and `existingUser` to refuse taking over another issuer's (or
   * tenant's) pending invite. On `'reuse'` the row's roles and extras are
   * REPLACED by this invite's, and every link issued before is superseded
   * (answers 410 "replaced").
   */
  protected duplicateInviteCheck(input: {
    email: string;
    existingUser: UserCredentials | null;
    /** The issuer of THIS invite (session user id). */
    invitedBy?: string;
    /** This invite's app context ({@link resolveInviteContext}). */
    app?: Record<string, unknown>;
    /** This invite's extra admin-form fields. */
    form?: Record<string, unknown>;
    /** The pending invite already on `existingUser`, when there is one. */
    pending?: { invitedBy?: string };
  }): Promise<"allow" | "reject" | "reuse"> | "allow" | "reject" | "reuse" {
    if (input.existingUser?.account?.pendingInvitation) return "reuse";
    return input.existingUser ? "reject" : "allow";
  }

  /**
   * Implements the "log out other sessions" branch of `sessionPolicy.concurrencyLimit`.
   * Default revokes every existing session via `auth.revokeAllForUser` — which is
   * mandatory on every store (stateless ones use a per-user epoch sentinel), so the
   * kick works without an override. Runs BEFORE `issue`, so the session about to be
   * minted survives. Override to scope the revoke (e.g. keep the current device).
   */
  protected async logoutOtherSessions(username: string): Promise<void> {
    await this.auth.revokeAllForUser(username);
  }

  /**
   * Return the number of active (non-revoked, non-expired) sessions for the user,
   * used by the concurrency-limit gate. Default delegates to `auth.listForUser`,
   * which counts access-kind credentials and returns `[]` for stateless stores
   * (no round-trip) — so the count is real when the store can enumerate and `0`
   * (gate disabled) when it can't. Only consulted when `resolveSessionPolicy`
   * declared a `concurrencyLimit`. Override for a custom session source.
   */
  protected async loadActiveSessionsCount(username: string): Promise<number> {
    return (await this.auth.listForUser(username)).length;
  }

  /**
   * Resolves the post-login redirect URL. Default reads `finalize.redirect`:
   * `false` / `null` → no redirect; `'home'` → `/`; `'referer'` → request
   * `Referer` header (undefined when absent).
   */
  protected resolveRedirect(ctx: AuthWfCtx): string | undefined {
    // OAuth flow: honor the validated app redirect carried across the bounce
    // (already screened by `resolveOAuthRedirect` in `sso-callback`), ahead of
    // the generic `finalize.redirect` policy.
    if (ctx.oauth?.redirect) return ctx.oauth.redirect;
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

  // ── OAuth / federated-login dependency seam ─────────────────────────────
  //
  // The `sso-callback` step needs two app-provided singletons that are NOT
  // ctor deps — so a deployment that doesn't use federated login is never
  // forced to provide them, and `AuthWorkflow`'s documented subclass ctor stays
  // unchanged. They are bundled in {@link OAuthRuntime} (an `@Injectable` whose
  // ctor deps resolve THROUGH the provide-registry — unlike a direct
  // `infact.get(token)` of a factory-provided/abstract class, which fails).
  // Reached ONLY when the OAuth flow actually runs. Override in a unit test to
  // inject fakes without standing up the DI container. Named as a plain getter
  // (NOT `resolveXxx`, reserved for policy resolvers, nor `loadXxx`, for
  // external-store fetchers).

  protected oauthRuntime(): Promise<OAuthRuntime> {
    // `instantiate` (NOT `getMoostInfact().get`) carries the app's
    // provide-registry, so `OAuthRuntime`'s `@Inject` token deps resolve — the
    // same path `WfTrigger` uses for `WfTriggerProvider`. The step runs in the
    // HTTP-parented wf event, so the controller context is reachable.
    return useControllerContext().instantiate(OAuthRuntime);
  }

  /**
   * Resolve the {@link AuthorizeRuntime} (the pending-authorization + auth-code
   * stores) for the `mint-authz-code` terminal — same `instantiate` path as
   * {@link oauthRuntime}, reached ONLY when a login was started from
   * `/auth/authorize` (`ctx.authz` set). Override in a unit test to inject fakes.
   */
  protected authorizeRuntime(): Promise<AuthorizeRuntime> {
    return useControllerContext().instantiate(AuthorizeRuntime);
  }

  /**
   * Redirect target for a federated-login FAILURE terminal — provider denial,
   * invalid/expired state, CSRF mismatch, missing transaction, exchange
   * failure, `denied` / `needs-link` resolution, or a locked/inactive account.
   * Benign + generic: it MUST NOT reveal WHICH check tripped (no
   * tamper-vs-expiry oracle — see invariant #5). Default: the login URL with a
   * single generic `?error=oauth`. Override to route to a dedicated SPA error
   * page (still without leaking the reason).
   */
  protected resolveOAuthErrorRedirect(_ctx: AuthWfCtx, _reason: string): string {
    return `${this.opts.loginUrl}?error=oauth`;
  }

  /**
   * Leg 1 of federated login: turn an `sso-<id>` click on the login form into a
   * redirect to the provider, then END the login wf. STATELESS — no flow store:
   * a fresh non-secret `seed` is minted, the PKCE verifier + OIDC nonce are
   * DERIVED from it (`registry.deriveSeededPkce`), the `challenge`/`nonce` build
   * the authorize URL, and the seed rides in BOTH the signed `state` and a Lax
   * double-submit CSRF cookie. The callback re-derives the identical verifier
   * from `state.random` to redeem the `code` (see `sso-callback`) — so nothing
   * secret is ever in the URL and no server-side transaction is persisted.
   *
   * The CSRF cookie is attached to the FINISH ENVELOPE's `cookies` (which the
   * wf-trigger outlet writes onto the real HTTP response), NOT via
   * `useResponse().setCookie` — the outlet builds its response from the
   * `WfFinished` envelope and ignores response-context cookies. Same mechanism
   * `issue` uses for the session cookie. The resume is a same-origin XHR, so the
   * `Set-Cookie` is stored before `AsWfForm` follows the redirect.
   */
  protected async beginSso(providerId: string, authzHandle?: string): Promise<void> {
    const { registry } = await this.oauthRuntime();
    const provider = registry.require(providerId);
    const redirect = resolveOAuthRedirect(getInputField("redirect"), "/");
    // Carry an in-flight authorization-server grant through the provider detour:
    // fold its handle into the signed state so `sso-callback` re-raises `ctx.authz`.
    const { seed, authUrl } = await buildOAuthAuthorizeRequest(registry, provider, {
      redirect,
      ...(authzHandle !== undefined && { handle: authzHandle }),
    });
    const envelope: WfFinished = {
      finished: true,
      next: {
        trigger: "immediate",
        action: { type: "redirect", target: authUrl, reason: `sso-${providerId}` },
      },
    };
    useWfFinished().set({
      type: "data",
      value: envelope,
      cookies: {
        [OAUTH_CSRF_COOKIE]: {
          value: seed,
          options: oauthCsrfCookieAttrs({
            secure: useAuth().options.cookie.secure,
            maxAgeSec: OAUTH_TTL_SEC,
          }),
        },
      },
    });
  }

  // ── Resolved policy surface (override on subclass to customize) ─────────

  /**
   * How recovery proves the inbox: `'otp'` (default — a one-time code),
   * `'magicLink'` (a single-use link, sent through the email outlet as
   * `recovery.magicLink`) or `'choice'` (the user picks on
   * `RecoveryModeSelectForm` after the identifier). Reached from recovery.flow.
   */
  protected resolveRecoveryDeliveryMode(
    _ctx: AuthWfCtx,
  ): AuthWfRecoveryDeliveryMode | Promise<AuthWfRecoveryDeliveryMode> {
    return "otp";
  }

  /**
   * Resolve the alternate-credentials policy (forgot-password / signup /
   * magic-link / SSO providers). Reached from login.flow.
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
      ssoProviders: [],
      recoveryUrl: "/recover",
      signupUrl: "/signup",
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
   * Vouch that an MFA-enrolment address is verified-by-construction, skipping
   * the pincode round-trip: `enroll-send` sends nothing and `enroll-confirm`
   * writes the confirmed factor (+ `verifiedEmail` for email) with no
   * code-entry pause. Asked once per dispatch with the staged transport +
   * normalized address (ctx-first, extra positional args — same convention as
   * `resolveOtpDisclosure`).
   *
   * Default `false` — every enrolment proves its address. The canonical
   * override is the invite-accept case, where the user is inside the flow
   * only because they redeemed a magic link delivered to that exact address
   * minutes earlier (the same proof `activate-user` trusts to write
   * `account.verifiedEmail`):
   *
   * ```ts
   * protected resolveEnrollPreConfirmed(ctx: AuthWfCtx, method: MfaTransport, address: string) {
   *   return !!ctx.accept && method === "email" && address === ctx.email;
   * }
   * ```
   *
   * Keep the equality check — the proof transfers ONLY to the address the
   * magic link was delivered to; vouching for a different address the user
   * typed would confirm an unproven inbox. Never asked for TOTP.
   */
  protected resolveEnrollPreConfirmed(
    _ctx: AuthWfCtx,
    _method: MfaTransport,
    _address: string,
  ): boolean | Promise<boolean> {
    return false;
  }

  /**
   * Pin the enrolment address for an sms/email transport — the policy seam
   * for deployments whose factor must be BOUND to an account record (e.g.
   * staff MFA locked to the work mailbox so portal access dies with it at
   * offboarding; a free-text form would let a self-service swap to a personal
   * inbox defeat that control entirely). Asked by `enroll-address` BEFORE its
   * form renders, with the staged transport (ctx-first, extra positional arg —
   * same convention as `resolveEnrollPreConfirmed`).
   *
   * Returning a string stages it as the enrolment address (normalized via
   * `normalizeMfaAddress`; the free-text form is SKIPPED — the same staging
   * seam consumer pre-seeding uses, so the user is never shown a form whose
   * only valid input is one known string). `'collect'` (the default) keeps
   * the free-text form. A pinned address composes with the rest of the trio
   * machinery untouched: `enroll-send` dispatches the pincode to it, and
   * `resolveEnrollPreConfirmed` may vouch it (a deployment pinning to a
   * verified-by-construction address gets the no-code path for free).
   *
   * ```ts
   * protected async resolveEnrollAddress(ctx: AuthWfCtx, method: MfaTransport) {
   *   if (method !== "email") return "collect";
   *   const user = await this.users.getUser(ctx.subject!);
   *   return (user as { email?: string }).email ?? "collect";
   * }
   * ```
   *
   * The returned address is trusted as-is (no `validateMfaAddress` pass) —
   * the deployment is authoritative for its own records. An empty/blank
   * return falls back to `'collect'`. For nuanced RULES on a user-typed
   * address (domain allowlists, record comparisons) override the ctx-first
   * {@link validateMfaAddress} instead.
   */
  protected resolveEnrollAddress(
    _ctx: AuthWfCtx,
    _method: MfaTransport,
    // oxlint-disable-next-line typescript/no-redundant-type-constituents -- 'collect' is the documented sentinel; keep it visible in the signature for overriders
  ): string | "collect" | Promise<string | "collect"> {
    return "collect";
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
   * Re-authentication policy for authorization-server logins (`ctx.authz`
   * runs). Consulted inline by `init-login` — BEFORE `credentials`, like that
   * step's own inline resolver calls — and only when the START input carried
   * an `authz` handle; a plain login never consults it. Default keeps today's
   * behavior: every authorize leg re-collects credentials. Override to
   * `{ mode: 'consent-only' }` so a live browser session skips straight to
   * the authorize-consent screen (browser binding + explicit approval still
   * apply); see {@link AuthzReauthPolicy} for `maxSessionAgeMs` freshness and
   * the `requireMfa` knob.
   */
  protected resolveAuthzReauthPolicy(
    _ctx: AuthWfCtx,
  ): AuthzReauthPolicy | Promise<AuthzReauthPolicy> {
    return { mode: "always-reauth" };
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
   * Resolve the authenticated change-password policy. Reached from
   * change-password.flow only. Default revokes the user's other sessions on a
   * successful change (OWASP Session Management) and applies NO rate limit —
   * current-password re-entry (enforced by `UserService.changePassword`) is the
   * primary protection, not throttling. Customers override to add a min-interval
   * (`rateLimit.minIntervalMs`) or to keep other sessions alive. The session the
   * change was made from is always ended (see `finish-change-password`).
   *
   * Whether the flow may be STARTED at all is governed by arbac on the trigger
   * route (deny the `change-password` action to forbid it for SSO-only orgs) —
   * there is deliberately no on/off flag here.
   */
  protected resolveChangePasswordPolicy(
    _ctx: AuthWfCtx,
  ): NonNullable<AuthWfCtx["changePassword"]> | Promise<NonNullable<AuthWfCtx["changePassword"]>> {
    return { revokeOtherSessions: true };
  }

  /**
   * Resolve the self-signup policy. Reached from signup.flow's `init-signup`.
   * Default `allowSignup: false` — invite-only is the safe default (mirrors
   * `resolveAlternateCredentials().signup`); a deployment that wants open
   * self-serve overrides this to `true` (and flips the login form's `signup`
   * alt-action on via `resolveAlternateCredentials`). `collectUsername: false`
   * means `username := email`; override + replace `opts.forms.signup` to
   * collect a distinct username. There is intentionally no rate-limit field
   * here yet — override the `signup-form` step (or front it with a captcha /
   * IP gate) for abuse control; the OTP resend cooldown already bounds repeat
   * sends per run.
   */
  protected resolveSignupPolicy(
    _ctx: AuthWfCtx,
  ): NonNullable<AuthWfCtx["signup"]> | Promise<NonNullable<AuthWfCtx["signup"]>> {
    return { allowSignup: false, collectUsername: false };
  }

  /**
   * Resolve the failed-login lockout posture (admin-only / self-service /
   * temporary — see `AuthWfLockoutMode`). Reached from login.flow (decides the
   * lock duration passed to `users.login` / `users.verifyMfa` on a threshold
   * trip) and recovery.flow (decides whether `unlock-account` runs after a
   * reset). Default `temporary` preserves the prior auto-expiry behavior.
   * Customers override per-tenant / per-user (e.g. force `admin-only` for
   * privileged accounts).
   */
  protected resolveLockout(
    _ctx: AuthWfCtx,
  ): NonNullable<AuthWfCtx["lockout"]> | Promise<NonNullable<AuthWfCtx["lockout"]>> {
    return { mode: "temporary" };
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
   * Transports the user may NOT change or remove via the manage-MFA flow.
   * Default: none — every factor is freely manageable. Reached from
   * `auth/add-mfa/flow` (`prepare-locked-mfa-transports`).
   *
   * Override to forbid changing a factor whose value IS a login handle — e.g.
   * the MFA `email` equals the `@aooth.user.email` handle, so letting the user
   * swap it here would desync identity. A typical override loads the user and
   * compares each enrolled channel value against the boot-resolved handle
   * fields (`getAoothUserHandleSpec(...).emailField` / `.phoneField`):
   *
   * ```ts
   * protected async resolveLockedMfaTransports(ctx: AuthWfCtx): Promise<MfaTransport[]> {
   *   const user = await this.users.getUser(ctx.subject!);
   *   const locked: MfaTransport[] = [];
   *   const email = user.mfa?.methods?.find((m) => m.name === "email" && m.confirmed);
   *   if (email && email.value === (user as { email?: string }).email) locked.push("email");
   *   return locked;
   * }
   * ```
   */
  protected resolveLockedMfaTransports(_ctx: AuthWfCtx): MfaTransport[] | Promise<MfaTransport[]> {
    return [];
  }

  /**
   * Whether the manage-MFA step-up must collect explicit consent BEFORE
   * dispatching its sms/email pincode (the `manage-stepup-confirm` pause:
   * "To continue, we will send a verification code to ma•••@x"). Default
   * `true` — nothing should email/text the user as a side effect of opening
   * a manage dialog: a user who opened it by mistake (or just to look)
   * closes it with zero codes consumed, no resend cooldown burnt. Override
   * to `false` to restore the zero-click dispatch (the code is already in
   * flight when the first form renders). Never asked for TOTP step-up
   * (nothing is dispatched) and not consulted by the login flow (its
   * challenge is mid-authentication, where zero-click is the norm).
   */
  protected resolveStepUpConfirmBeforeSend(_ctx: AuthWfCtx): boolean | Promise<boolean> {
    return true;
  }

  /**
   * What the user's authenticator app shows as the ACCOUNT half of
   * "issuer: account" for a TOTP enrolment (the issuer half is
   * `resolveMfaPolicy().issuer` / `opts.totpIssuer`). Cosmetic only — never
   * used for lookup — but it is how a user with several entries tells
   * accounts apart, and it is encoded into the `otpauth://` URI at
   * secret-provisioning time, so it lives in the authenticator FOREVER
   * (re-labeling requires re-enrolment). Default prefers a human-readable
   * identifier the flow already carries (`ctx.email` — invite/recovery/
   * signup) and otherwise loads the user's `username`; the stable-uuid
   * `ctx.subject` is the last resort. Override for a richer label (display
   * name, tenant-qualified email, …).
   */
  protected resolveTotpAccountLabel(ctx: AuthWfCtx): string | Promise<string> {
    if (ctx.email) return ctx.email;
    if (!ctx.subject) return "";
    const subject = ctx.subject;
    return this.users.getUser(subject).then((u) => u.username || subject);
  }

  /**
   * Resolve the channel-OTP disclosure copy rendered beneath the email/phone
   * input on `AskEmailForm` / `AskPhoneForm`. Reached from login.flow Phase 3.
   * Default returns a TCPA / PECR / CASL / GDPR-safe paragraph that is
   * GENERIC per channel (no target templated in — the user hasn't submitted
   * yet at ask-time): `OTP_DISCLOSURE_EMAIL` / `OTP_DISCLOSURE_PHONE` in the
   * request's language. The text is kept in the workflow state as shown and
   * recorded with the consent (`recordOtpChannelConsent`) — the one text the
   * state keeps translated, because the record must be what the user saw.
   */
  protected resolveOtpDisclosure(
    _ctx: AuthWfCtx,
    channel: "email" | "phone",
  ): string | Promise<string> {
    return this.msg(channel === "phone" ? "OTP_DISCLOSURE_PHONE" : "OTP_DISCLOSURE_EMAIL");
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
   * `AuthWorkflowOpts.autoLoginOnInvite` boolean (per §2 decision). Return
   * `confirmationMessage` to replace the default confirmation text
   * (`AOOTH_ACCOUNT_CREATED`, rendered in the finishing request's language) with your
   * own, shown as is.
   */
  protected resolveAccept(
    _ctx: AuthWfCtx,
  ): NonNullable<AuthWfCtx["accept"]> | Promise<NonNullable<AuthWfCtx["accept"]>> {
    return {
      alreadyAcceptedRedirectUrl: this.opts.loginUrl,
      loginUrl: this.opts.loginUrl,
      showConfirmation: true,
    };
  }

  /**
   * Copy (heading + intro) for the unified set-password screen, staged by
   * `create-password-form` BEFORE the pause. The default picks message codes
   * — `SET_PASSWORD_{EXPIRED,RESET,INVITE,INITIAL}_{HEADING,INTRO}` by the
   * resolved `ctx.password.changeReason` (`expired` / `reset`), then
   * invite-accept (`ctx.accept`), then the initial-password fallback — which
   * are rendered through `msg()` in each request's language.
   *
   * Override to re-brand any phase: `heading` / `intro` are your own text,
   * shown as is (they win over the codes); `headingCode` / `introCode` pick
   * other codes. Return a partial to change one field and leave the other at
   * whatever an earlier step staged (spread `super`'s result to keep the
   * default for it), or `{}` to keep both as-is.
   */
  protected resolveSetPasswordCopy(ctx: AuthWfCtx): SetPasswordCopy | Promise<SetPasswordCopy> {
    const reason = ctx.password?.changeReason;
    const phase =
      reason === "expired"
        ? "EXPIRED"
        : reason === "reset"
          ? "RESET"
          : ctx.accept
            ? "INVITE"
            : "INITIAL";
    return {
      headingCode: `SET_PASSWORD_${phase}_HEADING`,
      introCode: `SET_PASSWORD_${phase}_INTRO`,
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
   *
   * In recovery it also runs for an identifier with no account a code can go
   * to (unknown, inactive), on a copy of `ctx` whose `subject` is the
   * placeholder `00000000-0000-4000-8000-000000000000` — so every identifier
   * makes the same calls. Its result (or any error) is discarded there.
   */
  protected resolvePincodeTarget(
    ctx: AuthWfCtx,
  ):
    | { address: string; channel: "sms" | "email" }
    | Promise<{ address: string; channel: "sms" | "email" }> {
    if (ctx.mfa?.method && ctx.mfa.method !== "totp") {
      const channel = ctx.mfa.method;
      const summary = ctx.mfa.enrolledMethods?.find((mm) => mm.kind === channel);
      if (!ctx.subject) throw new HttpError(500, "Workflow state corrupted: missing subject");
      return this.users.getUser(ctx.subject).then((user) => {
        const methodName = summary?.methodName ?? channel;
        const method = user.mfa.methods.find((m) => m.name === methodName && m.confirmed);
        if (!method) throw new HttpError(500, "MFA method no longer present");
        return { address: method.value, channel };
      });
    }
    // Recovery branch — `resolveRecoveryDeliverySource` picks the delivery
    // model. M1 (`"typed"`, default): OTP to the typed identifier. M2
    // (`"registered"`): OTP to a channel already verified on the row (read off
    // the selected confirmed method, never from user input).
    const sourceResult = this.resolveRecoveryDeliverySource(ctx);
    if (sourceResult instanceof Promise) {
      return sourceResult.then((source) => this.recoveryPincodeTarget(ctx, source));
    }
    return this.recoveryPincodeTarget(ctx, sourceResult);
  }

  /**
   * Resolve the recovery OTP `{ address, channel }` for the chosen delivery
   * `source`.
   *
   * - `"typed"` (M1): the address is the typed recovery identifier (`ctx.email`)
   *   — identifier == destination, so no cross-account redirect — and the
   *   channel comes from `resolveRecoveryChannel` (identifier-shape inference).
   * - `"registered"` (M2): the address is read off a confirmed MFA method on the
   *   row (`selectRecoveryRegisteredMethod`) and the channel is that method's own
   *   kind. The user only typed an account identifier; the destination is a
   *   pre-verified channel they already control, so this also can't redirect
   *   cross-account. With no deliverable method this throws
   *   `RecoveryMethodUnavailableError`, which recovery treats as "no account"
   *   (nothing sent, every code refused) — never a distinguishable 500.
   */
  private recoveryPincodeTarget(
    ctx: AuthWfCtx,
    source: "typed" | "registered",
  ):
    | { address: string; channel: "sms" | "email" }
    | Promise<{ address: string; channel: "sms" | "email" }> {
    if (source === "registered") {
      this.requireSubject(ctx);
      return this.users.getUser(ctx.subject).then((user) => {
        const method = this.selectRecoveryRegisteredMethod(user);
        const channel = method && this.mfaKindOf(method.name);
        if (!method || (channel !== "sms" && channel !== "email")) {
          throw new RecoveryMethodUnavailableError();
        }
        return { address: method.value, channel };
      });
    }
    const address = ctx.email ?? "";
    const channel = this.resolveRecoveryChannel(ctx);
    return channel instanceof Promise
      ? channel.then((c) => ({ address, channel: c }))
      : { address, channel };
  }

  /** `resolveRecoveryDeliverySource`, awaited. */
  private async recoveryDeliverySource(ctx: AuthWfCtx): Promise<"typed" | "registered"> {
    const source = this.resolveRecoveryDeliverySource(ctx);
    return source instanceof Promise ? await source : source;
  }

  /**
   * Recovery OTP delivery channel. The address is ALWAYS the typed recovery
   * identifier (`ctx.email`) — symmetric with how email recovery already works:
   * the OTP goes to the value the user typed, which is the handle that resolved
   * the account (`findByHandle`), so identifier == destination and there is no
   * cross-account redirect. Default `"email"`. A deployment whose recovery form
   * accepts a phone overrides this to route SMS (e.g. infer from the identifier
   * shape) — see the demo's `DemoAuthWorkflow`. Recovery picks ONE channel per
   * run, so the single `resendAllowedAt` cooldown gate still suffices.
   */
  protected resolveRecoveryChannel(_ctx: AuthWfCtx): "email" | "sms" | Promise<"email" | "sms"> {
    return "email";
  }

  /**
   * Recovery OTP delivery model. Two options:
   *
   * - `"typed"` (default — M1): the OTP goes to the recovery identifier the user
   *   types. Identifier == destination, so there is no cross-account redirect;
   *   `resolveRecoveryChannel` picks email vs SMS from the identifier shape.
   * - `"registered"` (M2): the user enters only an account identifier (e.g. a
   *   username) and the OTP is delivered to a channel **already verified on the
   *   row** — `selectRecoveryRegisteredMethod` picks the confirmed MFA method;
   *   the destination is never taken from user input, so it cannot be redirected
   *   to an attacker-controlled address. A row with no deliverable confirmed
   *   method runs the ghost OTP pause, like an unknown identifier (see `request`).
   *
   * Consulted inline by `request` (no-method guard) and `recoveryPincodeTarget`
   * — no `prepare-*` step, mirroring `resolveRecoveryChannel`. Override to arm
   * M2 (per-tenant / per-variant); see the demo's `DemoAuthWorkflow`.
   */
  protected resolveRecoveryDeliverySource(
    _ctx: AuthWfCtx,
  ): "typed" | "registered" | Promise<"typed" | "registered"> {
    return "typed";
  }

  /**
   * Pick the confirmed MFA method a registered-channel recovery (M2) delivers
   * its OTP to. Prefers a confirmed SMS method, then a confirmed email method —
   * phone-recovery-first. TOTP carries no deliverable address and is skipped.
   * Returns `null` when the row has no deliverable confirmed method; the caller
   * turns that into the ghost OTP run (anti-enumeration). Stays sync (operates on
   * an already-loaded row); override to change the selection policy (e.g. honour
   * the user's `mfa.defaultMethod`).
   */
  protected selectRecoveryRegisteredMethod(user: UserCredentials): MfaMethod | null {
    const methods = user.mfa?.methods ?? [];
    const pick = (kind: "sms" | "email") =>
      methods.find((m) => m.confirmed && !!m.value && this.mfaKindOf(m.name) === kind);
    return pick("sms") ?? pick("email") ?? null;
  }

  /**
   * Decide which login-handle column a freshly-confirmed channel should be
   * promoted into — so a verified email/phone becomes a login + recovery
   * handle (`findByHandle`) automatically. Returns the target field name, or
   * `undefined` to NOT promote (the default).
   *
   * Default is OFF: the handle columns are declared via `@aooth.user.*`
   * annotations on the consumer's concrete model and resolved ONCE at boot
   * (`@aooth/arbac-moost`'s `getAoothUserHandleSpec`) — `AuthWorkflow` holds no
   * handle to that model and stays off the per-request reflection path. A
   * deployment turns promotion ON by overriding this to return the
   * boot-resolved `emailField` / `phoneField` for the channel — see the demo's
   * `DemoAuthWorkflow`. `channel` is the wire protocol (`'email'` | `'sms'`),
   * matching `resolveOtpDisclosure` / the MFA transport.
   */
  protected resolvePromoteHandleField(
    _ctx: AuthWfCtx,
    _channel: "email" | "sms",
  ): string | undefined | Promise<string | undefined> {
    return undefined;
  }

  /**
   * Decide whether a verified federated profile's email claim counts as inbox
   * proof for the CORRESPONDENCE address (`users.setVerifiedEmail`). Default
   * trusts the provider's `email_verified` claim — a provider trusted to
   * AUTHENTICATE the user is strictly more trusted than its email claim. The
   * capture is correspondence-only: it never promotes the address to a login
   * handle and never resolves accounts by it. Override to exclude providers
   * whose claim should not be taken at face value (e.g. an internal OIDC
   * issuer that stamps `email_verified` on unverified directory entries).
   */
  protected resolveFederatedEmailTrust(
    _ctx: AuthWfCtx,
    profile: FederatedProfileSnapshot,
  ): boolean | Promise<boolean> {
    return profile.emailVerified === true;
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
   * Asserts `ctx.subject` is populated. Throws `HttpError(500)` on miss;
   * narrows `subject` to `string` for the caller. Ported from
   * `AuthWorkflowBase` since the unified class no longer extends it.
   */
  protected requireSubject<T extends { subject?: string }>(
    ctx: T,
  ): asserts ctx is T & { subject: string } {
    if (!ctx.subject) throw new HttpError(500, "Workflow state corrupted: missing subject");
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
   * `WfTriggerProvider` strips the projection before persisting the state.
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
      if (sub) pub.consents = sub;
    }
    if (ctx.altActions) {
      const sub = pickDefined(ctx.altActions, [
        "forgotPassword",
        "signup",
        "magicLink",
        "ssoProviders",
      ] as const);
      if (sub) pub.altActions = sub;
    }
    if (ctx.mfa) {
      const sub = pickDefined(ctx.mfa, ["method", "methodCount", "enrolledMethods"] as const);
      if (sub) pub.mfa = sub;
    }
    if (ctx.pincode) {
      const sub = pickDefined(ctx.pincode, ["sentTo", "codeLength", "resendAllowedAt"] as const);
      if (sub) pub.pincode = sub;
    }
    if (ctx.trust) {
      const sub = pickDefined(ctx.trust, ["optIn"] as const);
      if (sub) pub.trust = sub;
    }
    if (ctx.password) {
      // Texts in the request's language — persisted state holds codes / English only.
      const { heading, headingCode, intro, introCode, policies } = ctx.password;
      const sub = pickDefined(
        {
          heading: heading ?? (headingCode ? this.msg(headingCode) : undefined),
          intro: intro ?? (introCode ? this.msg(introCode) : undefined),
          policies: policies?.map(translatePolicyTexts),
        },
        ["heading", "intro", "policies"] as const,
      );
      if (sub) pub.password = sub;
      // The confirm-password validator runs client-side too: ship its text
      // when the app overrides it (the form's built-in English otherwise).
      const mismatch = this.msg("PASSWORDS_DO_NOT_MATCH");
      if (mismatch !== AOOTH_MESSAGES.PASSWORDS_DO_NOT_MATCH) {
        pub.messages = { PASSWORDS_DO_NOT_MATCH: mismatch };
      }
    }
    if (ctx.admin) {
      const sub = pickDefined(ctx.admin, ["availableRoles"] as const);
      if (sub) pub.admin = sub;
    }
    if (ctx.channel) {
      const sub = pickDefined(ctx.channel, ["otpDisclosure"] as const);
      if (sub) pub.channel = sub;
    }
    if (ctx.mfaEnroll) {
      const sub = pickDefined(ctx.mfaEnroll, [
        "method",
        "mode",
        "availableTransports",
        "secret",
        "uri",
      ] as const);
      if (sub) pub.mfaEnroll = sub;
    }
    if (ctx.addMfa) {
      // Manage-menu inputs only — `candidates` (Add options), `locked`
      // (omit from Change/Remove), `removeBlocked` (omit Remove for the last
      // factor under a required policy). Internal manage fields (`action`,
      // `target`, `stepUp*`, `blocked`) stay server-only.
      const sub = pickDefined(ctx.addMfa, ["candidates", "locked", "removeBlocked"] as const);
      if (sub) pub.manage = sub;
    }
    if (ctx.defaults) {
      const sub = pickDefined(ctx.defaults, ["email"] as const);
      if (sub) pub.defaults = sub;
    }
    if (ctx.pendingLink) {
      // Only the masked/UX fields — `candidateUserId` / `subject` / proof `pin`
      // stay server-only (never whitelisted onto the wire).
      const sub = pickDefined(ctx.pendingLink, [
        "mode",
        "hint",
        "sentTo",
        "resendAllowedAt",
      ] as const);
      if (sub) pub.proveControl = sub;
    }
    if (ctx.newPasswordRequired !== undefined) {
      pub.newPasswordRequired = ctx.newPasswordRequired;
    }
    if (ctx.magicLink?.sentAt && ctx.magicLink.address && !ctx.magicLink.confirmed) {
      // The landing step's "Continue as …" — masked; the link went there.
      pub.magicLink = { account: this.maskAddress(ctx.magicLink.address, "email") };
    }
    if (ctx.authz) {
      // Display-only — `handle`/`approved`/`silent` stay server-only.
      // `clientName`/`scope`/`redirectHost` are staged by `authz-consent` from
      // the pending authorization; `signedInAs` by the silent-consent probe.
      const sub = pickDefined(ctx.authz, [
        "clientName",
        "scope",
        "redirectHost",
        "signedInAs",
      ] as const);
      if (sub) pub.authz = sub;
    }
    ctx.public = pub;
    markPublicProjection(pub);
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
        throw userAuthErrorToHttp(err);
      }
      throw err;
    }
  }

  /**
   * Mint a numeric one-time code for `binding` (who it is sent for) and return
   * the plain code for delivery. The state keeps only a random nonce and a
   * keyed digest of `nonce|binding|code` — fixed lengths, never the code — so
   * a read of the state does not reveal it, and {@link verifyPin} accepts it
   * only for the same binding. `length` and `ttlMs` default to
   * `mfa.pincodeLength` / `mfa.pincodeTtlMs`.
   */
  protected mintPin(
    ctx: PinState,
    binding: string,
    length = this.opts.mfa.pincodeLength,
    ttlMs = this.opts.mfa.pincodeTtlMs,
  ): string {
    // SECURITY: CSPRNG, never Math.random(). This pin gates account recovery,
    // the email/SMS MFA second factor, signup email verification, and the
    // federated link proof-of-control challenge — a predictable code is an
    // account-takeover primitive (CWE-338).
    const code = generateMfaCode(length);
    ctx.pinNonce = randomBytes(16).toString("base64url");
    ctx.pinDigest = this.pinDigest(ctx.pinNonce, binding, code);
    ctx.pinExpire = Date.now() + ttlMs;
    return code;
  }

  /** Drop the code in flight (its nonce stays spent or counted server-side). */
  protected clearPin(ctx: PinState): void {
    delete ctx.pinNonce;
    delete ctx.pinDigest;
    delete ctx.pinExpire;
  }

  /** Binding of a code sent to `address` in this run (and for its subject, once known). */
  private pinFor(ctx: AuthWfCtx, address: string): string {
    return `${ctx.subject ?? ""}|${address}`;
  }

  /**
   * Binding of a recovery code: the account and the address it went to (a
   * changed registered channel refuses the old channel's code). Without an
   * account, the placeholder — the digest has the same length either way.
   */
  private recoveryBinding(account: { subject: string; address: string } | null): string {
    return account ? `${account.subject}|${account.address}` : `${UNKNOWN_ACCOUNT_ID}|`;
  }

  /**
   * Server-side key of where a code goes — its resend cooldown and failed-code
   * budget. Never an account id the caller could not know: recovery and signup
   * key on the typed identifier, so known and unknown ones behave alike.
   */
  private codeTarget(...parts: Array<string | undefined>): string {
    return sha256url(parts.map((p) => (p ?? "").trim().toLowerCase()).join("|"));
  }

  /** {@link codeTarget} of a code sent to `address` to enrol or verify a channel. */
  private enrollTarget(ctx: AuthWfCtx, address: string | undefined): string {
    return this.codeTarget("enroll", ctx.subject, address);
  }

  /** {@link codeTarget} of a federated link's proof-of-control code. */
  private linkTarget(pending: NonNullable<AuthWfCtx["pendingLink"]>): string {
    return this.codeTarget("link", pending.candidateUserId);
  }

  /** {@link codeTarget} of the `pincode-send` / `pincode-check` pair. */
  private pincodeTarget(ctx: AuthWfCtx, address: string | undefined): string {
    if (ctx.mfa?.method) return this.codeTarget("mfa", ctx.subject, address);
    return this.codeTarget(ctx.signup ? "signup" : "recovery", ctx.email);
  }

  /**
   * Server-side gate of a code send to `target`, before minting: answers
   * `429 AOOTH_CODE_LIMIT_REACHED` once the target's failed-code budget is
   * spent (this client IP's, or all IPs' together), applies the per-account
   * `aooth.send-user` limit when `account` is given (sends after a first
   * factor), and claims this client IP's resend wait for the target
   * (`mfa.pincodeResendTimeoutMs`) and a slot of the target's send cap from
   * all IPs (`mfa.pincodeMaxSendsGlobal` per `pincodeFailureWindowMs`).
   * Returns whether the code may go out: `false` inside the wait or past the
   * cap — the caller mints a code all the same and sends nothing, for known
   * and unknown destinations alike.
   */
  protected async claimCodeSend(target: string, account?: string): Promise<boolean> {
    if (account !== undefined) {
      await enforceRateLimit(SEND_USER_RATE_LIMIT, `user:${account}`);
    }
    await this.assertCodeBudget(this.counterKeys(CODE_FAIL_PREFIX, target));
    const store = this.opts.lockoutShadowStore;
    const keys = this.counterKeys(CODE_SEND_PREFIX, target);
    // The wait is this client's own: another IP's requests never delay it.
    if ((await store.hit(keys.client, this.opts.mfa.pincodeResendTimeoutMs)) > 1) return false;
    // All clients together: at most `pincodeMaxSendsGlobal` per window.
    const sends = await store.hit(keys.global, this.opts.mfa.pincodeFailureWindowMs);
    return sends <= this.opts.mfa.pincodeMaxSendsGlobal;
  }

  /** Whether a send to `target` is cooling down (`false` when the store cannot peek). */
  private async codeSendCoolingDown(target: string): Promise<boolean> {
    const store = this.opts.lockoutShadowStore;
    if (!store.get) return false;
    const keys = this.counterKeys(CODE_SEND_PREFIX, target);
    return (
      (await store.get(keys.client)) > 0 ||
      (await store.get(keys.global)) >= this.opts.mfa.pincodeMaxSendsGlobal
    );
  }

  /**
   * Counters of a destination, per client IP and across all IPs:
   * - sends (`CODE_SEND_PREFIX`): this client's resend wait, and the sends
   *   from all IPs together in the window (the cap on mail-bombing and SMS
   *   pumping spread over many IPs);
   * - failed codes (`CODE_FAIL_PREFIX`): the budget one caller can spend (so
   *   an attacker cannot lock the owner out from elsewhere), and the backstop
   *   against distributed guessing.
   *
   * The client IP is hashed: fixed-size keys, no raw IPs in the store.
   */
  private counterKeys(prefix: string, target: string): { client: string; global: string } {
    return {
      client: `${prefix}${target}:${sha256url(requestClientIp())}`,
      global: `${prefix}${target}`,
    };
  }

  /** Answer `429 AOOTH_CODE_LIMIT_REACHED` once a destination's failed-code budget is spent. */
  private async assertCodeBudget(keys: { client: string; global: string }): Promise<void> {
    const store = this.opts.lockoutShadowStore;
    if (!store.get) return;
    const [client, global] = await Promise.all([store.get(keys.client), store.get(keys.global)]);
    if (
      client >= this.opts.mfa.pincodeMaxFailures ||
      global >= this.opts.mfa.pincodeMaxFailuresGlobal
    ) {
      throw aoothHttpError(429, "AOOTH_CODE_LIMIT_REACHED");
    }
  }

  /**
   * Verify a submitted code against the one minted for `binding`. Returns an
   * error map (keyed under `code` so it renders on the code input) or `null`
   * on success.
   *
   * Attempts are counted server-side in `lockoutShadowStore`, per minted code
   * (its nonce), before the comparison: a replayed older state token shares
   * the counter, so `pincodeMaxAttempts` holds across replays and parallel
   * submits. A code is single-use: once it verifies, its nonce is spent and
   * the same code through any copy of the state is refused. A binding that
   * differs from the one at mint (the account resolved differently since the
   * send) reads as a wrong code. Wrong codes also count against `target`'s
   * failed-code budgets across resends (`mfa.pincodeMaxFailures` per client
   * IP, `pincodeMaxFailuresGlobal` for all IPs, per
   * `pincodeFailureWindowMs`); once one is spent every check answers
   * `429 AOOTH_CODE_LIMIT_REACHED`.
   */
  protected async verifyPin(
    ctx: PinState,
    submitted: string | undefined,
    binding: string,
    target: string,
  ): Promise<{ code: string } | null> {
    const failureKeys = this.counterKeys(CODE_FAIL_PREFIX, target);
    await this.assertCodeBudget(failureKeys);
    const { pinNonce: nonce, pinDigest: digest, pinExpire: expire } = ctx;
    const now = Date.now();
    if (!nonce || !digest || !expire || now > expire) {
      return { code: this.msg("AOOTH_CODE_EXPIRED") };
    }
    const store = this.opts.lockoutShadowStore;
    // Counters live as long as the code (plus a grace for clock skew between instances).
    const ttl = expire - now + PIN_COUNTER_GRACE_MS;
    const attempts = await store.hit(`${PIN_ATTEMPT_PREFIX}${nonce}`, ttl);
    const max = this.opts.mfa.pincodeMaxAttempts;
    // The code stays in the state: every later submit for it, through this
    // state or any copy, lands here — only a resend mints a usable one.
    if (attempts > max) return { code: this.msg("AOOTH_TOO_MANY_CODE_ATTEMPTS") };
    if (!safeEqual(this.pinDigest(nonce, binding, submitted ?? ""), digest)) {
      // The destination's budgets across all its codes (resends included):
      // this client's, and all clients' together.
      const window = this.opts.mfa.pincodeFailureWindowMs;
      const [client, global] = await Promise.all([
        store.hit(failureKeys.client, window),
        store.hit(failureKeys.global, window),
      ]);
      if (
        client > this.opts.mfa.pincodeMaxFailures ||
        global > this.opts.mfa.pincodeMaxFailuresGlobal
      ) {
        throw aoothHttpError(429, "AOOTH_CODE_LIMIT_REACHED");
      }
      return {
        code: this.msg(attempts >= max ? "AOOTH_TOO_MANY_CODE_ATTEMPTS" : "AOOTH_INVALID_CODE"),
      };
    }
    const spent = await store.hit(`${PIN_SPENT_PREFIX}${nonce}`, ttl);
    this.clearPin(ctx);
    if (spent > 1) return { code: this.msg("AOOTH_CODE_EXPIRED") };
    return null;
  }

  /** Keyed digest of a code, bound to its nonce and to who it was sent for. */
  private pinDigest(nonce: string, binding: string, code: string): string {
    return createHmac("sha256", this.pincodeKey())
      .update(`${nonce}|${binding}|${code}`)
      .digest("base64url");
  }

  /**
   * Key of the code digests: the one `WfTriggerProvider` publishes for the
   * request (derived from its `pincodeSecret()`), else the key a default
   * provider publishes (`defaultPincodeKey`: derived from the default wf-state
   * secret), so a code minted on one path verifies on the other. Throws
   * `INVALID_CONFIG` outside a provider when the credential store has no
   * derivable secret. Override when the workflow runs outside a
   * `WfTriggerProvider` whose `wfStateSecret()` / `pincodeSecret()` is
   * overridden — return that provider's key; every instance must agree.
   */
  protected pincodeKey(): Buffer {
    const ctx = tryGetCurrent();
    if (ctx?.has(pincodeKeySlot)) return ctx.get(pincodeKeySlot);
    return (this.fallbackPincodeKey ??= defaultPincodeKey(this.auth));
  }

  private fallbackPincodeKey?: Buffer;

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
   * recipient. Reached only through {@link mintAndSendEnrollPincode}; kept
   * separate as the delivery-only override seam.
   */
  protected async sendEnrollPincode(ctx: AuthWfCtx, address: string, code: string): Promise<void> {
    const pincode = (ctx.pincode ??= {});
    const channel = ctx.mfaEnroll?.method === "email" ? "email" : "sms";
    pincode.sentTo = this.maskAddress(address, channel);
    await this.dispatch({
      kind: "enroll-pincode",
      channel,
      recipient: address,
      code,
      expiresInMs: this.opts.mfa.pincodeTtlMs,
    });
  }

  /**
   * The single enrol-dispatch implementation: mint a fresh pin, arm the
   * resend cooldown + the code-length form hint, and deliver the code.
   * Shared by `enrollSend` (initial dispatch) and the resend arm inside
   * `enrollConfirm`, so the arming policy cannot drift between first send
   * and resend.
   */
  private async mintAndSendEnrollPincode(
    ctx: AuthWfCtx,
    address: string,
    claimed?: boolean,
  ): Promise<void> {
    const deliver =
      claimed ?? (await this.claimCodeSend(this.enrollTarget(ctx, address), ctx.subject));
    const code = this.mintPin(ctx, this.pinFor(ctx, address));
    const pincode = (ctx.pincode ??= {});
    pincode.resendAllowedAt = Date.now() + this.opts.mfa.pincodeResendTimeoutMs;
    pincode.codeLength = this.opts.mfa.pincodeLength;
    if (deliver) await this.sendEnrollPincode(ctx, address, code);
  }

  /** Seconds a resend still has to wait — the state's hint, else a full cooldown. */
  private resendWaitSeconds(until: number | undefined): number {
    const now = Date.now();
    const ms = until && until > now ? until - now : this.opts.mfa.pincodeResendTimeoutMs;
    return Math.ceil(ms / 1000);
  }

  /**
   * Idempotent TOTP secret provisioning into wf-state ONLY (the QR renders
   * from `public.mfaEnroll.secret/uri`; the user record is written on confirm
   * — write-on-confirm). The single implementation behind BOTH provisioning
   * sites — `enroll-pick-method`'s auto-pick/picker tail and `enroll-totp-qr`
   * (covers the manage add/change path where the picker is skipped) — so the
   * account label baked into the `otpauth://` URI cannot drift between them.
   * The label comes from {@link resolveTotpAccountLabel} (human-readable
   * default); blank falls back to the subject uuid so the URI always carries
   * SOME account discriminator.
   */
  private provisionTotpSecret(ctx: AuthWfCtx): undefined | Promise<undefined> {
    const m = (ctx.mfaEnroll ??= {});
    if (m.method !== "totp" || m.secret) return undefined;
    const issuer = ctx.mfaPolicy?.issuer ?? this.opts.totpIssuer;
    const secret = generateTotpSecret();
    const apply = (label: string): undefined => {
      m.secret = secret;
      m.uri = generateTotpUri(secret, issuer, label.trim() || (ctx.subject ?? ""));
      return undefined;
    };
    const label = this.resolveTotpAccountLabel(ctx);
    if (label instanceof Promise) return label.then(apply);
    return apply(label);
  }

  /**
   * Drop the per-enrolment scratch fields (the `mfaEnroll` provisioning fields +
   * the pincode timers/`sentTo`) off ctx — the shared teardown used by the
   * opt-in `skip` / `useDifferentMethod` arms and {@link cancelManageEnrollment}.
   * Does NOT touch the user record: the enrol trio stages every candidate value
   * (sms/email address, totp secret) in wf-state and writes it to the store ONLY
   * on confirm (write-on-confirm), so a bailed enrolment never persisted a
   * partial row to undo.
   */
  protected clearEnrollScratch(ctx: AuthWfCtx): void {
    const m = ctx.mfaEnroll;
    if (m) {
      delete m.method;
      delete m.address;
      delete m.secret;
      delete m.uri;
      delete m.qrSeen;
      // A vouched address must never outlive the address it was vouched FOR —
      // a stale flag would let `enroll-confirm` write a later, unproven
      // address as confirmed without any pincode round-trip.
      delete m.preConfirmed;
    }
    this.clearPin(ctx);
    if (ctx.pincode) delete ctx.pincode.sentTo;
  }

  /**
   * Validate a user-typed MFA address for its transport. Server-side counterpart
   * to `EnrollAddressForm`'s client `@ui.form.validate` hint — the authoritative
   * check (a client can bypass the hint). Returns an error string for the form,
   * or `undefined` when valid. Email must look like an email; SMS is permissive
   * E.164-ish (normalized by {@link normalizeMfaAddress}). Override for stricter
   * (e.g. libphonenumber) validation.
   *
   * Ctx-first and async-capable, so record-based rules need no ctx-stash
   * workaround — an override can load the account and compare directly
   * (e.g. domain-allowlist the typed inbox, or require it to match a
   * record field). To PIN the address outright — never show the free-text
   * form at all — use {@link resolveEnrollAddress} instead; this hook is for
   * nuanced rules on what the user typed.
   *
   * ```ts
   * protected async validateMfaAddress(ctx: AuthWfCtx, method: MfaTransport, value: string) {
   *   if (method === "email" && !value.trim().toLowerCase().endsWith("@corp.example")) {
   *     return "Use your corporate email address";
   *   }
   *   return super.validateMfaAddress(ctx, method, value);
   * }
   * ```
   */
  protected validateMfaAddress(
    _ctx: AuthWfCtx,
    method: MfaTransport,
    value: string,
  ): string | undefined | Promise<string | undefined> {
    const v = (value ?? "").trim();
    if (!v) return this.msg("AOOTH_ADDRESS_REQUIRED");
    if (method === "email") {
      return /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(v)
        ? undefined
        : this.msg("AOOTH_INVALID_EMAIL_ADDRESS");
    }
    if (method === "sms") {
      const digits = v.replace(/[\s()+.-]/g, "");
      return /^[1-9]\d{6,14}$/.test(digits) ? undefined : this.msg("AOOTH_INVALID_PHONE_NUMBER");
    }
    return undefined;
  }

  /**
   * Light normalization of a validated MFA address before it is stored. Default:
   * trims, and strips spacing/punctuation from SMS numbers while KEEPING the
   * leading `+` (E.164 canonical form). Email is just trimmed. Override for full
   * E.164 canonicalization.
   */
  protected normalizeMfaAddress(method: MfaTransport, value: string): string {
    const v = value.trim();
    return method === "sms" ? v.replace(/[\s().-]/g, "") : v;
  }

  /**
   * Abort an in-progress manage-MFA enrolment cleanly: drop the wf-state scratch
   * and set `ctx.aborted` so the schema breaks to `finish-add-mfa` (cancelled
   * terminal). Nothing to undo in the user record — the manage flow stages every
   * candidate value (sms/email address, totp secret) in wf-state and writes it
   * to the store ONLY on confirm (write-on-confirm), so an in-progress
   * add/change/replace never touched the existing factors. This is exactly why
   * a cancel — or a crafted `useDifferentMethod` routed here — can never strand
   * or clobber a live factor.
   */
  protected cancelManageEnrollment(ctx: AuthWfCtx): void {
    this.clearEnrollScratch(ctx);
    ctx.aborted = true;
  }

  /**
   * Shared skip / cancel / useDifferentMethod triage for the enrol-trio steps
   * that pause after the candidate value is staged (`enroll-totp-qr` +
   * `enroll-confirm`): `cancel` / `useDifferentMethod` (manage) abort the flow,
   * `skip` (opt-in) and `useDifferentMethod` (opt-in) drop the wf-state scratch.
   * Returns `true` when the action terminated the step so the caller can
   * `return undefined`. (`enroll-pick-method` / `enroll-address` keep their own
   * preludes — their skip/useDifferentMethod arms diverge from this one.)
   *
   * SECURITY: in `'manage'` mode BOTH `cancel` and `useDifferentMethod` (the
   * manage forms HIDE the latter but it stays in their declared action
   * whitelist, so a crafted resume can still send it) route through the abort,
   * which only clears scratch. Because the enrol trio writes the user record
   * ONLY on confirm (write-on-confirm), an in-progress add/change has touched
   * nothing in the store — so a cancel/useDifferentMethod can never strand or
   * clobber the user's live factor, by construction.
   */
  protected handleEnrollExit(ctx: AuthWfCtx, action: string | undefined): boolean {
    const m = (ctx.mfaEnroll ??= {});
    const mode = m.mode ?? "optional";
    if (mode === "manage" && (action === "cancel" || action === "useDifferentMethod")) {
      this.cancelManageEnrollment(ctx);
      return true;
    }
    if (mode === "optional" && action === "skip") {
      this.clearEnrollScratch(ctx);
      m.done = true;
      (ctx.otp ??= {}).verified = true;
      return true;
    }
    if (action === "useDifferentMethod") {
      // opt-in/required only — nothing was persisted (write-on-confirm), so
      // dropping the wf-state scratch re-fires the picker cleanly.
      this.clearEnrollScratch(ctx);
      return true;
    }
    return false;
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
  initLogin(@WorkflowParam("context") ctx: AuthWfCtx): undefined | Promise<undefined> {
    // Federated leg: a START whose input carries the OAuth callback `state`
    // routes the schema to `sso-callback` and skips the `credentials` form.
    // CAPTURE the inputs onto ctx NOW — the engine clears the step input after
    // this step, so `sso-callback` (the next step) can't read them from the
    // input anymore. `state` presence is the marker; `sso-callback` fully
    // verifies it (a forged/garbage `state` just lands on the benign
    // OAuth-failure terminal, never bypasses anything). A normal form GET /
    // password resume carries no `state`.
    const state = getInputField("state");
    if (state) {
      const code = getInputField("code");
      const error = getInputField("error");
      ctx.idpInbound = {
        state,
        ...(code !== undefined && { code }),
        ...(error !== undefined && { error }),
      };
    }
    // Authorization-server leg: a START whose input carries the pending-auth
    // `authz` handle (the SPA forwards it from `/auth/authorize`'s `?authz=`
    // bounce) routes the login tail to `mint-authz-code` instead of `issue`. A
    // bogus handle just dead-ends at that terminal's benign "expired" finish.
    const authz = getInputField("authz");
    if (authz) ctx.authz = { handle: authz };
    // Consent-only authorize: on an authz START (never a federated re-entry —
    // `sso-callback` owns that subject), consult the re-auth policy and, under
    // `consent-only`, try to bind `ctx.subject` from a live browser session so
    // the `credentials` form is skipped and the run pauses straight on
    // `authz-consent`. Every probe failure (no/expired/garbage credential,
    // stale session, locked account) falls through silently to the credentials
    // path — the probe never throws. The default policy resolves sync to
    // `always-reauth`, keeping the non-authz/default path on the engine's sync
    // fast path.
    if (authz && !ctx.idpInbound) {
      const policyResult = this.resolveAuthzReauthPolicy(ctx);
      if (policyResult instanceof Promise) {
        return policyResult.then((policy) => this.maybeBindSilentAuthz(ctx, policy));
      }
      return this.maybeBindSilentAuthz(ctx, policyResult);
    }
    return undefined;
  }

  /**
   * `init-login`'s consent-only dispatch: run {@link probeSilentAuthz} and, on
   * a successful bind, move to the durable store strategy (the run will pause
   * on the consent form; mirrors `credentials` / `sso-callback` post-subject).
   * Split from the probe so unit tests can exercise the probe without a live
   * wf engine (`swapStrategy` requires one).
   */
  private maybeBindSilentAuthz(
    ctx: AuthWfCtx,
    policy: AuthzReauthPolicy,
  ): undefined | Promise<undefined> {
    if (policy.mode !== "consent-only") return undefined;
    return this.probeSilentAuthz(ctx, policy).then((bound) => {
      if (bound) swapStrategy("store");
      return undefined;
    });
  }

  /**
   * Silent-authorize session probe (consent-only re-auth policy). Reads the
   * auth context the guard interceptor stashed for THIS trigger request —
   * `getAuthContext()` is `null` for a missing, expired, or invalid credential
   * on a `@Public()` route, so the probe is non-throwing by construction (no
   * 401 can leak out of the flow). Requires the trigger route to actually see
   * the session credential (true for cookie-carried sessions on a same-origin
   * SPA) and the guard interceptor to be mounted on it.
   *
   * Binds on success: `ctx.subject`, `ctx.authz.silent` (+ `signedInAs` for
   * the consent copy), pre-sets `otp.verified` unless `policy.requireMfa`, and
   * seeds channel state from the user row (same `seedChannelState` as the
   * federated path) so the shared enrolment / notice gates behave exactly as
   * after a fresh login. Fail-closed ordering mirrors `sso-callback`: the
   * ACCOUNT-STATE GATE runs before the subject is bound, so a locked/inactive
   * account falls back to the credentials form (where `users.login` rejects
   * it) instead of silently reaching consent.
   */
  /**
   * Account-state gate shared by the three no-password entry paths — the
   * silent-authorize probe, `sso-callback`'s success gate, and `prove-control`'s
   * candidate gate. A blocked account must never bind a subject on any of them.
   */
  protected isAccountBlocked(user: UserCredentials): boolean {
    return user.account.locked || !user.account.active;
  }

  protected async probeSilentAuthz(ctx: AuthWfCtx, policy: AuthzReauthPolicy): Promise<boolean> {
    const session = useAuth().getAuthContext();
    if (!session) return false;
    // Freshness ceiling — GitHub sudo-style: the SESSION ORIGIN (family
    // `createdAt`, stable across refresh rotation) must be younger than the
    // ceiling. A legacy token without a `sessionId` has no provable origin →
    // treated as stale (fail toward credentials).
    if (policy.maxSessionAgeMs !== undefined) {
      if (!session.sessionId) return false;
      const sessions = await this.auth.listSessions(session.userId);
      const origin = sessions.find((s) => s.sessionId === session.sessionId);
      if (!origin || Date.now() - origin.createdAt > policy.maxSessionAgeMs) return false;
    }
    let user: UserCredentials;
    try {
      user = await this.users.getUser(session.userId);
    } catch {
      // Session points at a deleted/unknown row — fall through to credentials.
      return false;
    }
    if (this.isAccountBlocked(user)) return false;
    ctx.subject = session.userId;
    const authz = ctx.authz!;
    authz.silent = true;
    authz.signedInAs = user.username;
    // The live session already proved its factors at login time; skip the MFA
    // loop unless the deployment demands a fresh challenge for authorize legs.
    if (!policy.requireMfa) (ctx.otp ??= {}).verified = true;
    await this.seedChannelState(ctx, user);
    return true;
  }

  @Step("init-invite-admin")
  @ArbacResource("auth.invite")
  @ArbacAction("start")
  async initInviteAdmin(@WorkflowParam("context") ctx: AuthWfCtx): Promise<undefined> {
    ctx.autoLogin = this.opts.autoLoginOnInvite;
    const startFormData = useWfState().input<{ formData?: Record<string, unknown> }>()?.formData;
    const app = await this.resolveInviteContext(ctx, startFormData);
    if (app !== undefined) (ctx.admin ??= {}).app = app;
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
    if (this.opts.inviteUsername === "choose") (ctx.accept ??= {}).chooseUsername = true;
    return undefined;
  }

  @Step("init-recovery")
  @Public()
  initRecovery(@WorkflowParam("context") ctx: AuthWfCtx): void {
    ctx.autoLogin = this.opts.autoLoginOnRecover;
    return undefined;
  }

  /**
   * Bind the change-password flow to the CURRENT authenticated user. Identity
   * comes from the session (`useAuth().getUserId()`) — NEVER from form input —
   * so the flow is structurally "change MY password" with no target-user
   * parameter. NOT `@Public()`: the trigger, the `@Workflow` body, and every
   * step in this flow are gated by `@ArbacResource("auth.change-password")` +
   * `@ArbacAction("self")`, so a customer enables the whole feature with a
   * single `allow("auth.change-password", "*")` grant and forbids it (SSO-only
   * orgs) by omitting it. `getUserId()` throws 401 if unauthenticated — defense
   * in depth on top of the guarded trigger route.
   */
  @Step("init-change-password")
  @ArbacResource("auth.change-password")
  @ArbacAction("self")
  initChangePassword(@WorkflowParam("context") ctx: AuthWfCtx): void {
    ctx.subject = useAuth().getUserId();
    const password = (ctx.password ??= {});
    password.headingCode = "CHANGE_PASSWORD_HEADING";
    password.introCode = "CHANGE_PASSWORD_INTRO";
    return undefined;
  }

  /**
   * Bind the standalone "Manage two-factor authentication" flow (add / change /
   * remove) to the CURRENT authenticated user. Identity comes from the session
   * (`useAuth().getUserId()`) — never form input — so it is structurally "manage
   * MY factors". Mirrors `init-change-password`'s arbac gate (`auth.add-mfa` /
   * `self`): a customer enables the feature with a single
   * `allow("auth.add-mfa", "*")` grant and forbids it by omitting it.
   * `getUserId()` throws 401 if unauthenticated — defence in depth on top of the
   * guarded trigger route.
   *
   * Sets `ctx.mfaPolicy.availableTransports` to the FULL policy set (so the
   * step-up's `load-enrolled-mfa-methods` can see the confirmed factors to
   * challenge) and tracks the un-enrolled `candidates` separately on
   * `ctx.addMfa` for the menu's Add options. `stepUpRequired` is set when the
   * user has ANY confirmed factor — gating both the step-up and the management
   * menu; a zero-MFA user skips both and falls through to the first-time enrol
   * picker (the opt-in path). `stepUpMode` picks the step-up method: `'mfa'`
   * when a confirmed factor is still challengeable, else `'password'` (a
   * password re-auth fallback for an orphaned factor). Puts the enrol forms in
   * `'manage'` mode (Cancel, not "Skip for now") and keeps the existing default.
   */
  @Step("init-add-mfa")
  @ArbacResource("auth.add-mfa")
  @ArbacAction("self")
  async initAddMfa(@WorkflowParam("context") ctx: AuthWfCtx): Promise<undefined> {
    const username = useAuth().getUserId();
    ctx.subject = username;
    const policyResult = this.resolveMfaPolicy(ctx);
    const policy = policyResult instanceof Promise ? await policyResult : policyResult;
    const all = policy.availableTransports;
    const user = await this.users.getUser(username);
    const enrolledKinds = new Set(
      this.users
        .getAvailableMfaMethods(user.mfa)
        .map((m) => this.mfaKindOf(m.name))
        .filter((k): k is MfaTransport => k !== null),
    );
    // Un-enrolled transports = the "Add" options on the manage menu.
    const candidates = all.filter((t) => !enrolledKinds.has(t));
    // Step-up whenever the user has ANY confirmed factor — re-verify identity
    // before letting them manage factors. HOW depends on what's challengeable:
    // a factor whose kind the policy still allows can be MFA-challenged; if the
    // ONLY confirmed factor(s) are of kinds the policy dropped (so nothing is
    // challengeable), the `mfaStepUpLoop` would never flip `otp.verified`, so we
    // fall back to a password re-auth. This closes the gap where a post-enrolment
    // policy tightening would otherwise let an orphaned-factor user manage with
    // NO re-verification.
    const challengeable = [...enrolledKinds].filter((k) => all.includes(k));
    const hasFactors = enrolledKinds.size > 0;
    // FULL transport set on the policy so the step-up's `load-enrolled-mfa-methods`
    // (which filters by `availableTransports`) sees the confirmed factors. The
    // un-enrolled `candidates` for the Add menu are tracked separately on `addMfa`.
    ctx.mfaPolicy = { mode: policy.mode, availableTransports: all, issuer: policy.issuer };
    ctx.addMfa = {
      candidates,
      stepUpRequired: hasFactors,
      stepUpMode: challengeable.length > 0 ? "mfa" : "password",
    };
    // 'manage' mode drives the enrol forms' skip/cancel visibility (no "Skip for
    // now" — the user opened this on purpose — and a "Cancel" action instead).
    const m = (ctx.mfaEnroll ??= {});
    m.mode = "manage";
    // Preserve the user's existing default — adding/replacing a factor must not
    // silently change which method is challenged first at next login. (A zero-MFA
    // user has no default to keep, so the first added one becomes default — same
    // as login-time forced enrolment.)
    if (user.mfa?.defaultMethod) m.keepExistingDefault = true;
    return undefined;
  }

  // ── Authentication entry (2) ──

  @Step("credentials")
  @Public()
  async credentials(@WorkflowParam("context") ctx: AuthWfCtx): Promise<unknown> {
    // Runs BEFORE the `!ctx.subject` gate / prepare-* steps, so we inline
    // the alt-cred + guards resolvers we need (idempotent vs. later prepare-*).
    const altResult = this.resolveAlternateCredentials(ctx);
    const alt = altResult instanceof Promise ? await altResult : altResult;
    ctx.alternateCredentials = alt;
    const guardsResult = this.resolveGuards(ctx);
    ctx.guards = guardsResult instanceof Promise ? await guardsResult : guardsResult;
    // Lockout posture is needed at lock-SET time (a failed login below), which
    // runs before prepare-lockout — so inline-resolve it here (idempotent vs.
    // the later prepare-lockout step, mirroring the guards pattern above).
    const lockoutResult = this.resolveLockout(ctx);
    ctx.lockout = lockoutResult instanceof Promise ? await lockoutResult : lockoutResult;
    // Mirror alt-credentials config into ctx so the form can hide each alt-action
    // button when its feature is disabled (`@ui.form.fn.hidden`).
    const altActions = (ctx.altActions ??= {});
    altActions.forgotPassword = alt.forgotPassword;
    altActions.signup = alt.signup;
    altActions.magicLink = alt.magicLink;
    if (alt.ssoProviders.length > 0) altActions.ssoProviders = alt.ssoProviders;
    const wf = this.useAtscriptWfPublic(ctx, this.opts.forms.loginCredentials);

    // Alt-action routing — handled BEFORE the form-input pause so the user
    // can hit "Forgot password?" without filling in the form at all. SSO
    // provider ids (from `alt.ssoProviders[].id`) must be declared as phantom
    // `ui.action` fields on the consumer's custom `LoginCredentialsForm`.
    const action = wf.resolveAction();
    if (action === "magicLink" && alt.magicLink) {
      // Hand over to the magic-link steps (identifier form → link → MFA).
      ctx.magicLink = { purpose: "login" };
      return undefined;
    }
    if (action) {
      const typedUsername = getInputField("username");
      const handled = await this.handleCredentialsAlt(
        action,
        typedUsername,
        alt,
        ctx.authz?.handle,
      );
      if (handled === ALT_HANDLED) return undefined;
    }

    const input = wf.resolveInput() as { username: string; password: string };

    try {
      const result = await this.users.login(
        input.username,
        input.password,
        this.lockoutOverride(ctx),
      );
      // `users.login()` already stamped `account.lastLogin` on this valid verify,
      // so latch the `record-login` funnel to a no-op stamp (it still fires
      // `afterLogin`) — no redundant second write. Federated / auto-login paths
      // never call `login()`, so they leave this unset and `record-login` does
      // the stamp. Stamping here (before `prepare-semantic-flags`) also keeps
      // the password path's `isFirstLogin` derivation byte-identical to before.
      ctx.loginRecorded = true;
      // First validated input passed → move off the cheap encapsulated start to
      // the durable store strategy, so the MFA / enrollment / password-change
      // pauses survive restarts. Pre-validation stays encapsulated (no server row),
      // so an idle login form can't 410-GONE. Sticky for the rest of the run.
      swapStrategy("store");
      await this.bindSignedInUser(ctx, result.user);
    } catch (err) {
      if (err instanceof UserAuthError) {
        const locked = await this.failedLoginReadsLocked(ctx, err, input.username);
        throw this.throwPublic(ctx, wf, {
          formMessage: this.msg(locked ? "AOOTH_ACCOUNT_LOCKED" : "INVALID_CREDENTIALS"),
        });
      }
      throw err;
    }
    return undefined;
  }

  /**
   * Bind the login run to the account that passed its first factor — shared
   * by the password and magic-link sign-ins, so both leave the run alike:
   * - `ctx.subject` and the password stamp;
   * - the inline password guards (`ctx.guards`): top-level
   *   `isPasswordInitial` / `isPasswordExpired` (read by
   *   `prepare-semantic-flags` later as a fallback) and the change reason;
   * - the account's confirmed channels, so `ensureEmail` / `ensurePhone` skip
   *   what is already confirmed and security notices have a recipient.
   */
  private async bindSignedInUser(ctx: AuthWfCtx, user: UserCredentials): Promise<void> {
    ctx.subject = user.id;
    ctx.passwordStamp = user.password.lastChanged ?? 0;
    if (ctx.guards?.passwordInitial && user.password.isInitial) ctx.isPasswordInitial = true;
    if (ctx.guards?.passwordExpiry && this.users.isPasswordExpired(user)) {
      ctx.isPasswordExpired = true;
    }
    if (ctx.isPasswordInitial) (ctx.password ??= {}).changeReason = "initial";
    else if (ctx.isPasswordExpired) (ctx.password ??= {}).changeReason = "expired";
    const email = user.mfa.methods.find((m) => m.name === "email" && m.confirmed);
    if (email) {
      (ctx.notice ??= {}).email = email.value;
      (ctx.channel ??= {}).emailConfirmed = true;
    }
    const phone = user.mfa.methods.find((m) => m.name === "sms" && m.confirmed);
    if (phone) {
      const channel = (ctx.channel ??= {});
      channel.phone = phone.value;
      channel.phoneConfirmed = true;
    }
    // Correspondence fallback — users who proved an inbox WITHOUT enrolling
    // email MFA (invite magic-link, signup / recovery OTP, trusted federated
    // claim) still get security notices.
    if (!ctx.notice?.email) await this.seedCorrespondenceEmail(ctx, user);
  }

  /**
   * Whether a failed password sign-in answers "Account locked" — see
   * `AuthWorkflowOpts.lockoutDisclosure`. Under `'uniform'` an unknown or
   * inactive handle keeps a shadow failure counter in `lockoutShadowStore`
   * that mirrors a real account exactly: every failure counts (the counter is
   * not reset when it trips — like `failedLoginAttempts`), a lock starts when
   * `failures >= threshold` and none is active, the tripping attempt still
   * reads "Invalid credentials", and a permanent lock stays on while probed.
   * Keys are a hash of the normalised handle (bounded size); the counter
   * slides for 30 days of inactivity.
   */
  private async failedLoginReadsLocked(
    ctx: AuthWfCtx,
    err: UserAuthError,
    handle: string,
  ): Promise<boolean> {
    const mode = this.opts.lockoutDisclosure;
    if (mode === "generic") return false;
    if (err.type === "LOCKED") return true;
    if (mode !== "uniform" || (err.type !== "NOT_FOUND" && err.type !== "INACTIVE")) return false;
    const { threshold, duration } = {
      ...this.users.getConfig().lockout,
      ...this.lockoutOverride(ctx),
    };
    if (threshold <= 0) return false;
    const store = this.opts.lockoutShadowStore;
    const id = sha256url(handle.trim().toLowerCase());
    const lockKey = `${SHADOW_LOCK_PREFIX}${id}`;
    if (store.get && (await store.get(lockKey)) > 0) {
      // A permanent lock never lapses while someone keeps trying.
      if (duration <= 0) await store.expire?.(lockKey, SHADOW_TTL_MS);
      return true;
    }
    const failKey = `shadow-fail:${id}`;
    const failures = await store.hit(failKey, SHADOW_TTL_MS);
    // A fresh counter already got the full TTL from `hit`; later ones slide.
    if (failures > 1) await store.expire?.(failKey, SHADOW_TTL_MS);
    if (!store.get) return failures > threshold; // no lock key without reads: count only
    if (failures >= threshold) {
      await store.hit(lockKey, duration > 0 ? duration : SHADOW_TTL_MS);
    }
    return false;
  }

  /**
   * Route a credentials alt-action click (forgotPassword / signup / magicLink
   * / sso-<id>) to a `finishWf` redirect envelope. Returns `ALT_HANDLED` when
   * the caller should short-circuit without running form validation.
   */
  private async handleCredentialsAlt(
    action: string,
    typedUsername: string | undefined,
    alt: AuthWfAltCredsPolicy,
    authzHandle?: string,
  ): Promise<AltHandled | undefined> {
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
    if (action === "sso") {
      // The bundled `AsSsoProviders` sets the chosen provider id into the
      // `ssoProvider` field, then invokes this single data-carrying action.
      const providerId = getInputField("ssoProvider");
      const sso = providerId ? alt.ssoProviders.find((p) => p.id === providerId) : undefined;
      // A missing / unoffered id is a malformed request — the bundled component
      // only ever submits an offered provider.
      if (!sso) throw this.httpError(400, "UNKNOWN_SSO_PROVIDER");
      await this.beginSso(sso.id, authzHandle);
      return ALT_HANDLED;
    }
    return undefined;
  }

  @Step("request")
  @Public()
  async request(@WorkflowParam("context") ctx: AuthWfCtx): Promise<unknown> {
    // Runs BEFORE the `!ctx.subject` gate / prepare-* steps; inline the
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

    const modeResult = this.resolveRecoveryDeliveryMode(ctx);
    // 'choice': the picker pauses next, holding only what the user typed.
    await this.applyRecoveryMode(
      ctx,
      modeResult instanceof Promise ? await modeResult : modeResult,
    );
    return undefined;
  }

  /**
   * Start recovery's delivery `mode` — the same way for known and unknown
   * identifiers:
   * - `'magicLink'`: the link for the typed identifier, resolved now but held
   *   only in the link's server-side pause (the requester never gets a token
   *   for it, and an earlier picker's state holds nothing about the account);
   * - `'otp'`: the durable store strategy. Nothing about the account goes into
   *   the state before the code is verified: `pincode-send` /
   *   `pincode-check` resolve it from the typed identifier each time.
   */
  private async applyRecoveryMode(
    ctx: AuthWfCtx,
    mode: NonNullable<AuthWfCtx["recoveryDelivery"]>,
  ): Promise<void> {
    ctx.recoveryDelivery = mode;
    if (mode === "magicLink") ctx.magicLink = await this.recoveryMagicLink(ctx);
    else if (mode === "otp") swapStrategy("store");
  }

  /** A recovery magic link for the typed identifier (`subject` unset when it matches no account). */
  private async recoveryMagicLink(ctx: AuthWfCtx): Promise<NonNullable<AuthWfCtx["magicLink"]>> {
    const email = ctx.email ?? "";
    const subject = await this.lookupRecoverySubject(email);
    return {
      purpose: "recovery",
      identifier: email.trim().toLowerCase(),
      ...(subject && { subject }),
    };
  }

  /** `emailToUserId`, with an unknown identifier as `undefined`. */
  private async lookupRecoverySubject(identifier: string): Promise<string | undefined> {
    try {
      return (await this.emailToUserId(identifier)) ?? undefined;
    } catch (err) {
      if (!(err instanceof UserAuthError) || err.type !== "NOT_FOUND") throw err;
      return undefined;
    }
  }

  /**
   * The account a recovery code for the typed identifier goes to, and where —
   * or `null` when no code can go anywhere: an unknown identifier, an inactive
   * (pending / deactivated) account, or under M2 an account without a
   * deliverable confirmed channel. A locked account may recover (self-service
   * unlock). Resolved from `ctx.email` on every send and at verification —
   * never kept in the state — and with the same reads for every identifier
   * (an unknown one reads a placeholder row).
   */
  private async recoveryAccount(
    ctx: AuthWfCtx,
  ): Promise<{ subject: string; address: string; channel: "sms" | "email" } | null> {
    const subject = await this.lookupRecoverySubject(ctx.email ?? "");
    let user: UserCredentials | undefined;
    try {
      user = await this.users.getUser(subject ?? UNKNOWN_ACCOUNT_ID);
    } catch (err) {
      if (!(err instanceof UserAuthError) || err.type !== "NOT_FOUND") throw err;
    }
    const known = Boolean(subject && user?.account.active);
    try {
      // `resolvePincodeTarget` (M1: the typed address; M2: a confirmed channel
      // of the row) — on a copy, so `ctx.subject` stays unset until verified.
      // Without an account it runs too, on the placeholder row: the same
      // resolvers and reads (M2 reads the row again) as for a known account.
      const target = await this.resolvePincodeTarget({
        ...ctx,
        subject: known ? subject : UNKNOWN_ACCOUNT_ID,
      });
      return known ? { subject: subject as string, ...target } : null;
    } catch (err) {
      // Without an account, any failure of the resolvers on the placeholder
      // is "no account" — an error only unknown identifiers raise would be an
      // oracle.
      if (!known || err instanceof RecoveryMethodUnavailableError) return null;
      throw err;
    }
  }

  /**
   * Resolves the recovery-step `email` input to the user's stable `id` (the
   * token subject). Default: resolves via `findByHandle` (username exact, then
   * email exact). Override for custom handle→id mapping; return `null` when no
   * user matches.
   */
  protected async emailToUserId(email: string): Promise<string | null> {
    const user = await this.users.findByHandle(email);
    return user?.id ?? null;
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
    if (!ctx.subject) {
      ctx.isFirstLogin = false;
      return undefined;
    }
    return this.users.getUserSnapshot(ctx.subject, current()).then(
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
    if (!ctx.subject) return undefined;
    const result = this.consentStore.getPendingConsents(ctx.subject);
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

  @Step("prepare-lockout")
  @Public()
  prepareLockout(@WorkflowParam("context") ctx: AuthWfCtx): undefined | Promise<undefined> {
    const result = this.resolveLockout(ctx);
    if (result instanceof Promise) {
      return result.then((resolved) => {
        ctx.lockout = resolved;
        return undefined;
      });
    }
    ctx.lockout = result;
    return undefined;
  }

  /**
   * Per-call lockout override for `users.login` / `users.verifyMfa`, derived
   * from the resolved mode. A permanent mode (`admin-only` / `self-service`)
   * forces `duration: 0` so the threshold trip locks permanently;
   * `temporary` (or an unresolved policy) returns `undefined` so UserService's
   * own configured duration applies. Threshold stays UserService config.
   */
  protected lockoutOverride(ctx: AuthWfCtx): { duration: number } | undefined {
    return ctx.lockout && ctx.lockout.mode !== "temporary" ? { duration: 0 } : undefined;
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

  @Step("prepare-change-password")
  @ArbacResource("auth.change-password")
  @ArbacAction("self")
  prepareChangePassword(@WorkflowParam("context") ctx: AuthWfCtx): undefined | Promise<undefined> {
    const result = this.resolveChangePasswordPolicy(ctx);
    if (result instanceof Promise) {
      return result.then((resolved) => {
        ctx.changePassword = resolved;
        return undefined;
      });
    }
    ctx.changePassword = result;
    return undefined;
  }

  /**
   * Merges login's `prepare-mfa-setup` + invite's `prepare-mfa` + `setup-mfa`.
   * Writes `ctx.mfaPolicy`; with `ctx.subject` bound, pre-picks
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
      if (!ctx.subject) {
        autoPickEnroll();
        return undefined;
      }
      return this.users.getUserSnapshot(ctx.subject, current()).then(
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
    if (roles) {
      (ctx.admin ??= {}).availableRoles = roles;
    } else if (!warnedOnce.openInviteWhitelist && this.inviteWhitelistIsOpen()) {
      warnedOnce.openInviteWhitelist = true;
      useLogger("aooth:auth", current()).warn(
        "Invite role whitelist is OFF — the admin invite form can assign ANY role, " +
          "including privileged ones. Set `invitableRoles` (intersected with the " +
          "inviter's ARBAC grants), override `getAvailableRoles()`, or set " +
          "`allowAnyInviteRole: true` to acknowledge the open default.",
      );
    }
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
   * Roles the server will honor from the admin invite form. SECURITY boundary:
   * when `resolveAdminForm` returned `collectRoles: false` the role picker is
   * hidden, so any submitted `roles[]` is a crafted or buggy payload and is
   * IGNORED — roles in that mode come from `inferAdminRoles` (server-side),
   * never client input. This keeps role authorization independent of whether
   * `prepare-available-roles` ran: that step populates the `availableRoles`
   * whitelist the `admin-form` guard enforces against, but it is schema-gated on
   * `collectRoles`, so WITHOUT this check a `collectRoles:false` deployment
   * would let a crafted POST assign ANY role with no whitelist / per-role ARBAC
   * `assign:<role>` check.
   */
  protected effectiveInviteRoles(ctx: AuthWfCtx, submitted: string[]): string[] {
    if (ctx.adminForm?.collectRoles === false) return [];
    return parseInviteRoles(submitted);
  }

  /**
   * Admin-side invite form. Pauses for `InviteForm`; binds `ctx.email` +
   * `ctx.admin.roles`. Server-side enforces the `availableRoles` whitelist
   * (populated by `prepare-available-roles`) and, via {@link effectiveInviteRoles},
   * ignores any submitted roles when `resolveAdminForm` set `collectRoles:false`.
   * Calls `duplicateInviteCheck` to decide whether to reject duplicates.
   */
  @Step("admin-form")
  @ArbacResource("auth.invite")
  @ArbacAction("start")
  async adminForm(@WorkflowParam("context") ctx: AuthWfCtx): Promise<unknown> {
    const wf = this.useAtscriptWfPublic(ctx, this.opts.forms.invite);
    const { email, roles, ...extra } = wf.resolveInput() as {
      email: string;
      roles: string[];
    } & Record<string, unknown>;
    const parsed = this.effectiveInviteRoles(ctx, roles);
    if (Array.isArray(ctx.admin?.availableRoles)) {
      const allowed = new Set(ctx.admin.availableRoles);
      const bad = parsed.find((r) => !allowed.has(r));
      if (bad !== undefined) {
        throw this.throwPublic(ctx, wf, { errors: { roles: this.msg("AOOTH_INVALID_ROLE") } });
      }
    }
    if (Object.keys(extra).length > 0) (ctx.admin ??= {}).form = extra;
    const existing = await this.users.findByHandle(email);
    const invitedBy = useAuth().getAuthContext()?.userId;
    const pendingIssuer = existing?.account?.pendingInvitation
      ? (existing.account.invitedBy ?? undefined)
      : undefined;
    if (invitedBy) (ctx.admin ??= {}).invitedBy = invitedBy;
    const action = await this.duplicateInviteCheck({
      email,
      existingUser: existing,
      ...this.inviteHookInput(ctx),
      ...(existing?.account?.pendingInvitation && {
        pending: pendingIssuer === undefined ? {} : { invitedBy: pendingIssuer },
      }),
    });
    if (action === "reject") {
      if (existing?.account?.pendingInvitation) {
        throw this.throwPublic(ctx, wf, { errors: { email: this.msg("INVITE_ALREADY_PENDING") } });
      }
      if (existing)
        throw this.throwPublic(ctx, wf, {
          errors: { email: this.msg("AOOTH_USER_ALREADY_EXISTS") },
        });
      throw this.throwPublic(ctx, wf, { errors: { email: this.msg("DUPLICATE_INVITE_REJECTED") } });
    }
    if (action === "reuse") {
      // Decision stamp only — `create-user` re-validates against a fresh read
      // (pending-invitation guard + vanished-row fall-through), so a stale or
      // wrong verdict can't silently re-pend an accepted account.
      (ctx.admin ??= {}).reuseExisting = true;
      if (pendingIssuer !== undefined && invitedBy !== undefined && pendingIssuer !== invitedBy) {
        this.warnCrossIssuerReuse();
      }
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
    const inferred = await this.inferAdminRoles({ email: ctx.email, ...this.inviteHookInput(ctx) });
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
    // Stamped by `admin-form`; a resumed run whose admin-form predates it
    // falls back to the session.
    const invitedBy = ctx.admin?.invitedBy ?? useAuth().getAuthContext()?.userId;
    if (invitedBy) (ctx.admin ??= {}).invitedBy = invitedBy;
    const preparedInput = {
      email: ctx.email,
      roles: ctx.admin?.roles ?? [],
      ...this.inviteHookInput(ctx),
    };
    // A falsy result means "no extras" — never a reason to skip creating the user.
    const extras = (await this.prepareUser(preparedInput)) ?? {};
    (ctx.admin ??= {}).userExtras = extras;
    return undefined;
  }

  /**
   * Invariant of the invite issue phase: once the admin form is accepted, the
   * pending user must exist before the link is sent. An issue phase that ends
   * without one (a broken override, a store that silently dropped the row) is
   * a server error — never a bare `{ finished: true }`.
   */
  @Step("assert-invite-created")
  @ArbacResource("auth.invite")
  @ArbacAction("start")
  assertInviteCreated(@WorkflowParam("context") ctx: AuthWfCtx): undefined {
    if (ctx.email && !ctx.subject) {
      throw new HttpError(500, "Invite issue failed: the invited user was not created");
    }
    return undefined;
  }

  /**
   * Create the user row from `ctx.admin.userExtras` (plus the admin-supplied
   * `ctx.admin.roles`), then stamp `pendingInvitation = true` via a follow-up
   * deep-merge update so `createUser`-applied account defaults survive.
   *
   * Re-invite (`ctx.admin.reuseExisting`, stamped by `admin-form` on a
   * `'reuse'` verdict): REFRESH the existing row instead of creating — apply
   * the freshly-picked roles + `prepareUser` extras, re-assert
   * `pendingInvitation`, and leave password/MFA state untouched (a pending
   * record never had usable credentials). `send-email` downstream then mints
   * a fresh durable handle, i.e. a new full-TTL magic link. Guarded by a
   * FRESH `pendingInvitation` read: a `'reuse'` verdict for an accepted
   * account 409s as a logic error rather than silently re-pending a live
   * user; a row that vanished since `admin-form` falls through to the normal
   * create path. The refresh is a deep-merge update: arrays (`roles`)
   * replace wholesale, but extras keys the current `prepareUser` no longer
   * returns linger from the original invite.
   */
  @Step("create-user")
  @ArbacResource("auth.invite")
  @ArbacAction("start")
  async createUser(@WorkflowParam("context") ctx: AuthWfCtx): Promise<undefined> {
    if (!ctx.email) throw new HttpError(500, "Workflow state corrupted: missing email");
    const admin = (ctx.admin ??= {});
    const adminRoles = admin.roles;
    const fields: Record<string, unknown> = {
      ...admin.userExtras,
      ...(adminRoles && adminRoles.length > 0 && { roles: adminRoles }),
    };
    // A fresh marker per issued link: a later re-invite rotates the row's
    // marker, which supersedes this run's link (checked at accept).
    admin.inviteNonce = randomBytes(16).toString("base64url");
    const pendingAccount = {
      pendingInvitation: true,
      inviteNonce: admin.inviteNonce,
      ...(admin.invitedBy && { invitedBy: admin.invitedBy }),
    };
    if (admin.reuseExisting) {
      const existing = await this.users.findByHandle(ctx.email);
      if (existing) {
        if (!existing.account?.pendingInvitation) {
          throw this.httpError(409, "AOOTH_USER_ALREADY_EXISTS");
        }
        await this.users.update(existing.id, {
          ...fields,
          account: pendingAccount,
        } as Partial<UserCredentials>);
        ctx.subject = existing.id;
        return undefined;
      }
    }
    let created: UserCredentials;
    try {
      created = await this.users.createUser(ctx.email, undefined, fields);
    } catch (err) {
      if (err instanceof UserAuthError && err.type === "ALREADY_EXISTS") {
        throw this.httpError(409, "AOOTH_USER_ALREADY_EXISTS");
      }
      throw err;
    }
    await this.users.update(created.id, {
      account: pendingAccount,
    } as Partial<UserCredentials>);
    // The subject is the stable id (NOT the email handle) — downstream steps
    // resolve the user via id-keyed UserService calls.
    ctx.subject = created.id;
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
    const mode = this.opts.inviteDelivery;
    admin.inviteDelivery = mode;
    // swap BEFORE the email-outlet pause so the magic-link token is a durable store handle the invitee can resume days later; the admin-form pause before this stayed encapsulated
    swapStrategy("store");
    const email = ctx.email as string;
    if (mode === "outlet-email") {
      return outletEmail(email, "invite.magicLink", {
        username: email,
        ...(ctx.subject && { userId: ctx.subject }),
        ...(admin.roles && { roles: admin.roles }),
      });
    }
    // `deliver` / `return-link`: the resume token exists only once this pause
    // is persisted, so hand the `invite` outlet a callback that turns it into
    // the link and delivers (or returns) it.
    const buildUrl = this.opts.inviteLinkUrl;
    if (!buildUrl) {
      throw new HttpError(500, `inviteDelivery '${mode}' requires AuthWorkflowOpts.inviteLinkUrl`);
    }
    const userId = ctx.subject;
    setPendingInviteLink(async (token) => {
      const url = buildUrl(token, { ...(userId && { userId }) });
      if (mode === "return-link") {
        return { outlet: "invite", data: { inviteLink: url, ...(userId && { userId }) } };
      }
      await this.dispatch({
        kind: "invite-link",
        channel: "email",
        recipient: email,
        url,
        expiresInMs: INVITE_LINK_TTL_MS,
      });
      return { sent: true, outlet: "invite" };
    });
    return outlet(INVITE_OUTLET, { target: email });
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
    // The superseded check comes FIRST, so a superseded link never reaches the
    // already-accepted envelope (or anything after it) once the newer link
    // was accepted.
    const existing = await this.currentInviteRow(ctx);
    if (!existing.account?.pendingInvitation) {
      // `idempotent-redirect` renders the envelope; the schema then breaks.
      (ctx.accept ??= {}).alreadyAccepted = true;
    }
    return undefined;
  }

  /**
   * Username policy for `inviteUsername: 'choose'`, applied to the normalised
   * (NFKC, trimmed) pick. Return a message code to refuse it. Default: at most
   * 256 characters, no whitespace or control characters, and no `@` unless it
   * is the invited address itself — a chosen name must not look like someone
   * else's email handle (sign-in resolves `username` before email columns).
   */
  protected validateChosenUsername(ctx: AuthWfCtx, username: string): AoothMessageCode | undefined {
    if (username.length === 0 || username.length > 256) return "USERNAME_NOT_ALLOWED";
    // oxlint-disable-next-line no-control-regex
    if (/[\s\u0000-\u001f\u007f]/.test(username)) return "USERNAME_NOT_ALLOWED";
    if (username.includes("@") && username.toLowerCase() !== ctx.email?.toLowerCase()) {
      return "USERNAME_NOT_ALLOWED";
    }
    return undefined;
  }

  /**
   * The invited account, refusing a cancelled invite (410 `INVITE_CANCELLED`,
   * the row is gone) or a superseded link (410 `INVITE_REPLACED`, a re-invite
   * rotated the account's marker away from this run's).
   */
  private async currentInviteRow(ctx: AuthWfCtx): Promise<UserCredentials> {
    this.requireSubject(ctx);
    const user = await this.users.findByIdentifier(ctx.subject);
    if (!user) throw this.httpError(410, "INVITE_CANCELLED");
    // `!= null`: a pre-0.2 invite has no marker, and a SQL store may read the
    // unset column back as `null` rather than leaving it out.
    const current = user.account?.inviteNonce;
    if (current != null && current !== ctx.admin?.inviteNonce) {
      throw this.httpError(410, "INVITE_REPLACED");
    }
    return user;
  }

  /**
   * Re-check, right before an invite-accept write, that this run's link is
   * still the current one and the invite is still pending — a re-invite or a
   * parallel acceptance may have happened while this run was paused.
   */
  private async assertInviteStillOpen(ctx: AuthWfCtx): Promise<void> {
    const user = await this.currentInviteRow(ctx);
    if (!user.account?.pendingInvitation) throw this.httpError(410, "INVITE_ALREADY_ACCEPTED");
  }

  /**
   * `inviteUsername: 'choose'` — the invitee picks the username they will
   * sign in with (the invited email stays the correspondence address). The
   * pick replaces the account's login handle; a taken one re-pauses.
   */
  @Step("choose-username")
  @Public()
  async chooseUsername(@WorkflowParam("context") ctx: AuthWfCtx): Promise<undefined> {
    this.requireSubject(ctx);
    const wf = this.useAtscriptWfPublic(ctx, this.opts.forms.inviteChooseUsername);
    const username = normalizeUsername((wf.resolveInput() as { username: string }).username);
    await this.assertInviteStillOpen(ctx);
    const refused = this.validateChosenUsername(ctx, username);
    if (refused) throw this.throwPublic(ctx, wf, { errors: { username: this.msg(refused) } });
    const taken = await this.users.findByHandle(username);
    if (taken && taken.id !== ctx.subject) {
      throw this.throwPublic(ctx, wf, { errors: { username: this.msg("CHOOSE_USERNAME_TAKEN") } });
    }
    await this.users.update(ctx.subject, { username });
    (ctx.accept ??= {}).usernameChosen = true;
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
        ...(this.opts.messages !== undefined && { messages: this.opts.messages }),
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
    this.requireSubject(ctx);
    // Compare-and-set: only this run's (current) link of a still-pending
    // invite may accept it — a superseded or already-used link gets 410.
    if (!(await this.users.acceptInvitation(ctx.subject, ctx.admin?.inviteNonce))) {
      await this.assertInviteStillOpen(ctx);
      throw this.httpError(410, "INVITE_ALREADY_ACCEPTED");
    }
    return undefined;
  }

  /** Activate the invited user account (flips the account status flag). */
  @Step("activate-user")
  @Public()
  async activateUser(@WorkflowParam("context") ctx: AuthWfCtx): Promise<undefined> {
    this.requireSubject(ctx);
    // Invite accept: `unset-pending-invitation` just accepted THIS link — a
    // re-invite racing in between rotated the marker; refuse then.
    if (ctx.accept) await this.currentInviteRow(ctx);
    // The invite magic-link click (or signup's pre-create OTP — this step is
    // reused there) proved this inbox — record the correspondence address in
    // the same write that flips the account active.
    // Not when the link went back to the issuer (`return-link`: a click proves
    // nothing about the inbox), and only for an actual email address.
    const proved =
      ctx.email && ctx.admin?.inviteDelivery !== "return-link" && EMAIL_SHAPE.test(ctx.email)
        ? ctx.email
        : undefined;
    await this.users.activateAccount(ctx.subject, proved ? { verifiedEmail: proved } : {});
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
      message: {
        level: "success",
        text: ctx.accept?.confirmationMessage ?? this.msg("AOOTH_ACCOUNT_CREATED"),
      },
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
    this.requireSubject(ctx);
    // Stage context-aware copy BEFORE the pause so the inputRequired envelope
    // carries the rendered heading/intro alongside the form schema.
    const password = (ctx.password ??= {});
    const copy = await this.resolveSetPasswordCopy(ctx);
    // Guarded assigns — never write `undefined` (wf state-token persistence
    // rejects it; see CLAUDE.md), so a partial override leaves the untouched
    // field at whatever an earlier step staged.
    Object.assign(password, pickDefined(copy, SET_PASSWORD_COPY_KEYS));
    const user = await this.refusePasswordFormReplay(ctx);
    const wf = this.useAtscriptWfPublic(ctx, this.opts.forms.setPassword);
    let input: { newPassword: string; confirmPassword: string; consents?: string[] };
    try {
      input = wf.resolveInput() as typeof input;
    } catch (err) {
      if (ctx.postReset && err instanceof StepRetriableError) throw this.stampRecoveryExpiry(err);
      throw err;
    }
    if (input.newPassword !== input.confirmPassword) {
      throw this.throwPublic(ctx, wf, {
        errors: { confirmPassword: this.msg("PASSWORDS_DO_NOT_MATCH") },
      });
    }
    // Invite accept: never set a password through a used link (a superseded
    // or cancelled one was already refused when `user` was read).
    if (ctx.accept && !user?.account?.pendingInvitation) {
      throw this.httpError(410, "INVITE_ALREADY_ACCEPTED");
    }
    try {
      await this.users.setPassword(ctx.subject, input.newPassword);
    } catch (err) {
      if (err instanceof UserAuthError) {
        throw this.throwPublic(ctx, wf, { errors: { newPassword: userAuthErrorText(err) } });
      }
      throw err;
    }
    this.processInlineConsent(ctx, input, wf);
    ctx.isPasswordInitial = false;
    ctx.isPasswordExpired = false;
    // login.flow: gates the post-MFA `revoke-sessions` and exempts the run
    // from `check-password-unchanged`. Other flows ignore it.
    ctx.passwordChanged = true;
    delete ctx.passwordFormStamp;
    // Clear the forced-change flag now that the user has set a fresh
    // password — without this, downstream forms keep seeing the gate as
    // active. Notably `PincodeForm.rememberDevice` is hidden while
    // `newPasswordRequired` is true, so an MFA pause that follows
    // set-password would silently lose the trust-prompt UX.
    ctx.newPasswordRequired = false;
    // `delete` (not `= undefined`) — wf state-token persistence rejects
    // explicit undefined.
    delete password.changeReason;
    for (const key of SET_PASSWORD_COPY_KEYS) delete password[key];
    return undefined;
  }

  // ── Authenticated change-password (change-password.flow) ──

  /**
   * Optional min-interval rate limit (Okta "minimum password age"). Gated
   * upstream by `!!ctx.changePassword?.rateLimit`. Reuses `password.lastChanged`
   * (no extra storage) — if the last change is more recent than
   * `minIntervalMs`, emit a warn terminal and set `ctx.aborted` so the schema's
   * `{ break }` short-circuits BEFORE the form pause (the user can't fix this by
   * retrying the form — they must wait — so this is a terminal, not a
   * `requireInput`). NOT the primary protection: current-password re-entry is.
   */
  @Step("enforce-change-password-rate-limit")
  @ArbacResource("auth.change-password")
  @ArbacAction("self")
  async enforceChangePasswordRateLimit(
    @WorkflowParam("context") ctx: AuthWfCtx,
  ): Promise<undefined> {
    const rl = ctx.changePassword?.rateLimit;
    if (!rl) return undefined;
    this.requireSubject(ctx);
    const user = await this.users.getUser(ctx.subject);
    const last = user.password.lastChanged;
    if (last && Date.now() - last < rl.minIntervalMs) {
      ctx.aborted = true;
      finishWf({
        message: {
          level: "warn",
          text: this.msg("PASSWORD_CHANGE_TOO_RECENT"),
        },
        next: {
          trigger: "manual",
          primary: {
            label: this.msg("AOOTH_BACK"),
            action: {
              type: "redirect",
              target: this.opts.loginUrl,
              reason: "change-password-rate-limited",
            },
          },
        },
      });
    }
    return undefined;
  }

  /**
   * Authenticated self-service password change. `ctx.subject` is the SIGNED-IN
   * user (set by `init-change-password` from the session — never form input).
   * Pauses for `ChangePasswordForm`, then calls `users.changePassword`, which
   * re-verifies the CURRENT password (primary protection) before applying the
   * policy + history checks. `UserAuthError`s map to per-field form errors so
   * the user can fix and retry in place (per the requireInput-not-HttpError
   * convention).
   */
  @Step("change-password-form")
  @ArbacResource("auth.change-password")
  @ArbacAction("self")
  async changePasswordForm(@WorkflowParam("context") ctx: AuthWfCtx): Promise<unknown> {
    this.requireSubject(ctx);
    await this.refusePasswordFormReplay(ctx);
    const wf = this.useAtscriptWfPublic(ctx, this.opts.forms.changePassword);
    const input = wf.resolveInput() as {
      currentPassword: string;
      newPassword: string;
      confirmPassword: string;
    };
    if (input.newPassword !== input.confirmPassword) {
      throw this.throwPublic(ctx, wf, {
        errors: { confirmPassword: this.msg("PASSWORDS_DO_NOT_MATCH") },
      });
    }
    try {
      await this.users.changePassword(
        ctx.subject,
        input.currentPassword,
        input.newPassword,
        input.confirmPassword,
      );
    } catch (err) {
      if (err instanceof UserAuthError) {
        const field = userAuthErrorField(err.type) ?? "newPassword";
        throw this.throwPublic(ctx, wf, { errors: { [field]: userAuthErrorText(err) } });
      }
      throw err;
    }
    delete ctx.passwordFormStamp;
    return undefined;
  }

  /**
   * Refuse a password form whose account password changed after the form was
   * first reached: the first visit stamps `password.lastChanged`
   * (`ctx.passwordFormStamp`); a later visit that finds another value is a
   * replay of an already-used form — a single-use token put back by the
   * trigger's `restoreOnError` after a later failure, or a re-submitted
   * encapsulated token — and answers 410 `PASSWORD_CHANGED_SIGN_IN_AGAIN`
   * instead of changing the password again. Returns the account row; on an
   * invite accept it is read through {@link currentInviteRow}, so a cancelled
   * or superseded invite answers 410. A deleted account returns `null` and is
   * not checked: the step's own password write then answers it as a form error.
   */
  private async refusePasswordFormReplay(
    ctx: AuthWfCtx & { subject: string },
  ): Promise<UserCredentials | null> {
    const user = ctx.accept
      ? await this.currentInviteRow(ctx)
      : await this.users.getUser(ctx.subject).catch((err: unknown) => {
          if (err instanceof UserAuthError && err.type === "NOT_FOUND") return null;
          throw err;
        });
    if (!user) return null;
    const current = user.password.lastChanged ?? 0;
    if (ctx.passwordFormStamp === undefined) {
      ctx.passwordFormStamp = current;
    } else if (ctx.passwordFormStamp !== current) {
      throw this.httpError(410, "PASSWORD_CHANGED_SIGN_IN_AGAIN");
    }
    return user;
  }

  /**
   * Change-password terminal — sign the current device in on a FRESH session
   * and end the one the change was made from, then emit a success message.
   * The new pair is minted under a new session id, so the pre-change session
   * (its access token, refresh token and every rotation) is revoked here —
   * whatever `revokeOtherSessions` says, since that policy covers only the
   * user's OTHER sessions. Runs AFTER the optional `revoke-sessions` step, so
   * the default net effect is "kill every old session, keep this device on a
   * new one" (OWASP Session Management: no ghost sessions survive a credential
   * change).
   *
   * The pre-change session is revoked BEFORE the issue, so a failed issue
   * (store error, `maxConcurrent` refusal) leaves the user signed out, never on
   * the old session. A refresh in flight during the change is covered by
   * `AuthCredential`'s revocation protocol (it can't leave live credentials in
   * a revoked session).
   *
   * When one session can't be targeted — a stateless store (JWT /
   * encapsulated), or a legacy credential minted before `sessionId` existed
   * (its fallback id, the access token's fingerprint, never reaches the refresh
   * row) — ALL of the user's sessions are revoked (`revokeAllForUser`, also
   * under `revokeOtherSessions: false`). A stateless store also denylists the
   * presented access token (best effort): its revocation epoch is process-local.
   */
  @Step("finish-change-password")
  @ArbacResource("auth.change-password")
  @ArbacAction("self")
  async finishChangePassword(@WorkflowParam("context") ctx: AuthWfCtx): Promise<undefined> {
    this.requireSubject(ctx);
    const auth = useAuth();
    const prior = auth.getAuthContext();
    const priorSessionId = prior?.sessionId;
    const stateful = this.auth.canEnumerateSessions;
    const targeted =
      stateful && priorSessionId !== undefined && priorSessionId !== prior?.credentialId;
    if (targeted) {
      await this.auth.revokeSession(ctx.subject, priorSessionId);
    } else {
      await this.auth.revokeAllForUser(ctx.subject);
      const accessToken = stateful ? undefined : auth.extractToken();
      if (accessToken) await this.auth.revoke(accessToken).catch(() => undefined);
    }
    const issue = await this.issueForContext(ctx);
    const envelope: WfFinished = {
      finished: true,
      data: auth.buildLoginResponse(ctx.subject, issue),
      message: { level: "success", text: this.msg("PASSWORD_CHANGED") },
    };
    useWfFinished().set({
      type: "data",
      value: envelope,
      cookies: auth.buildFinishedCookies(issue),
    });
    // Single firing point for the password-changed lifecycle hook. This is a
    // ROTATION, not a login (the user was already authenticated), so `afterLogin`
    // is deliberately NOT fired — only `afterPasswordChanged`. In-terminal (not a
    // dedicated `after-*` step) because `finish-change-password` is exclusive to
    // this flow, so there's no shared terminal to disambiguate.
    await this.afterPasswordChanged(ctx);
    return undefined;
  }

  /**
   * Terminal for the manage-MFA flow. The user KEEPS their current session (no
   * re-issue, no cookies) — a plain data finish. Outcomes, in priority order:
   * removed → changed (`replace` + done) → added (done) → blocked
   * (un-removable operation aborted by `confirm-remove-mfa`) →
   * nothing-available (zero candidates, never had to step-up) → cancelled.
   */
  @Step("finish-add-mfa")
  @ArbacResource("auth.add-mfa")
  @ArbacAction("self")
  finishAddMfa(@WorkflowParam("context") ctx: AuthWfCtx): undefined | Promise<undefined> {
    useWfFinished().set({ type: "data", value: this.buildAddMfaFinishEnvelope(ctx) });
    // Single firing point for the mfa-changed lifecycle hook — only on a real
    // mutation (removed / added / changed), never on blocked / nothing-available
    // / cancelled (those leave both flags unset, see `buildAddMfaFinishEnvelope`).
    // The user keeps their session, so `afterLogin` does NOT fire. In-terminal
    // (not an `after-*` step) because this terminal is exclusive to add-mfa.
    // Mirror `buildAddMfaFinishEnvelope`'s "a change happened" condition exactly:
    // removed, or a confirmed enrol (done + method). `done && !method` can't
    // happen today, but gating on both keeps the hook firing iff the envelope
    // reports a mutation.
    if (!ctx.addMfa?.removed && !(ctx.mfaEnroll?.done && ctx.mfaEnroll?.method)) return undefined;
    const hook = this.afterMfaChanged(ctx);
    return hook instanceof Promise ? hook.then(() => undefined) : undefined;
  }

  /**
   * `finish-add-mfa`'s envelope construction, extracted pure so the outcome
   * priority (removed → changed → added → blocked → nothing-available →
   * cancelled) is unit-testable without a wf event context.
   */
  protected buildAddMfaFinishEnvelope(ctx: AuthWfCtx): WfFinished {
    const label = (method: MfaTransport) => this.msg(MFA_METHOD_LABEL_CODES[method]);
    const m = ctx.mfaEnroll;
    const addMfa = ctx.addMfa;
    const method = m?.method;
    const candidates = addMfa?.candidates ?? [];
    let envelope: WfFinished;
    if (addMfa?.removed) {
      envelope = {
        finished: true,
        data: { removed: true, method: addMfa.removed },
        message: {
          level: "success",
          text: this.msg("MFA_METHOD_REMOVED", { method: label(addMfa.removed) }),
        },
      };
    } else if (m?.done && method && addMfa?.action === "replace") {
      envelope = {
        finished: true,
        data: { changed: true, method },
        message: {
          level: "success",
          text: this.msg("MFA_METHOD_UPDATED", { method: label(method) }),
        },
      };
    } else if (m?.done && method) {
      envelope = {
        finished: true,
        data: { added: true, method },
        message: {
          level: "success",
          text: this.msg("MFA_METHOD_ADDED", { method: label(method) }),
        },
      };
    } else if (addMfa?.blocked) {
      // `confirm-remove-mfa` aborted an un-removable operation (stale/crafted
      // route — the menu filters these) — say WHY instead of the generic
      // "no changes" cancel copy. Outranks nothing-available: a blocked remove
      // implies the user HAS a factor, so "every method set up" would mislead.
      envelope = {
        finished: true,
        data: { added: false, reason: addMfa.blocked },
        message: {
          level: "info",
          text:
            addMfa.blocked === "last-required-factor"
              ? this.msg("LAST_MFA_METHOD_NOT_REMOVABLE")
              : this.msg("AOOTH_METHOD_NOT_CHANGEABLE"),
        },
      };
    } else if (candidates.length === 0 && !addMfa?.stepUpRequired) {
      envelope = {
        finished: true,
        data: { added: false, reason: "no-methods-available" },
        message: {
          level: "info",
          text: this.msg("ALL_MFA_METHODS_SET_UP"),
        },
      };
    } else {
      envelope = {
        finished: true,
        data: { added: false, reason: "cancelled" },
        message: { level: "info", text: this.msg("NO_MFA_CHANGES") },
      };
    }
    return envelope;
  }

  /**
   * Resolve which transports the user may NOT change/remove via the manage flow
   * (calls {@link resolveLockedMfaTransports}) and write them to
   * `ctx.addMfa.locked`. Mirrors the `prepare-<group>` convention.
   */
  @Step("prepare-locked-mfa-transports")
  @ArbacResource("auth.add-mfa")
  @ArbacAction("self")
  prepareLockedMfaTransports(
    @WorkflowParam("context") ctx: AuthWfCtx,
  ): undefined | Promise<undefined> {
    const result = this.resolveLockedMfaTransports(ctx);
    const apply = (locked: MfaTransport[]): undefined => {
      (ctx.addMfa ??= {}).locked = locked;
      return undefined;
    };
    if (result instanceof Promise) return result.then(apply);
    return apply(result);
  }

  /**
   * Fires once the step-up factor verifies — anchor the rest of the flow in the
   * durable `store` strategy (mirrors login's swap-after-credentials): the
   * pincode becomes single-use server state and the staged new factor lives
   * server-side instead of in the SPA-held encapsulated token. Degrades to
   * encapsulated when no durable store is wired (the registry default).
   */
  @Step("manage-stepup-done")
  @ArbacResource("auth.add-mfa")
  @ArbacAction("self")
  manageStepUpDone(@WorkflowParam("context") ctx: AuthWfCtx): undefined {
    swapStrategy("store");
    (ctx.addMfa ??= {}).stepUpDone = true;
    return undefined;
  }

  /**
   * Manage-MFA step-up consent — pauses on `StepUpConfirmForm` ("To continue,
   * we will send a verification code to ma•••@x") BEFORE `pincode-send`
   * dispatches the step-up code, so opening the manage dialog never consumes
   * a code send as a side effect. Fires only on the auto-picked paths (single
   * factor, or default factor) — an explicit `select-2fa` pick already
   * counts as consent (`select2fa` sets `stepUpConfirmed`). `Continue`
   * consents and the SAME engine pass mints + sends; `useDifferentMethod`
   * re-opens the picker; `cancel` aborts with nothing dispatched (the
   * schema's `{ break: aborted }` right after this step keeps the pair from
   * sending the declined code). Gated by {@link resolveStepUpConfirmBeforeSend}
   * (default on) — an opt-out marks consent and falls straight through.
   */
  @Step("manage-stepup-confirm")
  @ArbacResource("auth.add-mfa")
  @ArbacAction("self")
  manageStepUpConfirm(@WorkflowParam("context") ctx: AuthWfCtx): undefined | Promise<undefined> {
    const result = this.resolveStepUpConfirmBeforeSend(ctx);
    if (result instanceof Promise) return result.then((r) => this.applyStepUpConfirm(ctx, r));
    return this.applyStepUpConfirm(ctx, result);
  }

  /** `manage-stepup-confirm` tail — opt-out fall-through or the consent pause. */
  private applyStepUpConfirm(ctx: AuthWfCtx, confirmBeforeSend: boolean): undefined {
    const addMfa = (ctx.addMfa ??= {});
    if (!confirmBeforeSend) {
      addMfa.stepUpConfirmed = true;
      return undefined;
    }
    const wf = this.useAtscriptWfPublic(ctx, this.opts.forms.stepUpConfirm);
    const action = wf.resolveAction();
    if (action === "cancel") {
      ctx.aborted = true;
      return undefined;
    }
    if (action === "useDifferentMethod") {
      const mfa = (ctx.mfa ??= {});
      mfa.ignoreDefault = true;
      delete mfa.method;
      return undefined;
    }
    wf.resolveInput(); // pauses on first arrival; the 'Continue' submit resumes here
    addMfa.stepUpConfirmed = true;
    return undefined;
  }

  /**
   * Manage-MFA password re-auth — the step-up FALLBACK when the user's only
   * confirmed factor(s) are of kinds the policy no longer allows, so nothing is
   * MFA-challengeable (`addMfa.stepUpMode === "password"`; see `init-add-mfa`).
   * Pauses on `PasswordReauthForm`, verifies the account password via
   * `UserService.verifyPassword`, and on success flips `ctx.otp.verified` — the
   * SAME step-up success signal `mfaStepUpLoop` sets — so `manage-stepup-done`
   * (swap-to-store) and `manage-menu` proceed identically. `cancel` aborts to
   * the cancelled terminal (fail closed: no management write without a fresh
   * proof of identity). Only ARBAC-gated callers reach it (session-bound
   * subject), and `verifyPassword` is the same check `changePassword` enforces.
   */
  @Step("manage-password-reauth")
  @ArbacResource("auth.add-mfa")
  @ArbacAction("self")
  async managePasswordReauth(@WorkflowParam("context") ctx: AuthWfCtx): Promise<undefined> {
    this.requireSubject(ctx);
    const username = ctx.subject;
    const wf = this.useAtscriptWfPublic(ctx, this.opts.forms.passwordReauth);
    if (wf.resolveAction() === "cancel") {
      ctx.aborted = true;
      return undefined;
    }
    const input = wf.resolveInput() as { password: string };
    const ok = await this.users.verifyPassword(username, input.password);
    if (!ok)
      throw this.throwPublic(ctx, wf, { errors: { password: this.msg("INCORRECT_PASSWORD") } });
    (ctx.otp ??= {}).verified = true;
    return undefined;
  }

  /**
   * The keep-at-least-one rule: removing the user's LAST confirmed factor under
   * a `required` policy can never succeed. The single source for the predicate
   * `manage-menu` mirrors into `addMfa.removeBlocked` (to drop the Remove option)
   * AND `confirm-remove-mfa` re-checks before its pause (defence in depth) — so
   * a policy change (e.g. "keep at least two", or a backup-codes exception)
   * lands in one place, not two copies that can drift.
   */
  private isLastRequiredFactor(ctx: AuthWfCtx): boolean {
    return (ctx.mfa?.enrolledMethods?.length ?? 0) <= 1 && ctx.mfaPolicy?.mode === "required";
  }

  /**
   * Manage-MFA menu — pauses on `ManageMfaForm` and routes the chosen
   * `operation` (`add:<t>` / `replace:<t>` / `remove:<t>`). Only reached when
   * the user has ≥1 confirmed factor (a zero-MFA user goes straight to the enrol
   * picker). Re-checks the locked set + candidate membership server-side, then
   * sets `ctx.addMfa.action`/`target` (and pre-seeds `mfaEnroll.method` for
   * add/change). `cancel`, or nothing actionable, aborts to the finish terminal.
   */
  @Step("manage-menu")
  @ArbacResource("auth.add-mfa")
  @ArbacAction("self")
  async manageMenu(@WorkflowParam("context") ctx: AuthWfCtx): Promise<undefined> {
    this.requireSubject(ctx);
    const addMfa = (ctx.addMfa ??= {});
    const enrolled = ctx.mfa?.enrolledMethods ?? [];
    const locked = new Set(addMfa.locked ?? []);
    const candidates = addMfa.candidates ?? [];
    const changeable = enrolled.filter((e) => !locked.has(e.kind));
    // Nothing to add and nothing changeable → benign finish (avoids a radio
    // form with zero options that could never be submitted).
    if (candidates.length === 0 && changeable.length === 0) {
      ctx.aborted = true;
      return undefined;
    }
    // Removing the LAST confirmed factor under a `required` policy can never
    // succeed (`confirm-remove-mfa`'s keep-at-least-one guard) — compute the
    // flag BEFORE the pause so `ManageMfaForm` omits the Remove option (and
    // explains why) instead of offering a dead-end.
    if (this.isLastRequiredFactor(ctx)) {
      addMfa.removeBlocked = true;
    } else {
      delete addMfa.removeBlocked;
    }
    const wf = this.useAtscriptWfPublic(ctx, this.opts.forms.manageMfa);
    if (wf.resolveAction() === "cancel") {
      ctx.aborted = true;
      return undefined;
    }
    const input = wf.resolveInput() as { operation: string };
    const sep = input.operation.indexOf(":");
    const action = (sep >= 0 ? input.operation.slice(0, sep) : "") as "add" | "replace" | "remove";
    const target = (sep >= 0 ? input.operation.slice(sep + 1) : "") as MfaTransport;
    if (action === "add") {
      if (!candidates.includes(target)) {
        throw this.throwPublic(ctx, wf, {
          errors: { operation: this.msg("AOOTH_METHOD_UNAVAILABLE") },
        });
      }
    } else if (action === "replace" || action === "remove") {
      if (locked.has(target)) {
        throw this.throwPublic(ctx, wf, { formMessage: this.msg("AOOTH_METHOD_NOT_CHANGEABLE") });
      }
      if (!enrolled.some((e) => e.kind === target)) {
        throw this.throwPublic(ctx, wf, {
          errors: { operation: this.msg("AOOTH_UNKNOWN_METHOD") },
        });
      }
      // The Remove option was filtered off the menu when blocked — a submitted
      // remove here is a crafted/stale client. Re-pause on the menu (which
      // still has workable options) rather than routing into the confirm
      // step's abort-to-finish.
      if (action === "remove" && addMfa.removeBlocked) {
        throw this.throwPublic(ctx, wf, {
          formMessage: this.msg("KEEP_ONE_MFA_METHOD"),
        });
      }
    } else {
      throw this.throwPublic(ctx, wf, { errors: { operation: this.msg("AOOTH_CHOOSE_OPTION") } });
    }
    addMfa.action = action;
    addMfa.target = target;
    const m = (ctx.mfaEnroll ??= {});
    if (action === "add" || action === "replace") {
      // Pre-seed the chosen transport + reset any prior enrol scratch. add vs
      // replace need no write-path difference — the trio stages in wf-state and
      // upserts on confirm either way (write-on-confirm); `addMfa.action` is the
      // sole add/replace discriminator (read by `finish-add-mfa`).
      m.method = target;
      delete m.address;
      delete m.qrSeen;
      delete m.done;
      delete m.secret;
      delete m.uri;
    } else {
      // remove — expose the target to the confirm form via public.mfaEnroll.method
      m.method = target;
    }
    return undefined;
  }

  /**
   * Manage-MFA remove confirmation. Pauses on `RemoveMfaConfirmForm`; the
   * 'Remove' submit performs the removal, 'Cancel' aborts. Re-checks the locked
   * set and the keep-at-least-one rule (LAST confirmed factor under a
   * `required` policy) BEFORE the pause — and an un-removable state aborts to
   * the `finish-add-mfa` terminal (reason on `addMfa.blocked`) instead of
   * pausing: `manage-menu` filters these operations out, so arriving here
   * blocked means a stale/crafted route, and a retryable form whose only
   * submit re-throws the same guard would be a dead-end loop (the manage
   * forms hide their built-in cancel — the host owns it).
   */
  @Step("confirm-remove-mfa")
  @ArbacResource("auth.add-mfa")
  @ArbacAction("self")
  async confirmRemoveMfa(@WorkflowParam("context") ctx: AuthWfCtx): Promise<undefined> {
    this.requireSubject(ctx);
    const username = ctx.subject;
    const addMfa = (ctx.addMfa ??= {});
    const target = addMfa.target as MfaTransport;
    const enrolled = ctx.mfa?.enrolledMethods ?? [];
    if ((addMfa.locked ?? []).includes(target)) {
      addMfa.blocked = "method-locked";
      ctx.aborted = true;
      return undefined;
    }
    if (this.isLastRequiredFactor(ctx)) {
      addMfa.blocked = "last-required-factor";
      ctx.aborted = true;
      return undefined;
    }
    const wf = this.useAtscriptWfPublic(ctx, this.opts.forms.removeMfaConfirm);
    if (wf.resolveAction() === "cancel") {
      ctx.aborted = true;
      return undefined;
    }
    wf.resolveInput(); // pauses on first arrival; the 'Remove' submit resumes here
    const methodName = enrolled.find((e) => e.kind === target)?.methodName ?? target;
    await this.withStoreErrorTranslation(() => this.users.removeMfaMethod(username, methodName));
    addMfa.removed = target;
    return undefined;
  }

  // ── Channel enrolment (2) — login only, parameterized by :channel ──

  @Step("ask/:channel(email|phone)")
  @Public()
  async askChannel(
    @WorkflowParam("context") ctx: AuthWfCtx,
    @Param("channel") channel: "email" | "phone",
  ): Promise<unknown> {
    this.requireSubject(ctx);
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
    const username = ctx.subject;
    await this.withStoreErrorTranslation(() =>
      this.users.addMfaMethod(username, { name: methodName, value, confirmed: false }),
    );
    if (isEmail) {
      // `channel.email` is the sole enrollment ask→verify target (mirrors
      // `phone`) — the gates key on it. The security-notice recipient lives on
      // `notice.email`, refreshed only once `verify/email` proves the inbox.
      (ctx.channel ??= {}).email = value;
    } else {
      (ctx.channel ??= {}).phone = value;
    }
    const deliver = await this.claimCodeSend(this.enrollTarget(ctx, value), ctx.subject);
    await this.sendChannelPincode(ctx, value, isEmail ? "email" : "sms", deliver);
    const pincodeWf = this.useAtscriptWfPublic(ctx, this.opts.forms.pincode);
    throw this.throwPublic(ctx, pincodeWf);
  }

  /**
   * Mint the code proving a channel (`ask/*`, `verify/*`), deliver it when
   * `deliver`, and arm the PincodeForm: the resend wait `verifyChannel`
   * gates "Resend code" on (the same cooldown contract as `pincode-send`),
   * the masked `sentTo` its "Code sent to …" hint renders, and the code length.
   */
  private async sendChannelPincode(
    ctx: AuthWfCtx,
    address: string,
    channel: "email" | "sms",
    deliver: boolean,
  ): Promise<void> {
    const code = this.mintPin(ctx, this.pinFor(ctx, address));
    if (deliver) {
      await this.dispatch({
        kind: "enroll-pincode",
        channel,
        recipient: address,
        code,
        expiresInMs: this.opts.mfa.pincodeTtlMs,
      });
    }
    const pincode = (ctx.pincode ??= {});
    pincode.resendAllowedAt = Date.now() + this.opts.mfa.pincodeResendTimeoutMs;
    pincode.sentTo = this.maskAddress(address, channel);
    pincode.codeLength = this.opts.mfa.pincodeLength;
  }

  @Step("verify/:channel(email|phone)")
  @Public()
  async verifyChannel(
    @WorkflowParam("context") ctx: AuthWfCtx,
    @Param("channel") channel: "email" | "phone",
  ): Promise<unknown> {
    this.requireSubject(ctx);
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
      const cooldown = ctx.pincode?.resendAllowedAt;
      const recipient = (isEmail ? ctx.channel?.email : ctx.channel?.phone) as string;
      // The state's wait, then the server-side cooldown per destination (a
      // replayed older state carries a stale wait).
      if (
        (cooldown && cooldown > Date.now()) ||
        !(await this.claimCodeSend(this.enrollTarget(ctx, recipient), ctx.subject))
      ) {
        throw this.throwPublic(ctx, pincodeWf, {
          formMessage: this.msg("AOOTH_RESEND_WAIT", {
            seconds: this.resendWaitSeconds(cooldown),
          }),
        });
      }
      await this.sendChannelPincode(ctx, recipient, isEmail ? "email" : "sms", true);
      throw this.throwPublic(ctx, pincodeWf);
    }
    const input = pincodeWf.resolveInput() as { code: string };
    const recipient = (isEmail ? ctx.channel?.email : ctx.channel?.phone) ?? "";
    const pinErr = await this.verifyPin(
      ctx,
      input.code,
      this.pinFor(ctx, recipient),
      this.enrollTarget(ctx, recipient),
    );
    if (pinErr) throw this.throwPublic(ctx, pincodeWf, { errors: pinErr });
    await this.withStoreErrorTranslation(() =>
      this.users.confirmMfaMethod(ctx.subject, isEmail ? "email" : "sms"),
    );
    const channelState = (ctx.channel ??= {});
    if (isEmail) {
      channelState.emailConfirmed = true;
      // The pincode just verified delivery to `channel.email` (the address
      // `ask/email` collected) — record the inbox proof, and promote the
      // freshly-proven inbox to the security-notice recipient.
      if (channelState.email) {
        await this.users.setVerifiedEmail(ctx.subject, channelState.email);
        (ctx.notice ??= {}).email = channelState.email;
      }
    } else {
      channelState.phoneConfirmed = true;
    }
    // Record the OTP-channel disclosure AFTER channel ownership is confirmed.
    if (channelState.otpDisclosure) {
      const channelArg: "email" | "sms" = isEmail ? "email" : "sms";
      const target = (isEmail ? channelState.email : channelState.phone) as string;
      await this.consentStore.recordOtpChannelConsent(
        ctx.subject,
        channelArg,
        target,
        channelState.otpDisclosure,
      );
    }
    this.clearPin(ctx);
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
    if (!ctx.subject) return undefined;
    const cookieValue = useCookies(current()).getCookie(this.opts.deviceTrust.cookieName);
    const trust = (ctx.trust ??= {});
    if (!cookieValue) {
      trust.newDevice = true;
      return undefined;
    }
    const ip = this.opts.deviceTrust.bindsTo === "cookie+ip" ? this.resolveClientIp() : undefined;
    const ok = await this.users.verifyTrustedDevice(ctx.subject, cookieValue, ip);
    if (ok) {
      (ctx.otp ??= {}).verified = true;
      trust.deviceTrustToken = cookieValue;
    } else {
      trust.newDevice = true;
    }
    return undefined;
  }

  /**
   * Resolve the client IP from the active HTTP request — the IP the HTTP app
   * resolves (its `trustProxy` / `proxyHeaders`), the same one the rate
   * limiter keys on — swallowing the case where there is no HTTP context
   * (unit tests that hand-roll the wf runtime).
   */
  protected resolveClientIp(): string | undefined {
    return requestClientIp() || undefined;
  }

  /**
   * Resolve the client `User-Agent` from the active HTTP request. Sibling to
   * {@link resolveClientIp}; swallows the no-HTTP case (unit tests that
   * hand-roll the wf runtime) by returning `undefined`.
   */
  protected resolveUserAgent(): string | undefined {
    try {
      const ua = useHeaders()["user-agent"];
      const first = Array.isArray(ua) ? ua[0] : ua;
      return typeof first === "string" && first.length > 0 ? first : undefined;
    } catch {
      return undefined;
    }
  }

  /**
   * Build the {@link CredentialMetadata} captured onto every credential at
   * issue time. Default records the request IP + User-Agent (the raw facts the
   * session UI derives device/location from at read time). Returns `undefined`
   * outside an HTTP context — so a hand-rolled (no-HTTP) wf run issues with
   * `metadata: undefined`. Override to add a `label`, trim PII, etc.
   */
  protected resolveIssueMetadata(_ctx: AuthWfCtx): CredentialMetadata | undefined {
    const ip = this.resolveClientIp();
    const userAgent = this.resolveUserAgent();
    if (ip === undefined && userAgent === undefined) return undefined;
    return {
      ...(ip !== undefined && { ip }),
      ...(userAgent !== undefined && { userAgent }),
    };
  }

  /**
   * Mint a fresh credential for the workflow user, stamping the default
   * issue-time metadata (IP + User-Agent via {@link resolveIssueMetadata}).
   * Shared by every finish step that issues a session (login, change-password,
   * recovery auto-login). Call after {@link requireSubject} has narrowed
   * `subject` (the typed param enforces it at the call site).
   */
  private issueForContext(ctx: AuthWfCtx & { subject: string }) {
    return this.auth.issue(ctx.subject, { metadata: this.resolveIssueMetadata(ctx) });
  }

  /**
   * Load + summarise the user's enrolled MFA methods (filtered against
   * `ctx.mfaPolicy.availableTransports`) and mirror form-gating flags
   * (`mfa.methodCount`, `trust.optIn`) onto ctx. Pure data-load.
   */
  @Step("load-enrolled-mfa-methods")
  @Public()
  async loadEnrolledMfaMethods(@WorkflowParam("context") ctx: AuthWfCtx): Promise<undefined> {
    if (!ctx.subject) return undefined;
    const user = await this.users.getUserSnapshot(ctx.subject, current());
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
      throw this.throwPublic(ctx, wf, { errors: { methodName: this.msg("UNKNOWN_MFA_METHOD") } });
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
          formMessage: this.msg("AOOTH_RESEND_WAIT_CHANNEL", { seconds: waitSec, channel }),
        });
      }
    }
    mfa.method = picked.kind;
    // Manage step-up only: an explicit pick of "Email (ma•••@x)" + submit IS
    // the dispatch consent — don't double-pause on `manage-stepup-confirm`.
    // No-op for login (no `ctx.addMfa`).
    if (ctx.addMfa) ctx.addMfa.stepUpConfirmed = true;
    mfa.saveAsDefault = Boolean(input.saveAsDefault);
    if (mfa.saveAsDefault && ctx.subject) {
      await this.users.setDefaultMfaMethod(ctx.subject, picked.methodName);
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
    const recovery = !ctx.mfa?.method && !ctx.signup;
    // Anonymous sends (recovery, signup) count against the per-IP send limit —
    // every request alike, whether or not a message goes out.
    if (!ctx.mfa?.method) await enforceRateLimit(SEND_RATE_LIMIT);
    let target: { address: string; channel: "sms" | "email" };
    let account: Awaited<ReturnType<AuthWorkflow["recoveryAccount"]>> = null;
    if (recovery) {
      // Resolved from the typed identifier on every send, never kept in the
      // state. No account (unknown, inactive, M2 without a channel — or a
      // channel deleted since the last send): nothing is sent, and the run
      // looks exactly like a real one.
      account = await this.recoveryAccount(ctx);
      target = await this.recoveryPincodeTarget(ctx, "typed");
    } else {
      const targetResult = this.resolvePincodeTarget(ctx);
      target = targetResult instanceof Promise ? await targetResult : targetResult;
    }
    // M2 shows no destination (not even masked) — it would disclose part of
    // the account's own channel to whoever typed the identifier.
    const registeredRecovery =
      recovery && (await this.recoveryDeliverySource(ctx)) === "registered";
    // Recovery binds the code to the account it is sent for (a fixed-length
    // id, so a run without an account looks the same): if the identifier
    // resolves to another account by the time it is entered, it is refused.
    const binding = recovery ? this.recoveryBinding(account) : this.pinFor(ctx, target.address);
    // Server-side resend cooldown + failed-code budget per destination (the
    // typed identifier for recovery and signup — known or not), and the
    // per-account send limit after a first factor. In a cooldown a code is
    // minted all the same and nothing is sent.
    const deliver = await this.claimCodeSend(
      this.pincodeTarget(ctx, target.address),
      ctx.mfa?.method ? ctx.subject : undefined,
    );
    const code = this.mintPin(ctx, binding);
    // Branched on `kind` discriminator. `recovery-pincode` carries
    // `target.channel` — email by default, SMS when `resolveRecoveryChannel`
    // routes it (the address is the typed identifier either way). Signup is
    // always email.
    // In a cooldown nothing goes out.
    if (deliver) {
      if (ctx.mfa?.method) {
        await this.dispatch({
          kind: "mfa-pincode",
          channel: target.channel,
          recipient: target.address,
          code,
          expiresInMs: this.opts.mfa.pincodeTtlMs,
        });
      } else if (ctx.signup) {
        // Signup verify-first: prove email ownership before the row exists. The
        // target is always email (`resolvePincodeTarget`'s non-MFA branch).
        await this.dispatch({
          kind: "signup-pincode",
          channel: "email",
          recipient: target.address,
          code,
          expiresInMs: this.opts.mfa.pincodeTtlMs,
        });
      } else if (account) {
        await this.dispatch({
          kind: "recovery-pincode",
          channel: account.channel,
          recipient: account.address,
          code,
          expiresInMs: this.opts.mfa.pincodeTtlMs,
        });
      }
    }
    // Stash the delivery target so `pincode-check` can record the email inbox
    // proof against the address the code went to — except in recovery, where
    // `pincode-check` resolves it again (the state holds nothing about the
    // account before the code is verified). `ctx.otp` is server-only.
    if (!recovery) {
      const otp = (ctx.otp ??= {});
      otp.deliveredTo = target.address;
      otp.deliveredChannel = target.channel;
    }
    const pincode = (ctx.pincode ??= {});
    if (registeredRecovery) delete pincode.sentTo;
    else pincode.sentTo = this.maskAddress(target.address, target.channel);
    pincode.codeLength = this.opts.mfa.pincodeLength;
    const cooldownAt = Date.now() + this.opts.mfa.pincodeResendTimeoutMs;
    pincode.resendAllowedAt = cooldownAt;
    // Per-channel cooldown lives alongside `resendAllowedAt` so the gate
    // survives a `useDifferentMethod` clear (see `pincode-check` +
    // `select-2fa`). Only MFA-challenge sends are tracked here — recovery
    // picks ONE channel per run (email or SMS), so the single `resendAllowedAt`
    // gate suffices and per-channel persistence is moot.
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
        // The state's wait, then the destination's server-side cooldown (a
        // replayed older state carries a stale wait). `pincode-send` claims it.
        if (
          (ctx.pincode?.resendAllowedAt && ctx.pincode.resendAllowedAt > Date.now()) ||
          (await this.codeSendCoolingDown(this.pincodeTarget(ctx, ctx.otp?.deliveredTo)))
        ) {
          throw this.throwPublic(ctx, wf, {
            formMessage: this.msg("AOOTH_RESEND_WAIT", {
              seconds: this.resendWaitSeconds(ctx.pincode?.resendAllowedAt),
            }),
          });
        }
        this.clearPin(ctx);
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
        this.clearPin(ctx);
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
    // Recovery resolves the account again (the state holds nothing about it).
    // No account — a ghost run, or one deactivated / emptied since the send —
    // refuses every code as a wrong one, with the same attempt counting.
    const recovery = !ctx.mfa?.method && !ctx.signup;
    const account = recovery ? await this.recoveryAccount(ctx) : null;
    const binding = recovery
      ? this.recoveryBinding(account)
      : this.pinFor(ctx, ctx.otp?.deliveredTo ?? "");
    const pinErr = await this.verifyPin(
      ctx,
      recovery && !account ? NO_CODE : input.code,
      binding,
      this.pincodeTarget(ctx, ctx.otp?.deliveredTo),
    );
    if (pinErr) throw this.throwPublic(ctx, wf, { errors: pinErr });
    const otp = (ctx.otp ??= {});
    if (account) {
      ctx.subject = account.subject;
      otp.deliveredTo = account.address;
      otp.deliveredChannel = account.channel;
    }
    otp.verified = true;
    // Verified pin DELIVERED to an email address — the user just proved that
    // inbox; record it as the correspondence address. One uniform rule for
    // every pincode surface (login email-MFA challenge, recovery M1/M2).
    // Signup's OTP verifies pre-create (no `ctx.subject`) so it naturally
    // skips here — its capture stays at `activate-user`.
    if (ctx.subject && otp.deliveredChannel === "email" && otp.deliveredTo) {
      await this.users.setVerifiedEmail(ctx.subject, otp.deliveredTo);
    }
    // Re-arm risk step-up so it re-evaluates after this verification.
    (ctx.session ??= {}).riskStepUpEvaluated = false;
    if (ctx.deviceTrust?.enabled && ctx.deviceTrust?.optIn) {
      (ctx.trust ??= {}).rememberDevice = Boolean(input.rememberDevice);
    }
    this.clearPin(ctx);
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
    this.requireSubject(ctx);
    try {
      await this.withStoreErrorTranslation(() =>
        this.users.verifyMfa(ctx.subject, input.code, undefined, this.lockoutOverride(ctx)),
      );
      (ctx.otp ??= {}).verified = true;
      (ctx.session ??= {}).riskStepUpEvaluated = false;
      if (ctx.deviceTrust?.enabled && ctx.deviceTrust?.optIn) {
        (ctx.trust ??= {}).rememberDevice = Boolean(input.rememberDevice);
      }
    } catch (err) {
      if (err instanceof UserAuthError) {
        if (err.type === "LOCKED") {
          throw this.throwPublic(ctx, wf, {
            formMessage: this.msg("AOOTH_ACCOUNT_LOCKED"),
          });
        }
        if (err.type === "INACTIVE") {
          throw this.throwPublic(ctx, wf, { errors: { code: this.msg("AOOTH_INVALID_CODE") } });
        }
        if (err.type === "MFA_NOT_CONFIGURED") {
          throw this.httpError(400, "TOTP_NOT_CONFIGURED");
        }
        if (err.type === "MFA_INVALID") {
          if (err.details?.lockEnds !== undefined) {
            throw this.throwPublic(ctx, wf, {
              formMessage: this.msg("AOOTH_ACCOUNT_LOCKED"),
            });
          }
          throw this.throwPublic(ctx, wf, { errors: { code: this.msg("AOOTH_INVALID_CODE") } });
        }
      }
      throw err;
    }
    return undefined;
  }

  /**
   * Unified MFA-enrol phase 1 (pick method). Auto-picks a single transport,
   * otherwise pauses for `EnrollPickMethodForm`. When TOTP is picked, the
   * secret is idempotently provisioned in the same step body. Handles `skip`
   * (optional opt-in) / `cancel` (manage). In the manage flow this only runs
   * for a zero-MFA user — once the user has factors, the menu pre-seeds
   * `mfaEnroll.method` (add/change) so the picker is skipped.
   */
  @Step("enroll-pick-method")
  @Public()
  enrollPickMethod(@WorkflowParam("context") ctx: AuthWfCtx): undefined | Promise<undefined> {
    this.requireSubject(ctx);
    const transports = ctx.mfaPolicy?.availableTransports ?? [];
    const m = (ctx.mfaEnroll ??= {});
    // Preserve a pre-set 'manage' mode (init-add-mfa); otherwise derive from policy.
    const mode =
      m.mode === "manage" ? "manage" : ctx.mfaPolicy?.mode === "required" ? "required" : "optional";
    m.mode = mode;
    if (!m.availableTransports) m.availableTransports = [...transports];

    // 0-transport guard — only `required` mode (forced enrolment) is a hard
    // error; optional/manage finish gracefully.
    if (transports.length === 0) {
      if (mode !== "required") {
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
      const action = wf.resolveAction();
      if (mode === "manage" && action === "cancel") {
        ctx.aborted = true;
        return undefined;
      }
      if (mode === "optional" && action === "skip") {
        m.done = true;
        (ctx.otp ??= {}).verified = true;
        return undefined;
      }
      const input = wf.resolveInput() as { method: string };
      const picked = input.method as MfaTransport;
      if (!m.availableTransports.includes(picked)) {
        throw this.throwPublic(ctx, wf, { errors: { method: this.msg("AOOTH_UNKNOWN_METHOD") } });
      }
      m.method = picked;
    }

    // Idempotent TOTP secret provisioning (see `provisionTotpSecret`). Covers
    // the picker path; the manage add/change path (picker skipped, method
    // pre-seeded by `manage-menu`) provisions in `enroll-totp-qr` instead.
    return this.provisionTotpSecret(ctx);
  }

  /**
   * Unified MFA-enrol phase 2 (collect sms/email address). Not invoked for
   * totp. Asks {@link resolveEnrollAddress} FIRST — a deployment that pins
   * the address (factor bound to an account record) stages it here and the
   * free-text form never renders; this single call site covers every trio
   * path (picker, auto-pick, manage add/replace pre-seed), and `enroll-send`
   * dispatches to the pinned address in the same engine pass. Otherwise
   * (`'collect'`) handles `skip` (opt-in) / `cancel` (manage) /
   * `useDifferentMethod`, validates the typed address server-side via the
   * ctx-first {@link validateMfaAddress} (the client `@ui.form.validate`
   * hint is advisory), then STAGES the candidate value in wf-state
   * (`m.address`) — the user record is written only on confirm
   * (write-on-confirm), so an ADD leaves no partial row and a REPLACE keeps
   * the old confirmed value live until the new code verifies in
   * `enroll-confirm`. Collection ONLY: the pincode dispatch lives in
   * `enroll-send` (same engine pass, no extra round-trip), so a consumer
   * pre-seeding `mfaEnroll.address` — which skips this whole step via its
   * schema condition — still gets exactly one code.
   */
  @Step("enroll-address")
  @Public()
  enrollAddress(@WorkflowParam("context") ctx: AuthWfCtx): undefined | Promise<undefined> {
    this.requireSubject(ctx);
    const m = (ctx.mfaEnroll ??= {});
    const methodName = m.method as MfaTransport;
    const pinned = this.resolveEnrollAddress(ctx, methodName);
    if (pinned instanceof Promise) {
      return pinned.then((p) => this.collectEnrollAddress(ctx, methodName, p));
    }
    return this.collectEnrollAddress(ctx, methodName, pinned);
  }

  /**
   * `enroll-address` tail — stage a pinned address, or run the free-text
   * collect pause (skip/cancel/useDifferentMethod triage + ctx-first
   * validation + write-on-confirm staging).
   */
  private collectEnrollAddress(
    ctx: AuthWfCtx,
    methodName: MfaTransport,
    pinned: string,
  ): undefined | Promise<undefined> {
    const m = (ctx.mfaEnroll ??= {});
    // Pinned address — consumer-authoritative (no validateMfaAddress pass),
    // normalized like any typed one. Blank/'collect' falls through to the form.
    if (pinned !== "collect" && pinned.trim()) {
      m.address = this.normalizeMfaAddress(methodName, pinned.trim());
      return undefined;
    }
    const mode = m.mode ?? "optional";
    const wf = this.useAtscriptWfPublic(ctx, this.opts.forms.enrollAddress);
    const action = wf.resolveAction();
    if (mode === "manage" && action === "cancel") {
      this.cancelManageEnrollment(ctx);
      return undefined;
    }
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
    const stage = (addrErr: string | undefined): undefined => {
      if (addrErr) throw this.throwPublic(ctx, wf, { errors: { address: addrErr } });
      // Stage the candidate value in wf-state ONLY (write-on-confirm) — nothing
      // is written to the user record until the pincode verifies in enroll-confirm.
      m.address = this.normalizeMfaAddress(methodName, input.address);
      return undefined;
    };
    const addrErr = this.validateMfaAddress(ctx, methodName, input.address);
    if (addrErr instanceof Promise) return addrErr.then(stage);
    return stage(addrErr);
  }

  /**
   * Unified MFA-enrol dispatch (sms/email only) — the trio's ONLY pincode
   * send. A separate step (the canonical "send if no pin" gate, mirroring
   * `pincode-send`) so both address paths share one dispatch site: collected
   * by `enroll-address`, or pre-seeded by a consumer (which skips
   * `enroll-address` entirely — previously skipping the dispatch with it and
   * stranding the user on a code form no code was sent for). Asks
   * `resolveEnrollPreConfirmed` first: a verified-by-construction address
   * (e.g. the invite email the magic link just proved) skips the round-trip —
   * `enroll-confirm` then writes the factor without pausing.
   */
  @Step("enroll-send")
  @Public()
  async enrollSend(@WorkflowParam("context") ctx: AuthWfCtx): Promise<undefined> {
    this.requireSubject(ctx);
    const m = (ctx.mfaEnroll ??= {});
    const method = m.method as MfaTransport;
    const address = m.address as string;
    if (await this.resolveEnrollPreConfirmed(ctx, method, address)) {
      m.preConfirmed = true;
      return undefined;
    }
    await this.mintAndSendEnrollPincode(ctx, address);
    return undefined;
  }

  /**
   * MFA-enrol TOTP QR step — shown on its OWN pause between method-pick and
   * code-entry (so the user scans first, types the code next). Idempotently
   * provisions the TOTP secret in wf-state ONLY (covers the auto-pick /
   * menu-pre-seeded paths where `enroll-pick-method` was skipped), then pauses
   * on `EnrollTotpQrForm`. The user record is written only on confirm
   * (write-on-confirm), so a manage **replace** never clobbers the live totp
   * secret and a cancel/crash leaves the existing factor intact — no stash or
   * restore needed. Handles `skip` (opt-in) / `cancel` (manage) /
   * `useDifferentMethod`.
   */
  @Step("enroll-totp-qr")
  @Public()
  async enrollTotpQr(@WorkflowParam("context") ctx: AuthWfCtx): Promise<undefined> {
    this.requireSubject(ctx);
    const m = (ctx.mfaEnroll ??= {});
    await this.provisionTotpSecret(ctx);
    const wf = this.useAtscriptWfPublic(ctx, this.opts.forms.enrollTotpQr);
    if (this.handleEnrollExit(ctx, wf.resolveAction())) return undefined;
    wf.resolveInput(); // pauses on first arrival; the 'Continue' submit resumes here
    m.qrSeen = true;
    return undefined;
  }

  /**
   * Unified MFA-enrol phase 3 (verify pincode/TOTP, then write the factor). On
   * success sets `ctx.mfaEnroll.done = true` AND `ctx.otp.verified = true`
   * (the loop-exit signal — enrol-confirm verifies an OTP, so the unified
   * `otp.verified` flag fires alongside the MFA-specific `mfaEnroll.done`).
   * This is the ONLY place the enrol trio touches the user record
   * (write-on-confirm): the proven value (sms/email address or totp secret,
   * staged in wf-state) is upserted as confirmed via `addMfaMethod`, which
   * atomically swaps in a REPLACE with no pre-confirm clobber window and creates
   * a fresh row for an ADD.
   */
  @Step("enroll-confirm")
  @Public()
  async enrollConfirm(@WorkflowParam("context") ctx: AuthWfCtx): Promise<undefined> {
    this.requireSubject(ctx);
    const m = (ctx.mfaEnroll ??= {});
    // Verified-by-construction address (`enroll-send` set `preConfirmed` per
    // `resolveEnrollPreConfirmed`): the inbox/number was proven by the very
    // channel that brought the user here, so re-proving it with a pincode to
    // the same destination adds nothing — run the write-on-confirm tail
    // directly, no code-entry pause. Server-only flag; TOTP never sets it.
    if (m.preConfirmed && m.method !== "totp" && m.address) {
      await this.confirmEnrolledFactor(ctx);
      return undefined;
    }
    const wf = this.useAtscriptWfPublic(ctx, this.opts.forms.enrollConfirm);
    const action = wf.resolveAction();
    if (this.handleEnrollExit(ctx, action)) return undefined;
    if (action === "resend") {
      if (m.method === "totp") {
        throw this.throwPublic(ctx, wf, { formMessage: this.msg("TOTP_RESEND_NOT_APPLICABLE") });
      }
      const cooldown = ctx.pincode?.resendAllowedAt;
      // The state's wait, then the server-side cooldown per destination (a
      // replayed older state carries a stale wait).
      if (
        (cooldown && Date.now() < cooldown) ||
        !(await this.claimCodeSend(this.enrollTarget(ctx, m.address), ctx.subject))
      ) {
        throw this.throwPublic(ctx, wf, {
          formMessage: this.msg("AOOTH_RESEND_WAIT_ANOTHER", {
            seconds: this.resendWaitSeconds(cooldown),
          }),
        });
      }
      await this.mintAndSendEnrollPincode(ctx, m.address as string, true);
      return undefined;
    }
    const input = wf.resolveInput() as { code: string };
    if (m.method === "totp") {
      // Verify against the wf-state secret (write-on-confirm — no user-record row
      // exists yet). verifyTotpCode returns the matched counter, or null.
      if (verifyTotpCode(m.secret as string, input.code) === null) {
        throw this.throwPublic(ctx, wf, { errors: { code: this.msg("AOOTH_INVALID_CODE") } });
      }
    } else {
      const pinErr = await this.verifyPin(
        ctx,
        input.code,
        this.pinFor(ctx, m.address ?? ""),
        this.enrollTarget(ctx, m.address),
      );
      if (pinErr) throw this.throwPublic(ctx, wf, { errors: pinErr });
    }
    await this.confirmEnrolledFactor(ctx);
    return undefined;
  }

  /**
   * `enroll-confirm`'s write-on-confirm tail (uniform for ADD and REPLACE, all
   * transports): the staged value (sms/email `address`, totp `secret`) is now
   * proven — by a verified pincode/TOTP code, or vouched by
   * `resolveEnrollPreConfirmed` — so upsert it as confirmed. `addMfaMethod`
   * replaces any row of the same name, so a REPLACE atomically swaps in the
   * new value with no pre-confirm clobber window, and an ADD creates the row
   * fresh.
   */
  private async confirmEnrolledFactor(ctx: AuthWfCtx): Promise<void> {
    this.requireSubject(ctx);
    // Invite accept: no factor lands through a superseded / used link.
    if (ctx.accept) await this.assertInviteStillOpen(ctx);
    const username = ctx.subject;
    const m = (ctx.mfaEnroll ??= {});
    const methodName = m.method as MfaTransport;
    const value = (methodName === "totp" ? m.secret : m.address) as string;
    await this.withStoreErrorTranslation(() =>
      this.users.addMfaMethod(username, { name: methodName, value, confirmed: true }),
    );
    // A freshly-confirmed email factor is an inbox proof — record the
    // correspondence address. Unconditional sibling of the policy-gated
    // `promote-to-handle` write that follows this step.
    if (methodName === "email") await this.users.setVerifiedEmail(username, value);
    // Make this the default UNLESS the flow asked to keep the existing one (the
    // user is adding/replacing a secondary factor, not setting their first). On
    // the login/invite forced-enrolment path `keepExistingDefault` is unset and
    // the user has no default yet, so the first method still becomes default.
    if (!m.keepExistingDefault) await this.users.setDefaultMfaMethod(username, methodName);
    m.done = true;
    (ctx.otp ??= {}).verified = true;
    this.clearPin(ctx);
  }

  /**
   * Promote a freshly-confirmed channel into its login-handle column so future
   * login + recovery resolve the account by it (`findByHandle`). Runs once,
   * right after `enroll-confirm` in the shared enrolment trio (so it covers
   * add-mfa AND login/invite forced first-time enrolment). Default is a no-op
   * unless `resolvePromoteHandleField` is overridden to name a handle column.
   *
   * Overridable extension point: a deployment can replace this with richer
   * logic — e.g. pause on a carrier form asking whether to use the new number
   * as a login handle before writing it.
   *
   * Fires only for a freshly-confirmed `email` / `sms` factor carrying an
   * address. TOTP has no address; a skipped / `useDifferentMethod` enrolment
   * cleared `method` + `address` via `clearEnrollScratch`, so the guard below
   * excludes both — only an actually-confirmed channel is promoted.
   */
  @Step("promote-to-handle")
  @Public()
  async promoteToHandle(@WorkflowParam("context") ctx: AuthWfCtx): Promise<undefined> {
    const m = ctx.mfaEnroll;
    if (ctx.subject && m?.address && (m.method === "email" || m.method === "sms")) {
      const field = await this.resolvePromoteHandleField(ctx, m.method);
      if (field) await this.applyHandlePromotion(ctx.subject, field, m.address);
    }
    ctx.promoteToHandleDone = true;
    return undefined;
  }

  /**
   * Best-effort write of a confirmed channel value into its handle column.
   * Swallows `ALREADY_EXISTS` — the value is already a handle on ANOTHER
   * account (e.g. two accounts legitimately sharing one phone for MFA): the
   * second account keeps the factor as MFA-only and is simply not promoted.
   * Any other store error propagates. (`UserService.update` translates a
   * unique-index `CONFLICT` to `ALREADY_EXISTS` for both store adapters.)
   */
  protected async applyHandlePromotion(
    subject: string,
    field: string,
    value: string,
  ): Promise<void> {
    try {
      await this.users.update(subject, { [field]: value });
    } catch (err) {
      if (err instanceof UserAuthError && err.type === "ALREADY_EXISTS") return;
      throw err;
    }
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
      this.clearPin(ctx);
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
    if (!ctx.subject) return undefined;
    const ip = this.opts.deviceTrust.bindsTo === "cookie+ip" ? this.resolveClientIp() : undefined;
    const record = await this.issueTrustedDevice(ctx.subject, ip, this.opts.deviceTrust.ttlMs);
    await this.storeTrustedDevice(ctx.subject, record);
    // Stash the token for `issue` to attach to the FINISH ENVELOPE's `cookies`
    // map — NOT `useResponse().setCookie` here. The wf-trigger outlet builds its
    // response from the `WfFinished` envelope and ignores response-context
    // cookies on a redirect finish: a response-context `setCookie` survives a
    // DATA finish by luck, but a consumer whose login finishes with a server
    // `redirect` (the `redirect` step preserves only `existing.cookies`) would
    // silently lose the trusted-device cookie → MFA never gets skipped on the
    // next login. Same envelope mechanism `issue` uses for the session cookie
    // and `beginSso` for the CSRF cookie.
    (ctx.trust ??= {}).deviceTrustToken = record.token;
    return undefined;
  }

  /**
   * Always-on device RECOGNITION — verify-or-mint the long-lived recognition
   * cookie against the `seenDevices` ledger. Recognition is a notification
   * suppressor ONLY (the notify-new-device gate reads `trust.recognized`); it
   * never skips MFA — that is `deviceTrust`, which stays opt-in and strict.
   *
   * Deliberately a SEPARATE step from `check-trusted-device`: that step is
   * schema-gated on `deviceTrust.enabled && skipsMfa`, so recognition must
   * not piggyback on it or recognition dies whenever trust is disabled —
   * exactly the consumers who get the noisiest notify behaviour today.
   * Verify-or-mint lives in ONE step so `trust.recognized` captures the
   * PRE-MINT arrival state the notify gate needs (a freshly minted token
   * must not mark the current login as recognized).
   *
   * A valid arriving cookie is verified with `slideTtlMs` (LRU bump) and
   * re-stashed on `trust.seenDeviceToken` so `issue` re-sets it with a fresh
   * maxAge. An unrecognized arrival mints + persists a new record (capped at
   * `deviceRecognition.maxDevices`) and stashes the new token — `recognized`
   * stays unset so the notification still fires for this login. Degrades
   * gracefully to a no-op when no `deviceTrust.secret` is configured,
   * preserving the legacy notify behaviour for those consumers.
   */
  @Step("device-recognition")
  @Public()
  async deviceRecognition(@WorkflowParam("context") ctx: AuthWfCtx): Promise<undefined> {
    if (!ctx.subject) return undefined;
    if (!this.users.hasDeviceTrustSecret()) return undefined;
    const cookieValue = useCookies(current()).getCookie(this.opts.deviceRecognition.cookieName);
    const trust = (ctx.trust ??= {});
    if (cookieValue) {
      const ok = await this.users.verifySeenDevice(ctx.subject, cookieValue, {
        slideTtlMs: this.opts.deviceRecognition.ttlMs,
      });
      if (ok) {
        trust.recognized = true;
        trust.seenDeviceToken = cookieValue;
        return undefined;
      }
    }
    // `issueSeenDevice` drops an `undefined` name itself — pass it through.
    const record = this.users.issueSeenDevice(ctx.subject, {
      ttlMs: this.opts.deviceRecognition.ttlMs,
      name: humanizeUserAgent(this.resolveUserAgent()),
    });
    await this.users.addSeenDevice(ctx.subject, record, {
      cap: this.opts.deviceRecognition.maxDevices,
    });
    trust.seenDeviceToken = record.token;
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
    if (!ctx.subject) return undefined;
    const n = await this.loadActiveSessionsCount(ctx.subject);
    (ctx.session ??= {}).activeSessions = n;
    return undefined;
  }

  /**
   * Concurrency-limit gate — pauses for `ConcurrencyLimitForm`. `reject` mode
   * blocks the login outright with a form-level error. `kickPrompt` mode pauses
   * on the fieldless prompt; submitting it (the 'Login' button) logs out the
   * user's other sessions and continues. `resolveInput()` throws to pause on
   * first arrival and returns once the submit resumes the step.
   */
  @Step("concurrency-limit")
  @Public()
  async concurrencyLimit(@WorkflowParam("context") ctx: AuthWfCtx): Promise<unknown> {
    const cfg = ctx.sessionPolicy?.concurrencyLimit;
    if (!cfg) return undefined;
    const wf = this.useAtscriptWfPublic(ctx, this.opts.forms.concurrencyLimit);
    if (cfg.onLimit === "reject") {
      throw this.throwPublic(ctx, wf, { formMessage: this.msg("SESSION_LIMIT_REACHED") });
    }
    wf.resolveInput(); // first arrival throws requireInput (pauses); the 'Login' submit resumes here
    if (ctx.subject) await this.logoutOtherSessions(ctx.subject);
    return undefined;
  }

  // ── Extra-step (1) — login + invite, gated on isFirstLogin ──

  /**
   * Consumer extension point — override in your subclass to inject extra
   * accept-tail logic (input pauses, alt actions, persistence). Default:
   * no-op.
   */
  @Step("extra-step")
  @Public()
  // oxlint-disable-next-line typescript/no-redundant-type-constituents -- explicit sync|async override seam, see CLAUDE.md "Pure extension-point stubs"
  extraStep(@WorkflowParam("context") _ctx: AuthWfCtx): unknown | Promise<unknown> {
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
    this.requireSubject(ctx);
    const group = ctx.consents ?? {};
    const pending = group.pending ?? [];
    if (pending.length === 0) return undefined;
    // Invite accept: no consent record lands through a superseded / used link.
    if (ctx.accept) await this.assertInviteStillOpen(ctx);
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
    await this.consentStore.save(ctx.subject, events);
    return undefined;
  }

  // ── Recovery (1) ──

  /**
   * Revoke the user's existing sessions. Shared by recovery (gated upstream by
   * `ctx.postReset.revokeAllSessions`), authenticated change-password (gated
   * by `ctx.changePassword.revokeOtherSessions`) and the forced password change
   * at login / invite (gated by `ctx.passwordChanged`).
   *
   * - Change-password runs in an authenticated context, so we KEEP the caller's
   *   current session via `revokeOtherSessions(username, currentSessionId)` —
   *   OWASP "invalidate other sessions" without logging the user out of the tab
   *   they just changed their password in. `finish-change-password` then moves
   *   that tab onto a fresh session and revokes the kept one (and covers stores
   *   that cannot enumerate, where `revokeOtherSessions` is a no-op). If the
   *   current session can't be resolved (no session id), fall back to revoking
   *   everything (fail-secure).
   * - Recovery and the forced change are anonymous (no current session to
   *   keep) → `revokeAllForUser`.
   */
  @Step("revoke-sessions")
  @Public()
  async revokeSessions(@WorkflowParam("context") ctx: AuthWfCtx): Promise<undefined> {
    if (!ctx.subject) return undefined;
    const currentSessionId = ctx.changePassword?.revokeOtherSessions
      ? useAuth().getSessionId()
      : undefined;
    // Clear the recognition ledger alongside the sessions — a recognition
    // cookie is a long-lived identifier, and password change / revoke-all are
    // its designed clearing points (each device re-mints on its next login,
    // and the single "new sign-in" email after a password change is desirable
    // signal). Independent stores, so the two revocations run concurrently.
    await Promise.all([
      currentSessionId
        ? this.auth.revokeOtherSessions(ctx.subject, currentSessionId)
        : this.auth.revokeAllForUser(ctx.subject),
      this.users.revokeSeenDevices(ctx.subject),
    ]);
    return undefined;
  }

  /**
   * Lift a failed-login lockout after a successful password reset. Recovery
   * only — gated upstream by `ctx.lockout?.mode === "self-service"` so the
   * `admin-only` mode keeps the account frozen (reset succeeds, lock stays)
   * and `temporary` continues to rely on its own timeout. `unlockAccount`
   * also zeroes `failedLoginAttempts`, so the next login starts clean.
   */
  @Step("unlock-account")
  @Public()
  async unlockAccount(@WorkflowParam("context") ctx: AuthWfCtx): Promise<undefined> {
    if (!ctx.subject) return undefined;
    await this.users.unlockAccount(ctx.subject);
    return undefined;
  }

  // ── Finalize (5) ──

  /**
   * Login-only guard before the `record-login` funnel (and again before
   * `mint-authz-code`, past the consent pause): the account's
   * `password.lastChanged` must still be the one the `credentials` step
   * verified (`ctx.passwordStamp`). A run paused after the password check (MFA,
   * enrolment, consents …) and resumed after the password was changed
   * elsewhere finishes with an error instead of issuing tokens or minting an
   * authorization code. Skipped when this run changed the password itself.
   */
  @Step("check-password-unchanged")
  @Public()
  async checkPasswordUnchanged(@WorkflowParam("context") ctx: AuthWfCtx): Promise<undefined> {
    this.requireSubject(ctx);
    const user = await this.users.getUser(ctx.subject);
    if ((user.password.lastChanged ?? 0) !== ctx.passwordStamp) {
      ctx.aborted = true;
      finishWf({ message: { level: "error", text: this.msg("PASSWORD_CHANGED_SIGN_IN_AGAIN") } });
    }
    return undefined;
  }

  /**
   * Login-only guard before the `record-login` funnel: an account deactivated
   * or locked while the run was paused (MFA, enrolment, consents …) is not
   * stamped, announced or signed in — the run finishes with an error.
   */
  @Step("check-can-sign-in")
  @Public()
  async checkCanSignIn(@WorkflowParam("context") ctx: AuthWfCtx): Promise<undefined> {
    await this.loginAccountBlocked(ctx);
    return undefined;
  }

  /**
   * Whether the run's account can no longer sign in (deactivated, locked or
   * deleted since it authenticated). If so the run is finished with an error
   * (`AOOTH_ACCOUNT_LOCKED` for a lock unless `lockoutDisclosure` is
   * `'generic'`, else `INVALID_CREDENTIALS`) and `ctx.aborted` is set.
   */
  private async loginAccountBlocked(ctx: AuthWfCtx): Promise<boolean> {
    this.requireSubject(ctx);
    try {
      await this.users.assertCanSignIn(ctx.subject);
      return false;
    } catch (err) {
      if (!(err instanceof UserAuthError)) throw err;
      const locked = err.type === "LOCKED" && this.opts.lockoutDisclosure !== "generic";
      ctx.aborted = true;
      finishWf({
        message: {
          level: "error",
          text: this.msg(locked ? "AOOTH_ACCOUNT_LOCKED" : "INVALID_CREDENTIALS"),
        },
      });
      return true;
    }
  }

  /**
   * The SINGLE login-completion funnel. Every flow that establishes an
   * authenticated session routes through here — placed in each login schema
   * right after the guards and BEFORE the delivery terminal (`issue` /
   * `mint-authz-code` / `finalize-auto-login`) — so a login can never be
   * delivered without passing this point. Two uniform jobs:
   *   1. Stamp `account.lastLogin` exactly once (the sole workflow writer of it).
   *   2. Fire the `afterLogin` customer hook.
   *
   * Idempotent per run via `ctx.loginRecorded`: the password `credentials` path
   * already stamped eagerly through `users.login()` and latched the flag, so the
   * stamp NO-OPS there (no double write) — but `afterLogin` still fires, so the
   * hook runs exactly once for password logins too. Federated (`sso-callback`)
   * and auto-login (invite/signup/recovery) paths never call `login()`, so this
   * is their sole stamp. Self-gates on `ctx.subject`. Runs AFTER
   * `prepare-semantic-flags` derived `isFirstLogin`, so a genuine first
   * federated login still observes `isFirstLogin === true`.
   *
   * A throw (from the stamp or the hook) aborts the flow BEFORE delivery, so the
   * login fails atomically — no half-issued session.
   */
  @Step("record-login")
  @Public()
  recordLogin(@WorkflowParam("context") ctx: AuthWfCtx): undefined | Promise<undefined> {
    if (!ctx.subject) return undefined;
    if (!ctx.loginRecorded) {
      ctx.loginRecorded = true;
      // Stamp branch (federated / auto-login): genuinely async (store write).
      return this.users
        .recordLogin(ctx.subject)
        .then(() => this.afterLogin(ctx))
        .then(() => undefined);
    }
    // Password path: `credentials` already stamped + latched, so the hook is the
    // only work left — stay on the sync fast path when afterLogin is the default
    // no-op (house "no async on a sync-default @Step body" rule; mirrors the
    // fire* dispatcher steps below).
    const hook = this.afterLogin(ctx);
    return hook instanceof Promise ? hook.then(() => undefined) : undefined;
  }

  /**
   * Recovery-only guard, extracted from the finalize terminals so they stay pure
   * delivery. An `admin-only` lockout never self-unlocks, so a reset that left
   * the account frozen must NOT be confirmed-as-success OR auto-logged-in
   * (minting tokens would defeat the very freeze). When still locked it emits the
   * warn terminal and sets `ctx.aborted`, so the schema's following `{ break }`
   * skips BOTH the `record-login` funnel and the finalize terminals — a frozen
   * account is never stamped or logged in. The schema gates this on
   * `ctx.lockout?.mode === "admin-only"` (the only mode that can reach finalize
   * still locked: self-service ran `unlock-account`; temporary auto-expires).
   */
  @Step("recovery-lock-check")
  @Public()
  async recoveryLockCheck(@WorkflowParam("context") ctx: AuthWfCtx): Promise<undefined> {
    if (await this.recoveryLeftAccountLocked(ctx)) {
      this.finishRecoveryReset(ctx, true);
      ctx.aborted = true;
    }
    return undefined;
  }

  /**
   * Auto-login guard, ahead of `record-login` on every auto-login path (invite,
   * recovery, signup): never stamp a login, fire `afterLogin` or issue a
   * session for an account that is no longer active (deactivated meanwhile —
   * every flow reaching here activated or verified it first). Recovery and
   * invite fall back to the fresh-login finish (no session); signup fails.
   */
  @Step("auto-login-check")
  @Public()
  async autoLoginCheck(@WorkflowParam("context") ctx: AuthWfCtx): Promise<undefined> {
    this.requireSubject(ctx);
    const { account } = await this.users.getUser(ctx.subject);
    if (account.active) return undefined;
    if (!ctx.postReset && !ctx.accept) throw new HttpError(403, "Account is not active");
    this.finalizeFreshLogin(ctx);
    // The run no longer logs in: `record-login` and `finalize-auto-login` skip.
    ctx.autoLogin = false;
    return undefined;
  }

  /**
   * Thin dispatcher steps for the flow-specific lifecycle hooks. Each is its own
   * schema step (rather than an in-terminal call) because its flow's finalize
   * terminals are SHARED across flows (`finalize-auto-login` serves invite +
   * recovery + signup; `finalize-fresh-login` serves invite + recovery), so a
   * dedicated step in the flow-specific schema fires the right hook without
   * ctx-discrimination inside a shared terminal. Named `fire*` so the overridable
   * `after*` hooks keep the clean public name.
   */
  @Step("after-invitation-accepted")
  @Public()
  fireInvitationAccepted(@WorkflowParam("context") ctx: AuthWfCtx): void | Promise<void> {
    return this.afterInvitationAccepted(ctx);
  }

  @Step("after-signup")
  @Public()
  fireSignup(@WorkflowParam("context") ctx: AuthWfCtx): void | Promise<void> {
    return this.afterSignup(ctx);
  }

  @Step("after-password-reset")
  @Public()
  firePasswordReset(@WorkflowParam("context") ctx: AuthWfCtx): void | Promise<void> {
    return this.afterPasswordReset(ctx);
  }

  /**
   * Issue access + refresh tokens via `auth.issue`. Stashes the login
   * response envelope on `useWfFinished` so downstream `redirect` can
   * override with a redirect envelope while preserving the cookies.
   */
  @Step("issue")
  @Public()
  async issue(@WorkflowParam("context") ctx: AuthWfCtx): Promise<void> {
    this.requireSubject(ctx);
    // Defense in depth (`check-can-sign-in` runs first in the bundled schema):
    // never a session for an account deactivated or locked meanwhile.
    try {
      await this.users.assertCanSignIn(ctx.subject);
    } catch (err) {
      if (err instanceof UserAuthError) throw new HttpError(403, "Account cannot sign in");
      throw err;
    }
    const issue = await this.issueForContext(ctx);
    const auth = useAuth();
    const envelope: WfFinished = {
      finished: true,
      data: auth.buildLoginResponse(ctx.subject, issue),
    };
    // Attach the trusted-device cookie (minted by `device-trust`) and the
    // recognition cookie (verified-or-minted by `device-recognition`) to the
    // finish envelope alongside the session cookies, so they survive a server
    // `redirect` finish (where the `redirect` step preserves only
    // `existing.cookies`, never response-context `setCookie`). Independent of
    // `enableCookie` — device trust/recognition are separate concerns from
    // token transport — so they're added even when `buildFinishedCookies`
    // returns undefined (cookieless deploys). The recognition cookie is set
    // even when the arriving one was valid — re-issuing refreshes its maxAge
    // in step with the server-side TTL slide.
    let cookies = auth.buildFinishedCookies(issue);
    const attachDeviceCookie = (name: string, value: string | undefined, ttlMs: number) => {
      if (!value) return;
      cookies = {
        ...cookies,
        // A unit-explicit `'<n>s'` string — wooks reads a bare number
        // differently across versions (milliseconds before 0.8, seconds since).
        [name]: {
          value,
          options: auth.cookieAttrs({ maxAge: `${Math.max(0, Math.floor(ttlMs / 1000))}s` }),
        },
      };
    };
    attachDeviceCookie(
      this.opts.deviceTrust.cookieName,
      ctx.trust?.deviceTrustToken,
      this.opts.deviceTrust.ttlMs,
    );
    attachDeviceCookie(
      this.opts.deviceRecognition.cookieName,
      ctx.trust?.seenDeviceToken,
      this.opts.deviceRecognition.ttlMs,
    );
    useWfFinished().set({
      type: "data",
      value: envelope,
      ...(cookies && { cookies }),
    });
  }

  /**
   * Notify the user of a login from a new device via the unified `deliver`
   * hook. Gated upstream by
   * `!ctx.isFirstLogin && !!ctx.finalize.notifyNewDevice && !ctx.trust.recognized`
   * — "not recognized" (no valid recognition cookie on arrival), NOT "no
   * valid trust cookie": users who decline remember-me, or whose strict trust
   * cookie expired / failed IP binding, must not get the email on every
   * login. Recognition is the loose always-on ledger minted by
   * `device-recognition`; trust stays strict and drives MFA skip only.
   *
   * Recipient is `notice.email` — the security-notice slot owned by the
   * `credentials` / `seedChannelState` seeding and refreshed by
   * `verify/email`. No recipient seeded → silently skips.
   */
  @Step("notify-new-device")
  @Public()
  async notifyNewDevice(@WorkflowParam("context") ctx: AuthWfCtx): Promise<undefined> {
    const recipient = ctx.notice?.email;
    if (!recipient) return undefined;
    await this.dispatch({
      kind: "new-device-notice",
      channel: "email",
      recipient,
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
   * Authorization-server consent gate (AUTH-SERVER.md §4.4 / §6). Runs BEFORE
   * `mint-authz-code` whenever `ctx.authz` is set. Two mandatory jobs:
   *
   *  1. **Browser binding** — verify the request carries the `aooth_authz`
   *     cookie that constant-time-matches the secret recorded on the pending
   *     authorization. An `authz` handle phished into a DIFFERENT browser (the
   *     account-takeover primitive) fails here, because the secret lives only
   *     in the browser that initiated `GET /auth/authorize`.
   *  2. **Explicit consent** — pause on the consent form and require the user
   *     to press 'Authorize'. 'Deny' (or abandoning) 302s the client back with
   *     `error=access_denied` and mints nothing. This blocks the same-browser
   *     forced-navigation variant: a logged-in / silently-SSO-re-authenticated
   *     victim is shown WHICH client is asking and must approve it.
   *
   * On approval it stamps `ctx.authz.approved`, which `mint-authz-code`
   * re-checks alongside a binding re-verification before minting.
   */
  @Step("authz-consent")
  @Public()
  async authzConsent(@WorkflowParam("context") ctx: AuthWfCtx): Promise<undefined> {
    this.requireSubject(ctx);
    const authz = ctx.authz;
    const { pending } = await this.authorizeRuntime();
    const req = authz ? await pending.get(authz.handle) : null;
    if (!authz || !req) {
      finishWf({
        message: { level: "error", text: this.msg("AUTHZ_EXPIRED") },
      });
      return undefined;
    }
    // (1) Browser binding — fail fast (and burn the handle) BEFORE prompting, so
    // a handle phished into the wrong browser never renders a consent prompt.
    if (!this.verifyAuthzBinding(req)) {
      await pending.delete(authz.handle);
      finishWf({
        message: {
          level: "error",
          text: this.msg("AUTHZ_BROWSER_MISMATCH"),
        },
      });
      return undefined;
    }
    // Stage the display copy for the consent form. `clientName` is the
    // registered display name (DCR `client_name` — UNTRUSTED text, the form
    // renders it as text only), falling back to the raw `clientId`; both absent
    // (public/loopback client) → the form reads "A local application". The
    // VALIDATED redirect host rides along as the trustworthy identity — it is
    // where the code is actually delivered, which a self-chosen name can't fake.
    const clientName = req.clientName ?? req.clientId;
    if (clientName !== undefined) authz.clientName = clientName;
    if (req.scope !== undefined) authz.scope = req.scope;
    try {
      authz.redirectHost = new URL(req.redirectUri).host;
    } catch {
      // Display-only — an unparsable URI (can't happen for a policy-validated
      // redirect) just leaves the host line off the consent copy.
    }

    // (2) Explicit consent — pause, then branch on Deny vs the Authorize submit.
    const wf = this.useAtscriptWfPublic(ctx, this.opts.forms.authzConsent);
    if (wf.resolveAction() === "deny") {
      await pending.delete(authz.handle);
      finishWf({
        next: {
          trigger: "immediate",
          action: {
            type: "redirect",
            target: authzRedirectUrl(req.redirectUri, {
              error: "access_denied",
              state: req.clientState,
            }),
            reason: "authz-denied",
          },
        },
      });
      return undefined;
    }
    wf.resolveInput(); // pause until the 'Authorize' submit
    authz.approved = true;
    return undefined;
  }

  /**
   * Constant-time match of the `aooth_authz` binding cookie against the secret
   * recorded on the pending authorization. Fail-closed (`false`) when the cookie
   * is absent or differs, so a request without the browser binding can never
   * redeem the handle. See {@link authzConsent}.
   */
  protected verifyAuthzBinding(req: { binding: string }): boolean {
    const cookie = useCookies(current()).getCookie(AUTHZ_BINDING_COOKIE);
    return safeEqual(cookie, req.binding);
  }

  /**
   * Authorization-server terminal (AUTH-SERVER.md §4.4). Reached INSTEAD of
   * `issue`/`redirect` when this login was started from `GET /auth/authorize`
   * (`ctx.authz` set by `init-login` or re-raised by `sso-callback`). Mints a
   * single-use authorization code bound to the authenticated user + the pending
   * request's PKCE challenge / redirect / token policy, then 302s the browser to
   * `redirect_uri?code&state`. It does NOT issue a session and attaches NO
   * cookies — the token is minted later, off the browser, at `POST /auth/token`.
   * Gated by {@link authzConsent} (binding + explicit approval).
   */
  @Step("mint-authz-code")
  @Public()
  async mintAuthzCode(@WorkflowParam("context") ctx: AuthWfCtx): Promise<undefined> {
    this.requireSubject(ctx);
    const handle = ctx.authz?.handle;
    const { pending, codes } = await this.authorizeRuntime();
    const req = handle ? await pending.get(handle) : null;
    if (!handle || !req) {
      // The pending authorization expired / is unknown (or a forged `authz`
      // handle) — fail soft: no session, no code.
      finishWf({
        message: { level: "error", text: this.msg("AUTHZ_EXPIRED") },
      });
      return undefined;
    }
    // Defense in depth: mint ONLY after `authz-consent` verified the browser
    // binding AND captured explicit approval. `authz-consent` runs first and
    // finishes the run on a binding failure or a deny, so in the normal path
    // `approved` is set and the binding re-check passes here; a reordering /
    // direct-resume that skips consent fails closed (no `approved` ⇒ no code).
    if (ctx.authz?.approved !== true || !this.verifyAuthzBinding(req)) {
      await pending.delete(handle);
      finishWf({
        message: {
          level: "error",
          text: this.msg("AUTHZ_FAILED"),
        },
      });
      return undefined;
    }
    // `authz-consent` paused: the account may have been deactivated or locked since.
    if (await this.loginAccountBlocked(ctx)) {
      await pending.delete(handle);
      return undefined;
    }
    const { code } = await codes.mint({
      userId: ctx.subject,
      codeChallenge: req.codeChallenge,
      redirectUri: req.redirectUri,
      ...(req.clientId !== undefined && { clientId: req.clientId }),
      ...(req.scope !== undefined && { scope: req.scope }),
      ...(req.resource !== undefined && { resource: req.resource }),
      ...(req.nonce !== undefined && { nonce: req.nonce }),
      ...(req.idToken !== undefined && { idToken: req.idToken }),
      ...(req.accessToken !== undefined && { accessToken: req.accessToken }),
      ...(req.audience !== undefined && { audience: req.audience }),
      tokenPolicy: req.tokenPolicy,
    });
    await pending.delete(handle);

    finishWf({
      next: {
        trigger: "immediate",
        action: {
          type: "redirect",
          target: authzRedirectUrl(req.redirectUri, { code, state: req.clientState }),
          reason: "authz-code",
        },
      },
    });
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
    // Invite — immediate redirect to login (no confirmation dwell).
    if (!ctx.postReset) {
      const target = ctx.accept!.loginUrl!;
      finishWf({
        next: {
          trigger: "immediate",
          action: { type: "redirect", target, reason: "fresh-login-required" },
        },
      });
      (ctx.completion ??= {}).redirectUrl = target;
      return undefined;
    }
    // Recovery — confirm success + auto-redirect to sign-in. The still-locked
    // case (an `admin-only` lock that survived the reset) is caught UPSTREAM by
    // `recovery-lock-check`, which emits its own warn terminal and `{ break }`s
    // before reaching here, so this terminal only ever sees an unlocked reset.
    this.finishRecoveryReset(ctx, false);
    return undefined;
  }

  /**
   * Post-reset store read: did an `admin-only` lockout survive the password
   * reset (account still frozen)? Callers MUST first confirm
   * `ctx.lockout?.mode === "admin-only"` so this read stays off the sync fast
   * path for every other recovery + invite finalize — `self-service` ran
   * `unlock-account` and `temporary` auto-expires, so only `admin-only` can
   * reach finalize still locked. Shared by BOTH finalize terminals: fresh-login
   * warns instead of confirming success, auto-login warns instead of minting
   * tokens (a still-frozen account must never be logged straight in).
   */
  private recoveryLeftAccountLocked(ctx: AuthWfCtx): Promise<boolean> {
    this.requireSubject(ctx);
    return this.users.getUser(ctx.subject).then((user) => user.account.locked);
  }

  /**
   * Emit the recovery password-reset terminal. `stillLocked` is only ever true
   * for an `admin-only` account whose lock survived the reset — that terminal
   * warns the user the account remains frozen and offers a manual back-to-
   * sign-in (no misleading auto-redirect to a login they can't pass yet).
   * Every other reset confirms success and auto-redirects to sign-in.
   */
  private finishRecoveryReset(ctx: AuthWfCtx, stillLocked: boolean): void {
    const target = ctx.postReset!.loginUrl!;
    if (stillLocked) {
      finishWf({
        message: {
          level: "warn",
          text: this.msg("PASSWORD_UPDATED_STILL_LOCKED"),
        },
        next: {
          trigger: "manual",
          primary: {
            label: this.msg("BACK_TO_SIGN_IN"),
            action: { type: "redirect", target, reason: "reset-locked" },
          },
        },
      });
    } else {
      finishWf({
        message: { level: "success", text: this.msg("PASSWORD_UPDATED_REDIRECTING") },
        next: {
          trigger: "auto",
          timeoutMs: 5000,
          action: { type: "redirect", target, reason: "reset-success" },
          skipButton: { label: this.msg("AOOTH_GO_NOW") },
        },
      });
    }
    (ctx.completion ??= {}).redirectUrl = target;
  }

  /**
   * Auto-login finalize — invite + recovery + signup. PURE delivery: issues
   * access + refresh tokens and stashes the login response envelope on
   * `useWfFinished`. Invite preserves any `message` set by an earlier terminal
   * (`confirmation`) so the SPA paints the confirmation text alongside the
   * tokens (WF-INVITE-020).
   *
   * It records NOTHING and guards NOTHING: `account.lastLogin` + the
   * `afterLogin` hook are owned by the upstream `record-login` funnel step,
   * the inactive-account guard by `auto-login-check`, and the
   * admin-only-survived-lock guard by `recovery-lock-check` — all upstream, so
   * an inactive or still-frozen account never reaches here.
   */
  @Step("finalize-auto-login")
  @Public()
  async finalizeAutoLogin(@WorkflowParam("context") ctx: AuthWfCtx): Promise<undefined> {
    this.requireSubject(ctx);
    // Defense in depth for custom schemas (`auto-login-check` runs first).
    if (!(await this.users.getUser(ctx.subject)).account.active) {
      throw new HttpError(403, "Account is not active");
    }
    const issue = await this.issueForContext(ctx);
    const auth = useAuth();
    const previousMessage = (useWfFinished().get()?.value as WfFinished | undefined)?.message;
    const envelope: WfFinished = {
      finished: true,
      data: auth.buildLoginResponse(ctx.subject, issue),
      ...(previousMessage && { message: previousMessage }),
    };
    useWfFinished().set({
      type: "data",
      value: envelope,
      cookies: auth.buildFinishedCookies(issue),
    });
    return undefined;
  }

  // ── Signup flow (4) — verify-first self-signup (auth/signup/flow) ──

  /**
   * Entry step of `auth/signup/flow`. Inline-resolves the signup policy (runs
   * BEFORE the `!allowSignup` gate, mirroring how `credentials` / `request`
   * inline the front policies they need) and stamps `ctx.signup` — whose
   * presence is the flow discriminator. Sets `ctx.autoLogin = true`: v1 always
   * issues a session on success (the shared `finalize-fresh-login` assumes
   * invite/recovery ctx slots, so signup uses `finalize-auto-login` only).
   * When self-signup is disabled (the default), emits a terminal finish so the
   * SPA shows a closed-signups message instead of a form; the schema's
   * `{ break: !allowSignup }` short-circuits the rest.
   */
  @Step("init-signup")
  @Public()
  initSignup(@WorkflowParam("context") ctx: AuthWfCtx): undefined | Promise<undefined> {
    const apply = (policy: NonNullable<AuthWfCtx["signup"]>): undefined => {
      ctx.signup = policy;
      ctx.autoLogin = true;
      if (!policy.allowSignup) {
        finishWf({ message: { level: "info", text: this.msg("SIGNUP_DISABLED") } });
      }
      return undefined;
    };
    const result = this.resolveSignupPolicy(ctx);
    return result instanceof Promise ? result.then(apply) : apply(result);
  }

  /**
   * Collect the signup email (verify-first — no account exists yet). First
   * entry pauses on `SignupForm`; on submit, stashes `ctx.email` and flips
   * `ctx.signup.submitted` to open the OTP loop. `backToLogin` aborts to the
   * login page. The bundled form is email-only (`username := email`); a custom
   * `opts.forms.signup` + an override here can collect more.
   */
  @Step("signup-form")
  @Public()
  async signupForm(@WorkflowParam("context") ctx: AuthWfCtx): Promise<undefined> {
    const wf = this.useAtscriptWfPublic(ctx, this.opts.forms.signup);
    if (wf.resolveAction() === "backToLogin") {
      // "I already have an account" — a deliberate cross-link to sign-in (NOT a
      // cancel), since signup is typically the initial flow. `goto-login`
      // distinguishes it from the post-OTP `already-registered` detection.
      finishWf({
        next: {
          trigger: "immediate",
          action: { type: "redirect", target: this.opts.loginUrl, reason: "goto-login" },
        },
      });
      ctx.aborted = true;
      return undefined;
    }
    const input = wf.resolveInput() as { email: string };
    ctx.email = input.email;
    (ctx.signup ??= {}).submitted = true;
    // Move off the cheap encapsulated start onto the durable store strategy so
    // the OTP + password-set pauses survive restarts (mirrors recovery's `request`).
    swapStrategy("store");
    return undefined;
  }

  /**
   * Create the account — runs AFTER the OTP loop, so the email is proven. The
   * existence check lives HERE (not before the OTP) so the wire path is
   * identical for new and already-registered emails: both received an OTP
   * pause, so an attacker on the wire cannot enumerate accounts. A taken email
   * is only revealed to someone who actually controls the inbox, at which point
   * we route them to sign-in. A new email creates the (still-inactive) user and
   * arms the shared password-set phase (`newPasswordRequired`); the reused
   * `activate-user` step flips it active AFTER the password is set.
   */
  @Step("signup-create-user")
  @Public()
  async signupCreateUser(@WorkflowParam("context") ctx: AuthWfCtx): Promise<undefined> {
    const email = ctx.email;
    if (!email) throw new HttpError(500, "Workflow state corrupted: missing email");
    const existing = await this.users.findByHandle(email);
    if (existing) {
      this.finishSignupAlreadyRegistered();
      return undefined;
    }
    // Reuse the invite `prepareUser` hook to source app-required columns
    // (e.g. a NOT-NULL `tenantId`). Signup is distinguishable inside an
    // override by the absence of `invitedBy` + empty `roles`.
    const extras = await this.prepareUser({ email, roles: [] });
    let created: UserCredentials;
    try {
      // username := email (bundled form is email-only); no password yet — the
      // shared SetPasswordForm collects it next, so nothing plaintext is held
      // in wf-state across the OTP wait.
      created = await this.users.createUser(email, undefined, extras);
    } catch (err) {
      // Race: a concurrent signup created the row between findByHandle and here.
      if (err instanceof UserAuthError && err.type === "ALREADY_EXISTS") {
        this.finishSignupAlreadyRegistered();
        return undefined;
      }
      throw err;
    }
    ctx.subject = created.id;
    // No verifiedEmail write here — the reused `activate-user` step captures
    // the OTP-proven inbox from `ctx.email` once the password is set.
    ctx.newPasswordRequired = true;
    (ctx.password ??= {}).changeReason = "initial";
    return undefined;
  }

  /** Generic "you already have an account" finish for the signup existence collision (safe — only reached post-OTP). */
  private finishSignupAlreadyRegistered(): void {
    finishWf({
      message: { level: "info", text: this.msg("AOOTH_ALREADY_HAVE_ACCOUNT") },
      next: {
        trigger: "immediate",
        action: { type: "redirect", target: this.opts.loginUrl, reason: "already-registered" },
      },
    });
  }

  /**
   * Customer extension point for signup — runs after the account is created,
   * activated, and consents persisted, just before `finalize-auto-login`. The
   * default is a no-op; a subclass overrides it to seed app-specific rows
   * (tenant, profile, welcome email, audit record, ConsentStore.save, …) for
   * the freshly-created `ctx.subject`. Mirrors login's `extra-step` seam.
   */
  @Step("signup-extra-step")
  @Public()
  // oxlint-disable-next-line typescript/no-redundant-type-constituents -- explicit sync|async override seam, see CLAUDE.md "Pure extension-point stubs"
  signupExtraStep(@WorkflowParam("context") _ctx: AuthWfCtx): unknown | Promise<unknown> {
    return undefined;
  }

  // ── Magic links (recovery + sign-in) ──

  /**
   * Login's `magicLink` alt-action: the identifier form. Resolves the account
   * (unknown, inactive or locked identifiers resolve to none — the answer is
   * the same) and hands over to `magic-link-send`.
   */
  @Step("magic-link-request")
  @Public()
  async magicLinkRequest(@WorkflowParam("context") ctx: AuthWfCtx): Promise<unknown> {
    const ml = ctx.magicLink;
    if (!ml || ml.purpose !== "login" || ml.sentAt !== undefined) return undefined;
    const wf = this.useAtscriptWfPublic(ctx, this.opts.forms.magicLinkRequest);
    const { identifier } = wf.resolveInput() as { identifier: string };
    const user = await this.users.findByHandle(identifier.trim());
    if (user) ml.subject = user.id;
    ml.identifier = identifier.trim().toLowerCase();
    return undefined;
  }

  /**
   * Send a magic link (recovery or sign-in) and pause until it is used. The
   * pause is persisted under the `magic-link` strategy — a fresh, hashed,
   * single-use handle that expires with the link (`magicLinkTtlMs`) — and the
   * `magic-link` outlet hands the token to the email outlet only. Known and
   * unknown identifiers take the same path and get the same answer; nothing is
   * sent for an unknown identifier, an account without a proven inbox, a
   * sign-in the account may not start (inactive, locked), or a repeat within
   * `mfa.pincodeResendTimeoutMs`. The click resumes here and moves on to the
   * purpose's verify step.
   */
  @Step("magic-link-send")
  @Public()
  async magicLinkSend(@WorkflowParam("context") ctx: AuthWfCtx): Promise<unknown> {
    const ml = ctx.magicLink;
    if (!ml || ml.sentAt !== undefined) return undefined;
    await enforceRateLimit(SEND_RATE_LIMIT);
    const now = Date.now();
    ml.sentAt = now;
    ml.expiresAt = now + this.opts.magicLinkTtlMs;
    const address = await this.magicLinkAddress(ctx, ml);
    if (address) ml.address = address;
    const cooldownKey = sha256url(`${ml.purpose}|${ml.subject ?? ml.identifier ?? ""}`);
    const sends = await this.opts.lockoutShadowStore.hit(
      `${MAGIC_LINK_SEND_PREFIX}${cooldownKey}`,
      this.opts.mfa.pincodeResendTimeoutMs,
    );
    const deliver = !!address && sends === 1;
    delete ml.identifier;
    if (ml.purpose === "login" && ctx.alternateCredentials?.magicLinkSameBrowser) {
      // Bind the link to this browser (set for every request alike).
      ml.browser = this.bindMagicLinkBrowser();
    }
    swapStrategy(MAGIC_LINK_STRATEGY);
    return {
      ...outlet(MAGIC_LINK_OUTLET, {
        target: deliver ? address : "",
        template: ml.purpose === "recovery" ? "recovery.magicLink" : "login.magicLink",
        context: { deliver, expiresAtMs: this.opts.magicLinkTtlMs },
      }),
      expires: ml.expiresAt,
    };
  }

  /**
   * Where a magic link may go — an inbox the account proved, or `undefined`
   * (nothing is sent). Recovery with the typed identifier as destination (M1,
   * email channel) sends to the typed address, like the recovery code; every
   * other case sends to the account's proven inbox: `account.verifiedEmail`,
   * else a confirmed email MFA method — never an unproven address. The account
   * must be active; a sign-in link also needs it unlocked (a recovery link may
   * go to a locked account — self-service unlock). Override to change the
   * destination.
   */
  protected async magicLinkAddress(
    ctx: AuthWfCtx,
    ml: NonNullable<AuthWfCtx["magicLink"]>,
  ): Promise<string | undefined> {
    let user: UserCredentials;
    try {
      // An unknown identifier reads a placeholder row: the same reads either way.
      user =
        ml.purpose === "login"
          ? await this.users.assertCanSignIn(ml.subject ?? UNKNOWN_ACCOUNT_ID)
          : await this.users.getUser(ml.subject ?? UNKNOWN_ACCOUNT_ID);
    } catch (err) {
      if (err instanceof UserAuthError) return undefined;
      throw err;
    }
    // Recovery, like the one-time code: an inactive (pending / deactivated)
    // account gets nothing; a locked one may recover.
    if (!ml.subject || !user.account.active) return undefined;
    if (ml.purpose === "recovery" && (await this.recoveryDeliverySource(ctx)) === "typed") {
      const typed = await this.recoveryPincodeTarget(ctx, "typed");
      return typed.channel === "email" && typed.address ? typed.address : undefined;
    }
    return (
      user.account.verifiedEmail ??
      user.mfa.methods.find((m) => m.name === "email" && m.confirmed)?.value
    );
  }

  /**
   * The landing step of a clicked link: "Continue as a•••@example.com". Opening
   * the link (or a mail scanner fetching it) only renders this step — the
   * pause stays on the link's own handle, so the link still works; it is used
   * up only when this form is submitted. The masked account lets the user see
   * which account the link signs into (a forwarded link would be someone
   * else's).
   */
  @Step("magic-link-confirm")
  @Public()
  magicLinkConfirm(@WorkflowParam("context") ctx: AuthWfCtx): unknown {
    const ml = ctx.magicLink;
    if (!ml?.sentAt || ml.confirmed) return undefined;
    const wf = this.useAtscriptWfPublic(ctx, this.opts.forms.magicLinkConfirm);
    try {
      wf.resolveInput();
    } catch (err) {
      if (err instanceof StepRetriableError) {
        // Same lifetime as the link; same handle (no strategy swap) — not used up.
        (err as { expires?: number }).expires = ml.expiresAt;
      }
      throw err;
    }
    ml.confirmed = true;
    return undefined;
  }

  /** Name of the cookie binding a sign-in link to the browser that asked for it. */
  protected magicLinkBrowserCookie(): string {
    return MAGIC_LINK_BROWSER_COOKIE;
  }

  /** Set the browser-binding cookie; returns the hash the link keeps. */
  private bindMagicLinkBrowser(): string {
    const nonce = randomBytes(24).toString("base64url");
    useResponse(current()).setCookie(
      this.magicLinkBrowserCookie(),
      nonce,
      authzBindingCookieAttrs({
        secure: useAuth().options.cookie.secure,
        maxAgeSec: Math.ceil(this.opts.magicLinkTtlMs / 1000),
      }),
    );
    return sha256url(nonce);
  }

  /** Whether this request carries the browser-binding cookie the link was sent with. */
  private sameMagicLinkBrowser(expected: string): boolean {
    const cookie = useCookies(current()).getCookie(this.magicLinkBrowserCookie());
    if (!cookie) return false;
    return safeEqual(sha256url(cookie), expected);
  }

  /**
   * A used sign-in link: the FIRST factor only. Re-checks the account
   * (active, not locked), binds `ctx.subject` and leaves the second factor to
   * the MFA loop, exactly as after a password. Refuses a link of another
   * purpose, an expired one, and one sent for no account.
   */
  @Step("magic-link-verified")
  @Public()
  async magicLinkVerified(@WorkflowParam("context") ctx: AuthWfCtx): Promise<unknown> {
    const ml = this.usedMagicLink(ctx, "login");
    if (!ml) return undefined;
    if (!ml.subject || (ml.browser && !this.sameMagicLinkBrowser(ml.browser))) {
      this.finishMagicLinkInvalid(ctx);
      return undefined;
    }
    let user: UserCredentials;
    try {
      user = await this.users.assertCanSignIn(ml.subject);
    } catch (err) {
      if (!(err instanceof UserAuthError)) throw err;
      this.finishMagicLinkInvalid(ctx);
      return undefined;
    }
    ctx.subject = user.id; // before the guards resolve (they may read it)
    // A link proves the inbox, not the password policy: an initial or expired
    // password must be changed, exactly as after a password sign-in.
    const guardsResult = this.resolveGuards(ctx);
    ctx.guards = guardsResult instanceof Promise ? await guardsResult : guardsResult;
    await this.bindSignedInUser(ctx, user);
    return undefined;
  }

  /**
   * A used recovery link: proof of the inbox it went to, exactly like a
   * verified recovery code — `ctx.otp.verified` set, the inbox recorded as
   * the account's verified email, and the flow goes on to the new password.
   * Refuses a link of another purpose, an expired one, one sent for no
   * account, and one whose account is no longer active.
   */
  @Step("recovery-link-verified")
  @Public()
  async recoveryLinkVerified(@WorkflowParam("context") ctx: AuthWfCtx): Promise<unknown> {
    const ml = this.usedMagicLink(ctx, "recovery");
    if (!ml) return undefined;
    // Re-read at click time: an account deactivated or deleted since the send
    // gets no reset.
    let active = false;
    if (ml.subject && ml.address) {
      try {
        active = (await this.users.getUser(ml.subject)).account.active;
      } catch (err) {
        if (!(err instanceof UserAuthError)) throw err;
      }
    }
    if (!active || !ml.subject || !ml.address) {
      this.finishMagicLinkInvalid(ctx);
      return undefined;
    }
    ctx.subject = ml.subject;
    const otp = (ctx.otp ??= {});
    otp.verified = true;
    otp.deliveredTo = ml.address;
    otp.deliveredChannel = "email";
    await this.users.setVerifiedEmail(ml.subject, ml.address);
    return undefined;
  }

  /**
   * The magic link this run was resumed through, checked for `purpose` and
   * expiry — or `undefined` after emitting the "invalid link" finish. Swaps
   * off the `magic-link` strategy first, so the link's token is never the
   * continuation (the next pause gets a fresh handle).
   */
  private usedMagicLink(
    ctx: AuthWfCtx,
    purpose: "recovery" | "login",
  ): NonNullable<AuthWfCtx["magicLink"]> | undefined {
    const ml = ctx.magicLink;
    if (!ml?.sentAt) return undefined;
    swapStrategy("store");
    if (ml.purpose !== purpose || !ml.expiresAt || Date.now() > ml.expiresAt) {
      this.finishMagicLinkInvalid(ctx);
      return undefined;
    }
    return ml;
  }

  /** The finish of a link that cannot be used (wrong purpose, expired, no account). */
  private finishMagicLinkInvalid(ctx: AuthWfCtx): void {
    ctx.aborted = true;
    finishWf({ message: { level: "error", text: this.msg("AOOTH_MAGIC_LINK_INVALID") } });
  }

  /**
   * Recovery's `'choice'` delivery: the user picks a magic link or a one-time
   * code. Shown for known and unknown identifiers alike. A one-time code for
   * an unknown identifier runs the ghost OTP pause, like the default path.
   */
  @Step("select-recovery-mode")
  @Public()
  async selectRecoveryMode(@WorkflowParam("context") ctx: AuthWfCtx): Promise<unknown> {
    const wf = this.useAtscriptWfPublic(ctx, this.opts.forms.recoveryModeSelect);
    let mode: string;
    try {
      ({ mode } = wf.resolveInput() as { mode: string });
    } catch (err) {
      if (err instanceof StepRetriableError) throw this.stampRecoveryExpiry(err);
      throw err;
    }
    if (mode !== "magicLink" && mode !== "otp") {
      throw this.throwPublic(ctx, wf, { errors: { mode: this.msg("AOOTH_CHOOSE_OPTION") } });
    }
    // Resolved only now, after the pick: the picker's state (client-held
    // under an encapsulated strategy) holds nothing about the account.
    await this.applyRecoveryMode(ctx, mode);
    return undefined;
  }

  @Step("passkey")
  @Public()
  // oxlint-disable-next-line typescript/no-redundant-type-constituents -- explicit sync|async override seam, see CLAUDE.md "Pure extension-point stubs"
  passkey(@WorkflowParam("context") _ctx: AuthWfCtx): unknown | Promise<unknown> {
    return undefined;
  }

  // ── Federated login (OAuth2 / OIDC) — leg 2: the callback exchange ───────
  //
  // ONE real step (`sso-callback`); everything after it reuses the shared login
  // tail by @Step id (prepare-* / channel / MFA / consent / issue / redirect) —
  // a federated user flows through the EXACT same gates as a password user. The
  // PKCE verifier + OIDC nonce are NOT stored: they are re-DERIVED here from the
  // signed-state `random` seed (the value `beginSso` derived them from at leg 1),
  // so the round-trip needs no server-side flow store and nothing secret rides
  // in the URL.

  /**
   * Verify the OAuth callback and resolve a user. Reaches here (instead of
   * `credentials`) when `init-login` saw an inbound `state` (`ctx.idpInbound`);
   * reads `{ provider, code, state, error }` from the START input (the SPA
   * bridges the provider callback into `/auth/trigger` STARTING `auth/login/flow`).
   * Order is security-critical:
   *
   *   verify state (HS256) → CSRF double-submit → re-derive PKCE verifier/nonce
   *   from the seed → provider.exchange (verified ID token) → link OR resolveUser
   *   → ACCOUNT-STATE GATE → seed ctx.subject → fall through to the shared tail.
   *
   * Replay defense is the provider's ONE-TIME `code` (a replayed callback fails
   * at `exchange` when the provider rejects the already-redeemed code), plus the
   * short-TTL signed state + CSRF cookie — the stateless design carries no
   * single-use server marker, by design.
   *
   * Every pre-subject failure collapses to one benign redirect terminal
   * (`finishOAuth`) so the wire is not an oracle for which check tripped. The
   * account-state gate MUST live here — `issue` does not re-gate, so without it
   * a locked/inactive account could log straight in via OAuth.
   */
  @Step("sso-callback")
  @Public()
  async ssoCallback(@WorkflowParam("context") ctx: AuthWfCtx): Promise<undefined> {
    // `init-login` captured the callback inputs onto `ctx.idpInbound` — the
    // step input is already cleared by the time this (the next step) runs.
    const code = ctx.idpInbound?.code;
    const state = ctx.idpInbound?.state;
    // Provider-side denial (user declined) or a malformed callback — the SPA
    // forwards the provider's `error`. Generic terminal either way.
    if (ctx.idpInbound?.error || !code || !state) {
      return this.finishOAuth(ctx, "provider-denied");
    }

    const { registry, federated } = await this.oauthRuntime();
    // STATE_INVALID and STATE_EXPIRED collapse to one terminal (no oracle).
    const payload = await registry.verifyState(state).catch(() => null);
    if (!payload) return this.finishOAuth(ctx, "state");

    // CSRF double-submit: the Lax cookie set by `beginSso` must match the
    // verified state's `random`. Constant-time; a missing cookie fails closed.
    const cookieSeed = useCookies(current()).getCookie(OAUTH_CSRF_COOKIE) ?? undefined;
    if (!safeEqual(cookieSeed, payload.random)) return this.finishOAuth(ctx, "csrf");

    // Re-derive the PKCE verifier + OIDC nonce from the signed-state seed — the
    // SAME pair `beginSso` built the authorize request from (no flow store). The
    // provider is bound by the signed `state`, so it needs no separate re-check.
    const { verifier, nonce } = registry.deriveSeededPkce(payload.random);

    let profile: NormalizedProfile;
    try {
      const provider = registry.require(payload.provider);
      profile = await provider.exchange({
        code,
        redirectUri: registry.redirectUri(payload.provider),
        codeVerifier: verifier,
        expectedNonce: nonce,
      });
    } catch {
      // UNKNOWN_PROVIDER / EXCHANGE_FAILED / ID_TOKEN_INVALID / JWKS_FAILED — all
      // benign-generic (a failed ID-token check must not differ from a network one).
      return this.finishOAuth(ctx, "exchange");
    }

    const redirect = resolveOAuthRedirect(payload.redirect, "/");

    // Authorization-server grant carried through this provider detour: the
    // pending-auth handle rode the signed federated `state` (folded in by
    // `beginSso`). Re-raise `ctx.authz` so this second run's tail mints the auth
    // code for the original client instead of issuing a browser session. Only
    // present on an authorize-initiated login — never an ordinary SSO login/link.
    if (payload.handle) ctx.authz = { handle: payload.handle };

    // ── /link mode — attach the verified identity to the initiating user ──
    // `state.userId` is set ONLY by the guarded `/:provider/link` route and is
    // HS256-signed (tamper-proof, server-minted), so its presence is a trusted
    // signal. `linkIdentity`'s cross-user guard is the final confused-deputy backstop.
    if (payload.userId) {
      try {
        await federated.linkIdentity({
          provider: profile.provider,
          subject: profile.subject,
          userId: payload.userId,
          profile,
        });
      } catch (err) {
        if (err instanceof UserAuthError && err.type === "ALREADY_EXISTS") {
          return this.finishOAuth(ctx, "already-linked");
        }
        throw err;
      }
      finishWf({
        message: { level: "success", text: this.msg("AOOTH_ACCOUNT_LINKED") },
        next: {
          trigger: "immediate",
          action: { type: "redirect", target: redirect, reason: "oauth-linked" },
        },
      });
      return undefined; // subject never set → `{ break: !ctx.subject }` halts here
    }

    // ── login mode — resolve the verified profile to a user ──
    const outcome = await federated.resolveUser(profile);
    // `denied` is a genuine terminal — no account to proceed into / signup refused.
    if (outcome.kind === "denied") return this.finishOAuth(ctx, "denied");
    // `needs-link` — a verified profile whose email matches an EXISTING local
    // account (default `require-interactive-link` policy). Don't silently merge:
    // stash the candidate + verified profile and divert to the `prove-control`
    // @Step, which challenges for control of the account BEFORE `linkIdentity`.
    // `ctx.subject` stays UNSET so the `{ break: !ctx.subject }` gate keeps the
    // unproven user out of the issue tail until proof succeeds.
    if (outcome.kind === "needs-link") {
      return this.stashPendingLink(ctx, profile, outcome.candidateUserId, redirect);
    }

    // outcome ∈ { linked, created, auto-linked } → carries `userId`.
    // ACCOUNT-STATE GATE — run BEFORE setting `ctx.subject` so a blocked account
    // leaves the subject unset and `{ break: !ctx.subject }` halts the flow.
    // `created` auto-activates in `resolveUser`, so only a `linked` login to a
    // disabled/locked account trips this — exactly what must be blocked.
    const user = await this.users.getUser(outcome.userId);
    if (this.isAccountBlocked(user)) {
      return this.finishOAuth(ctx, "account-state");
    }

    ctx.subject = outcome.userId;
    ctx.oauth = {
      provider: profile.provider,
      outcome: outcome.kind,
      isNew: outcome.kind === "created",
      redirect,
    };
    // A freshly federated account is a first login (drives `extra-step`).
    if (outcome.kind === "created") {
      ctx.isFirstLogin = true;
      // Provision it the SAME way password-signup / invite-accept do: run the
      // shared `prepareUser` hook and write its result onto the new row, so a
      // first-time SSO user lands with the app-required columns (roles, tenant
      // defaults, …) instead of a bare account. `resolveUser` already created +
      // activated + linked the row, so this is the post-create extras pass —
      // mirroring the invite `create-user` step's follow-up `users.update`. A
      // federated profile may carry no email; `prepareUser.email` is optional.
      const extras = await this.prepareUser({ email: profile.email, roles: [] });
      if (Object.keys(extras).length > 0) {
        await this.users.update(outcome.userId, extras);
      }
    }

    // Seed channel state from the resolved user so the shared enrolment / MFA /
    // notify-new-device gates behave; also captures a trusted provider email
    // claim as the proven correspondence address (`setVerifiedEmail`).
    await this.seedChannelState(ctx, user, profile);

    // Real subject resolved → durable store for any MFA / consent pause to come.
    swapStrategy("store");
    return undefined;
  }

  /**
   * Emit a benign, generic federated-login failure terminal (immediate redirect
   * to {@link resolveOAuthErrorRedirect}). Collapses EVERY pre-subject failure
   * mode so the wire response is never an oracle for which check tripped
   * (invariant #5). Returns `undefined` so the step can `return this.finishOAuth(...)`;
   * `{ break: !ctx.subject }` then halts the flow (subject is never set on failure).
   *
   * The precise `reason` is handed to `resolveOAuthErrorRedirect` (the override
   * seam — a consumer MAY branch the target on it, server-side) but the
   * CLIENT-facing `action.reason` is deliberately the constant `"oauth-failed"`:
   * exposing `oauth-${reason}` to the SPA would re-introduce the very
   * which-check-tripped oracle invariant #5 forbids.
   */
  private finishOAuth(ctx: AuthWfCtx, reason: string): undefined {
    finishWf({
      next: {
        trigger: "immediate",
        action: {
          type: "redirect",
          target: this.resolveOAuthErrorRedirect(ctx, reason),
          reason: "oauth-failed",
        },
      },
    });
    return undefined;
  }

  /**
   * Seed `ctx.notice.email` / `ctx.channel` from a resolved user's confirmed channels —
   * shared by `ssoCallback` (linked / created / auto-linked) and `proveControl`
   * (interactively-linked) so the post-success channel shape can't drift between
   * the two federated entry points. Mirrors `credentials`' post-login seeding,
   * including the correspondence fallback (confirmed email-MFA →
   * `users.getCorrespondenceEmail` → provider display email).
   *
   * Also the single federated capture point for `users.setVerifiedEmail`: a
   * trusted `profile.email` (per `resolveFederatedEmailTrust`) is recorded as
   * the proven correspondence address on EVERY federated login — first-time
   * create, returning link, and interactive link alike (the store write is
   * skipped when the capture is already current). The profile email is
   * otherwise a DISPLAY fallback only — never promoted to the unique login
   * handle (a gated, later-phase concern).
   */
  private async seedChannelState(
    ctx: AuthWfCtx,
    user: UserCredentials,
    profile?: FederatedProfileSnapshot,
  ): Promise<void> {
    // The provider authenticated this user AND attests the address — inbox
    // proof for correspondence purposes (policy-gated, default: email_verified).
    // An already-current capture skips the gate + store write — every federated
    // login (first-time AND returning) lands here.
    if (
      profile?.email &&
      user.account.verifiedEmail !== profile.email &&
      (await this.resolveFederatedEmailTrust(ctx, profile))
    ) {
      await this.users.setVerifiedEmail(user.id, profile.email);
      // Keep the in-hand row current so the correspondence chain below reads
      // the fresh capture, not the pre-write snapshot.
      user.account.verifiedEmail = profile.email;
    }
    const email = user.mfa.methods.find((m) => m.name === "email" && m.confirmed);
    if (email) {
      (ctx.notice ??= {}).email = email.value;
      (ctx.channel ??= {}).emailConfirmed = true;
    } else {
      await this.seedCorrespondenceEmail(ctx, user, profile?.email);
    }
    const phone = user.mfa.methods.find((m) => m.name === "sms" && m.confirmed);
    if (phone) {
      const channel = (ctx.channel ??= {});
      channel.phone = phone.value;
      channel.phoneConfirmed = true;
    }
  }

  /**
   * Correspondence tail of the `ctx.notice.email` seeding — shared by
   * `credentials` (post-login) and `seedChannelState` (federated) so the
   * fallback chain (`users.getCorrespondenceEmail` → optional display email)
   * can't drift between the two. Does NOT set `channel.emailConfirmed` — that
   * flag means "confirmed email-MFA channel" and gates enrolment; a
   * correspondence address is a notice recipient, not a proven OTP channel.
   */
  private async seedCorrespondenceEmail(
    ctx: AuthWfCtx,
    user: UserCredentials,
    displayEmail?: string,
  ): Promise<void> {
    const correspondence = await this.users.getCorrespondenceEmail(user);
    if (correspondence) (ctx.notice ??= {}).email = correspondence;
    else if (displayEmail) (ctx.notice ??= {}).email = displayEmail;
  }

  /**
   * `needs-link` setup (decision A — password, OTP fallback). Decide how the
   * user will prove control of the matched account, stash the pending-link
   * state, and return so the `prove-control` @Step (gated on `ctx.pendingLink`)
   * pauses for the challenge. Deliberately does NOT set `ctx.subject` — proving
   * control is exactly what authorizes that.
   *
   * Proof channel:
   *  - account has a real password (`!password.isInitial`) → `password`;
   *  - else a confirmed email/SMS factor exists → `otp` to THAT channel (NEVER
   *    the provider-supplied email — the attacker controls the provider account,
   *    so a code sent there would be circular);
   *  - else no provable channel → generic terminal (cannot safely link).
   */
  protected async stashPendingLink(
    ctx: AuthWfCtx,
    profile: NormalizedProfile,
    candidateUserId: string,
    redirect: string,
  ): Promise<undefined> {
    const candidate = await this.users.getUser(candidateUserId);
    let mode: "password" | "otp";
    let otpChannel: "email" | "sms" | undefined;
    if (!candidate.password.isInitial) {
      mode = "password";
    } else {
      const otp = candidate.mfa.methods.find(
        (m) => (m.name === "email" || m.name === "sms") && m.confirmed,
      );
      // Passwordless AND no confirmed contact channel of its own → unprovable.
      if (!otp) return this.finishOAuth(ctx, "needs-link");
      mode = "otp";
      otpChannel = otp.name as "email" | "sms";
    }
    // Display snapshot for the federated row — `NormalizedProfile` is a
    // structural superset of `FederatedProfileSnapshot`, so `pickDefinedProfile`
    // copies just the defined display fields and drops `profile.raw` (transient
    // verified claims must never land in the persisted wf state — RFC §7).
    const snapshot = pickDefinedProfile(profile);
    ctx.pendingLink = {
      candidateUserId,
      provider: profile.provider,
      subject: profile.subject,
      mode,
      snapshot,
      // `profile.email` is guaranteed on `needs-link` (resolveUser only returns
      // it inside `if (profile.email …)`); masked for the form's account hint.
      ...(profile.email ? { hint: maskEmail(profile.email) } : {}),
      ...(otpChannel ? { otpChannel } : {}),
      ...(redirect ? { redirect } : {}),
    };
    // Durable store so the prove-control pause (+ the rest of the run) survive.
    swapStrategy("store");
    return undefined;
  }

  /**
   * Mint + deliver an OTP proof code to the pending-link candidate's OWN
   * confirmed channel (NEVER the provider-supplied email — that would be
   * circular) and arm the resend cooldown. Shared by the first auto-dispatch
   * and the `resend` action. Returns the masked delivery target, or `null` if
   * the confirmed channel vanished between resolve and dispatch (the caller
   * routes that to the safe generic terminal).
   */
  private async deliverPendingLinkPin(
    candidate: UserCredentials,
    pending: NonNullable<AuthWfCtx["pendingLink"]>,
    claimed?: boolean,
  ): Promise<string | null> {
    const method = candidate.mfa.methods.find((m) => m.name === pending.otpChannel && m.confirmed);
    if (!method) return null;
    const deliver =
      claimed ?? (await this.claimCodeSend(this.linkTarget(pending), pending.candidateUserId));
    const code = this.mintPin(pending, pending.candidateUserId);
    if (deliver) {
      await this.dispatch({
        kind: "mfa-pincode",
        channel: pending.otpChannel as "email" | "sms",
        recipient: method.value,
        code,
        expiresInMs: this.opts.mfa.pincodeTtlMs,
      });
    }
    pending.resendAllowedAt = Date.now() + this.opts.mfa.pincodeResendTimeoutMs;
    return this.maskAddress(method.value, pending.otpChannel as "email" | "sms");
  }

  /**
   * Interactive `needs-link` completion — prove control of the matched local
   * account, then attach the verified federated identity to it. Gated by the
   * login schema on `ctx.pendingLink && !ctx.subject`, so it runs ONLY on the
   * federated email-collision path and ONLY while the account is unproven.
   *
   * PASSWORD mode re-verifies the account's password via `UserService.login`
   * with the username bound server-side from `candidateUserId` (the user never
   * types it, so this can't be repurposed to sign into a different account).
   * OTP mode verifies a code delivered to the account's OWN confirmed channel.
   * A wrong proof re-pauses with a generic inline error; `cancel` abandons the
   * link. On success: `linkIdentity` (cross-user `ALREADY_EXISTS` guarded) →
   * account-state gate → set `ctx.subject` + `ctx.oauth` → seed channel state →
   * fall through to the shared login tail exactly like any other login.
   */
  @Step("prove-control")
  @Public()
  async proveControl(@WorkflowParam("context") ctx: AuthWfCtx): Promise<undefined> {
    const pending = ctx.pendingLink;
    // Schema gates entry on `pendingLink && !subject`; defensive no-op otherwise.
    if (!pending || ctx.subject) return undefined;
    const { federated } = await this.oauthRuntime();
    // The candidate is re-fetched on every (re-)entry across the proof pause, so
    // it can vanish mid-flow (admin deletes the account while the user lingers on
    // the form). Route a NOT_FOUND to the same safe generic terminal as the other
    // pre-subject failures rather than letting it escape the workflow as a 500.
    let candidate: UserCredentials;
    try {
      candidate = await this.users.getUser(pending.candidateUserId);
    } catch (err) {
      if (err instanceof UserAuthError && err.type === "NOT_FOUND") {
        delete ctx.pendingLink;
        return this.finishOAuth(ctx, "needs-link");
      }
      throw err;
    }

    const isOtp = pending.mode === "otp";
    const wf = this.useAtscriptWfPublic(
      ctx,
      isOtp ? this.opts.forms.proveControlOtp : this.opts.forms.proveControl,
    );
    const action = wf.resolveAction();

    // `cancel` — abandon the link before the input pause (no link, no session).
    if (action === "cancel") {
      delete ctx.pendingLink;
      return this.finishOAuth(ctx, "needs-link");
    }

    // OTP mode: deliver the code to the account's OWN confirmed channel before
    // the first pause. `sent` guards against a re-mint/re-send on re-pause.
    if (isOtp && !pending.sent) {
      const sentTo = await this.deliverPendingLinkPin(candidate, pending);
      // Channel vanished between resolve and proof → safe generic terminal.
      if (sentTo === null) {
        delete ctx.pendingLink;
        return this.finishOAuth(ctx, "needs-link");
      }
      pending.sent = true;
      pending.sentTo = sentTo;
      // Re-pause WITH a fresh public projection so the form's "code sent to …"
      // copy (ctx.public.proveControl.sentTo, set just above) renders.
      throw this.throwPublic(ctx, wf);
    }

    // OTP mode: `resend` re-mints + re-delivers to the SAME own channel, gated
    // by the same per-pincode cooldown the MFA loop uses. (The password proof
    // form has no `resend` action, so this is unreachable in password mode.)
    if (isOtp && action === "resend") {
      const cooldown = pending.resendAllowedAt;
      // The state's wait, then the server-side cooldown of the account (a
      // replayed older state carries a stale wait).
      if (
        (cooldown && Date.now() < cooldown) ||
        !(await this.claimCodeSend(this.linkTarget(pending), pending.candidateUserId))
      ) {
        throw this.throwPublic(ctx, wf, {
          formMessage: this.msg("AOOTH_RESEND_WAIT_ANOTHER", {
            seconds: this.resendWaitSeconds(cooldown),
          }),
        });
      }
      const sentTo = await this.deliverPendingLinkPin(candidate, pending, true);
      if (sentTo === null) {
        delete ctx.pendingLink;
        return this.finishOAuth(ctx, "needs-link");
      }
      pending.sentTo = sentTo;
      throw this.throwPublic(ctx, wf);
    }

    const input = wf.resolveInput() as { password?: string; code?: string };

    // ── Verify proof of control (wrong proof → generic inline re-pause) ──
    if (isOtp) {
      const pinErr = await this.verifyPin(
        pending,
        input.code,
        pending.candidateUserId,
        this.linkTarget(pending),
      );
      if (pinErr) throw this.throwPublic(ctx, wf, { errors: pinErr });
    } else {
      try {
        await this.users.login(candidate.username, input.password ?? "", this.lockoutOverride(ctx));
      } catch (err) {
        if (err instanceof UserAuthError && err.type === "LOCKED") {
          throw this.throwPublic(ctx, wf, {
            formMessage: this.msg("AOOTH_ACCOUNT_LOCKED"),
          });
        }
        throw this.throwPublic(ctx, wf, { errors: { password: this.msg("INVALID_PASSWORD") } });
      }
    }

    // ── Account-state gate — BEFORE linking / setting subject (mirror the
    // sso-callback success gate; essential for the OTP path since verifyPin,
    // unlike users.login, does not itself reject a locked/inactive account). ──
    if (this.isAccountBlocked(candidate)) {
      delete ctx.pendingLink;
      return this.finishOAuth(ctx, "account-state");
    }

    // ── Attach the verified identity — cross-user takeover guarded ──
    try {
      await federated.linkIdentity({
        provider: pending.provider,
        subject: pending.subject,
        userId: pending.candidateUserId,
        ...(pending.snapshot ? { profile: pending.snapshot } : {}),
      });
    } catch (err) {
      if (err instanceof UserAuthError && err.type === "ALREADY_EXISTS") {
        delete ctx.pendingLink;
        return this.finishOAuth(ctx, "already-linked");
      }
      throw err;
    }

    // ── Converge to the post-success shape (mirror the ssoCallback success
    // branch) so the shared login tail runs identically for an interactive link. ──
    ctx.subject = pending.candidateUserId;
    ctx.oauth = {
      provider: pending.provider,
      outcome: "interactively-linked",
      isNew: false,
      ...(pending.redirect ? { redirect: pending.redirect } : {}),
    };
    await this.seedChannelState(ctx, candidate, pending.snapshot);

    delete ctx.pendingLink;
    swapStrategy("store");
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
    // Federated leg: an inbound OAuth callback (init-login set `idpInbound`)
    // runs the exchange and SKIPS the password form; a normal login runs
    // `credentials` and skips the exchange. Exactly one sets `ctx.subject` —
    // unless `init-login` already bound it from a live browser session (the
    // consent-only silent authorize path), in which case BOTH are skipped and
    // the run flows straight through the shared gates to `authz-consent`.
    { id: "sso-callback", condition: (ctx) => !!ctx.idpInbound },
    { id: "credentials", condition: (ctx) => !ctx.idpInbound && !ctx.subject && !ctx.magicLink },
    // Magic-link sign-in (the `magicLink` alt-action): identifier → link → the
    // click binds `ctx.subject`. First factor only — the MFA loop below still runs.
    {
      condition: (ctx) => ctx.magicLink?.purpose === "login" && !ctx.subject,
      steps: [
        { id: "magic-link-request" },
        { id: "magic-link-send" },
        { id: "magic-link-confirm" },
        { id: "magic-link-verified", condition: (ctx) => !ctx.aborted },
      ],
    },
    // Federated `needs-link` interactive completion — runs only when
    // `sso-callback` matched the verified profile to an existing account and
    // stashed `ctx.pendingLink`. Must precede the `!ctx.subject` break because
    // its whole job is to prove control and THEN set `ctx.subject`.
    { id: "prove-control", condition: (ctx) => !!ctx.pendingLink && !ctx.subject },
    { break: (ctx) => !ctx.subject },

    // Resolve all policy groups
    { id: "prepare-consents" },
    { id: "prepare-alternate-credentials" },
    { id: "prepare-device-trust" },
    { id: "prepare-enrollment" },
    { id: "prepare-finalize" },
    { id: "prepare-guards" },
    { id: "prepare-lockout" },
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
    { condition: () => false, steps: [{ id: "passkey" }] },

    // Forced channel enrolment. The email pair keys on `channel.email` — the
    // address `ask/email` actually collected and sent a code to — mirroring
    // the phone pair's `channel.phone`. NEVER on `notice.email`: that slot is
    // the security-notice recipient and may be pre-seeded (verifiedEmail
    // capture, provider display email) without any code sent — keying on it
    // either skips the ask (pausing on a code form no code was sent for) or,
    // inverted, breaks the ask→verify resume (`askChannel` pauses INSIDE
    // `ask/email`; the resume skips past it only because the stash flips this
    // gate false).
    {
      id: "ask/email",
      condition: (ctx) =>
        (!!ctx.enrollment?.ensureEmail || !!ctx.guards?.emailVerifiedRequired) &&
        !ctx.channel?.email &&
        !ctx.channel?.emailConfirmed,
    },
    {
      id: "verify/email",
      condition: (ctx) =>
        (!!ctx.enrollment?.ensureEmail || !!ctx.guards?.emailVerifiedRequired) &&
        !!ctx.channel?.email &&
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

    // Forced password change completed (password phase above) → end every
    // session opened with the old password. Placed AFTER the MFA loop: the old
    // password alone must not be able to sign the user out everywhere.
    { id: "revoke-sessions", condition: (ctx) => !!ctx.passwordChanged && !ctx.aborted },

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

    // Login funnel — stamp `account.lastLogin` + fire `afterLogin`, ONCE, for
    // BOTH delivery modalities below (browser-session AND authz-code), since the
    // user has authenticated and cleared every guard by here. Stamp-at-
    // authenticated: an authz login that the user later DENIES at `authz-consent`
    // still counts (they proved identity at the AS). A SILENT consent-only run
    // is NOT a login event — nothing was proved on this leg (the session did
    // the proving at its own login, which already stamped) — so it skips the
    // funnel: no second `lastLogin` write, no `afterLogin` fire.
    // A run that verified the password, paused, and resumes after that
    // password was changed elsewhere must not finish on it (no tokens, no code).
    {
      id: "check-password-unchanged",
      condition: (ctx) => ctx.passwordStamp !== undefined && !ctx.passwordChanged,
    },
    // …nor on an account deactivated or locked while it was paused.
    { id: "check-can-sign-in", condition: (ctx) => !!ctx.subject && !ctx.aborted },
    { break: (ctx) => !!ctx.aborted },
    { id: "record-login", condition: (ctx) => !!ctx.subject && !ctx.authz?.silent },

    // Finalize — EXACTLY ONE terminal. An authorization-server login (started
    // from /auth/authorize, `ctx.authz` set) mints an auth code and delivers it
    // to the client WITHOUT issuing a browser session; every other login takes
    // the normal issue → notify → redirect tail. `ctx.authz` is set by
    // init-login / sso-callback and never flips in the tail, so the condition is
    // safe to hoist onto the subflow.
    {
      condition: (ctx) => !ctx.authz,
      steps: [
        // Recognition runs BEFORE `issue` so the token lands on the finish
        // envelope's cookies, and unconditioned — the body self-gates on
        // subject + configured secret. The notify gate below reads the
        // pre-mint `recognized` flag it stamps.
        { id: "device-recognition" },
        { id: "issue" },
        {
          id: "notify-new-device",
          condition: (ctx) =>
            !ctx.isFirstLogin && !!ctx.finalize?.notifyNewDevice && !ctx.trust?.recognized,
        },
        { id: "redirect" },
      ],
    },
    // Authorization-server tail — consent gate FIRST (browser-binding check +
    // explicit approval), then the code mint. `authz-consent` finishes the run
    // itself on a binding failure or a Deny (a benign error / an
    // `error=access_denied` redirect) WITHOUT setting `approved`; `mint-authz-code`
    // runs ONLY when `approved` is set, so it never overwrites that finish.
    // (`finishWf` does NOT halt the schema — a bare `!!ctx.authz` would let
    // `mint-authz-code` re-run after a deny and clobber the redirect with
    // "expired"; the `approved` gate is what keeps the deny/binding finish intact.)
    { id: "authz-consent", condition: (ctx) => !!ctx.authz },
    // `authz-consent` pauses (up to the pending-authorization TTL): re-check
    // the password right before the code is minted.
    {
      id: "check-password-unchanged",
      condition: (ctx) =>
        ctx.authz?.approved === true && ctx.passwordStamp !== undefined && !ctx.passwordChanged,
    },
    { break: (ctx) => !!ctx.aborted },
    { id: "mint-authz-code", condition: (ctx) => ctx.authz?.approved === true },
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
      condition: (ctx) => !!(ctx.email && !ctx.subject && !ctx.admin?.userExtras),
    },
    {
      id: "create-user",
      condition: (ctx) => !!(ctx.email && !ctx.subject && !!ctx.admin?.userExtras),
    },
    { id: "assert-invite-created", condition: (ctx) => !!ctx.email && !ctx.subject },
    { id: "send-email", condition: (ctx) => !!ctx.subject },

    // ── Phase B: anonymous magic-link resume (all public) ──
    {
      condition: (ctx) => !!ctx.subject,
      steps: [
        { id: "init-invite-accept" }, // sets isFirstLogin=true, newPasswordRequired=true
        { id: "prepare-accept" },
        { id: "check-pending-invitation" },
        { id: "idempotent-redirect", condition: (ctx) => !!ctx.accept?.alreadyAccepted },
        // `finishWf()` only sets the finish envelope — stop the accept tail here.
        { break: (ctx) => !!ctx.accept?.alreadyAccepted },
        {
          id: "choose-username",
          condition: (ctx) => !!ctx.accept?.chooseUsername && !ctx.accept?.usernameChosen,
        },
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
        // Acceptance is complete (account activated) regardless of whether it
        // auto-logs-in — fire `afterInvitationAccepted` here, ahead of the
        // finalize split. An auto-login invite ALSO hits `record-login` below.
        { id: "after-invitation-accepted" },
        { id: "confirmation", condition: (ctx) => !!ctx.accept?.showConfirmation },

        // Finalize (invite tail — gated by ctx.autoLogin, mirrored from
        // `opts.autoLoginOnInvite` by init-invite-admin / init-invite-accept).
        // `record-login` runs only on the auto-login path (the fresh-login path
        // establishes no session, so it is not a login).
        { id: "finalize-fresh-login", condition: (ctx) => !ctx.autoLogin },
        { id: "auto-login-check", condition: (ctx) => !!ctx.autoLogin },
        { id: "record-login", condition: (ctx) => !!ctx.autoLogin },
        { id: "finalize-auto-login", condition: (ctx) => !!ctx.autoLogin },
      ],
    },
  ])
  inviteFlow(): void {}

  /**
   * recovery.flow — reset by a one-time code or a magic link
   * (`resolveRecoveryDeliveryMode`). `@Public()` on the body because anonymous
   * users start recovery.
   */
  @Workflow("auth/recovery/flow")
  @Public()
  @WorkflowSchema<AuthWfCtx>([
    { id: "init-recovery" },
    { id: "request" },
    // `resolveRecoveryDeliveryMode`: 'choice' asks; 'magicLink' sends a link
    // whose click stands for a verified code (`otp.verified`).
    { id: "select-recovery-mode", condition: (ctx) => ctx.recoveryDelivery === "choice" },
    {
      condition: (ctx) => ctx.recoveryDelivery === "magicLink",
      steps: [
        { id: "magic-link-send" },
        { id: "magic-link-confirm" },
        { id: "recovery-link-verified" },
      ],
    },
    // A link run continues only once its link bound the account; a code run
    // continues for every identifier (the account is resolved at verification).
    { break: (ctx) => !!ctx.aborted || (!ctx.subject && ctx.recoveryDelivery !== "otp") },

    { id: "prepare-post-reset" },
    { id: "prepare-recovery-alt-actions" },
    { id: "prepare-lockout" }, // self-service mode → unlock-account runs in the post-reset tail
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
      steps: [
        // Pending consents depend on the account: staged only once the inbox
        // is proven, so nothing before it differs between accounts (or from a
        // ghost run).
        { id: "prepare-consents" },
        { id: "prepare-password-rules" },
        { id: "create-password-form" },
      ],
    },
    { break: (ctx) => !!ctx.aborted },

    // Post-reset tail (recovery-specific) — sequential after the password
    // subflow above; cursor advancement past the `{ break: !!ctx.aborted }`
    // gate already guarantees the password form completed.
    { id: "revoke-sessions", condition: (ctx) => !!ctx.postReset?.revokeAllSessions },
    { id: "unlock-account", condition: (ctx) => ctx.lockout?.mode === "self-service" },
    ...consentsPersistTailSchema,
    // The password WAS reset by here (past the password subflow break), so fire
    // `afterPasswordReset` BEFORE the still-locked guard — the reset happened
    // even if an admin-only lock survives.
    { id: "after-password-reset" },
    // Admin-only-survived-lock guard (extracted from the finalize terminals so
    // they stay pure delivery): emits the warn terminal + sets `ctx.aborted`,
    // and the break then skips BOTH `record-login` and the finalize terminals.
    { id: "recovery-lock-check", condition: (ctx) => ctx.lockout?.mode === "admin-only" },
    { break: (ctx) => !!ctx.aborted },
    // Finalize (recovery tail — gated by ctx.autoLogin, mirrored from
    // `opts.autoLoginOnRecover` by init-recovery). `record-login` runs only on
    // the auto-login path (fresh-login establishes no session).
    { id: "finalize-fresh-login", condition: (ctx) => !ctx.autoLogin },
    { id: "auto-login-check", condition: (ctx) => !!ctx.autoLogin },
    { id: "record-login", condition: (ctx) => !!ctx.autoLogin },
    { id: "finalize-auto-login", condition: (ctx) => !!ctx.autoLogin },
    // Note: notify-new-device is NOT fired here in this pass — see §13.
  ])
  recoveryFlow(): void {}

  /**
   * change-password.flow — authenticated self-service "change my password".
   *
   * `@Public()` on the body lets the wf adapter dispatch start/resume (mirrors
   * the other flows); the FLOW itself is NOT public — `init-change-password` is
   * arbac-gated (`auth:change-password`) and binds `ctx.subject` from the
   * session, so an unauthenticated / unauthorized caller is rejected at the
   * first step. Customers forbid the feature (e.g. SSO-only orgs) by denying
   * the `change-password` action — there is no on/off opts flag.
   *
   * NOT in `DEFAULT_AUTH_WORKFLOWS` — it must be reached via a GUARDED trigger
   * route (see `AuthController.changePassword`), never the public
   * `/auth/trigger`.
   */
  @Workflow("auth/change-password/flow")
  @ArbacResource("auth.change-password")
  @ArbacAction("self")
  @WorkflowSchema<AuthWfCtx>([
    { id: "init-change-password" }, // binds ctx.subject from session + arbac gate
    { break: (ctx) => !ctx.subject },
    { id: "prepare-change-password" },
    { id: "prepare-password-rules" },
    {
      id: "enforce-change-password-rate-limit",
      condition: (ctx) => !!ctx.changePassword?.rateLimit,
    },
    { break: (ctx) => !!ctx.aborted }, // rate-limit emitted a terminal
    { id: "change-password-form" },
    // Revoke the user's OTHER sessions, then move the acting device onto a fresh
    // session and revoke the pre-change one (finish step, regardless of
    // `revokeOtherSessions`) — net: no ghost sessions survive the change.
    { id: "revoke-sessions", condition: (ctx) => !!ctx.changePassword?.revokeOtherSessions },
    { id: "finish-change-password" },
  ])
  changePasswordFlow(): void {}

  /**
   * add-mfa.flow — authenticated self-service "Manage two-factor
   * authentication" (add / change / remove). Same gating model as
   * change-password: NOT `@Public()` — `init-add-mfa` is arbac-gated
   * (`auth.add-mfa` / `self`) and binds `ctx.subject` from the session, so an
   * unauthenticated / unauthorized caller is rejected at the first step. NOT in
   * `DEFAULT_AUTH_WORKFLOWS` — reached only via the GUARDED trigger route
   * (`AuthController.addMfa`), never the public `/auth/trigger`.
   *
   * Shape:
   * 1. `init-add-mfa` — bind subject, resolve the FULL transport set + the
   *    un-enrolled `candidates`, mark `stepUpRequired` when the user already has
   *    ≥1 confirmed factor, and put the enrol forms in `'manage'` mode.
   * 2. `prepare-locked-mfa-transports` — resolve which factors the consumer
   *    forbids changing (handle-bound email/phone).
   * 3. STEP-UP (only when `stepUpRequired`): re-verify identity before any
   *    change — `mfaStepUpLoop` challenges an EXISTING factor when one is still
   *    challengeable (`stepUpMode==='mfa'`), else `manage-password-reauth` falls
   *    back to the account password (`stepUpMode==='password'`). The sms/email
   *    challenge collects explicit consent (`manage-stepup-confirm`) BEFORE
   *    dispatching its pincode — opening the dialog never sends a code as a
   *    side effect (see `resolveStepUpConfirmBeforeSend`). On success
   *    `manage-stepup-done` swaps off the encapsulated start onto the durable
   *    `store` strategy (server-anchored, replay-resistant; mirrors login's
   *    swap-after-credentials).
   * 4. `manage-menu` (only when `stepUpRequired`) — pick add / change / remove +
   *    target; pre-seeds `mfaEnroll.method` for add/change. Un-offerable
   *    operations never render: locked transports drop their Change/Remove
   *    options, and the LAST factor under a `required` policy drops Remove
   *    (`removeBlocked`) — `confirm-remove-mfa` aborts to the finish terminal
   *    if a blocked remove arrives anyway (no retryable dead-end form).
   * 5. Route: `confirm-remove-mfa` for remove; otherwise the REUSED enrol trio
   *    (`enroll-pick-method` → `enroll-address` / `enroll-totp-qr` →
   *    `enroll-confirm`). A zero-MFA user skips step-up + menu and lands on the
   *    enrol picker directly (the first-time opt-in path).
   * 6. `finish-add-mfa` — added / changed / removed / cancelled / nothing terminal.
   *    The user KEEPS their session (no token re-issue).
   */
  @Workflow("auth/add-mfa/flow")
  @ArbacResource("auth.add-mfa")
  @ArbacAction("self")
  @WorkflowSchema<AuthWfCtx>([
    { id: "init-add-mfa" }, // arbac gate + bind subject + full transports + candidates + stepUpRequired + mode='manage'
    { break: (ctx) => !ctx.subject }, // defence in depth (init throws 401 if unauth)
    { id: "prepare-locked-mfa-transports" }, // resolve handle-bound (non-changeable) factors
    // Step-up: re-verify an EXISTING factor before any change (no trusted-device
    // bypass). MFA challenge when a confirmed factor is still challengeable…
    {
      condition: (ctx) => !!ctx.addMfa?.stepUpRequired && ctx.addMfa?.stepUpMode === "mfa",
      steps: mfaStepUpLoop,
    },
    // …else a password re-auth fallback (the only confirmed factor's kind is no
    // longer in the policy, so nothing is MFA-challengeable). Same success
    // signal (`otp.verified`); a cancel sets `aborted` (caught by the break).
    {
      id: "manage-password-reauth",
      condition: (ctx) =>
        !!ctx.addMfa?.stepUpRequired && ctx.addMfa?.stepUpMode === "password" && !ctx.otp?.verified,
    },
    // A cancel/exit DURING step-up (mfaStepUpLoop breaks its while on aborted,
    // incl. the `manage-stepup-confirm` consent cancel; password re-auth sets
    // it directly) must not fall through into the menu/enrolment — every step
    // below is gated off `ctx.aborted` (or on `otp.verified`, which an aborted
    // step-up never set), so the run falls THROUGH to `finish-add-mfa`, which
    // emits the cancelled terminal. Deliberately NOT a `{ break }`: a top-level
    // break exits the whole schema and would skip the terminal, finishing with
    // a bare envelope. Fail closed either way: no management write without a
    // fresh challenge.
    // First validated input passed → anchor the rest of the flow in the durable
    // store (single-use OTP, server-side staging of the new factor).
    {
      id: "manage-stepup-done",
      condition: (ctx) =>
        !ctx.aborted &&
        !!ctx.addMfa?.stepUpRequired &&
        !!ctx.otp?.verified &&
        !ctx.addMfa?.stepUpDone,
    },
    // Management menu — only for users who have methods to manage. Sets
    // `addMfa.action` + `target` (and `mfaEnroll.method` for add/change), or sets
    // `ctx.aborted` on cancel.
    {
      id: "manage-menu",
      condition: (ctx) => !ctx.aborted && !!ctx.addMfa?.stepUpRequired && !ctx.addMfa?.action,
    },
    // Remove route.
    {
      id: "confirm-remove-mfa",
      condition: (ctx) => !ctx.aborted && ctx.addMfa?.action === "remove",
    },
    // Add / change route — REUSES the login/invite trio verbatim (+ QR step).
    // Gated so a zero-MFA user (no menu) still enrolls over `candidates`, and a
    // menu pick of add/change runs with `mfaEnroll.method` pre-seeded. NOT for
    // remove, and NOT once aborted (cancel must not fall through into enrolment).
    {
      condition: (ctx) =>
        !ctx.aborted &&
        ctx.addMfa?.action !== "remove" &&
        (ctx.addMfa?.action === "replace" || (ctx.addMfa?.candidates?.length ?? 0) > 0),
      steps: enrollTrioSteps,
    },
    { id: "finish-add-mfa" }, // always runs — added / changed / removed / cancelled terminal
  ])
  addMfaFlow(): void {}

  /**
   * signup.flow — verify-first self-signup. `@Public()` on the body (anonymous).
   * NOT arbac-gated at the flow level: the `resolveSignupPolicy().allowSignup`
   * gate is the on/off switch (default OFF — invite-only is the safe default).
   * Reachable via the public `/auth/trigger` (add `auth/signup/flow` to the
   * controller's `DEFAULT_AUTH_WORKFLOWS`).
   *
   * Shape = recovery's email→OTP front + invite's create→set-password→activate→
   * auto-login tail, so it reuses `pincodeSendCheckPair`, `passwordPhaseSchema`,
   * `prepare-consents` + `consentsPersistTailSchema`, `activate-user`, and
   * `finalize-auto-login` verbatim. The account-existence check is deferred to
   * `signup-create-user` (POST-OTP) so account existence never leaks on the
   * wire — every email gets an identical OTP pause regardless of whether it is
   * already registered.
   */
  @Workflow("auth/signup/flow")
  @Public()
  @WorkflowSchema<AuthWfCtx>([
    { id: "init-signup" }, // resolve policy → ctx.signup; ctx.autoLogin=true; gate allowSignup
    { break: (ctx) => !ctx.signup?.allowSignup }, // disabled → init-signup emitted the terminal
    { id: "signup-form" }, // collect email → ctx.email + ctx.signup.submitted
    { break: (ctx) => !ctx.signup?.submitted || !!ctx.aborted }, // backToLogin aborted

    // Email-ownership OTP — reuse the shared pincode pair. `ctx.mfa.method` is
    // unset + `ctx.signup` present → `pincode-send` emits `signup-pincode` and
    // `resolvePincodeTarget` returns `ctx.email`. The code lives in wf-state
    // (`mintPin`/`verifyPin`), so NO user row is needed to verify.
    {
      while: (ctx) => !ctx.otp?.verified && !ctx.aborted,
      steps: pincodeSendCheckPair,
    },
    { break: (ctx) => !!ctx.aborted },

    // Email proven → create the (inactive) account. Existence check is HERE,
    // not earlier, so the wire path is identical for new vs taken emails.
    { id: "signup-create-user", condition: (ctx) => !!ctx.otp?.verified && !ctx.subject },
    { break: (ctx) => !ctx.subject }, // taken-email path finished without a subject

    { id: "prepare-consents" }, // subject now set → pending consents render on SetPasswordForm

    // User chooses their password (shared SetPasswordForm) — armed by
    // `newPasswordRequired` set in `signup-create-user`.
    ...passwordPhaseSchema,
    { break: (ctx) => !!ctx.aborted },

    { id: "activate-user" }, // flip active AFTER the password is set (reuse invite)
    ...consentsPersistTailSchema,
    { id: "signup-extra-step" }, // customer extension point
    { id: "after-signup" }, // afterSignup hook (account created + activated)
    { id: "auto-login-check" }, // the account is still active
    { id: "record-login" }, // stamp lastLogin + afterLogin (signup always auto-logins)
    { id: "finalize-auto-login" }, // v1 always auto-logins
  ])
  signupFlow(): void {}
}
