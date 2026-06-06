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
import { AuthCredential, type CredentialMetadata } from "@aooth/auth";
import type { NormalizedProfile } from "@aooth/idp";
import {
  generateTotpSecret,
  generateTotpUri,
  maskEmail,
  maskPhone,
  type MfaMethodInfo,
  pickDefinedProfile,
  type TrustedDeviceRecord,
  UserAuthError,
  type UserCredentials,
  UserService,
} from "@aooth/user";
import { finishWf, type FinishWfOpts, useAtscriptWf, type WfFinished } from "@atscript/moost-wf";
import type { TAtscriptAnnotatedType } from "@atscript/typescript/utils";
import { HttpError } from "@moostjs/event-http";
import {
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
import { current } from "@wooksjs/event-core";
import { useCookies, useHeaders, useRequest, useUrlParams } from "@wooksjs/event-http";
import { ArbacAction, ArbacResource } from "@aooth/arbac-moost";
import { Controller, Inherit, Param, useControllerContext } from "moost";

import { useAuth } from "../auth.composables";
import { ConsentStore } from "../consent.store";
import { Public } from "../auth.decorator";
import { buildOAuthAuthorizeRequest, OAUTH_TTL_SEC } from "../oauth/oauth-authorize";
import { OAUTH_CSRF_COOKIE, oauthCsrfCookieAttrs, safeEqual } from "../oauth/oauth-csrf";
import { resolveOAuthRedirect } from "../oauth/oauth-redirect";
import { AuthorizeRuntime } from "../authz/authorize-runtime";
import { OAuthRuntime } from "../oauth/oauth-runtime";
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
  ChangePasswordForm,
  ConcurrencyLimitForm,
  EmailIdentifierForm,
  EnrollAddressForm,
  EnrollConfirmForm,
  EnrollPickMethodForm,
  InviteForm,
  LoginCredentialsForm,
  MfaCodeForm,
  PincodeForm,
  ProveControlForm,
  ProveControlOtpForm,
  Select2faForm,
  SetPasswordForm,
  SignupForm,
  TermsBumpForm,
} from "../atscript/models/forms.as";
import {
  consentsPersistTailSchema,
  enrollTrioSteps,
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
  changePassword: ChangePasswordForm,
  proveControl: ProveControlForm,
  proveControlOtp: ProveControlOtpForm,
  termsBump: TermsBumpForm,
  concurrencyLimit: ConcurrencyLimitForm,
  recoveryPincode: PincodeForm,
  signup: SignupForm,
};

function mergeAuthWorkflowOpts(opts: Partial<AuthWorkflowOpts>): ResolvedAuthWorkflowOpts {
  return {
    autoLoginOnInvite: opts.autoLoginOnInvite ?? true,
    autoLoginOnRecover: opts.autoLoginOnRecover ?? false,
    mfa: {
      pincodeLength: opts.mfa?.pincodeLength ?? 6,
      pincodeTtlMs: opts.mfa?.pincodeTtlMs ?? 5 * 60 * 1000,
      pincodeResendTimeoutMs: opts.mfa?.pincodeResendTimeoutMs ?? 60_000,
      pincodeMaxAttempts: opts.mfa?.pincodeMaxAttempts ?? 5,
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
   * Resolve the authenticated change-password policy. Reached from
   * change-password.flow only. Default revokes the user's other sessions on a
   * successful change (OWASP Session Management) and applies NO rate limit —
   * current-password re-entry (enforced by `UserService.changePassword`) is the
   * primary protection, not throttling. Customers override to add a min-interval
   * (`rateLimit.minIntervalMs`) or to keep other sessions alive.
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
      if (!ctx.subject) throw new HttpError(500, "Workflow state corrupted: missing subject");
      return this.users.getUser(ctx.subject).then((user) => {
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
      const sub = pickDefined(ctx.altActions, [
        "forgotPassword",
        "signup",
        "magicLink",
        "ssoProviders",
      ] as const);
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
    if (ctx.pendingLink) {
      // Only the masked/UX fields — `candidateUserId` / `subject` / proof `pin`
      // stay server-only (never whitelisted onto the wire).
      const sub = pickDefined(ctx.pendingLink, [
        "mode",
        "hint",
        "sentTo",
        "resendAllowedAt",
      ] as const);
      if (sub) pub.proveControl = sub as AuthWfPublicState["proveControl"];
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
    ctx: { pin?: string; pinExpire?: number; pinAttempts?: number },
    length: number,
    ttlMs: number,
  ): string {
    let code = "";
    for (let i = 0; i < length; i++) code += Math.floor(Math.random() * 10).toString();
    ctx.pin = code;
    ctx.pinExpire = Date.now() + ttlMs;
    // Fresh code → fresh attempt budget. `delete` (not `= 0`) because wf
    // state-token persistence rejects `undefined` AND we want the field
    // absent when never used.
    delete ctx.pinAttempts;
    return code;
  }

  /**
   * Verify a submitted pincode against `ctx.pin`. Returns an error map (with
   * the message keyed under `code` so it renders inline on the code input) or
   * `null` on success. Brute-force protection: wrong-code attempts increment
   * `ctx.pinAttempts`; on the `pincodeMaxAttempts`-th miss the code is
   * invalidated (clears `pin` + `pinExpire` + `pinAttempts`) and the returned
   * error tells the user to request a fresh code. Without this gate the user
   * could probe the full 10^pincodeLength space inside one `pincodeTtlMs`
   * window.
   */
  protected verifyPin(
    ctx: { pin?: string; pinExpire?: number; pinAttempts?: number },
    submitted: string | undefined,
  ): { code: string } | null {
    if (!ctx.pin || !ctx.pinExpire || Date.now() > ctx.pinExpire) return { code: "Code expired" };
    if (submitted !== ctx.pin) {
      const attempts = (ctx.pinAttempts ?? 0) + 1;
      if (attempts >= this.opts.mfa.pincodeMaxAttempts) {
        delete ctx.pin;
        delete ctx.pinExpire;
        delete ctx.pinAttempts;
        return { code: "Too many invalid attempts. Please request a new code." };
      }
      ctx.pinAttempts = attempts;
      return { code: "Invalid code" };
    }
    delete ctx.pinAttempts;
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
  initLogin(@WorkflowParam("context") ctx: AuthWfCtx): void {
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
    password.heading = "Change your password";
    password.intro = "Enter your current password, then choose a new one.";
    return undefined;
  }

  /**
   * Bind the standalone "add an MFA method" flow to the CURRENT authenticated
   * user and narrow enrolment to the transports they have NOT enrolled yet.
   * Identity comes from the session (`useAuth().getUserId()`) — never form input
   * — so it is structurally "add a factor to MY account". Mirrors
   * `init-change-password`'s arbac gate (`auth.add-mfa` / `self`): a customer
   * enables the feature with a single `allow("auth.add-mfa", "*")` grant and
   * forbids it by omitting it. `getUserId()` throws 401 if unauthenticated —
   * defence in depth on top of the guarded trigger route.
   *
   * Drives the REUSED enrol trio (`enroll-pick-method` / `enroll-address` /
   * `enroll-confirm`) by setting `ctx.mfaPolicy.availableTransports` to the
   * un-enrolled remainder — so the picker offers only those and auto-picks when
   * exactly one remains. Forces `mode: "optional"` (the user opted in; an empty
   * remainder must finish gracefully, never 500 as `required` would). The
   * remainder is stashed on `ctx.addMfa.candidates` (flow discriminator + finish
   * summary); when the user already has a default, `enroll-confirm` is asked to
   * keep it (`mfaEnroll.keepExistingDefault`).
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
    const enrolled = new Set(
      (user.mfa?.methods ?? []).filter((m) => m.confirmed).map((m) => m.name as MfaTransport),
    );
    const remaining = all.filter((t) => !enrolled.has(t));
    ctx.mfaPolicy = { mode: "optional", availableTransports: remaining, issuer: policy.issuer };
    ctx.addMfa = { candidates: remaining };
    // Preserve the user's existing default — adding a secondary factor must not
    // silently change which method is challenged first at next login. (With zero
    // methods there's no default to keep, so the first added one becomes default
    // — same as login-time forced enrolment.)
    if (user.mfa?.defaultMethod) (ctx.mfaEnroll ??= {}).keepExistingDefault = true;
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
      ctx.subject = result.user.id;
      // First validated input passed → move off the cheap encapsulated start to
      // the durable store strategy, so the MFA / enrollment / password-change
      // pauses survive restarts. Pre-validation stays encapsulated (no server row),
      // so an idle login form can't 410-GONE. Sticky for the rest of the run.
      swapStrategy("store");
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
    if (action === "magicLink" && alt.magicLink) {
      throw new HttpError(501, "Magic-link login path not implemented in this version");
    }
    if (action === "sso") {
      // The bundled `AsSsoProviders` sets the chosen provider id into the
      // `ssoProvider` field, then invokes this single data-carrying action.
      const providerId = getInputField("ssoProvider");
      const sso = providerId ? alt.ssoProviders.find((p) => p.id === providerId) : undefined;
      // A missing / unoffered id is a malformed request — the bundled component
      // only ever submits an offered provider.
      if (!sso) throw new HttpError(400, "Unknown SSO provider");
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

    let subject: string | undefined;
    try {
      // `emailToUserId` already returns the stable `id` (the token subject) — no
      // follow-up `getUser` round-trip needed; downstream OTP/reset steps re-read.
      subject = (await this.emailToUserId(email)) ?? undefined;
    } catch (err) {
      if (!(err instanceof UserAuthError) || err.type !== "NOT_FOUND") throw err;
    }

    if (!subject) {
      // Anti-enumeration: same generic response. Downstream skips via `ctx.subject` gate.
      this.finishGenericRecovery();
      return undefined;
    }

    ctx.subject = subject;
    // real user resolved → durable store for the OTP-send + password-reset pauses (resumable, 1h TTL); unknown-email anti-enumeration path above never reaches here
    swapStrategy("store");
    return undefined;
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
    if (!ctx.subject) {
      ctx.isFirstLogin = false;
      return undefined;
    }
    return this.users.getUser(ctx.subject).then(
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
      return this.users.getUser(ctx.subject).then(
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
    const existing = await this.users.findByHandle(email);
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
    let created: UserCredentials;
    try {
      created = await this.users.createUser(ctx.email, undefined, fields);
    } catch (err) {
      if (err instanceof UserAuthError && err.type === "ALREADY_EXISTS") {
        throw new HttpError(409, "User already exists");
      }
      throw err;
    }
    await this.users.update(created.id, {
      account: { pendingInvitation: true },
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
    // swap BEFORE the email-outlet pause so the magic-link token is a durable store handle the invitee can resume days later; the admin-form pause before this stayed encapsulated
    swapStrategy("store");
    return outletEmail(ctx.email as string, "invite.magicLink", {
      username: ctx.email,
      ...(ctx.subject && { userId: ctx.subject }),
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
    if (!ctx.subject) {
      throw new HttpError(500, "Workflow state corrupted: missing subject at accept");
    }
    const existing = await this.users.findByIdentifier(ctx.subject);
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
    this.requireSubject(ctx);
    await this.users.update(ctx.subject, {
      account: { pendingInvitation: false },
    } as Partial<UserCredentials>);
    return undefined;
  }

  /** Activate the invited user account (flips the account status flag). */
  @Step("activate-user")
  @Public()
  async activateUser(@WorkflowParam("context") ctx: AuthWfCtx): Promise<undefined> {
    this.requireSubject(ctx);
    await this.users.activateAccount(ctx.subject);
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
    this.requireSubject(ctx);
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
      await this.users.setPassword(ctx.subject, input.newPassword);
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
          text: "You changed your password too recently. Please try again later.",
        },
        next: {
          trigger: "manual",
          primary: {
            label: "Back",
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
    const wf = this.useAtscriptWfPublic(ctx, this.opts.forms.changePassword);
    const input = wf.resolveInput() as {
      currentPassword: string;
      newPassword: string;
      confirmPassword: string;
    };
    if (input.newPassword !== input.confirmPassword) {
      throw this.throwPublic(ctx, wf, { errors: { confirmPassword: "Passwords do not match" } });
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
        const field =
          err.type === "INVALID_CREDENTIALS"
            ? "currentPassword"
            : err.type === "PASSWORDS_MISMATCH"
              ? "confirmPassword"
              : "newPassword";
        throw this.throwPublic(ctx, wf, { errors: { [field]: err.message } });
      }
      throw err;
    }
    return undefined;
  }

  /**
   * Change-password terminal — rotate the acting session's token (so the
   * current device stays signed in on a FRESH credential) and emit a success
   * message. Runs AFTER the optional `revoke-sessions` step, so the net effect
   * is "kill every other session, keep this one on a new token" (OWASP Session
   * Management: no ghost sessions survive a credential change).
   */
  @Step("finish-change-password")
  @ArbacResource("auth.change-password")
  @ArbacAction("self")
  async finishChangePassword(@WorkflowParam("context") ctx: AuthWfCtx): Promise<undefined> {
    this.requireSubject(ctx);
    const issue = await this.issueForContext(ctx);
    const auth = useAuth();
    const envelope: WfFinished = {
      finished: true,
      data: auth.buildLoginResponse(ctx.subject, issue),
      message: { level: "success", text: "Your password has been changed." },
    };
    useWfFinished().set({
      type: "data",
      value: envelope,
      cookies: auth.buildFinishedCookies(issue),
    });
    return undefined;
  }

  /**
   * Terminal for the add-MFA flow. The user KEEPS their current session (no
   * re-issue, no cookies) — this is a plain data finish. `mfaEnroll.done &&
   * mfaEnroll.method` is the success signal: a real confirm keeps `.method`,
   * whereas a cancel runs `cleanupEnrollment` (which deletes it). An empty
   * `addMfa.candidates` distinguishes "nothing left to add" from a user cancel.
   */
  @Step("finish-add-mfa")
  @ArbacResource("auth.add-mfa")
  @ArbacAction("self")
  finishAddMfa(@WorkflowParam("context") ctx: AuthWfCtx): undefined {
    const labels: Record<MfaTransport, string> = {
      totp: "Authenticator app",
      email: "Email code",
      sms: "Text-message code",
    };
    const method = ctx.mfaEnroll?.method;
    const candidates = ctx.addMfa?.candidates ?? [];
    let envelope: WfFinished;
    if (ctx.mfaEnroll?.done && method) {
      envelope = {
        finished: true,
        data: { added: true, method },
        message: { level: "success", text: `${labels[method]} added.` },
      };
    } else if (candidates.length === 0) {
      envelope = {
        finished: true,
        data: { added: false, reason: "no-methods-available" },
        message: {
          level: "info",
          text: "You've already set up every available authentication method.",
        },
      };
    } else {
      envelope = {
        finished: true,
        data: { added: false, reason: "cancelled" },
        message: { level: "info", text: "No authentication method was added." },
      };
    }
    useWfFinished().set({ type: "data", value: envelope });
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
    pincode.codeLength = this.opts.mfa.pincodeLength;
    const pincodeWf = this.useAtscriptWfPublic(ctx, this.opts.forms.pincode);
    throw this.throwPublic(ctx, pincodeWf);
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
      pincode.codeLength = this.opts.mfa.pincodeLength;
      throw this.throwPublic(ctx, pincodeWf);
    }
    const input = pincodeWf.resolveInput() as { code: string };
    const pinErr = this.verifyPin(ctx, input.code);
    if (pinErr) throw this.throwPublic(ctx, pincodeWf, { errors: pinErr });
    await this.withStoreErrorTranslation(() =>
      this.users.confirmMfaMethod(ctx.subject, isEmail ? "email" : "sms"),
    );
    const channelState = (ctx.channel ??= {});
    if (isEmail) channelState.emailConfirmed = true;
    else channelState.phoneConfirmed = true;
    // Record the OTP-channel disclosure AFTER channel ownership is confirmed.
    if (channelState.otpDisclosure) {
      const channelArg: "email" | "sms" = isEmail ? "email" : "sms";
      const target = (isEmail ? ctx.email : channelState.phone) as string;
      await this.consentStore.recordOtpChannelConsent(
        ctx.subject,
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
    const user = await this.users.getUser(ctx.subject);
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
    } else if (ctx.signup) {
      // Signup verify-first: prove email ownership before the row exists. The
      // target is always email (`resolvePincodeTarget`'s non-MFA branch).
      await this.deliver({
        kind: "signup-pincode",
        channel: "email",
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
    this.requireSubject(ctx);
    try {
      await this.users.verifyMfa(ctx.subject, input.code, undefined, this.lockoutOverride(ctx));
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
    this.requireSubject(ctx);
    const username = ctx.subject;
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
    this.requireSubject(ctx);
    const username = ctx.subject;
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
    const pincode = (ctx.pincode ??= {});
    pincode.resendAllowedAt = Date.now() + this.opts.mfa.pincodeResendTimeoutMs;
    pincode.codeLength = this.opts.mfa.pincodeLength;
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
    this.requireSubject(ctx);
    const username = ctx.subject;
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
      const pincode = (ctx.pincode ??= {});
      pincode.resendAllowedAt = Date.now() + this.opts.mfa.pincodeResendTimeoutMs;
      pincode.codeLength = this.opts.mfa.pincodeLength;
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
    // Make this the default UNLESS the add-MFA flow asked to keep the existing
    // one (the user is adding a secondary factor, not their first). On the
    // login/invite forced-enrolment path `keepExistingDefault` is unset and the
    // user has no default yet, so the first method still becomes default.
    if (!m.keepExistingDefault) await this.users.setDefaultMfaMethod(username, methodName);
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
      throw this.throwPublic(ctx, wf, { formMessage: "Session limit reached" });
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
   * `ctx.postReset.revokeAllSessions`) and authenticated change-password (gated
   * by `ctx.changePassword.revokeOtherSessions`).
   *
   * - Change-password runs in an authenticated context, so we KEEP the caller's
   *   current device via `revokeOtherSessions(username, currentSessionId)` —
   *   OWASP "invalidate other sessions" without logging the user out of the tab
   *   they just changed their password in. If the current session can't be
   *   resolved (no session id), fall back to revoking everything (fail-secure).
   * - Recovery is anonymous (no current session to keep) → `revokeAllForUser`.
   */
  @Step("revoke-sessions")
  @Public()
  async revokeSessions(@WorkflowParam("context") ctx: AuthWfCtx): Promise<undefined> {
    if (!ctx.subject) return undefined;
    if (ctx.changePassword?.revokeOtherSessions) {
      const currentSessionId = useAuth().getSessionId();
      if (currentSessionId) {
        await this.auth.revokeOtherSessions(ctx.subject, currentSessionId);
        return undefined;
      }
    }
    await this.auth.revokeAllForUser(ctx.subject);
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
   * Issue access + refresh tokens via `auth.issue`. Stashes the login
   * response envelope on `useWfFinished` so downstream `redirect` can
   * override with a redirect envelope while preserving the cookies.
   */
  @Step("issue")
  @Public()
  async issue(@WorkflowParam("context") ctx: AuthWfCtx): Promise<void> {
    this.requireSubject(ctx);
    const issue = await this.issueForContext(ctx);
    const auth = useAuth();
    const envelope: WfFinished = {
      finished: true,
      data: auth.buildLoginResponse(ctx.subject, issue),
    };
    // Attach the trusted-device cookie (minted by `device-trust`) to the finish
    // envelope alongside the session cookies, so it survives a server `redirect`
    // finish (where the `redirect` step preserves only `existing.cookies`,
    // never response-context `setCookie`). Independent of `enableCookie` —
    // device trust is a separate concern from token transport — so it's added
    // even when `buildFinishedCookies` returns undefined (cookieless deploys).
    const sessionCookies = auth.buildFinishedCookies(issue);
    const cookies = ctx.trust?.deviceTrustToken
      ? {
          ...sessionCookies,
          [this.opts.deviceTrust.cookieName]: {
            value: ctx.trust.deviceTrustToken,
            options: auth.cookieAttrs({ maxAge: this.opts.deviceTrust.ttlMs / 1000 }),
          },
        }
      : sessionCookies;
    useWfFinished().set({
      type: "data",
      value: envelope,
      ...(cookies && { cookies }),
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
   * Authorization-server terminal (AUTH-SERVER.md §4.4). Reached INSTEAD of
   * `issue`/`redirect` when this login was started from `GET /auth/authorize`
   * (`ctx.authz` set by `init-login` or re-raised by `sso-callback`). Mints a
   * single-use authorization code bound to the authenticated user + the pending
   * request's PKCE challenge / redirect / token policy, then 302s the browser to
   * `redirect_uri?code&state`. It does NOT issue a session and attaches NO
   * cookies — the token is minted later, off the browser, at `POST /auth/token`.
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
        message: { level: "error", text: "Authorization request expired. Please try again." },
      });
      return undefined;
    }
    const { code } = await codes.mint({
      userId: ctx.subject,
      codeChallenge: req.codeChallenge,
      redirectUri: req.redirectUri,
      ...(req.clientId !== undefined && { clientId: req.clientId }),
      ...(req.scope !== undefined && { scope: req.scope }),
      ...(req.nonce !== undefined && { nonce: req.nonce }),
      ...(req.idToken !== undefined && { idToken: req.idToken }),
      ...(req.accessToken !== undefined && { accessToken: req.accessToken }),
      ...(req.audience !== undefined && { audience: req.audience }),
      tokenPolicy: req.tokenPolicy,
    });
    await pending.delete(handle);

    const url = new URL(req.redirectUri);
    url.searchParams.set("code", code);
    if (req.clientState !== undefined) url.searchParams.set("state", req.clientState);
    finishWf({
      next: {
        trigger: "immediate",
        action: { type: "redirect", target: url.toString(), reason: "authz-code" },
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
  finalizeFreshLogin(@WorkflowParam("context") ctx: AuthWfCtx): undefined | Promise<undefined> {
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
    // Recovery — `admin-only` lockout never self-unlocks, so a reset that left
    // the account locked must NOT pretend success. Only this mode can reach
    // finalize still locked (self-service ran `unlock-account`; temporary
    // auto-expires), so read the post-reset lock state and warn accordingly. A
    // user who simply forgot their password (never tripped the lock) is not
    // locked and still gets the normal success even under `admin-only`.
    if (ctx.lockout?.mode === "admin-only") {
      return this.recoveryLeftAccountLocked(ctx).then((locked) => {
        this.finishRecoveryReset(ctx, locked);
        return undefined;
      });
    }
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
          text: "Password updated, but your account is still locked. Contact an administrator to regain access.",
        },
        next: {
          trigger: "manual",
          primary: {
            label: "Back to sign-in",
            action: { type: "redirect", target, reason: "reset-locked" },
          },
        },
      });
    } else {
      finishWf({
        message: { level: "success", text: "Password updated. Redirecting to sign-in…" },
        next: {
          trigger: "auto",
          timeoutMs: 5000,
          action: { type: "redirect", target, reason: "reset-success" },
          skipButton: { label: "Go now" },
        },
      });
    }
    (ctx.completion ??= {}).redirectUrl = target;
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
    this.requireSubject(ctx);
    // An `admin-only` lockout that survived the reset must NOT be auto-logged-in
    // — minting tokens would defeat the very freeze the fresh-login terminal
    // warns about. Emit that same warn terminal (no tokens) instead. Only
    // `admin-only` can reach here still locked (self-service unlocked,
    // temporary auto-expires), and only recovery resolves `ctx.lockout`, so
    // invite auto-login is unaffected.
    if (ctx.lockout?.mode === "admin-only" && (await this.recoveryLeftAccountLocked(ctx))) {
      this.finishRecoveryReset(ctx, true);
      return undefined;
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
        finishWf({ message: { level: "info", text: "Self-signup is currently disabled." } });
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
    ctx.newPasswordRequired = true;
    (ctx.password ??= {}).changeReason = "initial";
    return undefined;
  }

  /** Generic "you already have an account" finish for the signup existence collision (safe — only reached post-OTP). */
  private finishSignupAlreadyRegistered(): void {
    finishWf({
      message: { level: "info", text: "You already have an account. Please sign in." },
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

  // ── Alt-cred stubs (4; login-only, all condition: false placeholders) ──

  @Step("magic-link-request")
  @Public()
  // oxlint-disable-next-line typescript/no-redundant-type-constituents -- explicit sync|async override seam, see CLAUDE.md "Pure extension-point stubs"
  magicLinkRequest(@WorkflowParam("context") _ctx: AuthWfCtx): unknown | Promise<unknown> {
    return undefined;
  }

  @Step("magic-link-send")
  @Public()
  // oxlint-disable-next-line typescript/no-redundant-type-constituents -- explicit sync|async override seam, see CLAUDE.md "Pure extension-point stubs"
  magicLinkSend(@WorkflowParam("context") _ctx: AuthWfCtx): unknown | Promise<unknown> {
    return undefined;
  }

  @Step("magic-link-verified")
  @Public()
  // oxlint-disable-next-line typescript/no-redundant-type-constituents -- explicit sync|async override seam, see CLAUDE.md "Pure extension-point stubs"
  magicLinkVerified(@WorkflowParam("context") _ctx: AuthWfCtx): unknown | Promise<unknown> {
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
        message: { level: "success", text: "Account linked." },
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
    if (user.account.locked || !user.account.active) {
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
        await this.users.update(outcome.userId, extras as Partial<UserCredentials>);
      }
    }

    // Seed channel state from the resolved user so the shared enrolment / MFA /
    // notify-new-device gates behave. The provider email is a display fallback.
    this.seedChannelState(ctx, user, profile.email);

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
   * Seed `ctx.email` / `ctx.channel` from a resolved user's confirmed channels —
   * shared by `ssoCallback` (linked / created / auto-linked) and `proveControl`
   * (interactively-linked) so the post-success channel shape can't drift between
   * the two federated entry points. Mirrors `credentials`' post-login seeding.
   * `fallbackEmail` (the provider / snapshot email) is a DISPLAY fallback only —
   * never promoted to the unique login handle (a gated, later-phase concern).
   */
  private seedChannelState(ctx: AuthWfCtx, user: UserCredentials, fallbackEmail?: string): void {
    const email = user.mfa.methods.find((m) => m.name === "email" && m.confirmed);
    if (email) {
      ctx.email = email.value;
      (ctx.channel ??= {}).emailConfirmed = true;
    } else if (fallbackEmail) {
      ctx.email = fallbackEmail;
    }
    const phone = user.mfa.methods.find((m) => m.name === "sms" && m.confirmed);
    if (phone) {
      const channel = (ctx.channel ??= {});
      channel.phone = phone.value;
      channel.phoneConfirmed = true;
    }
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
  ): Promise<string | null> {
    const method = candidate.mfa.methods.find((m) => m.name === pending.otpChannel && m.confirmed);
    if (!method) return null;
    const code = this.mintPin(pending, this.opts.mfa.pincodeLength, this.opts.mfa.pincodeTtlMs);
    await this.deliver({
      kind: "mfa-pincode",
      channel: pending.otpChannel as "email" | "sms",
      recipient: method.value,
      code,
      expiresInMs: this.opts.mfa.pincodeTtlMs,
    });
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
      if (cooldown && Date.now() < cooldown) {
        const waitSec = Math.ceil((cooldown - Date.now()) / 1000);
        throw this.throwPublic(ctx, wf, {
          formMessage: `Please wait ${waitSec}s before requesting another code`,
        });
      }
      const sentTo = await this.deliverPendingLinkPin(candidate, pending);
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
      const pinErr = this.verifyPin(pending, input.code);
      if (pinErr) throw this.throwPublic(ctx, wf, { errors: pinErr });
    } else {
      try {
        await this.users.login(candidate.username, input.password ?? "", this.lockoutOverride(ctx));
      } catch (err) {
        if (err instanceof UserAuthError && err.type === "LOCKED") {
          throw this.throwPublic(ctx, wf, {
            formMessage: "Account locked, please try again later",
          });
        }
        throw this.throwPublic(ctx, wf, { errors: { password: "Invalid password" } });
      }
    }

    // ── Account-state gate — BEFORE linking / setting subject (mirror the
    // sso-callback success gate; essential for the OTP path since verifyPin,
    // unlike users.login, does not itself reject a locked/inactive account). ──
    if (candidate.account.locked || !candidate.account.active) {
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
    this.seedChannelState(ctx, candidate, pending.snapshot?.email);

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
    // `credentials` and skips the exchange. Exactly one sets `ctx.subject`.
    { id: "sso-callback", condition: (ctx) => !!ctx.idpInbound },
    { id: "credentials", condition: (ctx) => !ctx.idpInbound },
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
    {
      condition: () => false,
      steps: [
        { id: "magic-link-request" },
        { id: "magic-link-send" },
        { id: "magic-link-verified" },
        { id: "passkey" },
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

    // Finalize — EXACTLY ONE terminal. An authorization-server login (started
    // from /auth/authorize, `ctx.authz` set) mints an auth code and delivers it
    // to the client WITHOUT issuing a browser session; every other login takes
    // the normal issue → notify → redirect tail. `ctx.authz` is set by
    // init-login / sso-callback and never flips in the tail, so the condition is
    // safe to hoist onto the subflow.
    {
      condition: (ctx) => !ctx.authz,
      steps: [
        { id: "issue" },
        {
          id: "notify-new-device",
          condition: (ctx) =>
            !ctx.isFirstLogin && !!ctx.finalize?.notifyNewDevice && !!ctx.trust?.newDevice,
        },
        { id: "redirect" },
      ],
    },
    { id: "mint-authz-code", condition: (ctx) => !!ctx.authz },
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
    { id: "send-email", condition: (ctx) => !!ctx.subject },

    // ── Phase B: anonymous magic-link resume (all public) ──
    {
      condition: (ctx) => !!ctx.subject,
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
    { break: (ctx) => !ctx.subject },

    { id: "prepare-post-reset" },
    { id: "prepare-recovery-alt-actions" },
    { id: "prepare-lockout" }, // self-service mode → unlock-account runs in the post-reset tail
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
    { id: "unlock-account", condition: (ctx) => ctx.lockout?.mode === "self-service" },
    ...consentsPersistTailSchema,
    // Finalize (recovery tail — gated by ctx.autoLogin, mirrored from
    // `opts.autoLoginOnRecover` by init-recovery).
    { id: "finalize-fresh-login", condition: (ctx) => !ctx.autoLogin },
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
    // Revoke the user's OTHER sessions, then re-issue the acting one on a fresh
    // token (finish step) — net: no ghost sessions survive the change.
    { id: "revoke-sessions", condition: (ctx) => !!ctx.changePassword?.revokeOtherSessions },
    { id: "finish-change-password" },
  ])
  changePasswordFlow(): void {}

  /**
   * add-mfa.flow — authenticated self-service "add a second factor". Same
   * gating model as change-password: NOT `@Public()` — `init-add-mfa` is arbac-
   * gated (`auth.add-mfa` / `self`) and binds `ctx.subject` from the session, so
   * an unauthenticated / unauthorized caller is rejected at the first step. NOT
   * in `DEFAULT_AUTH_WORKFLOWS` — reached only via the GUARDED trigger route
   * (`AuthController.addMfa`), never the public `/auth/trigger`.
   *
   * The body REUSES the login/invite forced-enrolment trio verbatim
   * (`enroll-pick-method` → `enroll-address` → `enroll-confirm`); the only
   * difference is the driver: `init-add-mfa` narrows `ctx.mfaPolicy`
   * `availableTransports` to the transports the user has NOT enrolled, so the
   * picker offers exactly those and auto-picks when one remains. Available only
   * when something is un-enrolled — with everything enrolled the trio is skipped
   * and `finish-add-mfa` returns a benign "nothing to add" terminal.
   */
  @Workflow("auth/add-mfa/flow")
  @ArbacResource("auth.add-mfa")
  @ArbacAction("self")
  @WorkflowSchema<AuthWfCtx>([
    { id: "init-add-mfa" }, // arbac gate + bind subject + narrow transports to the un-enrolled remainder
    { break: (ctx) => !ctx.subject }, // defence in depth (init throws 401 if unauth)
    // Enrol the chosen method — REUSES the login/invite trio verbatim, gated on
    // there being something to add. One remaining transport auto-picks; more
    // than one pauses on the picker form listing exactly the remainder.
    {
      condition: (ctx) => (ctx.addMfa?.candidates?.length ?? 0) > 0,
      steps: enrollTrioSteps,
    },
    { id: "finish-add-mfa" },
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
    { id: "finalize-auto-login" }, // v1 always auto-logins
  ])
  signupFlow(): void {}
}
