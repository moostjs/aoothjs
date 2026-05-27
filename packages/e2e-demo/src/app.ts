import {
  arbacAuthorizeInterceptor,
  type ArbacDbScope,
  ArbacUserProviderToken,
  MoostArbac,
} from "@aooth/arbac-moost";
import { AtscriptArbacUserProvider } from "@aooth/arbac-moost/atscript";
import {
  AuthCredential,
  type AuthEmailEvent,
  type AuthSmsEvent,
  type EmailSender,
  type SmsSender,
} from "@aooth/auth";
import {
  type AuditEvent,
  AuthController,
  authGuardInterceptor,
  AuthOpts,
  type ConsentDescriptor,
  type ConsentEvent,
  ConsentStore,
  createAuthEmailOutlet,
  DEFAULT_AUTH_WORKFLOWS,
  type DeliverPayload,
  type DuplicateAction,
  type InvitePolicyOverrides,
  type InviteWfCtx,
  InviteWorkflow,
  type InviteWorkflowOpts,
  type LoginWfCtx,
  LoginWorkflow,
  type LoginWorkflowOpts,
  Public,
  type RecoveryPolicyOverrides,
  type RecoveryWfCtx,
  RecoveryWorkflow,
  type RecoveryWorkflowOpts,
  useAuth,
  WfTrigger,
  WfTriggerProvider,
} from "@aooth/auth-moost";
import { HandleStateStrategy, Step, WorkflowParam } from "@moostjs/event-wf";
import type { TAtscriptAnnotatedType } from "@atscript/typescript/utils";
import { type UserCredentials, UserService } from "@aooth/user";
import { MoostHttp, Post } from "@moostjs/event-http";
import { MoostWf } from "@moostjs/event-wf";
import {
  Controller,
  createProvideRegistry,
  createReplaceRegistry,
  getMoostInfact,
  Inherit,
  Injectable,
  Moost,
} from "moost";
import type { AddressInfo } from "node:net";

import { type AppAuth, createAooth } from "./aooth";
import { type AppDb, createAppDb, syncAppSchema } from "./db";
import { ConsoleEmailSender } from "./email/console-email-sender";
import { type AppEnv, ENV } from "./env";
import {
  HealthController,
  makeAuditController,
  makeCommentsController,
  makeDepartmentsController,
  makeDocumentsController,
  makeProjectsController,
  makeTasksController,
  makeTenantsController,
  makeUsersController,
} from "./controllers";
import { DemoUser, InviteAcceptProfileForm } from "./models/user.as";
import { allRoles, type UserAttrs } from "./roles";
import { seedAll } from "./seed";
import { createTestMailboxController, type OtpConsentRecord } from "./test-mailbox";
import {
  INVITE_VARIANTS,
  type InviteMfaCtxOverrides,
  LOGIN_VARIANTS,
  type LoginMfaCtxOverrides,
  type LoginPolicyOverrides,
  pickVariant,
  RECOVERY_VARIANTS,
} from "./variants";
import { readVariantHeader } from "./variants-server";
import { createWfStore } from "./wf-store";
import { makeHandoverWorkflow } from "./workflows/handover.workflow";

export interface BuildAppOptions {
  emailSender?: EmailSender;
  dbPath?: string;
  port?: number;
  envOverrides?: Partial<AppEnv>;
  /**
   * Per-workflow registration toggles. Defaults to all enabled. Used by
   * DX-07 to assert that a disabled workflow (`auth.invite`) is unreachable.
   */
  workflowsEnabled?: { login?: boolean; recovery?: boolean; invite?: boolean };
  /**
   * When `false`, the bundled `AuthController` (login/logout/refresh/status/
   * password) is NOT registered; the auth GUARD is still installed globally.
   * Used by DX-08.
   */
  authEndpointsEnabled?: boolean;
  /**
   * E2E coverage hook — per-workflow option overrides deep-merged into the
   * demo defaults (one nested group at a time, e.g.
   * `{ deviceTrust: { ttlMs: 1 } }` replaces only `deviceTrust.ttlMs` and
   * preserves the other `deviceTrust.*` keys).
   * Used by the workflow-options e2e specs to flip a single flag without
   * forking the whole demo wiring. For MFA mode/transports (stripped from
   * opts in PR9) use `loginMfaCtx` below.
   */
  /**
   * Override the shared `AuthOpts` defaults (pincode timers, magic-link TTL,
   * login URL, TOTP issuer). The demo builds a fresh `AuthOpts` instance,
   * shallow-merges this partial onto it (deep-merging the nested `mfa` group),
   * and registers the result via moost's DI so each workflow ctor resolves it.
   */
  authOpts?: {
    mfa?: Partial<AuthOpts["mfa"]>;
    magicLinkTtlMs?: number;
    loginUrl?: string;
    totpIssuer?: string;
  };
  /**
   * Override the singleton `ConsentStore` provider. Defaults to a no-op
   * `new ConsentStore()`. Customer / test subclasses go here and the demo
   * registers the result via moost's DI so each workflow ctor resolves it.
   */
  consentStore?: ConsentStore;
  loginOpts?: LoginWorkflowOpts;
  /**
   * Per-test login policy overrides applied via the `resolveXxx(ctx)` getters
   * on `DemoLoginWorkflow`. Each group in this payload wins over both the
   * demo's per-resolver defaults and the active variant's `policy.<group>`
   * — same precedence pattern as `loginMfaCtx` for the MFA setter. Use this
   * for tests that previously did `loginOpts: { guards: { ... } }` /
   * `loginOpts: { profile: { ... } }` etc.; those keys moved off opts.
   */
  loginPolicy?: LoginPolicyOverrides;
  recoveryOpts?: RecoveryWorkflowOpts;
  /**
   * Per-test recovery policy overrides applied via the `resolveXxx(ctx)`
   * getters on `DemoRecoveryWorkflow`. Same precedence pattern as
   * `loginPolicy` / `invitePolicy`. Tests that previously did
   * `recoveryOpts: { postReset: { ... } }` / `recoveryOpts: { delivery: {
   * mode: ..., otp: { transports: [...] } } }` etc. flip the matching group
   * here — those keys moved off `RecoveryWorkflowOpts` onto the resolver
   * surface.
   */
  recoveryPolicy?: RecoveryPolicyOverrides;
  inviteOpts?: InviteWorkflowOpts;
  /**
   * Per-test invite policy overrides applied via the `resolveXxx(ctx)` getters
   * on `DemoInviteWorkflow`. Same precedence pattern as `loginPolicy`. Tests
   * that previously did `inviteOpts: { accept: { ... } }` / `inviteOpts: {
   * cancellation: { ... } }` etc. flip the matching group here.
   */
  invitePolicy?: InvitePolicyOverrides;
  /**
   * Replace the default `DemoInviteWorkflow` controller with a consumer-
   * supplied class. Used by override-pattern e2e tests that need their own
   * `InviteWorkflow` subclass wired through the full HTTP+DI stack —
   * `inviteOpts` is opts-only, this knob swaps the whole class.
   */
  inviteWorkflowClass?: new (...args: never[]) => unknown;
  /**
   * Replace the default `DemoLoginWorkflow` controller with a consumer-
   * supplied class. Mirrors `inviteWorkflowClass`.
   */
  loginWorkflowClass?: new (...args: never[]) => unknown;
  /**
   * Static MFA ctx overrides injected via the single `prepareMfaSetup` step
   * setter. PR9 stripped the corresponding opts shape
   * (`mfa.mode` / `mfa.transports`); tests that previously poked those keys
   * pass this object instead. `buildApp` wraps the demo (or
   * `loginWorkflowClass` if supplied) with a tiny subclass that forces these
   * values into ctx and falls through to the base setter for any field not
   * supplied. Variant-driven mfa overrides (see `LOGIN_VARIANTS`) are applied
   * by `DemoLoginWorkflow` itself; this knob is the test-time escape hatch.
   */
  loginMfaCtx?: LoginMfaCtxOverrides;
  /** Invite-side counterpart of `loginMfaCtx`. */
  inviteMfaCtx?: InviteMfaCtxOverrides;
}

// Test-mode mailbox buffers anchored on `globalThis` so they survive vite's
// HMR re-evaluations of this module. Without this, every HMR cycle produces a
// fresh `CaptureEmailSender` instance with its own `.events` array; the
// `__test` controller (registered at boot) keeps reading the FIRST array
// while the workflow's `forwardDeliver` writes to the LATEST. globalThis is
// process-scoped, not module-scoped → both references converge.
/* eslint-disable no-underscore-dangle -- intentional `__`-prefix marks internal globalThis slots */
const g = globalThis as {
  __aoothE2eEmails?: AuthEmailEvent[];
  __aoothE2eSms?: AuthSmsEvent[];
  __aoothE2eActiveSessions?: Map<string, number>;
  // username → profile fields that must be collected before issue. Populated
  // by `seed.ts` for users that have no real DB column carrying this state
  // and consulted by `DemoLoginWorkflow.credentials()` to inject
  // `ctx.profileMissingFields` so the `profile-complete` step fires. See
  // WF-LOGIN-032.
  __aoothE2eProfileMissingFields?: Map<string, string[]>;
  // Captured `RecoveryWorkflow.audit()` payloads. Plain array so the
  // `/__test/audit` endpoint can return + the `__test/reset` flow can clear
  // (length = 0) without breaking the shared reference.
  __aoothE2eAuditEvents?: AuditEvent[];
  // When `true`, `DemoInviteWorkflow.duplicateCheck()` returns `'allow'` for
  // every email so the store-level uniqueness branch in `invitePreCreateUser`
  // gets exercised (WF-INVITE-018). Flipped via POST /__test/allow-duplicate-invites
  // and reset to `false` by `reseed()` / `__test/reset`.
  __aoothE2eAllowDuplicateInvites?: boolean;
  // username → ordered list of consent events captured by
  // `DemoConsentStore.save`. Drives WF-LOGIN-BUMP-01 etc.
  __aoothE2eConsentLog?: Map<string, ConsentEvent[]>;
  // username → ordered list of OTP-channel disclosure records captured by
  // `DemoConsentStore.recordOtpChannelConsent`. Separate buffer from
  // `__aoothE2eConsentLog` because the record shape doesn't fit
  // `ConsentEvent`. Drives WF-LOGIN-OTP-DISCLOSURE-01.
  __aoothE2eOtpConsentLog?: Map<string, OtpConsentRecord[]>;
};
g.__aoothE2eEmails ??= [];
g.__aoothE2eSms ??= [];
g.__aoothE2eActiveSessions ??= new Map();
g.__aoothE2eProfileMissingFields ??= new Map();
g.__aoothE2eAuditEvents ??= [];
g.__aoothE2eAllowDuplicateInvites ??= false;
g.__aoothE2eConsentLog ??= new Map();
g.__aoothE2eOtpConsentLog ??= new Map();
const sharedEmailsBuffer: AuthEmailEvent[] = g.__aoothE2eEmails;
const sharedSmsBuffer: AuthSmsEvent[] = g.__aoothE2eSms;
const sharedActiveSessionsBuffer: Map<string, number> = g.__aoothE2eActiveSessions;
const sharedProfileMissingFieldsBuffer: Map<string, string[]> = g.__aoothE2eProfileMissingFields;
const sharedAuditEventsBuffer: AuditEvent[] = g.__aoothE2eAuditEvents;
const sharedConsentLogBuffer: Map<string, ConsentEvent[]> = g.__aoothE2eConsentLog;
const sharedOtpConsentLogBuffer: Map<string, OtpConsentRecord[]> = g.__aoothE2eOtpConsentLog;
/* eslint-enable no-underscore-dangle */

/** Two-level deep merge — sufficient for the nested-pojo workflow opts. */
function mergeWfOpts<T>(base: T, over?: T): T {
  if (!over) return base;
  const baseRec = base as unknown as Record<string, unknown>;
  const overRec = over as unknown as Record<string, unknown>;
  const out: Record<string, unknown> = { ...baseRec };
  for (const [k, v] of Object.entries(overRec)) {
    const prev = out[k];
    if (
      prev &&
      typeof prev === "object" &&
      !Array.isArray(prev) &&
      v &&
      typeof v === "object" &&
      !Array.isArray(v)
    ) {
      out[k] = { ...(prev as Record<string, unknown>), ...(v as Record<string, unknown>) };
    } else {
      out[k] = v;
    }
  }
  return out as T;
}

export interface AppHandle {
  app: Moost;
  appDb: AppDb;
  baseUrl: string;
  emailSender: EmailSender;
  aooth: AppAuth;
  /**
   * Truncates every app DB table and re-runs `seedAll(handle)`. Returns the
   * number of seeded user records — used by the `__test/reset` endpoint and by
   * `src/main.ts` so the dev-entry seed path and the test-reset path share
   * exactly one implementation.
   */
  reseed: () => Promise<number>;
  close: () => Promise<void>;
}

/**
 * Per-variant `pendingConsents` map for the playwright SPA — read by
 * `DemoConsentStore.getPendingConsents` via the `x-wf-variant` header. Keeps
 * the consent-universe choice colocated with the rest of the per-variant
 * config. Used by WF-CONSENT-ARRAY-01.
 */
const VARIANT_PENDING_CONSENTS: Record<string, ConsentDescriptor[]> = {
  "consent-array": [
    {
      id: "terms",
      text: "I accept the Terms of Service",
      required: "Terms are mandatory",
      version: "v2",
    },
    { id: "marketing", text: "Send me product updates" },
  ],
  // Phase-5 reshape of the prior `recovery-terms-bump` / `invite-terms`
  // variants — the static `acceptance.termsVersion` driver retired; the
  // customer ConsentStore now declares the pending universe per variant.
  // Mirrors the prior test scenarios: a single required terms descriptor
  // captured on `SetPasswordForm` during recovery / invite accept-tail.
  "recovery-terms-bump": [
    {
      id: "terms",
      text: "I accept the updated Terms",
      required: "Terms are mandatory",
      version: "v2",
    },
  ],
  "invite-terms": [
    {
      id: "terms",
      text: "I accept the Terms",
      required: "Terms are mandatory",
      version: "v1",
    },
  ],
  // The prior `acceptance` login variant relied on `acceptance.termsVersion`
  // driving the standalone bump-prompt; Phase 5 moves that driver to the
  // customer ConsentStore. Keep the variant exercising the same scenario
  // (required-terms bump + optional marketing) so WF-LOGIN-024/025/HACK-01
  // still pin the standalone-bump path under the new shape.
  acceptance: [
    {
      id: "terms",
      text: "I accept the Terms and Conditions",
      required: "You must accept the terms",
      version: "v1",
    },
    { id: "marketing", text: "I would like to receive marketing emails" },
  ],
  // Same shape for the `terms-bump` variant — drives the WF-LOGIN-BUMP-01
  // standalone-bump scenario with the bumped `v3` version. Terms-only here
  // (matches the pre-Phase-5 `consentMarketing: false` variant intent).
  "terms-bump": [
    {
      id: "terms",
      text: "I accept the updated Terms",
      required: "You must accept the terms",
      version: "v3",
    },
  ],
  // The `full` variant exercises every optional step in one login (WF-LOGIN-032).
  // Required terms + optional marketing — mirrors the prior
  // `acceptance: { termsVersion: 'v1', consentMarketing: true }` intent now
  // that those static fields don't drive consent anymore.
  full: [
    {
      id: "terms",
      text: "I accept the Terms",
      required: "You must accept the terms",
      version: "v1",
    },
    { id: "marketing", text: "I would like to receive marketing emails" },
  ],
};

/**
 * Demo `ConsentStore` — appends every persisted batch into the
 * globalThis-anchored buffer the `/__test/consent-log/:username` endpoint
 * reads from. One writer shared across all three Demo workflows.
 *
 * `getPendingConsents` keys off the per-request `x-wf-variant` header so
 * playwright specs can opt a single workflow run into a non-empty consent
 * universe without rebooting the dev server.
 *
 * `recordOtpChannelConsent` writes to a sibling buffer
 * (`sharedOtpConsentLogBuffer`) read by `/__test/otp-consent-log/:username`.
 */
@Injectable() // SINGLETON
class DemoConsentStore extends ConsentStore {
  override async getPendingConsents(
    _username: string | undefined,
    _ctx: { workflow: string; channel?: "email" | "sms" },
  ): Promise<ConsentDescriptor[]> {
    const variant = readVariantHeader();
    if (!variant) return [];
    const pending = VARIANT_PENDING_CONSENTS[variant];
    return pending ? [...pending] : [];
  }
  override async save(username: string, events: ConsentEvent[]): Promise<void> {
    const prior = sharedConsentLogBuffer.get(username) ?? [];
    sharedConsentLogBuffer.set(username, [...prior, ...events]);
  }
  override async recordOtpChannelConsent(
    username: string,
    channel: "email" | "sms",
    target: string,
    disclosure: string,
  ): Promise<void> {
    const prior = sharedOtpConsentLogBuffer.get(username) ?? [];
    sharedOtpConsentLogBuffer.set(username, [
      ...prior,
      { channel, target, disclosure, at: Date.now() },
    ]);
  }
}

export async function buildApp(opts: BuildAppOptions = {}): Promise<AppHandle> {
  const env: AppEnv = { ...ENV, ...opts.envOverrides };
  const dbPath = opts.dbPath ?? env.DB_PATH;
  const port = opts.port ?? env.PORT;
  // Single-source DEMO_MODE check. `'test'` swaps in capturing senders and
  // mounts the `__test/*` controller. NEVER read this variable elsewhere —
  // the rest of the app gets test capability via the explicit refs below.
  const isTestMode = process.env.DEMO_MODE === "test";

  const appDb = createAppDb(dbPath);
  await syncAppSchema(appDb);

  // In test mode, route every outgoing email through the globalThis-anchored
  // shared buffer so the `__test/emails` controller and the workflow outlet
  // see the same array even across HMR module-reloads. The buffer survives
  // module re-eval; the sender is a thin adapter that pushes to it.
  // An explicit `opts.emailSender` still wins (vitest harness passes its own).
  const testCaptureSender: EmailSender | undefined = isTestMode
    ? {
        send(event) {
          sharedEmailsBuffer.push(event);
          return Promise.resolve();
        },
      }
    : undefined;
  const emailSender: EmailSender =
    opts.emailSender ?? testCaptureSender ?? new ConsoleEmailSender();
  const aooth = createAooth({ tables: appDb.tables, env });
  const wfStateStore = createWfStore(appDb);

  const app = new Moost();
  const moostHttp = new MoostHttp();
  app.adapter(moostHttp);
  app.adapter(new MoostWf());

  // Build the cross-workflow `AuthOpts` singleton — defaults seeded from
  // `min(env.RECOVERY_TTL_MS, env.INVITE_TTL_MS)` so a test that shrinks ONE
  // of the env vars (the per-workflow TTL-expiry tests) gets the short window
  // on the shared `AuthOpts.magicLinkTtlMs` knob. The cross-workflow singleton
  // means both flows now share a window — pre-AuthOpts each workflow had its
  // own `delivery.magicLinkTtlMs` / `send.tokenTtlMs`. `opts.authOpts` partial
  // layers on top here. Production consumers that want a separate per-flow
  // window override `resolveXxx` to compute an env-driven `expires` themselves,
  // or override `sendInviteEmail` / `sendMagicLink` step bodies.
  const authOpts = new AuthOpts();
  authOpts.magicLinkTtlMs = Math.min(env.RECOVERY_TTL_MS, env.INVITE_TTL_MS);
  const userAuthOpts = opts.authOpts;
  if (userAuthOpts) {
    if (userAuthOpts.mfa) authOpts.mfa = { ...authOpts.mfa, ...userAuthOpts.mfa };
    if (userAuthOpts.magicLinkTtlMs !== undefined) {
      authOpts.magicLinkTtlMs = userAuthOpts.magicLinkTtlMs;
    }
    if (userAuthOpts.loginUrl !== undefined) authOpts.loginUrl = userAuthOpts.loginUrl;
    if (userAuthOpts.totpIssuer !== undefined) authOpts.totpIssuer = userAuthOpts.totpIssuer;
  }

  const consentStore = opts.consentStore ?? new DemoConsentStore();

  /**
   * Per-event `AuthOpts` override applied inside each demo workflow subclass
   * ctor (FOR_EVENT scope). The cross-workflow `AuthOpts` instance is a moost
   * SINGLETON (per the brief), but the Playwright variant mechanism still needs
   * a per-request escape hatch for fields like `mfa.pincodeResendTimeoutMs`
   * (driven by `mfa-fast-resend` / `recovery-fast-resend`) and
   * `magicLinkTtlMs` (driven by `device-trust-short-ttl` etc.). We clone the
   * singleton and overlay the variant's `authOpts` payload — the override is
   * scoped to the current event instance only.
   */
  const cloneAuthOptsWithVariant = (
    overrides: { mfa?: Partial<AuthOpts["mfa"]>; magicLinkTtlMs?: number } | undefined,
  ): AuthOpts => {
    if (!overrides) return authOpts;
    const clone = new AuthOpts();
    clone.mfa = { ...authOpts.mfa, ...overrides.mfa };
    clone.magicLinkTtlMs = overrides.magicLinkTtlMs ?? authOpts.magicLinkTtlMs;
    clone.loginUrl = authOpts.loginUrl;
    clone.totpIssuer = authOpts.totpIssuer;
    return clone;
  };

  // SMS: in test mode, push into the shared globalThis buffer (same HMR-survival
  // rationale as the email buffer above); otherwise console-log.
  const demoSmsSender: SmsSender = {
    async send(event) {
      if (isTestMode) {
        sharedSmsBuffer.push(event);
        return;
      }
      console.log("[demo SMS]", event.kind, event.recipient, event.code);
    },
  };

  // Shared `deliver()` body for both workflow subclasses below. The
  // discriminated `DeliverPayload` narrows `kind` to the matching transport
  // type, so no casts are needed when forwarding to EmailSender / SmsSender.
  const forwardDeliver = async (payload: DeliverPayload): Promise<void> => {
    if (payload.channel === "email") {
      await emailSender.send({
        kind: payload.kind,
        recipient: payload.recipient,
        ...(payload.code !== undefined && { code: payload.code }),
        ...(payload.url !== undefined && { url: payload.url }),
        expiresAt: payload.expiresAt ?? Date.now(),
        ...(payload.userId !== undefined && { username: payload.userId }),
        ...(payload.metadata && { metadata: payload.metadata }),
      });
      return;
    }
    await demoSmsSender.send({
      kind: payload.kind,
      recipient: payload.recipient,
      code: payload.code,
      ttlMs: payload.ttlMs ?? 0,
      ...(payload.userId !== undefined && { userId: payload.userId }),
    });
  };

  // Phase-2 reshape: `LoginWorkflow` is configured via a consumer subclass
  // that overrides `protected` methods. `@Inherit()` carries the base
  // class's `@Workflow` / `@WorkflowSchema` / `@Step` metadata; the
  // re-declared ctor is required because TS emits fresh design-paramtypes per
  // class.
  //
  // MFA shape note: `mfa.mode` / `mfa.transports` were stripped from
  // `LoginWorkflowOpts` in PR9. The demo's defaults (`mfaMode: 'disabled'`,
  // 3-transport availability) now live on the single `prepareMfaSetup`
  // override below. Variants that previously poked those opts keys carry
  // `mfaCtx` payloads consumed by the same override.
  //
  // Post-resolver reshape: `LoginWorkflowOpts` is infrastructure-only — policy
  // (alt-cred flags, guards, …) lives on `resolveXxx(ctx)` overrides below.
  // Variants supply `policy.<group>` payloads that those resolvers merge with
  // the demo's per-group defaults.
  const demoLoginOpts: LoginWorkflowOpts = mergeWfOpts({}, opts.loginOpts);
  // FOR_EVENT scope is REQUIRED here: the ctor reads per-request HTTP headers
  // via `readVariantHeader()` to pick a variant config; SINGLETON would freeze
  // the variant decision at app boot. The base `LoginWorkflow` itself is fine
  // as SINGLETON (it just stores readonly fields), but composable-using
  // subclass ctors must opt into FOR_EVENT.
  @Inherit()
  @Injectable("FOR_EVENT")
  @Controller("auth/login")
  class DemoLoginWorkflow extends LoginWorkflow {
    constructor(
      users: UserService,
      authCred: AuthCredential,
      demoAuthOpts: AuthOpts,
      demoConsentStore: ConsentStore,
    ) {
      const variant = pickVariant(LOGIN_VARIANTS, readVariantHeader());
      super(
        variant?.opts
          ? mergeWfOpts(demoLoginOpts, variant.opts as LoginWorkflowOpts)
          : demoLoginOpts,
        users,
        authCred,
        // Apply the variant's per-request `authOpts` overlay (e.g.
        // `mfa-fast-resend` shrinks `mfa.pincodeResendTimeoutMs` to 1s);
        // returns the singleton verbatim when no overlay is supplied.
        // `demoAuthOpts` is captured but unused — the closure already has
        // `authOpts`; the param exists so moost can resolve `AuthOpts` DI.
        cloneAuthOptsWithVariant(variant?.authOpts),
        demoConsentStore,
      );
      void demoAuthOpts;
    }
    protected override deliver(payload: DeliverPayload) {
      return forwardDeliver(payload);
    }
    // ── Variant-driven resolveXxx policy overrides ──
    //
    // Each override layers the active variant's `policy.<group>` payload on
    // top of the demo's per-group default. The base library defaults remain
    // available via `super.resolveXxx(ctx)` for groups the variant doesn't
    // touch. Reads `readVariantHeader()` per request (FOR_EVENT scope ensures
    // a fresh instance per request).
    //
    // Precedence (high → low):
    //   1. test-time `opts.loginPolicy.<group>` (set by `buildTestApp`)
    //   2. variant `policy.<group>` (via `x-wf-variant` header)
    //   3. demo per-group default (tweaks on top of base)
    //   4. library default (`super.resolveXxx(ctx)`)
    protected override resolveProfile(ctx: LoginWfCtx): { required: boolean } {
      if (opts.loginPolicy?.profile) return opts.loginPolicy.profile;
      const variant = pickVariant(LOGIN_VARIANTS, readVariantHeader());
      if (variant?.policy?.profile) return variant.policy.profile;
      return super.resolveProfile(ctx) as { required: boolean };
    }
    protected override resolveAlternateCredentials(
      ctx: LoginWfCtx,
    ): NonNullable<LoginWfCtx["alternateCredentials"]> {
      if (opts.loginPolicy?.alternateCredentials) return opts.loginPolicy.alternateCredentials;
      const variant = pickVariant(LOGIN_VARIANTS, readVariantHeader());
      if (variant?.policy?.alternateCredentials) return variant.policy.alternateCredentials;
      // Demo default: forgotPassword + signup ON (dev UI dropdown surfaces them).
      const base = super.resolveAlternateCredentials(ctx) as NonNullable<
        LoginWfCtx["alternateCredentials"]
      >;
      return { ...base, forgotPassword: true, signup: true };
    }
    protected override resolveDeviceTrust(ctx: LoginWfCtx): NonNullable<LoginWfCtx["deviceTrust"]> {
      if (opts.loginPolicy?.deviceTrust) return opts.loginPolicy.deviceTrust;
      const variant = pickVariant(LOGIN_VARIANTS, readVariantHeader());
      if (variant?.policy?.deviceTrust) return variant.policy.deviceTrust;
      return super.resolveDeviceTrust(ctx) as NonNullable<LoginWfCtx["deviceTrust"]>;
    }
    protected override resolveEnrollment(ctx: LoginWfCtx): NonNullable<LoginWfCtx["enrollment"]> {
      if (opts.loginPolicy?.enrollment) return opts.loginPolicy.enrollment;
      const variant = pickVariant(LOGIN_VARIANTS, readVariantHeader());
      if (variant?.policy?.enrollment) return variant.policy.enrollment;
      return super.resolveEnrollment(ctx) as NonNullable<LoginWfCtx["enrollment"]>;
    }
    protected override resolveFinalize(ctx: LoginWfCtx): NonNullable<LoginWfCtx["finalize"]> {
      if (opts.loginPolicy?.finalize) return opts.loginPolicy.finalize;
      const variant = pickVariant(LOGIN_VARIANTS, readVariantHeader());
      if (variant?.policy?.finalize) return variant.policy.finalize;
      return super.resolveFinalize(ctx) as NonNullable<LoginWfCtx["finalize"]>;
    }
    protected override resolveGuards(ctx: LoginWfCtx): NonNullable<LoginWfCtx["guards"]> {
      if (opts.loginPolicy?.guards) return opts.loginPolicy.guards;
      const variant = pickVariant(LOGIN_VARIANTS, readVariantHeader());
      if (variant?.policy?.guards) return variant.policy.guards;
      // Demo default: passwordInitial ON (seed users land on the
      // create-password-form on first login).
      const base = super.resolveGuards(ctx) as NonNullable<LoginWfCtx["guards"]>;
      return { ...base, passwordInitial: true };
    }
    protected override resolveSessionPolicy(
      ctx: LoginWfCtx,
    ): NonNullable<LoginWfCtx["sessionPolicy"]> {
      if (opts.loginPolicy?.sessionPolicy) return opts.loginPolicy.sessionPolicy;
      const variant = pickVariant(LOGIN_VARIANTS, readVariantHeader());
      if (variant?.policy?.sessionPolicy) return variant.policy.sessionPolicy;
      return super.resolveSessionPolicy(ctx) as NonNullable<LoginWfCtx["sessionPolicy"]>;
    }
    // ── Variant-driven mfa-ctx setter override ──
    // Reads the active variant from the request header; if a variant is active
    // and supplies `mfaCtx.<field>`, force it onto ctx (after the base setter
    // ran). Otherwise the demo's default takes over: `mfaMode: 'disabled'`
    // (most seeded users have no MFA enrolled and the e2e harness's `loginAs`
    // helper expects to finish login without a prompt). This default fires
    // BOTH when no variant is active (UI tests) AND when an active variant
    // omits `mfaCtx` (e.g. `acceptance` / `concurrency` / `redirect-home` /
    // `choice` — variants exercising non-MFA concerns that need MFA out of
    // the flow so the test step reaches the form under test without an MFA
    // prompt blocking it).
    @Step("prepare-mfa-setup")
    @Public()
    override prepareMfaSetup(
      @WorkflowParam("context") ctx: LoginWfCtx,
    ): undefined | Promise<undefined> {
      const baseResult = super.prepareMfaSetup(ctx);
      const apply = (): undefined => {
        const variant = pickVariant(LOGIN_VARIANTS, readVariantHeader());
        const v = variant?.mfaCtx;
        ctx.mfaMode = v?.mfaMode ?? "disabled";
        if (v?.availableMfaTransports !== undefined) {
          ctx.availableMfaTransports = [...v.availableMfaTransports];
        }
        if (v?.currentMfa !== undefined) ctx.currentMfa = v.currentMfa;
        return undefined;
      };
      return baseResult instanceof Promise ? baseResult.then(apply) : apply();
    }
    // The credential store is JWT-based (stateless) so the demo can't query
    // "how many sessions for user X" from `authCredential`. The seed counts
    // its own `issue()` calls into a globalThis map; reading it here wires
    // `ctx.activeSessions` for the `concurrency-limit` step.
    protected override async loadActiveSessions(username: string): Promise<number> {
      return sharedActiveSessionsBuffer.get(username) ?? 0;
    }
    // After the bundled `credentials` step authenticates the user, inject
    // `ctx.profileMissingFields` from the demo's per-user buffer. There is no
    // DB column carrying this state, so this override is the bridge between
    // `seed.ts` and the `profile-complete` schema condition. Required by
    // WF-LOGIN-032.
    override async credentials(ctx: LoginWfCtx): Promise<unknown> {
      const result = await super.credentials(ctx);
      if (ctx.username) {
        const missing = sharedProfileMissingFieldsBuffer.get(ctx.username);
        if (missing && missing.length > 0) {
          ctx.profileMissingFields = [...missing];
        }
      }
      return result;
    }
  }

  // `RecoveryWorkflow` is configured via a consumer subclass that overrides
  // `protected` methods. The demo overrides `deliver` for OTP emails
  // (magic-link mode uses the email outlet on the trigger route) and
  // `emailToUserId` to map a recovery-step email to the canonical username.
  //
  // Post-resolver reshape: `RecoveryWorkflowOpts` is infrastructure-only
  // (magic-link TTL, OTP timers, forms). Policy (delivery.mode +
  // otpTransports, preReset, postReset, altActions, audit) lives on
  // `resolveXxx(ctx)` overrides below. Variants supply `policy.<group>`
  // payloads that those resolvers merge with the demo's per-group defaults.
  // `RecoveryWorkflowOpts` is forms-only after the AuthOpts reshape; the
  // `magicLinkTtlMs` default moved to the singleton `AuthOpts.magicLinkTtlMs`
  // built above (seeded from `env.RECOVERY_TTL_MS`).
  const demoRecoveryOpts: RecoveryWorkflowOpts = mergeWfOpts({}, opts.recoveryOpts);
  // FOR_EVENT — see DemoLoginWorkflow comment; ctor reads variant header.
  @Inherit()
  @Injectable("FOR_EVENT")
  @Controller("auth/recovery")
  class DemoRecoveryWorkflow extends RecoveryWorkflow {
    constructor(
      users: UserService,
      authCred: AuthCredential,
      demoAuthOpts: AuthOpts,
      demoConsentStore: ConsentStore,
    ) {
      const variant = pickVariant(RECOVERY_VARIANTS, readVariantHeader());
      super(
        variant?.opts ? mergeWfOpts(demoRecoveryOpts, variant.opts) : demoRecoveryOpts,
        users,
        authCred,
        cloneAuthOptsWithVariant(variant?.authOpts),
        demoConsentStore,
      );
      void demoAuthOpts;
    }
    protected override deliver(payload: DeliverPayload) {
      return forwardDeliver(payload);
    }
    // Maps a recovery-step email to the canonical username. In this demo
    // `DemoUser.username` happens to equal `DemoUser.email` for seeded users,
    // so a direct email lookup is enough — but the indirection is what makes
    // recovery work for any user model where `username !== email`.
    protected override async emailToUserId(email: string): Promise<string | null> {
      const user = await aooth.userStore.findByUsername(email);
      return user ? user.username : null;
    }
    // Captures audit payloads into the shared globalThis buffer so
    // `/__test/audit` can return them to Playwright specs (WF-RECOVERY audit
    // assertions). Default base impl is a no-op.
    protected override async audit(event: AuditEvent): Promise<void> {
      sharedAuditEventsBuffer.push(event);
    }
    // ── Variant-driven resolveXxx policy overrides ──
    //
    // Precedence (high → low):
    //   1. test-time `opts.recoveryPolicy.<group>` (set by `buildTestApp`)
    //   2. variant `policy.<group>` (via `x-wf-variant` header)
    //   3. demo per-group default (tweaks on top of base)
    //   4. library default (`super.resolveXxx(ctx)`)
    protected override resolveDelivery(
      ctx: RecoveryWfCtx,
    ): NonNullable<RecoveryWfCtx["delivery"]> | Promise<NonNullable<RecoveryWfCtx["delivery"]>> {
      if (opts.recoveryPolicy?.delivery) return opts.recoveryPolicy.delivery;
      const variant = pickVariant(RECOVERY_VARIANTS, readVariantHeader());
      if (variant?.policy?.delivery) return variant.policy.delivery;
      return super.resolveDelivery(ctx);
    }
    protected override resolvePreReset(
      ctx: RecoveryWfCtx,
    ): NonNullable<RecoveryWfCtx["preReset"]> | Promise<NonNullable<RecoveryWfCtx["preReset"]>> {
      if (opts.recoveryPolicy?.preReset) return opts.recoveryPolicy.preReset;
      const variant = pickVariant(RECOVERY_VARIANTS, readVariantHeader());
      if (variant?.policy?.preReset) return variant.policy.preReset;
      return super.resolvePreReset(ctx);
    }
    protected override resolvePostReset(
      ctx: RecoveryWfCtx,
    ): NonNullable<RecoveryWfCtx["postReset"]> | Promise<NonNullable<RecoveryWfCtx["postReset"]>> {
      if (opts.recoveryPolicy?.postReset) return opts.recoveryPolicy.postReset;
      const variant = pickVariant(RECOVERY_VARIANTS, readVariantHeader());
      if (variant?.policy?.postReset) return variant.policy.postReset;
      // Demo default: opt out of revokeAllSessions so WF-RECOVERY-05 can keep
      // documenting the "pre-existing session stays valid" branch. Production
      // consumers should leave the secure default on. `freshLoginRequired`
      // defaults to false (auto-login) — what this SPA demo wants.
      const baseResult = super.resolvePostReset(ctx);
      const patch = (
        r: NonNullable<RecoveryWfCtx["postReset"]>,
      ): NonNullable<RecoveryWfCtx["postReset"]> => ({ ...r, revokeAllSessions: false });
      return baseResult instanceof Promise ? baseResult.then(patch) : patch(baseResult);
    }
    protected override resolveAltActions(
      ctx: RecoveryWfCtx,
    ):
      | NonNullable<RecoveryWfCtx["altActions"]>
      | Promise<NonNullable<RecoveryWfCtx["altActions"]>> {
      if (opts.recoveryPolicy?.altActions) return opts.recoveryPolicy.altActions;
      const variant = pickVariant(RECOVERY_VARIANTS, readVariantHeader());
      if (variant?.policy?.altActions) return variant.policy.altActions;
      return super.resolveAltActions(ctx);
    }
    protected override resolveAudit(
      ctx: RecoveryWfCtx,
    ): NonNullable<RecoveryWfCtx["audit"]> | Promise<NonNullable<RecoveryWfCtx["audit"]>> {
      if (opts.recoveryPolicy?.audit) return opts.recoveryPolicy.audit;
      const variant = pickVariant(RECOVERY_VARIANTS, readVariantHeader());
      if (variant?.policy?.audit) return variant.policy.audit;
      return super.resolveAudit(ctx);
    }
  }

  // Phase-4 reshape: `InviteWorkflow` is also configured via a consumer
  // subclass that overrides `protected` methods — matching login + recovery.
  //
  // MFA shape note: `mfa.mode` / `mfa.transports` were stripped from
  // `InviteWorkflowOpts` in PR9. The demo's default (`mfaMode: 'disabled'` —
  // most invite e2e tests assert the auto-login response payload after
  // password-set, pre-dating the optional/required enrolment loops) lives on
  // the single `inviteSetupMfa` override below; variants exercising enrolment
  // override via `opts.inviteMfaCtx` / `withInviteMfaCtx`.
  //
  // Post-resolver reshape: `InviteWorkflowOpts` is infrastructure-only — policy
  // (adminForm, send.mode, accept, cancellation, audit, mfa.issuer) lives on
  // `resolveXxx(ctx)` overrides below. Variants supply `policy.<group>`
  // payloads that those resolvers merge with the demo's per-group defaults.
  // `InviteWorkflowOpts` is forms-only after the AuthOpts reshape; the
  // `send.tokenTtlMs` default moved to the singleton `AuthOpts.magicLinkTtlMs`
  // built above (seeded from min(RECOVERY_TTL_MS, INVITE_TTL_MS)).
  const demoInviteOpts: InviteWorkflowOpts = mergeWfOpts({}, opts.inviteOpts);
  // ARBAC is carried by the base `InviteWorkflow`: class-level
  // `@ArbacResource('auth/invite/start') @ArbacAction('start')` gates phase A,
  // per-method `@Public()` opens phase B (post magic-link send) so the
  // anonymous resume isn't denied. `@Inherit()` flows the class meta down.
  // FOR_EVENT — see DemoLoginWorkflow comment; ctor reads variant header.
  @Inherit()
  @Injectable("FOR_EVENT")
  @Controller("auth/invite")
  class DemoInviteWorkflow extends InviteWorkflow {
    constructor(
      users: UserService,
      authCred: AuthCredential,
      demoAuthOpts: AuthOpts,
      demoConsentStore: ConsentStore,
    ) {
      const variant = pickVariant(INVITE_VARIANTS, readVariantHeader());
      super(
        variant?.opts
          ? mergeWfOpts(demoInviteOpts, variant.opts as InviteWorkflowOpts)
          : demoInviteOpts,
        users,
        authCred,
        cloneAuthOptsWithVariant(variant?.authOpts),
        demoConsentStore,
      );
      void demoAuthOpts;
    }
    protected override deliver(payload: DeliverPayload) {
      // Invite's default send path uses `outletEmail` (handled by the
      // createAuthEmailOutlet at the trigger route); deliver() runs only if a
      // future override drives a manual send. Reuse the shared forwarder for
      // parity with login/recovery.
      return forwardDeliver(payload);
    }
    // `invite-init` runs on the admin's first trigger (variant header IS
    // present); `invite-setup-mfa` runs LATER on the invitee's anonymous resume
    // (variant header is NOT present — the magic-link click is plain HTTP).
    // The wf-state ctx is the only thing that crosses the admin→invitee
    // boundary, so stash the resolved mfaCtx on ctx here in `invite-init` and
    // read it back in `invite-setup-mfa` below. Without this stash the
    // `invite-mfa-optional-full` variant's mode/transports never reach the
    // enrolment loop on the invitee side and the workflow silently
    // skips MFA enrolment.
    @Step("init")
    @Public()
    override init(@WorkflowParam("context") ctx: InviteWfCtx): undefined | Promise<undefined> {
      const baseResult = super.init(ctx);
      const apply = (): undefined => {
        const variant = pickVariant(INVITE_VARIANTS, readVariantHeader());
        const v = variant?.mfaCtx;
        if (v) {
          // Stash on a non-typed ctx slot — InviteWfCtx doesn't have a field
          // for this and it's strictly a demo-test piece. The serializer is
          // structural JSON so any plain field rides through wf-state fine.
          (ctx as unknown as { __demoMfaCtx?: InviteMfaCtxOverrides }).__demoMfaCtx = {
            ...(v.mfaMode !== undefined && { mfaMode: v.mfaMode }),
            ...(v.availableMfaTransports !== undefined && {
              availableMfaTransports: [...v.availableMfaTransports],
            }),
            ...(v.enrollMethod !== undefined && { enrollMethod: v.enrollMethod }),
          };
        }
        // Mirror the mfaCtx stash for the variant's accept policy. `resolveAccept`
        // runs both on the admin side (variant header present) AND on the
        // anonymous invitee resume (variant header NOT present — magic-link
        // click is plain HTTP with no `?variant=`). The ctx field bridges the
        // gap so e.g. `choice-freshlogin` + `confirmation-message` reach the
        // resume tail. The stash is on a non-typed slot per the comment above.
        if (variant?.policy?.accept) {
          (
            ctx as unknown as { __demoAcceptPolicy?: NonNullable<InviteWfCtx["accept"]> }
          ).__demoAcceptPolicy = variant.policy.accept;
        }
        return undefined;
      };
      return baseResult instanceof Promise ? baseResult.then(apply) : apply();
    }
    // Variant-driven mfa-ctx setter override — mirrors the login side. Reads
    // the resolved mfaCtx stashed in `invite-init` (preferred path, survives
    // admin→invitee resume) and falls back to the live request header
    // (admin-only flows that re-enter inviteSetupMfa before a resume).
    // Default is `mfaMode: 'disabled'` so existing invite e2e tests that
    // assert the auto-login envelope after password-set keep working without
    // an enrolment pause. Variants like `invite-mfa-optional-full` flip the
    // mode + transport list per request via this override (PW MFA coverage).
    @Step("setup-mfa")
    @Public()
    override inviteSetupMfa(
      @WorkflowParam("context") ctx: InviteWfCtx,
    ): undefined | Promise<undefined> {
      const baseResult = super.inviteSetupMfa(ctx);
      const apply = (): undefined => {
        const stashed = (ctx as unknown as { __demoMfaCtx?: InviteMfaCtxOverrides }).__demoMfaCtx;
        const variant = pickVariant(INVITE_VARIANTS, readVariantHeader());
        const v = stashed ?? variant?.mfaCtx;
        ctx.mfaMode = v?.mfaMode ?? "disabled";
        if (v?.availableMfaTransports !== undefined) {
          ctx.availableMfaTransports = [...v.availableMfaTransports];
        }
        if (v?.enrollMethod !== undefined) (ctx.mfaEnroll ??= {}).method = v.enrollMethod;
        return undefined;
      };
      return baseResult instanceof Promise ? baseResult.then(apply) : apply();
    }
    // ── Variant-driven resolveXxx policy overrides ──
    //
    // Precedence (high → low):
    //   1. test-time `opts.invitePolicy.<group>` (set by `buildTestApp`)
    //   2. variant `policy.<group>` (via `x-wf-variant` header)
    //   3. demo per-group default (tweaks on top of base)
    //   4. library default (`super.resolveXxx(ctx)`)
    protected override resolveAdminForm(
      ctx: InviteWfCtx,
    ): NonNullable<InviteWfCtx["adminForm"]> | Promise<NonNullable<InviteWfCtx["adminForm"]>> {
      if (opts.invitePolicy?.adminForm) return opts.invitePolicy.adminForm;
      const variant = pickVariant(INVITE_VARIANTS, readVariantHeader());
      if (variant?.policy?.adminForm) return variant.policy.adminForm;
      return super.resolveAdminForm(ctx);
    }
    protected override resolveAccept(
      ctx: InviteWfCtx,
    ): NonNullable<InviteWfCtx["accept"]> | Promise<NonNullable<InviteWfCtx["accept"]>> {
      if (opts.invitePolicy?.accept) return opts.invitePolicy.accept;
      const variant = pickVariant(INVITE_VARIANTS, readVariantHeader());
      if (variant?.policy?.accept) return variant.policy.accept;
      // Fallback: variant-stashed accept policy from `invite-init` (survives
      // the admin→invitee resume where the variant header is absent).
      const stashed = (
        ctx as unknown as { __demoAcceptPolicy?: NonNullable<InviteWfCtx["accept"]> }
      ).__demoAcceptPolicy;
      if (stashed) return stashed;
      // Demo default: existing tests assert the auto-login response payload —
      // pre-dating the BIG 3.3 confirmation pause. Off here so the demo
      // matches today's behaviour; production should keep the default ON.
      const baseResult = super.resolveAccept(ctx);
      const patch = (
        r: NonNullable<InviteWfCtx["accept"]>,
      ): NonNullable<InviteWfCtx["accept"]> => ({ ...r, showConfirmation: false });
      return baseResult instanceof Promise ? baseResult.then(patch) : patch(baseResult);
    }
    protected override resolveMfa(
      ctx: InviteWfCtx,
    ): NonNullable<InviteWfCtx["mfa"]> | Promise<NonNullable<InviteWfCtx["mfa"]>> {
      if (opts.invitePolicy?.mfa) return opts.invitePolicy.mfa;
      const variant = pickVariant(INVITE_VARIANTS, readVariantHeader());
      if (variant?.policy?.mfa) return variant.policy.mfa;
      return super.resolveMfa(ctx);
    }
    // Demonstrates the `prepareUser` hook: populate the consumer-required
    // `tenantId` field before `userService.createUser` runs.
    protected override async prepareUser(): Promise<Record<string, unknown>> {
      return { tenantId: "_global" };
    }
    protected override async getAvailableRoles(): Promise<string[]> {
      // Includes "member" because existing vitest specs submit it; the
      // returned set is the workflow's whitelist, so anything tests pass
      // through has to appear here.
      return ["admin", "editor", "viewer", "member"];
    }
    // WF-INVITE-018: when the test-only flag is flipped (via
    // POST /__test/allow-duplicate-invites), bypass the workflow-level
    // duplicate reject so `invitePreCreateUser`'s store-level 409 catch
    // becomes reachable. Default behaviour (delegates to base) otherwise.
    protected override async duplicateCheck(input: {
      email: string;
      existingUser: UserCredentials | null;
    }): Promise<DuplicateAction> {
      if (g.__aoothE2eAllowDuplicateInvites) return "allow";
      return super.duplicateCheck(input);
    }
    // Demonstrates the consumer-supplied profile form. `applyProfile` defaults
    // to `users.update(username, profile)` when not overridden; the explicit
    // override below proves the escape hatch reaches user-supplied code.
    protected override getProfileForm(): TAtscriptAnnotatedType {
      return InviteAcceptProfileForm as unknown as TAtscriptAnnotatedType;
    }
    protected override async applyProfile(input: {
      username: string;
      profile: Record<string, unknown>;
    }): Promise<void> {
      await aooth.userService.update(input.username, input.profile as Record<string, never>);
    }
  }

  // Canonical REST + guard wiring + per-workflow providers registered via DI.
  // `UserService` is only consumed by `AuthController`; skipping the controller
  // leaves the guard active for the rest of the app (used by DX-08).
  const authProviders: Parameters<typeof createProvideRegistry> = [
    [AuthCredential, () => aooth.authCredential],
    [UserService, () => aooth.userService],
    [AuthOpts, () => authOpts],
    [ConsentStore, () => consentStore],
    // `EmailSender` is still consumed by `createAuthEmailOutlet` (the
    // trigger-side mailer for magic-link outlets). The three auth workflows
    // themselves no longer consume DI for senders/audit/trust/rate-limit —
    // they use `protected` method overrides (see the subclasses above).
    ["EmailSender", () => emailSender],
  ];
  app.setProvideRegistry(createProvideRegistry(...authProviders));
  app.applyGlobalInterceptors(authGuardInterceptor({ cookie: { secure: false } }));

  // AUTH-MOOST-5: `DemoWfTriggerProvider` is the consumer subclass of
  // `WfTriggerProvider` that wires this app's DB-backed wf state store and
  // adds the magic-link email outlet. Bound to `WfTriggerProvider` via the
  // replace registry so `AuthController.triggerWf()` (and the subclass
  // `DemoAuthController.triggerWf()`) picks it up automatically.
  const demoEmailOutletDeps = {
    emailSender,
    buildMagicLinkUrl: aooth.buildMagicLinkUrl,
    magicLinkTtlMs: (kind: import("@aooth/auth").AuthEmailKind) =>
      kind === "invite.magicLink" ? env.INVITE_TTL_MS : env.RECOVERY_TTL_MS,
  };
  @Injectable()
  class DemoWfTriggerProvider extends WfTriggerProvider {
    constructor(wf: MoostWf) {
      super(wf);
      this.state = new HandleStateStrategy({ store: wfStateStore });
      this.outlets = [...this.outlets, createAuthEmailOutlet(demoEmailOutletDeps)];
    }
  }

  // Extend the bundled `AuthController.triggerWf()` allow-list with the
  // demo-only `project.handover` workflow — the spec's recommended consumer
  // subclass pattern for adding app-specific workflows to the single trigger.
  // `@Inherit()` carries the parent's `@Get('status')` / `@Post('logout')` /
  // `@Post('refresh')` metadata; without it moost re-scans method decorators
  // only on the subclass and the unoverridden endpoints disappear.
  @Inherit()
  @Controller("auth")
  class DemoAuthController extends AuthController {
    constructor(auth: AuthCredential, users: UserService) {
      super(auth, users);
    }
    @Post("trigger")
    @Public()
    @WfTrigger({
      allow: [...DEFAULT_AUTH_WORKFLOWS, "project.handover"],
    })
    override triggerWf(): void {
      // see AuthController.triggerWf — body intentionally empty.
    }
  }
  app.setReplaceRegistry(createReplaceRegistry([WfTriggerProvider, DemoWfTriggerProvider]));

  if (opts.authEndpointsEnabled !== false) {
    app.registerControllers(DemoAuthController);
  }

  const wfEnabled = opts.workflowsEnabled ?? {};
  const wfControllers: Array<new (...args: never[]) => unknown> = [];
  if (wfEnabled.login !== false) {
    // Resolution order: (1) consumer `loginWorkflowClass` swaps the demo
    // entirely; (2) `loginMfaCtx` then wraps whichever class is active with
    // the static-ctx setter overrides — so tests can pass either knob alone
    // or both together (e.g. custom subclass + injected mfa ctx).
    const loginBase = (opts.loginWorkflowClass ?? DemoLoginWorkflow) as unknown as new (
      ...args: never[]
    ) => LoginWorkflow;
    const LoginCtor = opts.loginMfaCtx
      ? wrapWithLoginMfaCtx(loginBase, opts.loginMfaCtx)
      : loginBase;
    wfControllers.push(LoginCtor as unknown as new (...args: never[]) => unknown);
  }
  if (wfEnabled.recovery !== false) wfControllers.push(DemoRecoveryWorkflow);
  if (wfEnabled.invite !== false) {
    const inviteBase = (opts.inviteWorkflowClass ?? DemoInviteWorkflow) as unknown as new (
      ...args: never[]
    ) => InviteWorkflow;
    const InviteCtor = opts.inviteMfaCtx
      ? wrapWithInviteMfaCtx(inviteBase, opts.inviteMfaCtx)
      : inviteBase;
    wfControllers.push(InviteCtor as unknown as new (...args: never[]) => unknown);
  }
  if (wfControllers.length > 0) {
    app.registerControllers(...wfControllers);
  }

  // Bind the atscript-driven user provider to the JWT subject for ARBAC.
  // `DemoUser.@meta.id` is a UUID but the JWT subject is `username`;
  // `userStore.findByUsername` resolves either, so wrap it in the minimal
  // `ArbacUserTable` shim and ignore the projection (small fixture, low
  // payoff to optimize). This is the consumer-side override seam.
  const arbacUserTable = {
    async findOne(query: { filter: Record<string, unknown> }): Promise<DemoUser | null> {
      const userId = query.filter.id as string | undefined;
      if (!userId) return null;
      const user = await aooth.userStore.findByUsername(userId);
      return (user as DemoUser | null) ?? null;
    },
  };

  // `@Injectable()` (SINGLETON) — moost@0.6.x does NOT inherit injectable
  // metadata across `extends`, so each consumer subclass must re-apply it.
  // Per-event memoization happens via a wooks-slot cache inside
  // `AtscriptArbacUserProvider`.
  @Injectable()
  class DemoArbacUserProvider extends AtscriptArbacUserProvider<DemoUser> {
    constructor() {
      super(DemoUser, arbacUserTable);
    }
    override getUserId(): string {
      return useAuth().getUserId();
    }
  }
  app.setReplaceRegistry(createReplaceRegistry([ArbacUserProviderToken, DemoArbacUserProvider]));

  app.applyGlobalInterceptors(arbacAuthorizeInterceptor);

  app.registerControllers(...buildAppControllers(appDb));

  // `reseed()` truncates every app DB table and re-runs `seedAll`. Defined
  // up here so both `main.ts` (dev-entry seed) and the `__test/reset`
  // endpoint go through ONE implementation — there is no other way to drop
  // back to a known-good fixture set.
  const reseed = async (): Promise<number> => {
    // Same lifecycle for active-session counts (used by `loadActiveSessions`
    // override below to drive the `concurrency-limit` step).
    sharedActiveSessionsBuffer.clear();
    // Profile-missing-fields list keyed by username — same lifecycle.
    sharedProfileMissingFieldsBuffer.clear();
    // Captured `audit(event)` events — cleared so the next test starts clean.
    sharedAuditEventsBuffer.length = 0;
    // Captured consent events — cleared so a prior login's events don't bleed
    // into the next test's assertions.
    sharedConsentLogBuffer.clear();
    // Captured OTP-channel disclosure records — same lifecycle as
    // `sharedConsentLogBuffer`.
    sharedOtpConsentLogBuffer.clear();
    // WF-INVITE-018 toggle — reset between tests so a flipped flag in one
    // spec doesn't leak into the next.
    g.__aoothE2eAllowDuplicateInvites = false;
    // Order matters for FKs: drop dependent rows first. The model-typed
    // `AtscriptDbTable<T>` overloads produce a TS2590 union when combined in
    // one array — widen the whole array once to a plain `deleteMany` shape
    // (the runtime is identical; `{}` matches every row in atscript-db).
    type AnyDeletable = { deleteMany: (filter: Record<string, unknown>) => Promise<unknown> };
    const t = appDb.tables;
    const dropOrder = [
      t.documents,
      t.comments,
      t.tasks,
      t.projects,
      t.audit,
      t.wfStates,
      t.users,
      t.departments,
      t.tenants,
    ] as unknown as AnyDeletable[];
    for (const tbl of dropOrder) {
      await tbl.deleteMany({});
    }
    const fixtures = await seedAll({
      app,
      appDb,
      baseUrl: "",
      emailSender,
      aooth,
      reseed: async () => 0,
      close: async () => {},
    });
    return Object.keys(fixtures.users).length;
  };

  // Test-only mailbox/reset endpoints. The `__test` controller is mounted ONLY
  // when DEMO_MODE='test' — never in dev, never in CI prod boots.
  if (isTestMode) {
    const TestMailboxController = createTestMailboxController({
      emails: sharedEmailsBuffer,
      sms: sharedSmsBuffer,
      reseed,
      userService: aooth.userService,
      auditEvents: sharedAuditEventsBuffer,
      consentLog: sharedConsentLogBuffer,
      otpConsentLog: sharedOtpConsentLogBuffer,
    });
    app.registerControllers(TestMailboxController);
  }

  await app.init();
  await moostHttp.listen(port);

  const arbac = (await getMoostInfact().get(MoostArbac)) as MoostArbac<UserAttrs, ArbacDbScope>;
  for (const role of allRoles) arbac.registerRole(role);

  const baseUrl = `http://localhost:${resolveListeningPort(moostHttp, port)}`;
  const close = async (): Promise<void> => {
    const server = moostHttp.getHttpApp().getServer();
    if (server) {
      await new Promise<void>((resolve, reject) => {
        server.close((err) => (err ? reject(err) : resolve()));
      });
    }
    appDb.close();
  };

  return { app, appDb, baseUrl, emailSender, aooth, reseed, close };
}

function buildAppControllers(appDb: AppDb): ReadonlyArray<new (...args: never[]) => unknown> {
  const t = appDb.tables;
  return [
    HealthController,
    makeTenantsController(t.tenants),
    makeUsersController(t.users),
    makeDepartmentsController(t.departments),
    makeProjectsController(t.projects),
    makeTasksController(t.tasks),
    makeCommentsController(t.comments),
    makeDocumentsController(t.documents),
    makeAuditController(t.audit),
    makeHandoverWorkflow({
      projectsTable: t.projects,
      usersTable: t.users,
      auditTable: t.audit,
    }),
  ];
}

function resolveListeningPort(moostHttp: MoostHttp, fallback: number): number {
  const addr = moostHttp.getHttpApp().getServer()?.address() as AddressInfo | string | null;
  return addr && typeof addr === "object" && "port" in addr ? addr.port : fallback;
}

// ── Static-ctx setter override wrappers ──────────────────────────────────────
//
// PR9 stripped `mfa.mode` / `mfa.transports` from `LoginWorkflowOpts` and
// `InviteWorkflowOpts`. The values now live on ctx (populated by the single
// `prepareMfaSetup` / `inviteSetupMfa` `@Step` setter per workflow). Consumers
// that need to inject static values without declaring a full subclass wrap
// their target class with the helpers below; `buildApp` calls them when
// `opts.loginMfaCtx` / `opts.inviteMfaCtx` is supplied. The wrapper calls
// `super.X(ctx)` first and then writes ONLY the fields the caller supplied,
// so test-supplied values win over the base setter's defaults and unsupplied
// fields keep the wrapped base class's behaviour.

// `W extends new (...args: never[]) => LoginWorkflow` (NOT `typeof LoginWorkflow`)
// because the demo subclass has a 2-arg ctor signature `(users, auth)` (opts
// is curried in by the factory closure) while the base class is 3-arg
// `(opts, users, auth)`. The generic widens to "any LoginWorkflow-shaped
// class" so both fit.
function wrapWithLoginMfaCtx<W extends new (...args: never[]) => LoginWorkflow>(
  Base: W,
  ctx: LoginMfaCtxOverrides,
): W {
  // FOR_EVENT — wrapper's super(users, auth) reaches into DemoLoginWorkflow's
  // composable-using ctor; the scope must propagate.
  @Inherit()
  @Injectable("FOR_EVENT")
  @Controller("auth/login")
  class WithLoginCtx extends (Base as unknown as new (
    users: UserService,
    auth: AuthCredential,
    authOpts: AuthOpts,
    consentStore: ConsentStore,
  ) => LoginWorkflow) {
    // The forwarding ctor is required: moost reads `design:paramtypes`
    // metadata off the subclass to resolve DI, and TS only emits the
    // metadata when the ctor is explicit. Without it moost can't construct
    // the wrapper.
    // eslint-disable-next-line no-useless-constructor
    constructor(
      users: UserService,
      auth: AuthCredential,
      authOpts: AuthOpts,
      consentStore: ConsentStore,
    ) {
      super(users, auth, authOpts, consentStore);
    }
    @Step("prepare-mfa-setup")
    @Public()
    override prepareMfaSetup(
      @WorkflowParam("context") c: LoginWfCtx,
    ): undefined | Promise<undefined> {
      const baseResult = super.prepareMfaSetup(c);
      const apply = (): undefined => {
        if (ctx.mfaMode !== undefined) c.mfaMode = ctx.mfaMode;
        if (ctx.availableMfaTransports !== undefined) {
          c.availableMfaTransports = [...ctx.availableMfaTransports];
        }
        if (ctx.currentMfa !== undefined) c.currentMfa = ctx.currentMfa;
        if (!c.currentMfa && c.availableMfaTransports?.length === 1) {
          c.currentMfa = c.availableMfaTransports[0];
        }
        return undefined;
      };
      return baseResult instanceof Promise ? baseResult.then(apply) : apply();
    }
  }
  return WithLoginCtx as unknown as W;
}

function wrapWithInviteMfaCtx<W extends new (...args: never[]) => InviteWorkflow>(
  Base: W,
  ctx: InviteMfaCtxOverrides,
): W {
  // FOR_EVENT — wrapper's super(users, auth) reaches into DemoInviteWorkflow's
  // composable-using ctor; the scope must propagate.
  @Inherit()
  @Injectable("FOR_EVENT")
  @Controller("auth/invite")
  class WithInviteCtx extends (Base as unknown as new (
    users: UserService,
    auth: AuthCredential,
    authOpts: AuthOpts,
    consentStore: ConsentStore,
  ) => InviteWorkflow) {
    // eslint-disable-next-line no-useless-constructor -- see wrapWithLoginMfaCtx for why
    constructor(
      users: UserService,
      auth: AuthCredential,
      authOpts: AuthOpts,
      consentStore: ConsentStore,
    ) {
      super(users, auth, authOpts, consentStore);
    }
    @Step("setup-mfa")
    @Public()
    override inviteSetupMfa(
      @WorkflowParam("context") c: InviteWfCtx,
    ): undefined | Promise<undefined> {
      const baseResult = super.inviteSetupMfa(c);
      const apply = (): undefined => {
        if (ctx.mfaMode !== undefined) c.mfaMode = ctx.mfaMode;
        if (ctx.availableMfaTransports !== undefined) {
          c.availableMfaTransports = [...ctx.availableMfaTransports];
        }
        const m = (c.mfaEnroll ??= {});
        if (ctx.enrollMethod !== undefined) m.method = ctx.enrollMethod;
        if (!m.method && c.availableMfaTransports?.length === 1) {
          m.method = c.availableMfaTransports[0];
        }
        return undefined;
      };
      return baseResult instanceof Promise ? baseResult.then(apply) : apply();
    }
  }
  return WithInviteCtx as unknown as W;
}
