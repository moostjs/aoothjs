import {
  arbacAuthorizeInterceptor,
  type ArbacDbScope,
  ArbacUserProviderToken,
  MoostArbac,
} from "@aooth/arbac-moost";
import { type ArbacUserTable, AtscriptArbacUserProvider } from "@aooth/arbac-moost/atscript";
import {
  AuthCredential,
  type AuthEmailEvent,
  type AuthSmsEvent,
  type EmailSender,
  type SmsSender,
} from "@aooth/auth";
import {
  type AuditEvent,
  type AuthDeliveryPayload,
  AuthController,
  authGuardInterceptor,
  type AuthWfCtx,
  AuthWorkflow,
  type AuthWorkflowOpts,
  type ConsentDescriptor,
  type ConsentEvent,
  ConsentStore,
  createAuthEmailOutlet,
  DEFAULT_AUTH_WORKFLOWS,
  deriveWfStateSecret,
  Public,
  SessionsController,
  useAuth,
  WfTrigger,
  WfTriggerProvider,
} from "@aooth/auth-moost";
import { HandleStateStrategy, Step, type WfStateStrategy, WorkflowParam } from "@moostjs/event-wf";
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
import { DemoUser } from "./models/user.as";
import { allRoles, type UserAttrs } from "./roles";
import { seedAll } from "./seed";
import { createTestMailboxController, type OtpConsentRecord } from "./test-mailbox";
import {
  INVITE_VARIANTS,
  type InviteMfaCtxOverrides,
  LOGIN_VARIANTS,
  type LoginMfaCtxOverrides,
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
  // Captured audit-event payloads. Plain array so the `/__test/audit`
  // endpoint can return + the `__test/reset` flow can clear (length = 0)
  // without breaking the shared reference. The unified workflow moved audit
  // off the workflow surface onto interceptors; this buffer stays so the
  // existing test-mailbox endpoint shape is preserved.
  __aoothE2eAuditEvents?: AuditEvent[];
  // When `true`, `DemoAuthWorkflow.duplicateInviteCheck()` returns `'allow'`
  // for every email so the store-level uniqueness branch in
  // `invitePreCreateUser` gets exercised (WF-INVITE-018). Flipped via
  // POST /__test/allow-duplicate-invites and reset to `false` by
  // `reseed()` / `__test/reset`.
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
g.__aoothE2eAuditEvents ??= [];
g.__aoothE2eAllowDuplicateInvites ??= false;
g.__aoothE2eConsentLog ??= new Map();
g.__aoothE2eOtpConsentLog ??= new Map();
const sharedEmailsBuffer: AuthEmailEvent[] = g.__aoothE2eEmails;
const sharedSmsBuffer: AuthSmsEvent[] = g.__aoothE2eSms;
const sharedActiveSessionsBuffer: Map<string, number> = g.__aoothE2eActiveSessions;
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

// Map the workflow-side payload `kind` discriminator to the demo's
// EmailSender / SmsSender union. The workflow side uses purpose-grained
// kinds (`mfa-pincode` / `enroll-pincode` / …); the senders use
// delivery-grained kinds (`login.pincode` / `invite.magicLink` / …).
function toEmailKind(kind: AuthDeliveryPayload["kind"]): import("@aooth/auth").AuthEmailKind {
  switch (kind) {
    case "invite-link":
      return "invite.magicLink";
    case "recovery-pincode":
    case "signup-pincode":
      return "recovery.pincode";
    case "new-device-notice":
      return "notifyNewDevice";
    default:
      return "login.pincode";
  }
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
 * reads from. One writer shared across all three flows of `DemoAuthWorkflow`.
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
  override async getPendingConsents(_username: string | undefined): Promise<ConsentDescriptor[]> {
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

/**
 * Identify which flow is firing on the current `AuthWfCtx`. Drives the
 * variant-policy lookup in `DemoAuthWorkflow`'s resolvers: each flow consults
 * its own `LOGIN_VARIANTS` / `INVITE_VARIANTS` / `RECOVERY_VARIANTS` map.
 *
 * Discrimination is by ctx-slot presence (no `ctx.flow` field exists — the
 * unified ctx has shared slots populated by the prepare-* steps).
 */
type FlowKind = "login" | "invite-admin" | "invite-accept" | "recovery";

function detectFlow(ctx: AuthWfCtx): FlowKind {
  if (ctx.admin) return "invite-admin";
  if (ctx.accept) return "invite-accept";
  if (ctx.postReset) return "recovery";
  return "login";
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

  // Demo's base `AuthWorkflowOpts`. Cross-workflow infrastructure
  // (pincode timers, loginUrl, totpIssuer) lives on this single surface.
  // Magic-link TTL is owned by `@StepTTL` on the workflow's `send-email`
  // @Step; the outlet's per-kind TTL function (passed via `deps.magicLinkTtlMs`
  // below) drives the email-body "expires at" line independently.
  const demoBaseOpts: Partial<AuthWorkflowOpts> = {};

  const consentStore = new DemoConsentStore();

  // Shared `deliver()` body for `DemoAuthWorkflow`. The discriminated
  // `AuthDeliveryPayload` narrows `kind` to the matching transport type, so
  // no casts are needed when forwarding to EmailSender / SmsSender.
  const demoSmsSender: SmsSender = {
    async send(event) {
      if (isTestMode) {
        sharedSmsBuffer.push(event);
        return;
      }
      console.log("[demo SMS]", event.kind, event.recipient, event.code);
    },
  };

  const forwardDeliver = async (payload: AuthDeliveryPayload): Promise<void> => {
    if (payload.channel === "email") {
      const expiresInMs = "expiresInMs" in payload ? payload.expiresInMs : undefined;
      await emailSender.send({
        kind: toEmailKind(payload.kind),
        recipient: payload.recipient,
        ...("code" in payload && { code: payload.code }),
        ...("url" in payload && { url: payload.url }),
        expiresAt: expiresInMs !== undefined ? Date.now() + expiresInMs : Date.now(),
      });
      return;
    }
    // SMS only carries pincode kinds at runtime — they all map to the single
    // `login.pincode` AuthSmsKind that the demo SmsSender understands.
    await demoSmsSender.send({
      kind: "login.pincode",
      recipient: payload.recipient,
      code: payload.code,
      ttlMs: payload.expiresInMs ?? 0,
    });
  };

  // Unified consumer subclass — one `AuthWorkflow` extension covers all three
  // flows (login / invite / recovery). The single class carries the prior
  // `DemoLoginWorkflow` + `DemoInviteWorkflow` + `DemoRecoveryWorkflow`
  // overrides; per-resolver flow discrimination is via `detectFlow(ctx)`.
  //
  // FOR_EVENT scope is REQUIRED here: the ctor reads per-request HTTP
  // headers via `readVariantHeader()` to pick a variant config; SINGLETON
  // would freeze the variant decision at app boot.
  @Inherit()
  @Injectable("FOR_EVENT")
  @Controller()
  class DemoAuthWorkflow extends AuthWorkflow {
    constructor(users: UserService, authCred: AuthCredential, demoConsentStore: ConsentStore) {
      // Each of the three variant maps may carry an `opts` overlay (cookie
      // TTL, etc.) and an `authOpts` overlay (cross-workflow infra: pincode
      // cooldown, magic-link TTL). We don't yet know which flow is firing
      // (the wf engine dispatches AFTER ctor), so probe ALL three maps and
      // merge any matches. Variants are keyed by unique names per map, so
      // collisions don't happen in practice; if they did, the last merge
      // wins (recovery > invite > login).
      const header = readVariantHeader();
      const loginV = pickVariant(LOGIN_VARIANTS, header);
      const inviteV = pickVariant(INVITE_VARIANTS, header);
      const recoveryV = pickVariant(RECOVERY_VARIANTS, header);
      let merged: Partial<AuthWorkflowOpts> = demoBaseOpts;
      for (const v of [loginV, inviteV, recoveryV]) {
        if (!v) continue;
        if (v.opts) merged = mergeWfOpts(merged, v.opts);
        if (v.authOpts) merged = mergeWfOpts(merged, v.authOpts);
      }
      super(merged, users, authCred, demoConsentStore);
    }

    protected override deliver(payload: AuthDeliveryPayload): Promise<void> {
      return forwardDeliver(payload);
    }

    // ── Variant-driven resolveXxx policy overrides ──
    //
    // Precedence (high → low):
    //   1. variant `policy.<group>` (via `x-wf-variant` header).
    //   2. demo per-group default (tweaks on top of base).
    //   3. library default (`super.resolveXxx(ctx)`).
    //
    // The unified ctx means each resolver can fire on multiple flows. We
    // dispatch by `detectFlow(ctx)` to pick the right variant map.

    protected override resolveAlternateCredentials(
      ctx: AuthWfCtx,
    ):
      | NonNullable<AuthWfCtx["alternateCredentials"]>
      | Promise<NonNullable<AuthWfCtx["alternateCredentials"]>> {
      const variant = pickVariant(LOGIN_VARIANTS, readVariantHeader());
      if (variant?.policy?.alternateCredentials) return variant.policy.alternateCredentials;
      // Demo default: forgotPassword + signup ON (dev UI dropdown surfaces them).
      const base = super.resolveAlternateCredentials(ctx);
      if (base instanceof Promise) {
        return base.then((b) => ({ ...b, forgotPassword: true, signup: true }));
      }
      return { ...base, forgotPassword: true, signup: true };
    }

    // Demo enables open self-signup so `auth/signup/flow` is reachable. The
    // library default is `allowSignup: false` (invite-only); a real deployment
    // opts in here (and typically gates it behind a captcha / rate limiter).
    protected override resolveSignupPolicy(_ctx: AuthWfCtx): NonNullable<AuthWfCtx["signup"]> {
      return { allowSignup: true, collectUsername: false };
    }

    protected override resolveDeviceTrust(
      ctx: AuthWfCtx,
    ): NonNullable<AuthWfCtx["deviceTrust"]> | Promise<NonNullable<AuthWfCtx["deviceTrust"]>> {
      const variant = pickVariant(LOGIN_VARIANTS, readVariantHeader());
      if (variant?.policy?.deviceTrust) return variant.policy.deviceTrust;
      return super.resolveDeviceTrust(ctx);
    }

    protected override resolveEnrollment(
      ctx: AuthWfCtx,
    ): NonNullable<AuthWfCtx["enrollment"]> | Promise<NonNullable<AuthWfCtx["enrollment"]>> {
      const variant = pickVariant(LOGIN_VARIANTS, readVariantHeader());
      if (variant?.policy?.enrollment) return variant.policy.enrollment;
      return super.resolveEnrollment(ctx);
    }

    protected override resolveFinalize(
      ctx: AuthWfCtx,
    ): NonNullable<AuthWfCtx["finalize"]> | Promise<NonNullable<AuthWfCtx["finalize"]>> {
      const variant = pickVariant(LOGIN_VARIANTS, readVariantHeader());
      if (variant?.policy?.finalize) return variant.policy.finalize;
      return super.resolveFinalize(ctx);
    }

    protected override resolveGuards(
      ctx: AuthWfCtx,
    ): NonNullable<AuthWfCtx["guards"]> | Promise<NonNullable<AuthWfCtx["guards"]>> {
      const variant = pickVariant(LOGIN_VARIANTS, readVariantHeader());
      if (variant?.policy?.guards) return variant.policy.guards;
      // Demo default: passwordInitial ON (seed users land on the
      // create-password-form on first login).
      const base = super.resolveGuards(ctx);
      if (base instanceof Promise) return base.then((b) => ({ ...b, passwordInitial: true }));
      return { ...base, passwordInitial: true };
    }

    protected override resolveSessionPolicy(
      ctx: AuthWfCtx,
    ): NonNullable<AuthWfCtx["sessionPolicy"]> | Promise<NonNullable<AuthWfCtx["sessionPolicy"]>> {
      const variant = pickVariant(LOGIN_VARIANTS, readVariantHeader());
      if (variant?.policy?.sessionPolicy) return variant.policy.sessionPolicy;
      return super.resolveSessionPolicy(ctx);
    }

    // Flow-aware (like resolveMfaPolicy): the lock is SET during login but
    // LIFTED during recovery, so each flow reads the mode from its own variant
    // map. Same variant key in both LOGIN_VARIANTS + RECOVERY_VARIANTS drives
    // one end-to-end mode across the lock→reset→unlock journey.
    protected override resolveLockout(
      ctx: AuthWfCtx,
    ): NonNullable<AuthWfCtx["lockout"]> | Promise<NonNullable<AuthWfCtx["lockout"]>> {
      const variantMap = detectFlow(ctx) === "recovery" ? RECOVERY_VARIANTS : LOGIN_VARIANTS;
      const fromVariant = pickVariant(variantMap, readVariantHeader())?.policy?.lockout;
      return fromVariant ?? super.resolveLockout(ctx);
    }

    protected override resolveMfaPolicy(
      ctx: AuthWfCtx,
    ): NonNullable<AuthWfCtx["mfaPolicy"]> | Promise<NonNullable<AuthWfCtx["mfaPolicy"]>> {
      const flow = detectFlow(ctx);
      const isInvite = flow === "invite-admin" || flow === "invite-accept";
      const variantMap = isInvite
        ? INVITE_VARIANTS
        : flow === "recovery"
          ? RECOVERY_VARIANTS
          : LOGIN_VARIANTS;
      const fromVariant = pickVariant(variantMap, readVariantHeader())?.policy?.mfaPolicy;
      return fromVariant ?? super.resolveMfaPolicy(ctx);
    }

    protected override resolveAdminForm(
      ctx: AuthWfCtx,
    ): NonNullable<AuthWfCtx["adminForm"]> | Promise<NonNullable<AuthWfCtx["adminForm"]>> {
      const variant = pickVariant(INVITE_VARIANTS, readVariantHeader());
      if (variant?.policy?.adminForm) return variant.policy.adminForm;
      return super.resolveAdminForm(ctx);
    }

    protected override resolveAccept(
      ctx: AuthWfCtx,
    ): NonNullable<AuthWfCtx["accept"]> | Promise<NonNullable<AuthWfCtx["accept"]>> {
      const variant = pickVariant(INVITE_VARIANTS, readVariantHeader());
      if (variant?.policy?.accept) return variant.policy.accept;
      // Demo default: existing tests assert the auto-login response payload —
      // pre-dating the BIG 3.3 confirmation pause. Off here so the demo
      // matches today's behaviour; production should keep the default ON.
      const base = super.resolveAccept(ctx);
      if (base instanceof Promise) return base.then((r) => ({ ...r, showConfirmation: false }));
      return { ...base, showConfirmation: false };
    }

    protected override resolvePostReset(
      ctx: AuthWfCtx,
    ): NonNullable<AuthWfCtx["postReset"]> | Promise<NonNullable<AuthWfCtx["postReset"]>> {
      const variant = pickVariant(RECOVERY_VARIANTS, readVariantHeader());
      if (variant?.policy?.postReset) return variant.policy.postReset;
      return super.resolvePostReset(ctx);
    }

    protected override resolveRecoveryAltActions(
      ctx: AuthWfCtx,
    ):
      | NonNullable<AuthWfCtx["recoveryAltActions"]>
      | Promise<NonNullable<AuthWfCtx["recoveryAltActions"]>> {
      const variant = pickVariant(RECOVERY_VARIANTS, readVariantHeader());
      if (variant?.policy?.recoveryAltActions) return variant.policy.recoveryAltActions;
      return super.resolveRecoveryAltActions(ctx);
    }

    // The credential store is JWT-based (stateless) so the demo can't query
    // "how many sessions for user X" from `authCredential`. The seed counts
    // its own `issue()` calls into a globalThis map; reading it here wires
    // `ctx.session.activeSessions` for the `concurrency-limit` step.
    protected override async loadActiveSessionsCount(username: string): Promise<number> {
      return sharedActiveSessionsBuffer.get(username) ?? 0;
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
    // duplicate reject so the create-user step's store-level 409 catch
    // becomes reachable. Default behaviour (delegates to base) otherwise.
    protected override duplicateInviteCheck(input: {
      email: string;
      existingUser: UserCredentials | null;
    }): Promise<"allow" | "reject"> | "allow" | "reject" {
      if (g.__aoothE2eAllowDuplicateInvites) return "allow";
      return super.duplicateInviteCheck(input);
    }

    // Variant-driven mfa-ctx setter override. Base step (called via super)
    // writes `ctx.mfaPolicy` from `resolveMfaPolicy` and pre-picks
    // `ctx.mfa.current` / `ctx.mfaEnroll.method`. Demo default forces
    // `mode: 'disabled'` so seeded users skip MFA unless a variant opts in.
    @Step("prepare-mfa")
    @Public()
    override prepareMfa(@WorkflowParam("context") ctx: AuthWfCtx): undefined | Promise<undefined> {
      const baseResult = super.prepareMfa(ctx);
      const apply = (): undefined => {
        const flow = detectFlow(ctx);
        const variantMap =
          flow === "invite-admin" || flow === "invite-accept"
            ? INVITE_VARIANTS
            : flow === "login"
              ? LOGIN_VARIANTS
              : undefined;
        const v = variantMap ? pickVariant(variantMap, readVariantHeader())?.mfaCtx : undefined;
        // `super.prepareMfa` always assigned `ctx.mfaPolicy` from `resolveMfaPolicy`.
        const mfaPolicy = ctx.mfaPolicy!;
        if (!v) {
          mfaPolicy.mode = "disabled";
          return undefined;
        }
        if (v.mfaMode !== undefined) mfaPolicy.mode = v.mfaMode;
        if (v.availableMfaTransports !== undefined) {
          mfaPolicy.availableTransports = [...v.availableMfaTransports];
        }
        const mfa = (ctx.mfa ??= {});
        const m = v as LoginMfaCtxOverrides & InviteMfaCtxOverrides;
        if (m.currentMfa !== undefined) mfa.current = m.currentMfa;
        if (m.enrollMethod !== undefined) (ctx.mfaEnroll ??= {}).method = m.enrollMethod;
        return undefined;
      };
      return baseResult instanceof Promise ? baseResult.then(apply) : apply();
    }
  }

  // Canonical REST + guard wiring + per-workflow providers registered via DI.
  const authProviders: Parameters<typeof createProvideRegistry> = [
    [AuthCredential, () => aooth.authCredential],
    [UserService, () => aooth.userService],
    [ConsentStore, () => consentStore],
    // `EmailSender` is still consumed by `createAuthEmailOutlet` (the
    // trigger-side mailer for magic-link outlets). The unified auth workflow
    // itself no longer consumes DI for senders/audit/trust/rate-limit —
    // those use `protected` method overrides on `DemoAuthWorkflow`.
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
    constructor(wf: MoostWf, auth: AuthCredential) {
      super(wf, auth);
      this.outlets = [...this.outlets, createAuthEmailOutlet(demoEmailOutletDeps)];
    }
    // The credential store is now atscript-db (stateful, no `deriveSubkey`), so
    // the base `wfStateSecret()` (which HKDF-derives from the auth secret) would
    // throw. Supply the encapsulated-start key explicitly — `deriveWfStateSecret`
    // turns the app secret into the exact 32 bytes the strategy needs.
    protected override wfStateSecret(): Buffer {
      return deriveWfStateSecret(env.JWT_SECRET);
    }
    // Durable strategy a workflow swaps to after first validated input — the
    // app's DB-backed AsWfStore.
    protected override storeStrategy(): WfStateStrategy {
      return new HandleStateStrategy({ store: wfStateStore });
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

  // Mount the bundled sessions endpoints (`GET/DELETE /auth/sessions`). The
  // default `SessionEnricherProvider` (identity) is auto-resolved by DI; the
  // SPA's portal parses the raw `metadata.userAgent` client-side, so no
  // server-side enricher is wired here.
  app.registerControllers(DemoAuthController, DemoAuthWorkflow, SessionsController);

  // `@Injectable()` (SINGLETON) — moost@0.6.x does NOT inherit injectable
  // metadata across `extends`, so each consumer subclass must re-apply it.
  // Per-event memoization happens via a wooks-slot cache inside
  // `AtscriptArbacUserProvider`.
  @Injectable()
  class DemoArbacUserProvider extends AtscriptArbacUserProvider<DemoUser> {
    constructor() {
      // The session subject is now the stable surrogate `id`, so the provider
      // can query the REAL users table directly — its default
      // `findOne({ filter: { id } })` resolves the row by primary key.
      super(DemoUser, appDb.tables.users as unknown as ArbacUserTable<DemoUser>);
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
    // Same lifecycle for active-session counts (used by `loadActiveSessionsCount`
    // override below to drive the `concurrency-limit` step).
    sharedActiveSessionsBuffer.clear();
    // Captured audit events — cleared so the next test starts clean.
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
      t.credentials,
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
      wfStates: appDb.tables.wfStates,
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
