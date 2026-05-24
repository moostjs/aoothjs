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
  createAuthEmailOutlet,
  createAuthShareableLinkOutlet,
  DEFAULT_AUTH_WORKFLOWS,
  type DeliverPayload,
  type DuplicateAction,
  type InviteWfCtx,
  InviteWorkflow,
  type InviteWorkflowOpts,
  type LoginWfCtx,
  LoginWorkflow,
  type LoginWorkflowOpts,
  Public,
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
import { createTestMailboxController } from "./test-mailbox";
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
   * demo defaults (one nested group at a time, e.g. `{ mfa: { backupCodes: false } }`
   * replaces only `mfa.backupCodes` and preserves the other `mfa.*` keys).
   * Used by the workflow-options e2e specs to flip a single flag without
   * forking the whole demo wiring. For MFA mode/transports (stripped from
   * opts in PR9) use `loginMfaCtx` below.
   */
  loginOpts?: LoginWorkflowOpts;
  recoveryOpts?: RecoveryWorkflowOpts;
  inviteOpts?: InviteWorkflowOpts;
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
  __aoothE2eBackupCodes?: Map<string, string[]>;
  __aoothE2eActiveSessions?: Map<string, number>;
  // username → list of tenant ids the user belongs to. Populated by `seed.ts`
  // and consulted by `DemoLoginWorkflow.loadTenants()` to drive the
  // tenant-select step (skipped when length ≤ 1).
  __aoothE2eTenants?: Map<string, string[]>;
  // username → list of persona options the user can pick from. Populated by
  // `seed.ts` and consulted by `DemoLoginWorkflow.loadPersonas()` to drive
  // the `persona-select` step (skipped when length ≤ 1). Mirrors the tenants
  // buffer pattern. See WF-LOGIN-032.
  __aoothE2ePersonas?: Map<string, Array<{ id: string; label: string }>>;
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
};
g.__aoothE2eEmails ??= [];
g.__aoothE2eSms ??= [];
g.__aoothE2eBackupCodes ??= new Map();
g.__aoothE2eActiveSessions ??= new Map();
g.__aoothE2eTenants ??= new Map();
g.__aoothE2ePersonas ??= new Map();
g.__aoothE2eProfileMissingFields ??= new Map();
g.__aoothE2eAuditEvents ??= [];
g.__aoothE2eAllowDuplicateInvites ??= false;
const sharedEmailsBuffer: AuthEmailEvent[] = g.__aoothE2eEmails;
const sharedSmsBuffer: AuthSmsEvent[] = g.__aoothE2eSms;
const sharedBackupCodesBuffer: Map<string, string[]> = g.__aoothE2eBackupCodes;
const sharedActiveSessionsBuffer: Map<string, number> = g.__aoothE2eActiveSessions;
const sharedTenantsBuffer: Map<string, string[]> = g.__aoothE2eTenants;
const sharedPersonasBuffer: Map<
  string,
  Array<{ id: string; label: string }>
> = g.__aoothE2ePersonas;
const sharedProfileMissingFieldsBuffer: Map<string, string[]> = g.__aoothE2eProfileMissingFields;
const sharedAuditEventsBuffer: AuditEvent[] = g.__aoothE2eAuditEvents;
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
  const demoLoginOpts: LoginWorkflowOpts = mergeWfOpts(
    {
      // SMS is exercised via `demoSmsSender` which console-logs the code — fine for the UI harness.
      mfa: { backupCodes: true },
      alternateCredentials: { forgotPassword: true, signup: true },
      guards: { passwordInitial: true },
    },
    opts.loginOpts,
  );
  @Inherit()
  @Injectable("FOR_EVENT")
  @Controller()
  class DemoLoginWorkflow extends LoginWorkflow {
    constructor(users: UserService, authCred: AuthCredential) {
      const variant = pickVariant(LOGIN_VARIANTS, readVariantHeader());
      super(
        variant?.opts
          ? mergeWfOpts(demoLoginOpts, variant.opts as LoginWorkflowOpts)
          : demoLoginOpts,
        users,
        authCred,
      );
    }
    protected override deliver(payload: DeliverPayload) {
      return forwardDeliver(payload);
    }
    // ── Variant-driven mfa-ctx setter override ──
    // Reads the active variant from the request header; if a variant is active
    // and supplies `mfaCtx.<field>`, force it onto ctx (after the base setter
    // ran). Otherwise the demo's default takes over: `mfaMode: 'disabled'`
    // (most seeded users have no MFA enrolled and the e2e harness's `loginAs`
    // helper expects to finish login without a prompt). When a variant IS
    // active but its `mfaCtx` is empty, the base setter's defaults stand —
    // we only force `disabled` when there is no variant at all.
    @Step("prepareMfaSetup")
    @Public()
    override prepareMfaSetup(
      @WorkflowParam("context") ctx: LoginWfCtx,
    ): undefined | Promise<undefined> {
      const baseResult = super.prepareMfaSetup(ctx);
      const apply = (): undefined => {
        const variant = pickVariant(LOGIN_VARIANTS, readVariantHeader());
        const v = variant?.mfaCtx;
        if (v?.mfaMode !== undefined) ctx.mfaMode = v.mfaMode;
        else if (!variant) ctx.mfaMode = "disabled";
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
    // Drives the `tenant-select` step: returns the user's tenants from the
    // globalThis-anchored buffer populated by `seed.ts`. Single-tenant users
    // (length ≤ 1) cause the schema to skip the step entirely.
    protected override async loadTenants(
      username: string,
    ): Promise<Array<{ id: string; name: string }>> {
      const ids = sharedTenantsBuffer.get(username) ?? [];
      return ids.map((id) => ({ id, name: id }));
    }
    // Drives the `persona-select` step: returns the user's personas from the
    // globalThis-anchored buffer populated by `seed.ts`. Mirrors `loadTenants`
    // — single-persona users (length ≤ 1) skip the step entirely. Needed by
    // WF-LOGIN-032 so iris exercises the persona pause.
    protected override async loadPersonas(
      username: string,
    ): Promise<Array<{ id: string; label: string }>> {
      return sharedPersonasBuffer.get(username) ?? [];
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
        // Pre-populate tenant + persona arrays so the `tenant-select` and
        // `persona-select` schema conditions (gated on `length > 1`) can
        // evaluate BEFORE the step bodies run. The library's bundled step
        // bodies load these on first entry, but the schema gate is evaluated
        // first — so without this pre-fetch the steps are skipped.
        if (!ctx.availableTenants) {
          ctx.availableTenants = await this.loadTenants(ctx.username);
        }
        if (!ctx.availablePersonas) {
          ctx.availablePersonas = await this.loadPersonas(ctx.username);
        }
      }
      return result;
    }
  }

  // Phase-3 reshape: `RecoveryWorkflow` is configured via a consumer subclass
  // that overrides `protected` methods. The demo overrides `deliver` for OTP
  // emails (magic-link mode uses the email outlet on the trigger route) and
  // `emailToUserId` to map a recovery-step email to the canonical username.
  const demoRecoveryOpts: RecoveryWorkflowOpts = mergeWfOpts(
    {
      delivery: { magicLinkTtlMs: env.RECOVERY_TTL_MS },
      // The library default for `revokeAllSessions` is `true` (kick every
      // active session after a password reset). The demo opts out so
      // WF-RECOVERY-05 can keep documenting the "pre-existing session stays
      // valid" branch; production consumers should leave the secure default
      // on. `freshLoginRequired` defaults to false (auto-login), which is what
      // this SPA demo wants — no override needed.
      postReset: { revokeAllSessions: false },
    },
    opts.recoveryOpts,
  );
  @Inherit()
  @Injectable("FOR_EVENT")
  @Controller()
  class DemoRecoveryWorkflow extends RecoveryWorkflow {
    constructor(users: UserService, authCred: AuthCredential) {
      const variant = pickVariant(RECOVERY_VARIANTS, readVariantHeader());
      super(
        variant ? mergeWfOpts(demoRecoveryOpts, variant as RecoveryWorkflowOpts) : demoRecoveryOpts,
        users,
        authCred,
      );
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
  const demoInviteOpts: InviteWorkflowOpts = mergeWfOpts(
    {
      send: { tokenTtlMs: env.INVITE_TTL_MS },
      // Existing demo tests assert the auto-login response payload — pre-dating
      // the BIG 3.3 confirmation pause. Off here so the demo matches today's
      // behavior; production should keep the default ON.
      accept: { showConfirmation: false },
    },
    opts.inviteOpts,
  );
  // ARBAC is carried by the base `InviteWorkflow`: class-level
  // `@ArbacResource('auth.invite') @ArbacAction('start')` gates phase A,
  // per-method `@Public()` opens phase B (post magic-link send) so the
  // anonymous resume isn't denied. `@Inherit()` flows the class meta down.
  @Inherit()
  @Injectable("FOR_EVENT")
  @Controller()
  class DemoInviteWorkflow extends InviteWorkflow {
    constructor(users: UserService, authCred: AuthCredential) {
      const variant = pickVariant(INVITE_VARIANTS, readVariantHeader());
      super(
        variant ? mergeWfOpts(demoInviteOpts, variant as InviteWorkflowOpts) : demoInviteOpts,
        users,
        authCred,
      );
    }
    protected override deliver(payload: DeliverPayload) {
      // Invite's default send path uses `outletEmail` (handled by the
      // createAuthEmailOutlet at the trigger route); deliver() runs only if a
      // future override drives a manual send. Reuse the shared forwarder for
      // parity with login/recovery.
      return forwardDeliver(payload);
    }
    // Default `mfaMode: 'disabled'` — pre-PR9 lived under `opts.mfa.mode`.
    // No invite variant currently flips this through the variant header (the
    // few e2e tests that need enrolment pass `inviteMfaCtx` directly via
    // `buildTestApp`, which wraps this class with `withInviteMfaCtx`). The
    // override below is just the demo's static default; if a future variant
    // needs per-request mfa shape, follow the login pattern above and read
    // the variant header here.
    @Step("inviteSetupMfa")
    @Public()
    override inviteSetupMfa(
      @WorkflowParam("context") ctx: InviteWfCtx,
    ): undefined | Promise<undefined> {
      const baseResult = super.inviteSetupMfa(ctx);
      const apply = (): undefined => {
        ctx.mfaMode = "disabled";
        return undefined;
      };
      return baseResult instanceof Promise ? baseResult.then(apply) : apply();
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
      this.outlets = [
        ...this.outlets,
        createAuthEmailOutlet(demoEmailOutletDeps),
        createAuthShareableLinkOutlet({
          buildMagicLinkUrl: aooth.buildMagicLinkUrl,
          magicLinkTtlMs: demoEmailOutletDeps.magicLinkTtlMs,
        }),
      ];
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
      allow: [...DEFAULT_AUTH_WORKFLOWS, "auth.reInvite", "auth.cancelInvite", "project.handover"],
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
    // Plaintext backup-code list is only known at generation time — seed
    // populates the map, callers must clear it here so stale codes don't
    // outlive the user records they refer to.
    sharedBackupCodesBuffer.clear();
    // Same lifecycle for active-session counts (used by `loadActiveSessions`
    // override below to drive the `concurrency-limit` step).
    sharedActiveSessionsBuffer.clear();
    // Tenants list keyed by username — repopulated per-seed by `seed.ts`.
    sharedTenantsBuffer.clear();
    // Personas list keyed by username — mirrors tenants. Re-populated per-seed.
    sharedPersonasBuffer.clear();
    // Profile-missing-fields list keyed by username — same lifecycle.
    sharedProfileMissingFieldsBuffer.clear();
    // Captured `audit(event)` events — cleared so the next test starts clean.
    sharedAuditEventsBuffer.length = 0;
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
      backupCodes: sharedBackupCodesBuffer,
      auditEvents: sharedAuditEventsBuffer,
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
// because the demo subclass has the moost FOR_EVENT 2-arg ctor signature
// `(users, auth)` while the base class is 3-arg `(opts, users, auth)`. The
// generic widens to "any LoginWorkflow-shaped class" so both fit.
function wrapWithLoginMfaCtx<W extends new (...args: never[]) => LoginWorkflow>(
  Base: W,
  ctx: LoginMfaCtxOverrides,
): W {
  @Inherit()
  @Injectable("FOR_EVENT")
  @Controller()
  class WithLoginCtx extends (Base as unknown as new (
    users: UserService,
    auth: AuthCredential,
  ) => LoginWorkflow) {
    // The forwarding ctor is required: moost reads `design:paramtypes`
    // metadata off the subclass to resolve DI, and TS only emits the
    // metadata when the ctor is explicit. Without it moost can't construct
    // the wrapper.
    // eslint-disable-next-line no-useless-constructor
    constructor(users: UserService, auth: AuthCredential) {
      super(users, auth);
    }
    @Step("prepareMfaSetup")
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
  @Inherit()
  @Injectable("FOR_EVENT")
  @Controller()
  class WithInviteCtx extends (Base as unknown as new (
    users: UserService,
    auth: AuthCredential,
  ) => InviteWorkflow) {
    // eslint-disable-next-line no-useless-constructor -- see wrapWithLoginMfaCtx for why
    constructor(users: UserService, auth: AuthCredential) {
      super(users, auth);
    }
    @Step("inviteSetupMfa")
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
        if (ctx.enrollMethod !== undefined) c.enrollMethod = ctx.enrollMethod;
        if (!c.enrollMethod && c.availableMfaTransports?.length === 1) {
          c.enrollMethod = c.availableMfaTransports[0];
        }
        return undefined;
      };
      return baseResult instanceof Promise ? baseResult.then(apply) : apply();
    }
  }
  return WithInviteCtx as unknown as W;
}
