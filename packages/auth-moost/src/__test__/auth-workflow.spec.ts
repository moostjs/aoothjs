import { type AuthContext, AuthCredential, CredentialStoreMemory } from "@aooth/auth";
import type { useAtscriptWf } from "@atscript/moost-wf";
import {
  type FederatedProfileSnapshot,
  type UserCredentials,
  UserService,
  UserStoreMemory,
} from "@aooth/user";
import { current } from "@wooksjs/event-core";
import { prepareTestHttpContext } from "@wooksjs/event-http";
import { getMoostMate } from "moost";
import { describe, expect, it } from "vite-plus/test";

import { setAuthContext } from "../auth.composables";
import { ConsentStore } from "../consent.store";
import type {
  AuthWfAltCredsPolicy,
  AuthWfCtx,
  AuthzReauthPolicy,
  MfaTransport,
} from "../workflow/auth-workflow.ctx";
import type { AuthDeliveryPayload } from "../workflow/auth-workflow";
import { AuthWorkflow, haversineKm, humanizeUserAgent } from "../workflow/auth-workflow";
import { enrollTrioSteps, mfaStepUpLoop } from "../workflow/auth-workflow.schemas";
import type { AuthWorkflowOpts } from "../workflow/auth-workflow.opts";

// ── Test scaffolding ───────────────────────────────────────────────────────

/**
 * Subclass exposing the protected resolver + deliver surface as public
 * methods. We do NOT override behaviour — only widen visibility — so every
 * default we assert against here is the same default a production subclass
 * would inherit.
 */
class TestableAuthWorkflow extends AuthWorkflow {
  public readonly deliveries: AuthDeliveryPayload[] = [];

  // Capture every deliver() call so the dispatch test can assert routing.
  // Signature mirrors the base (`void | Promise<void>`) — the await in the
  // dispatch test then composes the same way a customer override would.
  protected override deliver(payload: AuthDeliveryPayload): void | Promise<void> {
    this.deliveries.push(payload);
    return undefined;
  }

  // ── Resolver exposure (single-line trampolines so tests reach the
  // protected surface; widen visibility only, do NOT change behaviour) ──
  public exposeAlternateCredentials = (ctx: AuthWfCtx) => this.resolveAlternateCredentials(ctx);
  public exposeDeviceTrust = (ctx: AuthWfCtx) => this.resolveDeviceTrust(ctx);
  public exposeEnrollment = (ctx: AuthWfCtx) => this.resolveEnrollment(ctx);
  public exposeFinalize = (ctx: AuthWfCtx) => this.resolveFinalize(ctx);
  public exposeGuards = (ctx: AuthWfCtx) => this.resolveGuards(ctx);
  public exposeLockout = (ctx: AuthWfCtx) => this.resolveLockout(ctx);
  public exposeLockoutOverride = (ctx: AuthWfCtx) => this.lockoutOverride(ctx);
  public exposeSessionPolicy = (ctx: AuthWfCtx) => this.resolveSessionPolicy(ctx);
  public exposeChangePasswordPolicy = (ctx: AuthWfCtx) => this.resolveChangePasswordPolicy(ctx);
  public exposeSignupPolicy = (ctx: AuthWfCtx) => this.resolveSignupPolicy(ctx);
  public exposeMfaPolicy = (ctx: AuthWfCtx) => this.resolveMfaPolicy(ctx);
  public exposeLockedMfaTransports = (ctx: AuthWfCtx) => this.resolveLockedMfaTransports(ctx);
  public exposeValidateMfaAddress = (m: MfaTransport, v: string) =>
    this.validateMfaAddress({}, m, v);
  public exposeEnrollAddress = (ctx: AuthWfCtx, m: MfaTransport) =>
    this.resolveEnrollAddress(ctx, m);
  public exposeStepUpConfirmBeforeSend = (ctx: AuthWfCtx) =>
    this.resolveStepUpConfirmBeforeSend(ctx);
  public exposeTotpAccountLabel = (ctx: AuthWfCtx) => this.resolveTotpAccountLabel(ctx);
  public exposeNormalizeMfaAddress = (m: MfaTransport, v: string) => this.normalizeMfaAddress(m, v);
  public exposeHandleEnrollExit = (ctx: AuthWfCtx, action: string | undefined) =>
    this.handleEnrollExit(ctx, action);
  public exposeEnrollPreConfirmed = (ctx: AuthWfCtx, m: MfaTransport, a: string) =>
    this.resolveEnrollPreConfirmed(ctx, m, a);
  public exposeOtpDisclosure = (ctx: AuthWfCtx, ch: "email" | "phone") =>
    this.resolveOtpDisclosure(ctx, ch);
  public exposeRiskStepUp = (ctx: AuthWfCtx) => this.resolveRiskStepUp(ctx);
  public exposeAuthzReauthPolicy = (ctx: AuthWfCtx) => this.resolveAuthzReauthPolicy(ctx);
  public exposeProbeSilentAuthz = (ctx: AuthWfCtx, policy: AuthzReauthPolicy) =>
    this.probeSilentAuthz(ctx, policy);
  public exposeRecoveryUrl = (u: string | undefined, alt: AuthWfAltCredsPolicy) =>
    this.resolveRecoveryUrl(u, alt);
  public exposeAdminForm = (ctx: AuthWfCtx) => this.resolveAdminForm(ctx);
  public exposeDuplicateInviteCheck = (input: {
    email: string;
    existingUser: UserCredentials | null;
  }) => this.duplicateInviteCheck(input);
  public exposeAccept = (ctx: AuthWfCtx) => this.resolveAccept(ctx);
  public exposeSetPasswordCopy = (ctx: AuthWfCtx) => this.resolveSetPasswordCopy(ctx);
  public exposeGetAvailableRoles = () => this.getAvailableRoles();
  public exposeInviteWhitelistIsOpen = () => this.inviteWhitelistIsOpen();
  public exposeEffectiveInviteRoles = (ctx: AuthWfCtx, submitted: string[]) =>
    this.effectiveInviteRoles(ctx, submitted);
  public exposePostReset = (ctx: AuthWfCtx) => this.resolvePostReset(ctx);
  public exposeRecoveryAltActions = (ctx: AuthWfCtx) => this.resolveRecoveryAltActions(ctx);
  public exposePincodeForm = (ctx: AuthWfCtx) => this.resolvePincodeForm(ctx);
  public exposePincodeTarget = (ctx: AuthWfCtx) => this.resolvePincodeTarget(ctx);
  public exposeRecoveryDeliverySource = (ctx: AuthWfCtx) => this.resolveRecoveryDeliverySource(ctx);
  public exposeSelectRecoveryRegisteredMethod = (user: UserCredentials) =>
    this.selectRecoveryRegisteredMethod(user);
  public exposePincodeAltAction = (ctx: AuthWfCtx, a: string) =>
    this.resolvePincodeAltAction(ctx, a);
  public exposeFederatedEmailTrust = (ctx: AuthWfCtx, profile: FederatedProfileSnapshot) =>
    this.resolveFederatedEmailTrust(ctx, profile);
  public exposeRedirect = (ctx: AuthWfCtx) => this.resolveRedirect(ctx);
  public exposeClientIp = () => this.resolveClientIp();
  public exposeUserAgent = () => this.resolveUserAgent();
  public exposeIssueMetadata = (ctx: AuthWfCtx) => this.resolveIssueMetadata(ctx);
  public exposePopulatePublic = (ctx: AuthWfCtx) => {
    this.populatePublic(ctx);
    return ctx.public;
  };
  public exposeAddMfaFinishEnvelope = (ctx: AuthWfCtx) => this.buildAddMfaFinishEnvelope(ctx);
  public exposeDeliver = (payload: AuthDeliveryPayload) => this.deliver(payload);
  public exposeSendSecurityAlert = (ctx: AuthWfCtx, reason: string, c?: Record<string, unknown>) =>
    this.sendSecurityAlert(ctx, reason, c);
  public exposeLoadActiveSessionsCount = (u: string) => this.loadActiveSessionsCount(u);
  public exposeLogoutOtherSessions = (u: string) => this.logoutOtherSessions(u);
  // `opts` is `protected readonly` — surfaced for the construction tests.
  public exposeOpts = () => this.opts;
}

function makeDeps(): {
  users: UserService;
  auth: AuthCredential;
  consentStore: ConsentStore;
} {
  const users = new UserService(new UserStoreMemory());
  const auth = new AuthCredential({
    store: new CredentialStoreMemory(),
    method: "token",
    accessTtl: 60_000,
  });
  const consentStore = new ConsentStore();
  return { users, auth, consentStore };
}

function makeWorkflow(opts: Partial<AuthWorkflowOpts> = {}): TestableAuthWorkflow {
  const { users, auth, consentStore } = makeDeps();
  return new TestableAuthWorkflow(opts, users, auth, consentStore);
}

/** Like `makeWorkflow` but surfaces the same `users` + `auth` deps the workflow
 * holds, so a test can seed real rows/sessions into the stores the hooks read back. */
function makeWorkflowWithDeps(): {
  wf: TestableAuthWorkflow;
  users: UserService;
  auth: AuthCredential;
} {
  const { users, auth, consentStore } = makeDeps();
  return { wf: new TestableAuthWorkflow({}, users, auth, consentStore), users, auth };
}

/**
 * Resolvers are typed as `T | Promise<T>` so default sync impls don't
 * allocate a Promise (see CLAUDE.md "Helpers stay strictly sync"). Tests
 * accept either shape — this helper normalises so a single assertion
 * works whether the customer override goes async or not.
 */
async function settle<T>(v: T | Promise<T>): Promise<T> {
  return v instanceof Promise ? await v : v;
}

/** Minimal `UserCredentials` carrying just the MFA methods a recovery-selection test reads. */
function userWithMethods(methods: UserCredentials["mfa"]["methods"]): UserCredentials {
  return { mfa: { methods, defaultMethod: "", autoSend: false } } as UserCredentials;
}

/** Evaluate a workflow-schema node's `condition` against a sample ctx. */
function evalCondition(node: unknown, ctx: AuthWfCtx): boolean {
  const c = (node as { condition?: (ctx: AuthWfCtx) => boolean }).condition;
  return c ? c(ctx) : true;
}

/** Flatten a workflow schema's step ids (recursing into nested `steps`). */
function collectSchemaStepIds(nodes: unknown[]): string[] {
  const out: string[] = [];
  for (const n of nodes as { id?: string; steps?: unknown[] }[]) {
    if (n.id) out.push(n.id);
    if (Array.isArray(n.steps)) out.push(...collectSchemaStepIds(n.steps));
  }
  return out;
}

// ───────────────────────────────────────────────────────────────────────────
// 1. Construction — opts defaults + merging
// WHY: `this.opts.<group>.<field>` is read by step bodies and schema
// conditions without optional chaining. A regression that drops a default
// (or splits the nested merge) silently corrupts every flow that reads it.
// ───────────────────────────────────────────────────────────────────────────

describe("AuthWorkflow construction (WF-AUTH-UNIFIED-002)", () => {
  it("populates every resolved-opts field from an empty input", () => {
    const wf = makeWorkflow({});
    const opts = wf.exposeOpts();

    // Auto-login flags — invite default ON (consumers expect a friction-free
    // accept-tail), recover default OFF (post-reset re-auth is the safer
    // default for password resets).
    expect(opts.autoLoginOnInvite).toBe(true);
    expect(opts.autoLoginOnRecover).toBe(false);

    // Invite whitelist — empty universe + open default unacknowledged out of
    // the box. This preserves the legacy "no whitelist" behaviour
    // (getAvailableRoles returns undefined), with prepare-available-roles
    // warning once so the fail-open default is never silent (TODO #1).
    expect(opts.invitableRoles).toEqual([]);
    expect(opts.allowAnyInviteRole).toBe(false);

    // Cross-flow pincode infra — defaults must match
    // `mergeAuthWorkflowOpts`. Schema conditions divide / compare by these
    // millisecond values; dropping a zero silently turns 5m into 5ms.
    expect(opts.mfa.pincodeLength).toBe(6);
    expect(opts.mfa.pincodeTtlMs).toBe(5 * 60 * 1000);
    expect(opts.mfa.pincodeResendTimeoutMs).toBe(60_000);

    // Recovery-state TTL — stamped on every recovery-side pause via
    // `stampRecoveryExpiry`. Dropping it makes recovery sessions immortal,
    // which is a security regression (stale OTP states become resumable
    // indefinitely).
    expect(opts.recoveryStateTtlMs).toBe(60 * 60 * 1000);

    // Canonical login URL — referenced by invite accept + recovery post-reset
    // resolvers. The default MUST stay stable so consumers can opt out of
    // overriding `loginUrl` and still get a sane redirect.
    expect(opts.loginUrl).toBe("/login");

    // TOTP issuer — surfaces into the resolveMfaPolicy() output (issuer is
    // pulled from opts, not hardcoded). Default brand string.
    expect(opts.totpIssuer).toBe("aooth");

    // Device-trust infra — cookieName + ttlMs + bindsTo all read by
    // check-trusted-device + device-trust @Steps. Dropping bindsTo's default
    // would shift every cookie check to undefined (truthy bug).
    expect(opts.deviceTrust.cookieName).toBe("aooth_trusted_device");
    expect(opts.deviceTrust.ttlMs).toBe(24 * 60 * 60_000);
    expect(opts.deviceTrust.bindsTo).toBe("cookie");

    // Device-recognition infra — the always-on notification-suppression
    // ledger. Cookie name DERIVES from the merged trust cookie name
    // (`<trust>_seen`); TTL is deliberately long (180 days — recognition is
    // noise control, not an MFA bypass) and the ledger is LRU-capped.
    expect(opts.deviceRecognition.cookieName).toBe("aooth_trusted_device_seen");
    expect(opts.deviceRecognition.ttlMs).toBe(180 * 24 * 60 * 60_000);
    expect(opts.deviceRecognition.maxDevices).toBe(5);

    // forms — defaulted to the bundled `forms.as` models so step bodies
    // (`useAtscriptWf(this.opts.forms.X)`) hit real annotated types out of
    // the box. Consumer override via `opts.forms.<field>` swaps any slot.
    // Pin a representative field-count + a key slot so a regression that
    // drops the default map is caught.
    expect(Object.keys(opts.forms).length).toBe(25);
    expect(opts.forms.loginCredentials).toBeTruthy();
    expect(opts.forms.recoveryEmailIdentifier).toBeTruthy();
    // Authorization-server consent gate (AUTH-SERVER.md §6).
    expect(opts.forms.authzConsent).toBeTruthy();
    // Manage-MFA additions: QR step + menu + remove-confirm + password
    // re-auth + the step-up dispatch-consent notice.
    expect(opts.forms.stepUpConfirm).toBeTruthy();
    expect(opts.forms.enrollTotpQr).toBeTruthy();
    expect(opts.forms.manageMfa).toBeTruthy();
    expect(opts.forms.removeMfaConfirm).toBeTruthy();
    expect(opts.forms.passwordReauth).toBeTruthy();
    expect(opts.forms.pincode).toBeTruthy();
    expect(opts.forms.setPassword).toBeTruthy();
    // Federated needs-link interactive completion ships its own proof forms
    // (password + OTP fallback) so `prove-control` resolves real annotated types.
    expect(opts.forms.proveControl).toBeTruthy();
    expect(opts.forms.proveControlOtp).toBeTruthy();
    // Self-signup ships its own email-entry form (`auth/signup/flow` entry pause).
    expect(opts.forms.signup).toBeTruthy();
    // Authenticated change-password ships its own standalone form (current +
    // new + confirm) — distinct from the reset/initial setPassword form.
    expect(opts.forms.changePassword).toBeTruthy();
    expect(opts.forms.changePassword).not.toBe(opts.forms.setPassword);
  });

  it("preserves overrides for top-level fields", () => {
    const wf = makeWorkflow({
      autoLoginOnInvite: false,
      autoLoginOnRecover: true,
      recoveryStateTtlMs: 1,
      loginUrl: "/signin",
      totpIssuer: "Acme",
    });
    const opts = wf.exposeOpts();

    // Only flipped fields change; other defaults survive — proves
    // mergeAuthWorkflowOpts walks every key independently rather than
    // wholesale-replacing on the first override.
    expect(opts.autoLoginOnInvite).toBe(false);
    expect(opts.autoLoginOnRecover).toBe(true);
    expect(opts.recoveryStateTtlMs).toBe(1);
    expect(opts.loginUrl).toBe("/signin");
    expect(opts.totpIssuer).toBe("Acme");

    // Untouched group still has all defaults.
    expect(opts.mfa.pincodeLength).toBe(6);
    expect(opts.mfa.pincodeTtlMs).toBe(5 * 60 * 1000);
    expect(opts.mfa.pincodeResendTimeoutMs).toBe(60_000);
  });

  it("merges nested groups field-by-field instead of replacing", () => {
    // WHY: a regression that does `mfa: opts.mfa ?? defaults` instead of
    // per-field defaulting would zero-out pincodeLength + pincodeTtlMs
    // here. The intent is "override one knob, keep the rest" — load-
    // bearing for consumers tuning just resend cooldown for tests.
    const wf = makeWorkflow({ mfa: { pincodeResendTimeoutMs: 1_000 } });
    const opts = wf.exposeOpts();
    expect(opts.mfa.pincodeResendTimeoutMs).toBe(1_000);
    expect(opts.mfa.pincodeLength).toBe(6);
    expect(opts.mfa.pincodeTtlMs).toBe(5 * 60 * 1000);

    const wf2 = makeWorkflow({
      deviceTrust: { cookieName: "tenant_cookie", bindsTo: "cookie+ip" },
    });
    const opts2 = wf2.exposeOpts();
    expect(opts2.deviceTrust.cookieName).toBe("tenant_cookie");
    expect(opts2.deviceTrust.bindsTo).toBe("cookie+ip");
    expect(opts2.deviceTrust.ttlMs).toBe(24 * 60 * 60_000);
  });

  it("derives the recognition cookie name from the MERGED trust cookie name", () => {
    // WHY: a consumer renaming the trust cookie should get a matching
    // recognition cookie for free — derivation must read the merged trust
    // name, not the default. An explicit deviceRecognition.cookieName wins
    // over the derivation (it's still an independent knob).
    const derived = makeWorkflow({ deviceTrust: { cookieName: "custom_td" } }).exposeOpts();
    expect(derived.deviceRecognition.cookieName).toBe("custom_td_seen");
    // Other recognition defaults survive the partial trust override.
    expect(derived.deviceRecognition.ttlMs).toBe(180 * 24 * 60 * 60_000);
    expect(derived.deviceRecognition.maxDevices).toBe(5);

    const explicit = makeWorkflow({
      deviceTrust: { cookieName: "custom_td" },
      deviceRecognition: { cookieName: "my_seen_cookie" },
    }).exposeOpts();
    expect(explicit.deviceRecognition.cookieName).toBe("my_seen_cookie");
  });

  it("MFA-policy issuer flows through opts.totpIssuer (single knob)", async () => {
    // WHY: the issuer label is the only TOTP-provisioning knob a consumer
    // should need. resolveMfaPolicy() reads opts.totpIssuer directly so
    // overriding the option flows into the resolver output without forcing
    // a class subclass — the unification design's "single knob" invariant.
    const wf = makeWorkflow({ totpIssuer: "MyApp" });
    const policy = await settle(wf.exposeMfaPolicy({}));
    expect(policy.issuer).toBe("MyApp");

    // accept + postReset resolvers both source loginUrl from opts — single-
    // knob invariant for the canonical sign-in URL.
    const accept = await settle(wf.exposeAccept({}));
    const postReset = await settle(wf.exposePostReset({}));
    expect(accept.loginUrl).toBe("/login");
    expect(accept.alreadyAcceptedRedirectUrl).toBe("/login");
    expect(postReset.loginUrl).toBe("/login");
  });
});

// ───────────────────────────────────────────────────────────────────────────
// 2. Resolver defaults — every public resolver returns a sane shape
// WHY: prepare-* @Steps write resolver output straight onto ctx slots. If a
// default drifts, every downstream step + schema condition that reads
// `ctx.<group>.<flag>` silently sees stale state. These tests pin the
// shape AND the documented default for each field.
// ───────────────────────────────────────────────────────────────────────────

describe("AuthWorkflow resolver defaults", () => {
  const wf = makeWorkflow({});
  const ctx: AuthWfCtx = {};

  it("resolveAlternateCredentials — forgot-on, signup-off, magic-link-off", async () => {
    const r = await settle(wf.exposeAlternateCredentials(ctx));
    // Forgot-password ON: aooth ships with recovery — the login form's
    // forgotPassword alt-action MUST be enabled by default.
    expect(r.forgotPassword).toBe(true);
    // Signup OFF: invite-only is the safer default (consumers opt-in).
    expect(r.signup).toBe(false);
    // Magic-link OFF until consumer wires the outlet.
    expect(r.magicLink).toBe(false);
    expect(r.magicLinkSkipsMfa).toBe(false);
    expect(r.ssoProviders).toEqual([]);
    expect(r.recoveryUrl).toBe("/recover");
    expect(r.signupUrl).toBe("/signup");
    // embedRecovery controls whether recovery runs inline as a sub-workflow.
    // Default OFF — recovery is a separate flow.
    expect(r.embedRecovery).toBe(false);
  });

  it("resolveSignupPolicy — allowSignup OFF, collectUsername OFF by default", async () => {
    const r = await settle(wf.exposeSignupPolicy(ctx));
    // allowSignup OFF: invite-only is the safer default — a deployment opts
    // into open self-serve explicitly (mirrors resolveAlternateCredentials.signup).
    expect(r.allowSignup).toBe(false);
    // collectUsername OFF: bundled SignupForm is email-only, `username := email`.
    expect(r.collectUsername).toBe(false);
  });

  it("resolveDeviceTrust — disabled by default, opt-in semantics, skips-MFA on remember", async () => {
    const r = await settle(wf.exposeDeviceTrust(ctx));
    // enabled OFF by default — turning device-trust on requires explicit opt-in
    // since it shapes the MFA loop's exit conditions.
    expect(r.enabled).toBe(false);
    // optIn TRUE: when the feature IS enabled, the user must click a
    // "remember device" checkbox — never silently bind on every login.
    expect(r.optIn).toBe(true);
    // skipsMfa TRUE: a trusted device legitimately skips the MFA loop —
    // turning this off makes device-trust cosmetic.
    expect(r.skipsMfa).toBe(true);
  });

  it("resolveEnrollment — ensureEmail/Phone off by default", async () => {
    const r = await settle(wf.exposeEnrollment(ctx));
    // Default both OFF — login Phase 3 carrier-form prompts are
    // consumer-opt-in. Flipping a default to ON would gate every existing
    // login until the user surfaces an email/phone.
    expect(r.ensureEmail).toBe(false);
    expect(r.ensurePhone).toBe(false);
  });

  it("resolveFinalize — notifyNewDevice off, no redirect", async () => {
    const r = await settle(wf.exposeFinalize(ctx));
    // notifyNewDevice OFF — login emits no `new-device-notice` deliver until
    // the consumer wires the email template.
    expect(r.notifyNewDevice).toBe(false);
    // redirect false: the login `redirect` @Step is a no-op unless explicitly
    // told to go to `home` or `referer`.
    expect(r.redirect).toBe(false);
  });

  it("resolveGuards — initial+expiry on, email-verified off", async () => {
    const r = await settle(wf.exposeGuards(ctx));
    // passwordInitial ON: a fresh account MUST set a real password on first
    // login. Disabling silently lets bootstrap-password users in unchanged.
    expect(r.passwordInitial).toBe(true);
    // passwordExpiry ON: the policy engine's `maxAgeDays` check runs by
    // default — turning off bypasses the rotation enforcement entirely.
    expect(r.passwordExpiry).toBe(true);
    // emailVerifiedRequired OFF — promoting this to ON would gate every
    // login on an email-verify carrier form (channel enrollment Phase 3).
    expect(r.emailVerifiedRequired).toBe(false);
  });

  it("resolveLockout — defaults to temporary (preserves prior auto-expiry behavior)", async () => {
    const r = await settle(wf.exposeLockout(ctx));
    // "temporary" → the threshold trip uses UserService's configured duration
    // and auto-expires. Flipping the default to a permanent mode would silently
    // start bricking every fat-fingering user into recovery/admin-unlock.
    expect(r.mode).toBe("temporary");
  });

  it("lockoutOverride — permanent modes force duration:0; temporary/unset pass through", () => {
    // The mapping the whole feature hinges on: only a NON-temporary mode forces
    // a permanent lock at lock-SET time. A regression here would either
    // downgrade admin-only/self-service to a timed lock (loss of the freeze) or
    // wrongly force-permanent a temporary policy (users never auto-recover).
    expect(wf.exposeLockoutOverride({})).toBeUndefined(); // no policy resolved yet
    expect(wf.exposeLockoutOverride({ lockout: { mode: "temporary" } })).toBeUndefined();
    expect(wf.exposeLockoutOverride({ lockout: { mode: "admin-only" } })).toEqual({ duration: 0 });
    expect(wf.exposeLockoutOverride({ lockout: { mode: "self-service" } })).toEqual({
      duration: 0,
    });
  });

  it("resolveSessionPolicy — empty (no concurrency limit by default)", async () => {
    const r = await settle(wf.exposeSessionPolicy(ctx));
    // Empty object — the `concurrencyLimit?` is OPTIONAL in `AuthWfCtx`,
    // and the `load-active-sessions` schema subtree is gated on its
    // presence. A bogus `{ concurrencyLimit: undefined }` would still
    // not satisfy the `!!ctx.sessionPolicy?.concurrencyLimit` gate, but
    // pinning `{}` documents the intended shape.
    expect(r).toEqual({});
  });

  it("resolveChangePasswordPolicy — revokes other sessions, no rate limit by default", async () => {
    // WHY: the two guarantees the change-password tail depends on. revokeOtherSessions
    // ON is the OWASP "no ghost sessions survive a credential change" default; rateLimit
    // ABSENT encodes the deliberate design call that current-password re-entry (enforced
    // by UserService.changePassword), NOT throttling, is the primary protection. A
    // regression that dropped revoke (ghost sessions) or shipped a default rate limit
    // (lockout friction + wrong threat model) is caught here. Both stay overridable.
    const r = await settle(wf.exposeChangePasswordPolicy(ctx));
    expect(r).toEqual({ revokeOtherSessions: true });
    expect(r.rateLimit).toBeUndefined();
  });

  it("loadActiveSessionsCount — reflects the store's access-kind session count", async () => {
    // WHY: a declared `concurrencyLimit` silently never tripped because the base
    // hardcoded `0`, making `ctx.session.activeSessions` always 0 (SESSION_CONCURRENCY.md).
    // Pin that the default now reports the store's REAL active-session count, so
    // `resolveSessionPolicy({ concurrencyLimit })` enforces with no override on any
    // store that can enumerate. A regression back to a constant re-breaks the gate.
    const { wf, auth } = makeWorkflowWithDeps();
    expect(await wf.exposeLoadActiveSessionsCount("alice")).toBe(0);
    await auth.issue("alice");
    await auth.issue("alice");
    await auth.issue("bob");
    expect(await wf.exposeLoadActiveSessionsCount("alice")).toBe(2);
    // Per-user — bob's sessions never leak into alice's count.
    expect(await wf.exposeLoadActiveSessionsCount("bob")).toBe(1);
  });

  it("logoutOtherSessions — default revokes the user's sessions, scoped per-user", async () => {
    // WHY: the kickPrompt "log out other sessions" branch was a silent no-op, so a
    // user who hit the limit could never actually free a slot without a consumer
    // override. Pin that the default revokes via `auth.revokeAllForUser` (mandatory
    // on every store) and stays scoped to the target user — the kick must not nuke
    // other users' sessions.
    const { wf, auth } = makeWorkflowWithDeps();
    await auth.issue("alice");
    await auth.issue("alice");
    await auth.issue("bob");
    await wf.exposeLogoutOtherSessions("alice");
    expect(await wf.exposeLoadActiveSessionsCount("alice")).toBe(0);
    expect(await wf.exposeLoadActiveSessionsCount("bob")).toBe(1);
  });

  it("resolveMfaPolicy — optional mode, all 3 transports, default issuer", async () => {
    const r = await settle(wf.exposeMfaPolicy(ctx));
    // mode "optional" — the MFA loop's `while` condition reads
    // `mfaPolicy?.mode !== "disabled"` to enter the loop. "optional" lets
    // users skip when no methods are enrolled and policy permits.
    expect(r.mode).toBe("optional");
    // All three transports available — load-enrolled-mfa-methods filters
    // the user's enrolled set against this allowlist.
    expect(r.availableTransports).toEqual(["sms", "email", "totp"]);
    // Issuer flows from opts (covered separately, asserted here so the
    // default branch stays linked to the default brand).
    expect(r.issuer).toBe("aooth");
  });

  it("resolveOtpDisclosure — per-channel TCPA/CASL-safe copy, no target templated in", async () => {
    const wEmail = await settle(wf.exposeOtpDisclosure(ctx, "email"));
    const wPhone = await settle(wf.exposeOtpDisclosure(ctx, "phone"));
    // WHY: disclosure is shown BEFORE the user submits their address, so
    // the copy MUST be generic (no `{target}` interpolation). Routing on
    // the protocol the user is enrolling locks the right legal basis.
    expect(wEmail).toMatch(/email/i);
    expect(wEmail).not.toMatch(/sms/i);
    expect(wPhone).toMatch(/sms/i);
    expect(wPhone).not.toMatch(/email/i);
    // Both branches MUST mention "consent" — the disclosure is the legal
    // basis for sending OTP traffic to the address.
    expect(wEmail.toLowerCase()).toContain("consent");
    expect(wPhone.toLowerCase()).toContain("consent");
  });

  it("resolveRiskStepUp — never require by default", async () => {
    const r = await wf.exposeRiskStepUp(ctx);
    // Default `{ require: false }` — risk-step-up is a consumer extension
    // point. Flipping `require` to true silently injects an extra MFA round.
    expect(r.require).toBe(false);
    expect(r.reason).toBeUndefined();
  });

  it("resolveRecoveryUrl — encodes the username into the recovery URL", () => {
    const alt: AuthWfAltCredsPolicy = {
      forgotPassword: true,
      signup: false,
      magicLink: false,
      magicLinkSkipsMfa: false,
      ssoProviders: [],
      recoveryUrl: "/recover",
      signupUrl: "/signup",
      embedRecovery: false,
    };
    // WHY: login's forgotPassword alt-action threads the typed username into
    // the recovery page so the email input pre-fills. Skipping URL encoding
    // would let `?username=foo&bar=` smuggle arbitrary query params from
    // user input — pin the `encodeURIComponent` invariant.
    expect(wf.exposeRecoveryUrl("alice@example.com", alt)).toBe(
      "/recover?username=alice%40example.com",
    );
    // Empty / undefined username — URL is still well-formed (recovery page
    // handles the empty pre-fill).
    expect(wf.exposeRecoveryUrl(undefined, alt)).toBe("/recover?username=");
  });

  it("resolveAdminForm — collectRoles ON by default", async () => {
    const r = await settle(wf.exposeAdminForm(ctx));
    // ON: invite admin form prompts for roles. Turning OFF skips the
    // `prepare-available-roles` step entirely (gated by collectRoles).
    expect(r.collectRoles).toBe(true);
  });

  it("resolveAccept — confirmation on, copy default, login URL inherits from opts", async () => {
    const r = await settle(wf.exposeAccept(ctx));
    expect(r.alreadyAcceptedRedirectUrl).toBe("/login");
    expect(r.loginUrl).toBe("/login");
    // showConfirmation ON: invite accept-tail renders a confirmation screen
    // before redirecting. Turning OFF skips the `confirmation` step.
    expect(r.showConfirmation).toBe(true);
    expect(r.confirmationMessage).toBe("Your account has been created.");
  });

  it("resolvePostReset — revoke all sessions, login URL inherits from opts", async () => {
    const r = await settle(wf.exposePostReset(ctx));
    // revokeAllSessions ON by default — a password reset MUST invalidate
    // every existing session (the comment notes CredentialStoreJwt uses
    // `>=` for the epoch check so this is safe to leave on).
    expect(r.revokeAllSessions).toBe(true);
    expect(r.loginUrl).toBe("/login");
  });

  it("resolveRecoveryAltActions — back-to-login enabled", async () => {
    const r = await settle(wf.exposeRecoveryAltActions(ctx));
    // backToLogin ON: recovery forms surface the cancel-and-go-back link.
    // Turning OFF traps the user in the recovery flow.
    expect(r.backToLogin).toBe(true);
  });

  it("resolvePincodeForm — routes by ctx.mfa.method presence (MFA vs recovery)", () => {
    // WHY: a single pair of @Step bodies (`pincode-send`/`pincode-check`)
    // serves login MFA and recovery OTP. `resolvePincodeForm` is the
    // override seam that picks WHICH form schema renders — splitting on
    // `ctx.mfa?.method` presence per the ctx-slot discrimination
    // convention. Without a forms override, both sides resolve to
    // undefined (consumer wires the schemas).
    const mfaCtx: AuthWfCtx = { mfa: { method: "sms" } };
    const recoveryCtx: AuthWfCtx = {};
    expect(wf.exposePincodeForm(mfaCtx)).toBe(wf.exposeOpts().forms.pincode);
    expect(wf.exposePincodeForm(recoveryCtx)).toBe(wf.exposeOpts().forms.recoveryPincode);
  });

  it("resolvePincodeTarget — recovery branch uses ctx.email + 'email' channel", async () => {
    // WHY: without `ctx.mfa.method`, the recovery branch takes over and
    // sources the address from `ctx.email`. The default for an empty email
    // is the empty string + email channel — pinning this prevents a
    // regression that returns undefined-address (the deliver call would
    // then ship undefined as the recipient).
    const empty = await settle(wf.exposePincodeTarget({}));
    expect(empty).toEqual({ address: "", channel: "email" });

    const withEmail = await settle(wf.exposePincodeTarget({ email: "bob@x.io" }));
    expect(withEmail).toEqual({ address: "bob@x.io", channel: "email" });
  });

  it("resolveRecoveryDeliverySource — defaults to 'typed' (M1)", async () => {
    // WHY: M2 (registered-channel recovery) is strictly opt-in. The default
    // MUST be "typed" so an un-overridden deployment keeps delivering the OTP
    // to the typed identifier (identifier == destination); a regression that
    // flipped the default would silently route every recovery to a row channel
    // and break the unknown-identifier anti-enumeration symmetry.
    expect(await settle(wf.exposeRecoveryDeliverySource({}))).toBe("typed");
  });

  it("selectRecoveryRegisteredMethod — SMS-first, email-fallback, TOTP/unconfirmed skipped", () => {
    // WHY: this is the M2 destination-selection policy. The OTP recipient is
    // read off the chosen method's `value`, so the selection rule is security-
    // relevant — it decides which pre-verified channel an account can recover
    // through. Pin: (1) a confirmed SMS wins over a confirmed email
    // (phone-first); (2) email is the fallback when no SMS; (3) TOTP carries no
    // deliverable address and is never selected; (4) unconfirmed methods don't
    // count; (5) no deliverable method → null (caller turns this into the
    // anti-enumeration generic finish).
    const sms = { name: "sms", confirmed: true, value: "+15555550101" };
    const email = { name: "email", confirmed: true, value: "a@b.io" };
    const totp = { name: "totp", confirmed: true, value: "SECRET" };

    // SMS wins even when email is also confirmed (order-independent).
    expect(wf.exposeSelectRecoveryRegisteredMethod(userWithMethods([email, sms]))).toBe(sms);
    expect(wf.exposeSelectRecoveryRegisteredMethod(userWithMethods([sms, email]))).toBe(sms);
    // Email fallback when no SMS.
    expect(wf.exposeSelectRecoveryRegisteredMethod(userWithMethods([email, totp]))).toBe(email);
    // TOTP-only → null (not deliverable).
    expect(wf.exposeSelectRecoveryRegisteredMethod(userWithMethods([totp]))).toBeNull();
    // Unconfirmed SMS does not count → falls back to confirmed email.
    expect(
      wf.exposeSelectRecoveryRegisteredMethod(
        userWithMethods([{ name: "sms", confirmed: false, value: "+15555550109" }, email]),
      ),
    ).toBe(email);
    // No methods at all → null.
    expect(wf.exposeSelectRecoveryRegisteredMethod(userWithMethods([]))).toBeNull();
    // An sms method with no value is not deliverable → null.
    expect(
      wf.exposeSelectRecoveryRegisteredMethod(
        userWithMethods([{ name: "sms", confirmed: true, value: "" }]),
      ),
    ).toBeNull();
  });

  it("resolvePincodeAltAction — maps canonical PincodeForm action ids; unknowns fall through", () => {
    // WHY: the bundled `PincodeForm` declares three actions (`resend`,
    // `useDifferentMethod`, `backToLogin`). The base maps each to the
    // canonical outcome the `pincode-check` @Step expects so consumers
    // don't have to override just to route the default form. Unknown
    // action ids return undefined → the @Step falls through to the verify
    // path (the override-when-adding-actions contract).
    expect(wf.exposePincodeAltAction({}, "resend")).toBe("resend");
    expect(wf.exposePincodeAltAction({}, "useDifferentMethod")).toBe("useDifferentMethod");
    expect(wf.exposePincodeAltAction({}, "backToLogin")).toBe("exit");
    expect(wf.exposePincodeAltAction({}, "anything")).toBeUndefined();
  });

  it("resolveRedirect — false/null/undefined → undefined, 'home' → '/'", () => {
    // WHY: the `redirect` @Step writes whatever this returns onto
    // `ctx.completion.redirectUrl`. The `false`/`null` branch produces a
    // no-redirect login outcome (the issue envelope stays as the response).
    expect(
      wf.exposeRedirect({ finalize: { notifyNewDevice: false, redirect: false } }),
    ).toBeUndefined();
    expect(
      wf.exposeRedirect({ finalize: { notifyNewDevice: false, redirect: null } }),
    ).toBeUndefined();
    expect(wf.exposeRedirect({ finalize: { notifyNewDevice: false, redirect: "home" } })).toBe("/");
    // 'referer' branch unconditionally calls `useHeaders(current())` and
    // throws outside an HTTP context — that path is covered by Playwright,
    // not asserted here (no architectural value in mocking Wooks ctx).
  });

  it("resolveClientIp — undefined outside HTTP context (swallow + return)", () => {
    // WHY: `check-trusted-device` calls `resolveClientIp()` and the
    // workflow can be exercised in tests without an HTTP context. The
    // resolver MUST swallow the "no event" throw and return undefined so
    // the cookie+ip bind path collapses to cookie-only safely.
    expect(wf.exposeClientIp()).toBeUndefined();
  });

  it("resolveUserAgent — undefined outside HTTP context (swallow + return)", () => {
    // Sibling to resolveClientIp; same no-event tolerance.
    expect(wf.exposeUserAgent()).toBeUndefined();
  });

  it("resolveIssueMetadata — undefined outside HTTP context (no IP, no UA)", () => {
    // WHY (Request 1 acceptance): a hand-rolled (no-HTTP) wf run must issue
    // with `metadata: undefined` rather than an empty `{}` object — so the
    // store never persists a metadata key for non-HTTP issuance.
    expect(wf.exposeIssueMetadata({} as AuthWfCtx)).toBeUndefined();
  });
});

// ───────────────────────────────────────────────────────────────────────────
// 3. Deliver dispatch (WF-AUTH-UNIFIED-004)
// WHY: `deliver(payload)` is the sole hook customers override for direct
// outbound dispatch (pincodes + new-device notices). Every kind in the
// `AuthDeliveryPayload` union must reach the hook with a stable `kind` +
// `channel`. This is dispatch-level only — content/templating belongs to
// the customer override.
// ───────────────────────────────────────────────────────────────────────────

describe("AuthWorkflow set-password copy (TODO #3 — resolveSetPasswordCopy)", () => {
  const wf = makeWorkflow({});

  it("expired changeReason → expired copy", async () => {
    const c = await settle(wf.exposeSetPasswordCopy({ password: { changeReason: "expired" } }));
    expect(c.heading).toBe("Your password has expired");
    expect(c.intro).toBe("Choose a new password to continue. The previous one is no longer valid.");
  });

  it("reset changeReason → reset copy", async () => {
    const c = await settle(wf.exposeSetPasswordCopy({ password: { changeReason: "reset" } }));
    expect(c.heading).toBe("Reset your password");
    expect(c.intro).toBe("Choose a new password for your account.");
  });

  it("invite-accept (ctx.accept present) → welcome copy", async () => {
    const c = await settle(wf.exposeSetPasswordCopy({ accept: {} }));
    expect(c.heading).toBe("Welcome — set your password");
    expect(c.intro).toBe("Choose a password to activate your account.");
  });

  it("no reason, no accept → initial-password fallback copy", async () => {
    const c = await settle(wf.exposeSetPasswordCopy({}));
    expect(c.heading).toBe("Set your initial password");
    expect(c.intro).toBe("Your account was created without a password. Choose one to continue.");
  });

  it("changeReason takes precedence over ctx.accept (expired beats accept)", async () => {
    const c = await settle(
      wf.exposeSetPasswordCopy({ accept: {}, password: { changeReason: "expired" } }),
    );
    // Order matters: the reason branch is checked before the accept branch, so
    // an expired/reset accept-phase set-password still shows the reason copy.
    expect(c.heading).toBe("Your password has expired");
  });

  it("override can re-brand a single phase; partial return leaves the other field", async () => {
    class BrandedAuth extends TestableAuthWorkflow {
      protected override resolveSetPasswordCopy(ctx: AuthWfCtx) {
        if (ctx.accept) return { heading: "Welcome to Acme!" };
        return super.resolveSetPasswordCopy(ctx);
      }
    }
    const { users, auth, consentStore } = makeDeps();
    const branded = new BrandedAuth({}, users, auth, consentStore);
    const c = await settle(branded.exposeSetPasswordCopy({ accept: {} }));
    expect(c.heading).toBe("Welcome to Acme!");
    // intro omitted by the partial override — createPasswordForm's guarded
    // assign leaves any earlier-staged intro untouched (never writes undefined).
    expect(c.intro).toBeUndefined();
  });
});

describe("AuthWorkflow invite role whitelist (TODO #1 — getAvailableRoles default)", () => {
  it("unset invitableRoles → getAvailableRoles() returns undefined (legacy no-whitelist)", async () => {
    const roles = await settle(makeWorkflow({}).exposeGetAvailableRoles());
    expect(roles).toBeUndefined();
  });

  it("invitableRoles set but ARBAC unreachable → universe verbatim (CLOSED, never fail-open)", async () => {
    // Called outside any event context, so `useArbac()` throws inside
    // filterInvitableRolesByArbac and the catch falls back to the configured
    // universe — a closed whitelist, NOT an open allow-all.
    const roles = await settle(
      makeWorkflow({ invitableRoles: ["admin", "editor"] }).exposeGetAvailableRoles(),
    );
    expect(roles).toEqual(["admin", "editor"]);
  });

  it("inviteWhitelistIsOpen — TRUE on the bare default (unset + not overridden + unacknowledged)", () => {
    expect(makeWorkflow({}).exposeInviteWhitelistIsOpen()).toBe(true);
  });

  it("inviteWhitelistIsOpen — FALSE when invitableRoles is configured", () => {
    expect(makeWorkflow({ invitableRoles: ["admin"] }).exposeInviteWhitelistIsOpen()).toBe(false);
  });

  it("inviteWhitelistIsOpen — FALSE when allowAnyInviteRole acknowledges the open default", () => {
    expect(makeWorkflow({ allowAnyInviteRole: true }).exposeInviteWhitelistIsOpen()).toBe(false);
  });

  it("inviteWhitelistIsOpen — FALSE when getAvailableRoles is overridden", () => {
    class OverridingAuth extends TestableAuthWorkflow {
      protected override getAvailableRoles(): string[] {
        return ["admin"];
      }
    }
    const { users, auth, consentStore } = makeDeps();
    const wf = new OverridingAuth({}, users, auth, consentStore);
    expect(wf.exposeInviteWhitelistIsOpen()).toBe(false);
  });
});

describe("AuthWorkflow invite role gating under collectRoles (fail-open fix)", () => {
  // WHY: `prepare-available-roles` (which populates the `availableRoles`
  // whitelist the admin-form guard enforces) is schema-gated on
  // `adminForm.collectRoles`. So when a consumer sets `collectRoles:false`
  // (hide the role picker) the whitelist guard is skipped — yet admin-form
  // still parses submitted roles. effectiveInviteRoles closes that fail-open:
  // when role collection is OFF, client-submitted roles are IGNORED entirely,
  // so a crafted POST cannot assign roles regardless of the whitelist.
  const wf = makeWorkflow({});

  it("collectRoles:true → submitted roles are parsed + honored", () => {
    const r = wf.exposeEffectiveInviteRoles({ adminForm: { collectRoles: true } }, [
      "admin",
      "editor",
    ]);
    expect(r).toEqual(["admin", "editor"]);
  });

  it("collectRoles:false → submitted roles are IGNORED (crafted POST cannot assign roles)", () => {
    const r = wf.exposeEffectiveInviteRoles({ adminForm: { collectRoles: false } }, [
      "admin",
      "superuser",
    ]);
    expect(r).toEqual([]);
  });

  it("adminForm unset → defaults to parsing (back-compat; whitelist guard still applies if set)", () => {
    expect(wf.exposeEffectiveInviteRoles({}, ["editor"])).toEqual(["editor"]);
  });

  it("trims + de-dupes when collecting (delegates to parseInviteRoles)", () => {
    const r = wf.exposeEffectiveInviteRoles({ adminForm: { collectRoles: true } }, [
      " admin ",
      "admin",
      "",
    ]);
    expect(r).toEqual(["admin"]);
  });
});

describe("AuthWorkflow deliver dispatch (WF-AUTH-UNIFIED-004)", () => {
  // WHY: every kind in the `AuthDeliveryPayload` union must reach the
  // override hook with a stable `(kind, channel)` pair. The discriminated
  // union narrows `channel` per-kind in the type system; this asserts the
  // runtime payload reaches the override unchanged for each kind. A
  // regression that rewrote `recovery-pincode` to SMS or dropped
  // `new-device-notice` entirely would show up here.
  it("captures every AuthDeliveryPayload kind via the override hook", async () => {
    const wf = makeWorkflow({});
    const payloads: AuthDeliveryPayload[] = [
      { kind: "mfa-pincode", channel: "sms", recipient: "+1", code: "0", expiresInMs: 1 },
      { kind: "mfa-pincode", channel: "email", recipient: "a@x", code: "0", expiresInMs: 1 },
      { kind: "enroll-pincode", channel: "sms", recipient: "+1", code: "0", expiresInMs: 1 },
      { kind: "enroll-pincode", channel: "email", recipient: "b@x", code: "0", expiresInMs: 1 },
      { kind: "recovery-pincode", channel: "email", recipient: "c@x", code: "0", expiresInMs: 1 },
      {
        kind: "invite-link",
        channel: "email",
        recipient: "d@x",
        url: "https://x/r",
        expiresInMs: 1,
      },
      { kind: "new-device-notice", channel: "email", recipient: "e@x", loginAt: 1 },
      { kind: "security-alert", channel: "email", recipient: "f@x", reason: "r", loginAt: 1 },
    ];

    for (const p of payloads) await wf.exposeDeliver(p);

    expect(wf.deliveries.map((d) => ({ kind: d.kind, channel: d.channel }))).toEqual(
      payloads.map((p) => ({ kind: p.kind, channel: p.channel })),
    );
    // Pass-through invariant: an invite-link payload's `url` reaches the
    // override unchanged — the override IS the integration point with the
    // outbound transport, so payload shape matters as much as routing.
    expect(wf.deliveries.find((d) => d.kind === "invite-link")).toMatchObject({
      url: "https://x/r",
    });
  });

  it("base-class deliver is a no-op (no implicit dispatch)", async () => {
    // WHY: the base default is void — the workflow's own @Step bodies call
    // `this.deliver(...)` and rely on the customer override for transport.
    // If the base ever sprouted a default network call, every unit-tested
    // workflow would suddenly hit the wire.
    class BaseSurfaced extends AuthWorkflow {
      public exposeBaseDeliver(payload: AuthDeliveryPayload) {
        return this.deliver(payload);
      }
    }
    const { users, auth, consentStore } = makeDeps();
    const wf = new BaseSurfaced({}, users, auth, consentStore);
    await expect(
      Promise.resolve(
        wf.exposeBaseDeliver({
          kind: "mfa-pincode",
          channel: "sms",
          recipient: "x",
          code: "0",
          expiresInMs: 0,
        }),
      ),
    ).resolves.toBeUndefined();
  });
});

describe("AuthWorkflow sendSecurityAlert", () => {
  // WHY: this is the blessed one-call alert path for risk overrides
  // (impossible-travel etc.) — it must route through the same deliver() as
  // every other notice, with the recipient sourced from the proven-first
  // correspondence chain (`ctx.notice.email`), and must NEVER throw or emit
  // when no provable inbox exists (mirrors notifyNewDevice's posture).
  it("delivers a security-alert payload to ctx.notice.email with reason + context", async () => {
    const wf = makeWorkflow();
    const ctx = { notice: { email: "owner@x" } } as AuthWfCtx;
    await wf.exposeSendSecurityAlert(ctx, "impossible-travel", {
      distanceKm: 9712,
      fromCity: "Paris",
      toCity: "Tokyo",
    });
    expect(wf.deliveries).toHaveLength(1);
    expect(wf.deliveries[0]).toMatchObject({
      kind: "security-alert",
      channel: "email",
      recipient: "owner@x",
      reason: "impossible-travel",
      context: { distanceKm: 9712, fromCity: "Paris", toCity: "Tokyo" },
    });
    expect(typeof (wf.deliveries[0] as { loginAt: number }).loginAt).toBe("number");
  });

  it("omits the context key entirely when none is passed", async () => {
    const wf = makeWorkflow();
    await wf.exposeSendSecurityAlert({ notice: { email: "owner@x" } } as AuthWfCtx, "reauth");
    expect(wf.deliveries).toHaveLength(1);
    expect("context" in wf.deliveries[0]).toBe(false);
  });

  it("is a SILENT no-op when ctx.notice.email is absent", async () => {
    const wf = makeWorkflow();
    await expect(
      wf.exposeSendSecurityAlert({} as AuthWfCtx, "impossible-travel"),
    ).resolves.toBeUndefined();
    await expect(
      wf.exposeSendSecurityAlert({ notice: {} } as AuthWfCtx, "impossible-travel"),
    ).resolves.toBeUndefined();
    expect(wf.deliveries).toHaveLength(0);
  });
});

// ───────────────────────────────────────────────────────────────────────────
// record-login funnel + afterLogin lifecycle hook.
// WHY: this single step is the sole workflow writer of `account.lastLogin` AND
// the uniform firing point for `afterLogin`, reached by every login flow before
// its delivery terminal. Its idempotency latch (`ctx.loginRecorded`) must skip a
// redundant stamp on the password path (which stamped via `users.login()`) yet
// STILL fire the hook, and a federated / auto-login path must get its sole stamp
// here. recovery-lock-check is the guard extracted out of the (now-pure)
// finalize terminals.
// ───────────────────────────────────────────────────────────────────────────

describe("record-login funnel + afterLogin hook (WF-AUTH-LASTLOGIN)", () => {
  class HookWorkflow extends TestableAuthWorkflow {
    public afterLoginCalls = 0;
    protected override afterLogin(): void {
      this.afterLoginCalls++;
    }
  }
  function make(): { wf: HookWorkflow; users: UserService } {
    const { users, auth, consentStore } = makeDeps();
    return { wf: new HookWorkflow({}, users, auth, consentStore), users };
  }

  it("stamps account.lastLogin once, fires afterLogin, and latches loginRecorded", async () => {
    const { wf, users } = make();
    const { id } = await users.createUser("alice", "pw");
    expect((await users.getUser(id)).account.lastLogin).toBe(0);
    const ctx: AuthWfCtx = { subject: id };
    await wf.recordLogin(ctx);
    expect((await users.getUser(id)).account.lastLogin).toBeGreaterThan(0);
    expect(ctx.loginRecorded).toBe(true);
    expect(wf.afterLoginCalls).toBe(1);
  });

  it("does NOT re-stamp when loginRecorded is already set (password path), but STILL fires afterLogin", async () => {
    const { wf, users } = make();
    const { id } = await users.createUser("bob", "pw");
    // Simulate the `credentials` step having already stamped + latched.
    const ctx: AuthWfCtx = { subject: id, loginRecorded: true };
    await wf.recordLogin(ctx);
    expect((await users.getUser(id)).account.lastLogin).toBe(0); // no second write
    expect(wf.afterLoginCalls).toBe(1); // hook still fires exactly once
  });

  it("no-ops with neither stamp nor hook when there is no subject", async () => {
    const { wf } = make();
    const ctx: AuthWfCtx = {};
    await wf.recordLogin(ctx);
    expect(wf.afterLoginCalls).toBe(0);
  });

  it("recovery-lock-check leaves an unlocked account alone (no abort, no stamp)", async () => {
    const { wf, users } = make();
    const { id } = await users.createUser("carol", "pw"); // account.locked defaults false
    const ctx: AuthWfCtx = {
      subject: id,
      lockout: { mode: "admin-only" } as AuthWfCtx["lockout"],
    };
    await wf.recoveryLockCheck(ctx);
    expect(ctx.aborted).toBeFalsy();
  });
});

describe("haversineKm", () => {
  // WHY: the published distance util consumers feed impossible-travel
  // thresholds with — a broken radian conversion or radius constant would
  // silently re-arm (or never arm) MFA for every geo-aware deployment.
  it("returns ~0 for identical points", () => {
    expect(haversineKm({ lat: 48.8566, lon: 2.3522 }, { lat: 48.8566, lon: 2.3522 })).toBeCloseTo(
      0,
      6,
    );
    expect(haversineKm({ lat: 0, lon: 0 }, { lat: 0, lon: 0 })).toBe(0);
  });

  it("Paris ↔ Tokyo is ≈ 9715 km (±50 km)", () => {
    const d = haversineKm({ lat: 48.8566, lon: 2.3522 }, { lat: 35.6764, lon: 139.65 });
    expect(d).toBeGreaterThan(9665);
    expect(d).toBeLessThan(9765);
  });

  it("is symmetric (a↔b)", () => {
    const a = { lat: 48.8566, lon: 2.3522 };
    const b = { lat: 35.6764, lon: 139.65 };
    expect(haversineKm(a, b)).toBeCloseTo(haversineKm(b, a), 9);
  });
});

// ───────────────────────────────────────────────────────────────────────────
// 3b. Invite re-invite — `duplicateInviteCheck` 'reuse' default + the
//     `create-user` refresh branch
// WHY: a pending invitee whose magic link expired used to be a dead end
// (delete the user, invite from scratch). The default verdict now routes
// pending rows to 'reuse' and `create-user` refreshes the row in place — the
// fresh-read guard must keep a 'reuse' verdict from ever re-pending an
// ACCEPTED account, and a vanished row must fall through to a normal create.
// ───────────────────────────────────────────────────────────────────────────

describe("AuthWorkflow invite re-invite ('reuse' verdict)", () => {
  it("duplicateInviteCheck — pending row → 'reuse', accepted row → 'reject', no row → 'allow'", async () => {
    const wf = makeWorkflow();
    const pending = { account: { pendingInvitation: true } } as UserCredentials;
    const accepted = { account: { pendingInvitation: false } } as UserCredentials;
    const check = (existingUser: UserCredentials | null) =>
      settle(wf.exposeDuplicateInviteCheck({ email: "a@example.com", existingUser }));
    expect(await check(pending)).toBe("reuse");
    expect(await check(accepted)).toBe("reject");
    expect(await check(null)).toBe("allow");
  });

  it("create-user reuse — refreshes the pending row in place: roles replaced, extras merged, pending re-asserted, subject = existing id", async () => {
    const { wf, users } = makeWorkflowWithDeps();
    const row = await users.createUser("invitee@example.com", undefined, {
      roles: ["admin", "editor"],
      tenantId: "t1",
    });
    await users.update(row.id, {
      account: { pendingInvitation: true },
    } as Partial<UserCredentials>);

    const ctx = {
      email: "invitee@example.com",
      admin: { reuseExisting: true, roles: ["viewer"], userExtras: { tenantId: "t2" } },
    } as AuthWfCtx;
    await wf.createUser(ctx);

    expect(ctx.subject).toBe(row.id);
    const updated = (await users.findByHandle("invitee@example.com"))!;
    // Same row refreshed, not a new one. Roles narrow correctly — the
    // deep-merge replaces arrays wholesale (no stale-privilege union).
    expect(updated.id).toBe(row.id);
    expect((updated as { roles?: string[] }).roles).toEqual(["viewer"]);
    expect((updated as { tenantId?: string }).tenantId).toBe("t2");
    expect(updated.account.pendingInvitation).toBe(true);
    // Credentials untouched: a pending record never had a usable password.
    expect(updated.password).toEqual(row.password);
  });

  it("create-user reuse guard — 'reuse' stamped for an ACCEPTED account → 409, row untouched", async () => {
    const { wf, users } = makeWorkflowWithDeps();
    await users.createUser("done@example.com", undefined, { roles: ["member"] });
    const ctx = { email: "done@example.com", admin: { reuseExisting: true } } as AuthWfCtx;
    await expect(wf.createUser(ctx)).rejects.toThrow(/User already exists/);
    const after = (await users.findByHandle("done@example.com"))!;
    expect(after.account.pendingInvitation).toBeFalsy();
    expect((after as { roles?: string[] }).roles).toEqual(["member"]);
    expect(ctx.subject).toBeUndefined();
  });

  it("create-user reuse fall-through — row vanished since admin-form → normal create path", async () => {
    const { wf, users } = makeWorkflowWithDeps();
    const ctx = {
      email: "ghost@example.com",
      admin: { reuseExisting: true, roles: ["member"] },
    } as AuthWfCtx;
    await wf.createUser(ctx);
    const created = (await users.findByHandle("ghost@example.com"))!;
    expect(created).toBeTruthy();
    expect(ctx.subject).toBe(created.id);
    expect(created.account.pendingInvitation).toBe(true);
    expect((created as { roles?: string[] }).roles).toEqual(["member"]);
  });
});

// ───────────────────────────────────────────────────────────────────────────
// 3b. Verified correspondence email — trust resolver + capture steps
// WHY: the "new sign-in" notice recipient resolves through
// `users.getCorrespondenceEmail`, whose middle level is `account.verifiedEmail`
// — populated ONLY by the inbox-proof captures. A capture that silently stops
// firing reverts invited / OTP-signup users (no email-MFA enrolled) to
// receiving no security notices at all.
// ───────────────────────────────────────────────────────────────────────────

describe("verified correspondence email capture", () => {
  it("resolveFederatedEmailTrust default — trusts exactly the provider's email_verified claim", async () => {
    const wf = makeWorkflow();
    const ctx = {} as AuthWfCtx;
    expect(await settle(wf.exposeFederatedEmailTrust(ctx, { emailVerified: true }))).toBe(true);
    expect(await settle(wf.exposeFederatedEmailTrust(ctx, { emailVerified: false }))).toBe(false);
    expect(await settle(wf.exposeFederatedEmailTrust(ctx, {}))).toBe(false);
  });

  it("activate-user — records ctx.email as account.verifiedEmail (magic-link proof) and still activates", async () => {
    const { wf, users } = makeWorkflowWithDeps();
    const row = await users.createUser("invitee@example.com", undefined, {});
    const ctx = { subject: row.id, email: "invitee@example.com" } as AuthWfCtx;
    await wf.activateUser(ctx);
    const after = await users.getUser(row.id);
    expect(after.account.verifiedEmail).toBe("invitee@example.com");
    expect(after.account.active).toBe(true);
  });

  it("activate-user — no ctx.email → activates without touching verifiedEmail", async () => {
    const { wf, users } = makeWorkflowWithDeps();
    const row = await users.createUser("plain@example.com", undefined, {});
    const ctx = { subject: row.id } as AuthWfCtx;
    await wf.activateUser(ctx);
    const after = await users.getUser(row.id);
    expect(after.account.verifiedEmail).toBeUndefined();
    expect(after.account.active).toBe(true);
  });

  it("notify-new-device — recipient comes from notice.email, never the flow-subject ctx.email", async () => {
    // WHY: the security-notice recipient has its OWN ctx slot (`notice.email`,
    // owned by the credentials/seedChannelState seeding) — deliberately
    // distinct from the flow-subject `ctx.email` recovery/invite/signup use
    // and from `channel.email` (the enrollment ask→verify target). A
    // regression that reads `ctx.email` again would mail security notices to
    // an enrollment-typed (yet unproven) address.
    const wf = makeWorkflow();
    // Flow-subject email alone → no recipient seeded → silently skips.
    await wf.notifyNewDevice({ email: "subject@example.com" } as AuthWfCtx);
    expect(wf.deliveries).toEqual([]);
    await wf.notifyNewDevice({ notice: { email: "inbox@example.com" } } as AuthWfCtx);
    expect(wf.deliveries).toEqual([
      expect.objectContaining({
        kind: "new-device-notice",
        channel: "email",
        recipient: "inbox@example.com",
      }),
    ]);
  });

  it("pincode-send — stashes the ACTUAL delivery target on ctx.otp (every branch, replaces the recovery-only postReset stash)", async () => {
    // WHY: `ctx.otp.deliveredTo`/`deliveredChannel` is the uniform inbox-proof
    // input `pincode-check` consumes (`users.setVerifiedEmail`) — for login
    // email-MFA challenges AND recovery, not just recovery as before. It must
    // record what the code was actually DELIVERED to (recovery M2 may differ
    // from the typed identifier), and it lives on server-only `ctx.otp` so an
    // unmasked address never rides the wire-passed `pincode` group.
    // Recovery/signup branch (no ctx.mfa.method): the typed identifier.
    const wf = makeWorkflow();
    const recoveryCtx = { email: "typed@example.com" } as AuthWfCtx;
    await wf.pincodeSend(recoveryCtx);
    expect(recoveryCtx.otp?.deliveredTo).toBe("typed@example.com");
    expect(recoveryCtx.otp?.deliveredChannel).toBe("email");
    // The old recovery-only stash is gone — nothing writes postReset here.
    expect(recoveryCtx.postReset).toBeUndefined();
    expect(wf.deliveries).toEqual([
      expect.objectContaining({ kind: "recovery-pincode", recipient: "typed@example.com" }),
    ]);

    // Login MFA email-challenge branch: the enrolled method's RAW value.
    const { wf: mfaWf, users } = makeWorkflowWithDeps();
    const row = await users.createUser("bob@example.com", undefined, {});
    await users.addMfaMethod(row.id, { name: "email", value: "mfa@example.com", confirmed: true });
    const mfaCtx = {
      subject: row.id,
      mfa: {
        method: "email",
        enrolledMethods: [{ kind: "email", methodName: "email", masked: "m***", isDefault: true }],
      },
    } as AuthWfCtx;
    await mfaWf.pincodeSend(mfaCtx);
    expect(mfaCtx.otp?.deliveredTo).toBe("mfa@example.com");
    expect(mfaCtx.otp?.deliveredChannel).toBe("email");
    // NOTE: the consuming half (`pincode-check` → `users.setVerifiedEmail`
    // when deliveredChannel === "email") and `verify/email`'s notice.email
    // refresh both sit behind wf composables (`useAtscriptWfPublic`), so
    // they're covered integration-level by the Playwright suite, not here.
  });

  it("signup — the reused activate-user step stamps verifiedEmail after signup-create-user (pre-create OTP proof)", async () => {
    const { wf, users } = makeWorkflowWithDeps();
    const ctx = { email: "fresh@example.com", otp: { verified: true } } as AuthWfCtx;
    await wf.signupCreateUser(ctx);
    const created = (await users.findByHandle("fresh@example.com"))!;
    expect(ctx.subject).toBe(created.id);
    expect(ctx.newPasswordRequired).toBe(true);
    // The capture happens at activate-user (shared with invite), not at create.
    expect(created.account.verifiedEmail).toBeUndefined();
    await wf.activateUser(ctx);
    const after = await users.getUser(created.id);
    expect(after.account.verifiedEmail).toBe("fresh@example.com");
  });
});

// ───────────────────────────────────────────────────────────────────────────
// 4. Schema integrity
// WHY: `@WorkflowSchema` arrays reference step IDs by string. A typo
// (e.g. `"prepare-mfa "` with trailing space) silently makes the engine
// no-op that step. The compiler can't catch this — we walk the prototype
// metadata to confirm every referenced ID resolves to a real `@Step`.
// ───────────────────────────────────────────────────────────────────────────

interface SchemaNode {
  id?: string;
  steps?: SchemaNode[];
}

function collectStepIds(schema: SchemaNode[] | undefined): Set<string> {
  const ids = new Set<string>();
  function walk(nodes: SchemaNode[] | undefined): void {
    if (!nodes) return;
    for (const node of nodes) {
      if (typeof node.id === "string") ids.add(node.id);
      if (Array.isArray(node.steps)) walk(node.steps);
    }
  }
  walk(schema);
  return ids;
}

function readSchemaFor(method: string): SchemaNode[] {
  const meta = getMoostMate().read(AuthWorkflow.prototype as object, method) as
    | { wfSchema?: SchemaNode[] }
    | undefined;
  if (!meta?.wfSchema) throw new Error(`No wfSchema metadata on ${method}`);
  return meta.wfSchema;
}

function collectStepIdsFromHandlers(): Set<string> {
  const mate = getMoostMate();
  const proto = AuthWorkflow.prototype as object;
  const propNames = Object.getOwnPropertyNames(proto);
  const ids = new Set<string>();
  for (const name of propNames) {
    if (name === "constructor") continue;
    const meta = mate.read(proto, name) as
      | { handlers?: { path: string; type: string }[] }
      | undefined;
    const handlers = meta?.handlers ?? [];
    for (const h of handlers) {
      if (h.type === "WF_STEP") ids.add(h.path);
    }
  }
  return ids;
}

describe("AuthWorkflow schema integrity", () => {
  // The route param syntax used by ask/verify steps — the schema references
  // `ask/email` / `verify/phone` (concrete) while the @Step IDs declare the
  // generic `ask/:channel(email|phone)` / `verify/:channel(email|phone)`
  // patterns. The wf engine matches via the param syntax, so we expand the
  // declared step IDs into their concrete variants for comparison.
  const CONCRETE_FROM_PARAMETERIZED: Record<string, string[]> = {
    "ask/:channel(email|phone)": ["ask/email", "ask/phone"],
    "verify/:channel(email|phone)": ["verify/email", "verify/phone"],
  };

  function expandStepIds(declared: Set<string>): Set<string> {
    const out = new Set<string>();
    for (const id of declared) {
      const expanded = CONCRETE_FROM_PARAMETERIZED[id];
      if (expanded) for (const v of expanded) out.add(v);
      else out.add(id);
    }
    return out;
  }

  it.each([
    ["loginFlow"],
    ["inviteFlow"],
    ["recoveryFlow"],
    ["changePasswordFlow"],
    ["addMfaFlow"],
    ["signupFlow"],
  ])("every step id referenced in %s resolves to a registered @Step", (method: string) => {
    const schema = readSchemaFor(method);
    const referenced = collectStepIds(schema);
    const declared = expandStepIds(collectStepIdsFromHandlers());

    const missing = [...referenced].filter((id) => !declared.has(id));
    // WHY: a typo (or a step renamed in source but not in the schema array)
    // would silently no-op at runtime. Failing loud here is the contract.
    expect(missing).toEqual([]);
    // Sanity: at least one id resolved — guards against a regression where
    // the schema-read fallback returned `[]` and the test "passed" trivially.
    expect(referenced.size).toBeGreaterThan(0);
  });

  it("declares six @Workflow methods (login, invite, recover, change-password, signup, add-mfa)", () => {
    const mate = getMoostMate();
    const proto = AuthWorkflow.prototype as object;
    const flows: { method: string; path: string }[] = [];
    for (const name of Object.getOwnPropertyNames(proto)) {
      if (name === "constructor") continue;
      const meta = mate.read(proto, name) as
        | { handlers?: { path: string; type: string }[] }
        | undefined;
      for (const h of meta?.handlers ?? []) {
        if (h.type === "WF_FLOW") flows.push({ method: name, path: h.path });
      }
    }
    // WHY: these flow paths are the canonical wf-id suffixes the controller
    // mounts at /auth/<path>/flow. Renaming or losing one would break the
    // public REST surface.
    expect(flows.map((f) => f.path).toSorted()).toEqual([
      "auth/add-mfa/flow",
      "auth/change-password/flow",
      "auth/invite/start",
      "auth/login/flow",
      "auth/recovery/flow",
      "auth/signup/flow",
    ]);
  });
});

// ───────────────────────────────────────────────────────────────────────────
// Device recognition — humanizeUserAgent + the notify-new-device gate flip.
// WHY: the gate moved from "no valid trust cookie" (`!!ctx.trust?.newDevice`)
// to "not recognized" (`!ctx.trust?.recognized`) so users who decline
// remember-me — or whose strict trust cookie expired / failed IP binding —
// stop getting the "new sign-in" email on every login. These tests pin the
// gate's source of truth (the schema node itself) and the UA label helper
// that names seen-device records.
// ───────────────────────────────────────────────────────────────────────────

describe("humanizeUserAgent", () => {
  it.each([
    [
      "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
      "Safari on macOS",
    ],
    [
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
      "Chrome on Windows",
    ],
    // Edge ships a `Chrome/` token — the `Edg` check must win.
    [
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
      "Edge on Windows",
    ],
    ["Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0", "Firefox on Linux"],
    // iPhone UAs carry `like Mac OS X` — the iOS check must win over macOS.
    [
      "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
      "Safari on iOS",
    ],
  ])("maps %s", (ua: string, expected: string) => {
    expect(humanizeUserAgent(ua)).toBe(expected);
  });

  it("returns undefined for empty input and degrades to one side when only one is detected", () => {
    expect(humanizeUserAgent(undefined)).toBeUndefined();
    expect(humanizeUserAgent("")).toBeUndefined();
    expect(humanizeUserAgent("some-unknown-bot/1.0")).toBeUndefined();
    // Only a browser token → just the browser; only an OS token → just the OS.
    expect(humanizeUserAgent("Firefox/125.0")).toBe("Firefox");
    expect(humanizeUserAgent("something (Windows NT 10.0)")).toBe("Windows");
  });
});

/** Find the schema node with the given id, recursing into nested `steps`. */
function findNode(nodes: SchemaNode[] | undefined, id: string): SchemaNode | undefined {
  for (const n of nodes ?? []) {
    if (n.id === id) return n;
    const nested = findNode(n.steps, id);
    if (nested) return nested;
  }
  return undefined;
}

describe("Device recognition — notify-new-device gate (login schema)", () => {
  const loginSchema = readSchemaFor("loginFlow");
  const notify = findNode(loginSchema, "notify-new-device")!;

  it("gates on NOT-recognized, not on trust.newDevice", () => {
    // Partial ctx samples — `finalize.redirect` is irrelevant to the gate.
    const base = { isFirstLogin: false, finalize: { notifyNewDevice: true } } as AuthWfCtx;
    // Recognized arrival → suppressed.
    expect(evalCondition(notify, { ...base, trust: { recognized: true } })).toBe(false);
    // Unrecognized arrival (empty trust state) → notify.
    expect(evalCondition(notify, { ...base, trust: {} })).toBe(true);
    // Recognition WINS over trust's newDevice flag — a declined remember-me
    // (newDevice stays true forever) must not re-trigger the email once the
    // device is recognized.
    expect(evalCondition(notify, { ...base, trust: { newDevice: true, recognized: true } })).toBe(
      false,
    );
    // Existing gates still apply: first login + policy off both suppress.
    expect(evalCondition(notify, { ...base, isFirstLogin: true, trust: {} })).toBe(false);
    expect(
      evalCondition(notify, {
        isFirstLogin: false,
        finalize: { notifyNewDevice: false },
        trust: {},
      } as AuthWfCtx),
    ).toBe(false);
  });

  it("device-recognition runs inside the non-authz finalize subflow, before issue", () => {
    // WHY: the recognition token must be stamped onto ctx BEFORE `issue`
    // builds the finish-envelope cookie map, and the step must be
    // unconditioned (the body self-gates on subject + configured secret).
    const finalize = (loginSchema ?? []).find(
      (n) => !n.id && Array.isArray(n.steps) && n.steps.some((s) => s.id === "issue"),
    )!;
    const ids = (finalize.steps ?? []).map((s) => s.id);
    expect(ids.indexOf("device-recognition")).toBeGreaterThanOrEqual(0);
    expect(ids.indexOf("device-recognition")).toBeLessThan(ids.indexOf("issue"));
    const node = findNode(finalize.steps, "device-recognition")!;
    expect((node as { condition?: unknown }).condition).toBeUndefined();
  });
});

// ───────────────────────────────────────────────────────────────────────────
// Manage-MFA (WF-MANAGE-MFA) — the unit-testable surface of the add/change/
// remove flow. Full-flow behaviour (step-up challenge, replace-no-strand,
// remove gating, garbage-address rejection, QR-before-code) is exercised
// end-to-end by the Playwright suite; here we pin the pure resolvers/helpers
// and the shared-schema shape that drives that behaviour.
// ───────────────────────────────────────────────────────────────────────────

describe("Manage-MFA resolvers + helpers (WF-MANAGE-MFA)", () => {
  it("resolveLockedMfaTransports defaults to none locked", async () => {
    const wf = makeWorkflow();
    expect(await settle(wf.exposeLockedMfaTransports({ subject: "u1" }))).toEqual([]);
  });

  it("validateMfaAddress rejects garbage and accepts well-formed values per transport", () => {
    const wf = makeWorkflow();
    // email branch — the finding-#2 bug ("blbalba" used to pass).
    expect(wf.exposeValidateMfaAddress("email", "blbalba")).toBeTruthy();
    expect(wf.exposeValidateMfaAddress("email", "alice@example.com")).toBeUndefined();
    expect(wf.exposeValidateMfaAddress("email", "")).toBeTruthy();
    // sms branch — permissive E.164-ish; punctuation tolerated, letters not.
    expect(wf.exposeValidateMfaAddress("sms", "blbalba")).toBeTruthy();
    expect(wf.exposeValidateMfaAddress("sms", "+1 (555) 555-0100")).toBeUndefined();
    expect(wf.exposeValidateMfaAddress("sms", "123")).toBeTruthy(); // too short
    // totp carries no deliverable address.
    expect(wf.exposeValidateMfaAddress("totp", "anything")).toBeUndefined();
  });

  it("normalizeMfaAddress strips SMS punctuation and trims email", () => {
    const wf = makeWorkflow();
    expect(wf.exposeNormalizeMfaAddress("sms", " +1 (555) 555-0100 ")).toBe("+15555550100");
    expect(wf.exposeNormalizeMfaAddress("email", "  Alice@Example.com ")).toBe("Alice@Example.com");
  });
});

describe("Manage-MFA shared-schema shape (WF-MANAGE-MFA)", () => {
  const cond = evalCondition;

  it("enrollTrioSteps puts the TOTP QR step BEFORE code entry", () => {
    const ids = enrollTrioSteps.map((s) => (s as { id?: string }).id);
    const qrIdx = ids.indexOf("enroll-totp-qr");
    const confirmIdx = ids.indexOf("enroll-confirm");
    expect(qrIdx).toBeGreaterThanOrEqual(0);
    expect(confirmIdx).toBeGreaterThanOrEqual(0);
    expect(qrIdx).toBeLessThan(confirmIdx);
  });

  it("the TOTP QR step gates on totp + !qrSeen; confirm waits for qrSeen (TOTP)", () => {
    const qr = enrollTrioSteps.find((s) => (s as { id?: string }).id === "enroll-totp-qr")!;
    const confirm = enrollTrioSteps.find((s) => (s as { id?: string }).id === "enroll-confirm")!;
    // QR shows for an un-scanned totp enrolment, hides once scanned.
    expect(cond(qr, { mfaEnroll: { method: "totp" } })).toBe(true);
    expect(cond(qr, { mfaEnroll: { method: "totp", qrSeen: true } })).toBe(false);
    expect(cond(qr, { mfaEnroll: { method: "email", address: "a@b.co" } })).toBe(false);
    // Confirm holds back for TOTP until the QR has been seen.
    expect(cond(confirm, { mfaEnroll: { method: "totp" } })).toBe(false);
    expect(cond(confirm, { mfaEnroll: { method: "totp", qrSeen: true } })).toBe(true);
    // sms/email confirm still gates on address (unchanged).
    expect(cond(confirm, { mfaEnroll: { method: "email", address: "a@b.co" } })).toBe(true);
  });

  it("mfaStepUpLoop reuses the challenge arm but excludes trusted-device + risk-step-up", () => {
    const ids = collectSchemaStepIds(mfaStepUpLoop);
    // Challenge an EXISTING factor.
    expect(ids).toContain("load-enrolled-mfa-methods");
    expect(ids).toContain("select-mfa-method");
    expect(ids).toContain("totp-check");
    // SECURITY: a trusted device must NOT bypass step-up, and no risk re-arm.
    expect(ids).not.toContain("check-trusted-device");
    expect(ids).not.toContain("risk-step-up");
    // And it must NOT enrol (no new-factor steps in the step-up arm).
    expect(ids).not.toContain("enroll-pick-method");
    expect(ids).not.toContain("enroll-confirm");
  });

  it("mfaStepUpLoop while breaks on abort (no guardless infinite spin on cancel/exit)", () => {
    const loop = mfaStepUpLoop[0] as { while?: (ctx: AuthWfCtx) => boolean };
    expect(typeof loop.while).toBe("function");
    // Keep challenging until verified…
    expect(loop.while!({})).toBe(true);
    expect(loop.while!({ otp: { verified: true } })).toBe(false);
    // …but a cancel/exit (`ctx.aborted`) must terminate the loop, NOT spin the
    // engine's guardless inner loop forever. The paired `{ break: !!aborted }`
    // in addMfaFlow then routes the aborted step-up to the cancelled terminal.
    expect(loop.while!({ aborted: true })).toBe(false);
  });

  it("addMfaFlow routes step-up by stepUpMode (MFA challenge vs password fallback)", () => {
    const meta = getMoostMate().read(AuthWorkflow.prototype as object, "addMfaFlow") as
      | { wfSchema?: Array<Record<string, unknown>> }
      | undefined;
    const schema = meta?.wfSchema ?? [];
    // The MFA-challenge node carries the shared `mfaStepUpLoop` by reference; the
    // password fallback is a single step with id `manage-password-reauth`.
    const mfaNode = schema.find((n) => n.steps === mfaStepUpLoop) as
      | { condition?: (c: AuthWfCtx) => boolean }
      | undefined;
    const pwNode = schema.find((n) => n.id === "manage-password-reauth") as
      | { condition?: (c: AuthWfCtx) => boolean }
      | undefined;
    expect(typeof mfaNode?.condition).toBe("function");
    expect(typeof pwNode?.condition).toBe("function");
    const challengeable: AuthWfCtx = { addMfa: { stepUpRequired: true, stepUpMode: "mfa" } };
    const orphaned: AuthWfCtx = { addMfa: { stepUpRequired: true, stepUpMode: "password" } };
    // MFA loop only for a challengeable factor; password fallback only for the
    // orphaned (non-challengeable) case — mutually exclusive.
    expect(mfaNode!.condition!(challengeable)).toBe(true);
    expect(mfaNode!.condition!(orphaned)).toBe(false);
    expect(pwNode!.condition!(orphaned)).toBe(true);
    expect(pwNode!.condition!(challengeable)).toBe(false);
    // Password fallback is a one-shot: once verified it must not re-run.
    expect(
      pwNode!.condition!({
        addMfa: { stepUpRequired: true, stepUpMode: "password" },
        otp: { verified: true },
      }),
    ).toBe(false);
    // A zero-MFA user (no step-up) takes neither path.
    expect(mfaNode!.condition!({ addMfa: {} })).toBe(false);
    expect(pwNode!.condition!({ addMfa: {} })).toBe(false);
  });
});

// ───────────────────────────────────────────────────────────────────────────
// Manage-MFA strand-safety (WF-MANAGE-MFA) — regression for the
// `useDifferentMethod`-in-manage strand/lockout. The manage forms HIDE
// `useDifferentMethod`, but it stays in their DECLARED action whitelist, so a
// crafted resume can still send it. Under write-on-confirm the enrol trio never
// touches the user record until the new value verifies, so an in-progress
// add/change has persisted NOTHING — a manage `cancel`/`useDifferentMethod` only
// clears scratch + sets `aborted`, and can never strand or clobber a live factor
// by construction. handleEnrollExit must route BOTH through that abort (never a
// store mutation).
// ───────────────────────────────────────────────────────────────────────────
describe("Manage-MFA strand-safety (WF-MANAGE-MFA)", () => {
  it.each(["cancel", "useDifferentMethod"] as const)(
    "manage REPLACE of sms: %s leaves the live confirmed factor + default untouched",
    async (action) => {
      const { users, auth, consentStore } = makeDeps();
      const wf = new TestableAuthWorkflow({}, users, auth, consentStore);
      const { id } = await users.createUser("strand-sms", "pw");
      await users.addMfaMethod(id, { name: "sms", value: "+15555550001", confirmed: true });
      await users.setDefaultMfaMethod(id, "sms");
      const ctx: AuthWfCtx = {
        subject: id,
        mfaEnroll: { mode: "manage", method: "sms", address: "+15555559999" },
        addMfa: { action: "replace", target: "sms" },
      };
      expect(wf.exposeHandleEnrollExit(ctx, action)).toBe(true);
      expect(ctx.aborted).toBe(true);
      const after = await users.getUser(id);
      expect(after.mfa.methods.find((m) => m.name === "sms")).toMatchObject({
        value: "+15555550001",
        confirmed: true,
      });
      expect(after.mfa.defaultMethod).toBe("sms"); // not blanked
      expect(ctx.mfaEnroll?.method).toBeUndefined(); // scratch cleared
    },
  );

  it("manage REPLACE of totp: useDifferentMethod never clobbers the live secret", async () => {
    const { users, auth, consentStore } = makeDeps();
    const wf = new TestableAuthWorkflow({}, users, auth, consentStore);
    const { id } = await users.createUser("strand-totp", "pw");
    await users.addMfaMethod(id, { name: "totp", value: "LIVE-SECRET", confirmed: true });
    await users.setDefaultMfaMethod(id, "totp");
    // write-on-confirm: the new secret only lives in wf-state (m.secret); the
    // store still holds the LIVE confirmed secret, never clobbered.
    const ctx: AuthWfCtx = {
      subject: id,
      mfaEnroll: { mode: "manage", method: "totp", secret: "STAGED-NEW-SECRET" },
      addMfa: { action: "replace", target: "totp" },
    };
    expect(wf.exposeHandleEnrollExit(ctx, "useDifferentMethod")).toBe(true);
    expect(ctx.aborted).toBe(true);
    const after = await users.getUser(id);
    expect(after.mfa.methods.find((m) => m.name === "totp")).toMatchObject({
      value: "LIVE-SECRET",
      confirmed: true,
    });
    expect(after.mfa.defaultMethod).toBe("totp");
  });

  it("manage ADD: cancel leaves no partial row and keeps the existing factor", async () => {
    const { users, auth, consentStore } = makeDeps();
    const wf = new TestableAuthWorkflow({}, users, auth, consentStore);
    const { id } = await users.createUser("add-drop", "pw");
    await users.addMfaMethod(id, { name: "email", value: "a@b.co", confirmed: true });
    await users.setDefaultMfaMethod(id, "email");
    // staged-but-unwritten add of sms — no store row exists pre-confirm.
    const ctx: AuthWfCtx = {
      subject: id,
      mfaEnroll: { mode: "manage", method: "sms", address: "+15555550002" },
      addMfa: { action: "add", target: "sms" },
    };
    expect(wf.exposeHandleEnrollExit(ctx, "cancel")).toBe(true);
    expect(ctx.aborted).toBe(true);
    const after = await users.getUser(id);
    expect(after.mfa.methods.find((m) => m.name === "sms")).toBeUndefined();
    expect(after.mfa.methods.find((m) => m.name === "email")).toMatchObject({ confirmed: true });
    expect(after.mfa.defaultMethod).toBe("email");
  });
});

describe("authorize-consent public projection (AUTH-SERVER.md §6)", () => {
  it("projects only the display fields of ctx.authz — handle + approval stay server-only", () => {
    const { users, auth, consentStore } = makeDeps();
    const wf = new TestableAuthWorkflow({}, users, auth, consentStore);
    const ctx: AuthWfCtx = {
      subject: "u-1",
      authz: {
        handle: "h-secret",
        clientName: "svc",
        scope: "openid email",
        redirectHost: "svc.example",
        approved: true,
      },
    };
    const pub = wf.exposePopulatePublic(ctx);
    const projected = pub?.authz as Record<string, unknown> | undefined;
    // Display copy reaches the consent form — incl. the validated redirect host
    // (the trustworthy identity next to the registrant-chosen clientName) …
    expect(projected).toEqual({
      clientName: "svc",
      scope: "openid email",
      redirectHost: "svc.example",
    });
    // … but the opaque handle and the approval gate must NEVER ride the wire
    // (the exact `toEqual` above already forbids extra keys; asserted explicitly
    // here as a regression guard against the whitelist widening).
    expect(projected?.handle).toBeUndefined();
    expect(projected?.approved).toBeUndefined();
  });

  it("omits ctx.public.authz entirely when no display fields are staged yet", () => {
    const { users, auth, consentStore } = makeDeps();
    const wf = new TestableAuthWorkflow({}, users, auth, consentStore);
    // init-login sets only the handle; authz-consent stages clientName/scope later.
    const pub = wf.exposePopulatePublic({ subject: "u-1", authz: { handle: "h" } });
    expect(pub?.authz).toBeUndefined();
  });
});

describe("Enroll-send dispatch (pre-seeded address must still get exactly one code)", () => {
  const cond = evalCondition;
  const sendNode = enrollTrioSteps.find((s) => (s as { id?: string }).id === "enroll-send")!;
  const addressNode = enrollTrioSteps.find((s) => (s as { id?: string }).id === "enroll-address")!;

  it("schema: enroll-send sits between collection and confirm as the trio's only dispatch", () => {
    const ids = enrollTrioSteps.map((s) => (s as { id?: string }).id);
    expect(ids.indexOf("enroll-send")).toBeGreaterThan(ids.indexOf("enroll-address"));
    expect(ids.indexOf("enroll-send")).toBeLessThan(ids.indexOf("enroll-confirm"));
  });

  it("schema: a PRE-SEEDED address skips collection but NOT the dispatch (the field-tested bug)", () => {
    // Consumer pre-staged the invited email in `resolveAccept` → `enroll-address`
    // self-skips (intended)…
    const preSeeded: AuthWfCtx = { mfaEnroll: { method: "email", address: "a@x.co" } };
    expect(cond(addressNode, preSeeded)).toBe(false);
    // …but the dispatch must STILL fire — before the fix it was welded to the
    // skipped collect step, pausing the user on a code form with no code sent.
    expect(cond(sendNode, preSeeded)).toBe(true);
  });

  it("schema: enroll-send is send-once and never fires for totp / done / pre-confirmed", () => {
    // `!ctx.pin` — a re-pause (wrong code typed, resume) must not re-send.
    expect(cond(sendNode, { mfaEnroll: { method: "email", address: "a@x.co" }, pin: "h" })).toBe(
      false,
    );
    // sms is a dispatch transport too; totp has nothing to send.
    expect(cond(sendNode, { mfaEnroll: { method: "sms", address: "+15550100" } })).toBe(true);
    expect(cond(sendNode, { mfaEnroll: { method: "totp", address: "x" } })).toBe(false);
    // After confirm (`done`) and for a vouched address (`preConfirmed`) nothing sends.
    expect(cond(sendNode, { mfaEnroll: { method: "email", address: "a@x.co", done: true } })).toBe(
      false,
    );
    expect(
      cond(sendNode, { mfaEnroll: { method: "email", address: "a@x.co", preConfirmed: true } }),
    ).toBe(false);
    // No address staged yet (picker path, enroll-address about to pause) → not yet.
    expect(cond(sendNode, { mfaEnroll: { method: "email" } })).toBe(false);
  });

  it("enrollSend mints + delivers exactly one enroll-pincode to the staged address", async () => {
    const wf = makeWorkflow();
    const ctx: AuthWfCtx = { subject: "u1", mfaEnroll: { method: "email", address: "a@x.co" } };
    await wf.enrollSend(ctx);
    expect(wf.deliveries).toEqual([
      expect.objectContaining({ kind: "enroll-pincode", channel: "email", recipient: "a@x.co" }),
    ]);
    // The pin + resend cooldown + form hint are armed exactly like the
    // collected-address path used to arm them inside `enroll-address`.
    expect(typeof ctx.pin).toBe("string");
    expect(ctx.pincode?.resendAllowedAt).toBeGreaterThan(Date.now() - 1);
    expect(ctx.pincode?.codeLength).toBeGreaterThan(0);
    expect(ctx.mfaEnroll?.preConfirmed).toBeUndefined();
  });

  it("enrollAddress STAGES only — nothing dispatches from the collect step", async () => {
    // Regression guard for the single-dispatch-site contract: if a send is
    // re-welded into the collect step, the collected path would mint here and
    // the `!ctx.pin` schema gate would then mask the drift by suppressing
    // `enroll-send`. Drive the step with a stubbed form round-trip (a unit
    // test has no wf event context) and assert it ONLY stages the address —
    // the sole dispatch is `enrollSend`'s, asserted above.
    class CollectOnlyWorkflow extends TestableAuthWorkflow {
      protected override useAtscriptWfPublic(
        _ctx: AuthWfCtx,
        _type: Parameters<typeof useAtscriptWf>[0],
      ): ReturnType<typeof useAtscriptWf> {
        return {
          resolveAction: () => undefined,
          resolveInput: () => ({ address: "a@x.co" }),
        } as unknown as ReturnType<typeof useAtscriptWf>;
      }
    }
    const { users, auth, consentStore } = makeDeps();
    const wf = new CollectOnlyWorkflow({}, users, auth, consentStore);
    const ctx: AuthWfCtx = { subject: "u1", mfaEnroll: { method: "email" } };
    await wf.enrollAddress(ctx);
    expect(ctx.mfaEnroll?.address).toBe("a@x.co");
    expect(wf.deliveries).toEqual([]);
    expect(ctx.pin).toBeUndefined();
    expect(ctx.pincode).toBeUndefined();
  });
});

describe("resolveEnrollPreConfirmed (verified-by-construction enrolment)", () => {
  it("default is false for every transport — every enrolment proves its address", async () => {
    const wf = makeWorkflow();
    const ctx: AuthWfCtx = { accept: {}, email: "a@x.co" };
    expect(await settle(wf.exposeEnrollPreConfirmed(ctx, "email", "a@x.co"))).toBe(false);
    expect(await settle(wf.exposeEnrollPreConfirmed(ctx, "sms", "+15550100"))).toBe(false);
  });

  it("vouched address: enroll-send skips the dispatch and enroll-confirm writes the factor with NO pause", async () => {
    // The canonical override from the resolver's docs: invite-accept, where the
    // user redeemed a magic link delivered to exactly this address minutes ago.
    class PreConfirmingWorkflow extends TestableAuthWorkflow {
      protected override resolveEnrollPreConfirmed(
        ctx: AuthWfCtx,
        method: MfaTransport,
        address: string,
      ): boolean {
        return !!ctx.accept && method === "email" && address === ctx.email;
      }
    }
    const users = new UserService(new UserStoreMemory());
    const auth = new AuthCredential({
      store: new CredentialStoreMemory(),
      method: "token",
      accessTtl: 60_000,
    });
    const wf = new PreConfirmingWorkflow({}, users, auth, new ConsentStore());
    const row = await users.createUser("invitee@x.co", undefined, {});
    const ctx: AuthWfCtx = {
      subject: row.id,
      accept: {},
      email: "invitee@x.co",
      mfaEnroll: { method: "email", address: "invitee@x.co", mode: "required" },
    };

    await wf.enrollSend(ctx);
    // Nothing dispatched, no pin minted — the proof transfers from the magic link.
    expect(wf.deliveries).toEqual([]);
    expect(ctx.pin).toBeUndefined();
    expect(ctx.mfaEnroll?.preConfirmed).toBe(true);

    // enroll-confirm then runs its write-on-confirm tail in the SAME engine
    // pass — confirmed factor + verifiedEmail + default method + loop exit —
    // without ever building the code-entry form.
    await wf.enrollConfirm(ctx);
    const after = await users.getUser(row.id);
    expect(after.mfa.methods).toEqual([
      expect.objectContaining({ name: "email", value: "invitee@x.co", confirmed: true }),
    ]);
    expect(after.mfa.defaultMethod).toBe("email");
    expect(after.account.verifiedEmail).toBe("invitee@x.co");
    expect(ctx.mfaEnroll?.done).toBe(true);
    expect(ctx.otp?.verified).toBe(true);
  });

  it("a DIFFERENT address than vouched still goes through the pincode round-trip", async () => {
    // The equality check in the recommended override is load-bearing: the
    // magic-link proof transfers ONLY to the address it was delivered to.
    class PreConfirmingWorkflow extends TestableAuthWorkflow {
      protected override resolveEnrollPreConfirmed(
        ctx: AuthWfCtx,
        method: MfaTransport,
        address: string,
      ): boolean {
        return !!ctx.accept && method === "email" && address === ctx.email;
      }
    }
    const { users, auth, consentStore } = makeDeps();
    const wf = new PreConfirmingWorkflow({}, users, auth, consentStore);
    const ctx: AuthWfCtx = {
      subject: "u1",
      accept: {},
      email: "invitee@x.co",
      mfaEnroll: { method: "email", address: "other@x.co" },
    };
    await wf.enrollSend(ctx);
    expect(ctx.mfaEnroll?.preConfirmed).toBeUndefined();
    expect(wf.deliveries).toEqual([
      expect.objectContaining({ kind: "enroll-pincode", recipient: "other@x.co" }),
    ]);
  });

  it("clearEnrollScratch drops preConfirmed — a vouch never outlives its address", () => {
    const wf = makeWorkflow();
    const ctx: AuthWfCtx = {
      mfaEnroll: { method: "email", address: "a@x.co", preConfirmed: true, mode: "optional" },
    };
    // `useDifferentMethod` routes through clearEnrollScratch; a later, freshly
    // typed address must NOT inherit the vouch (it would be written confirmed
    // without any proof).
    wf.exposeHandleEnrollExit(ctx, "useDifferentMethod");
    expect(ctx.mfaEnroll?.preConfirmed).toBeUndefined();
    expect(ctx.mfaEnroll?.address).toBeUndefined();
  });
});

// ───────────────────────────────────────────────────────────────────────────
// Manage-MFA step-up consent (BUG-4 item 1) — opening the manage dialog must
// never dispatch a pincode as a side effect. `manage-stepup-confirm` pauses
// BEFORE `pincode-send`; an explicit `select-2fa` pick counts as consent.
// ───────────────────────────────────────────────────────────────────────────

/**
 * Form-stub workflow for driving pause-style steps without a wf event
 * context: `useAtscriptWfPublic` returns a canned action/input and a
 * `requireInput` that RETURNS its opts (the step then `throw`s that value,
 * which the assertions catch as the pause payload). `formBuilt` counts how
 * many times a step reached for the form at all — the no-pause paths assert
 * it stays 0.
 */
class StubFormWorkflow extends TestableAuthWorkflow {
  public stubAction: string | undefined;
  public stubInput: Record<string, unknown> = {};
  public formBuilt = 0;

  protected override useAtscriptWfPublic(
    _ctx: AuthWfCtx,
    _type: Parameters<typeof useAtscriptWf>[0],
  ): ReturnType<typeof useAtscriptWf> {
    this.formBuilt++;
    return {
      resolveAction: () => this.stubAction,
      resolveInput: () => this.stubInput,
      requireInput: (opts: unknown) => opts,
    } as unknown as ReturnType<typeof useAtscriptWf>;
  }
}

function makeStubFormWorkflow(): { wf: StubFormWorkflow; users: UserService } {
  const { users, auth, consentStore } = makeDeps();
  return { wf: new StubFormWorkflow({}, users, auth, consentStore), users };
}

describe("Manage-MFA step-up consent (manage-stepup-confirm)", () => {
  const cond = evalCondition;
  const loop = mfaStepUpLoop[0] as { steps: Array<Record<string, unknown>> };
  const confirmNode = loop.steps.find((s) => s.id === "manage-stepup-confirm")!;

  it("schema: sits between method selection and the pincode dispatch", () => {
    const ids = collectSchemaStepIds(mfaStepUpLoop);
    const confirmIdx = ids.indexOf("manage-stepup-confirm");
    expect(confirmIdx).toBeGreaterThan(ids.indexOf("select-2fa"));
    expect(confirmIdx).toBeLessThan(ids.indexOf("pincode-send"));
  });

  it("schema: fires only for an unconsented sms/email step-up with no code in flight", () => {
    // The auto-picked single-factor path — the zero-click dispatch the pause exists for.
    expect(cond(confirmNode, { mfa: { method: "email" }, addMfa: {} })).toBe(true);
    expect(cond(confirmNode, { mfa: { method: "sms" }, addMfa: {} })).toBe(true);
    // TOTP dispatches nothing — no consent to collect.
    expect(cond(confirmNode, { mfa: { method: "totp" }, addMfa: {} })).toBe(false);
    // Consent already given (Continue submit or a select-2fa pick).
    expect(cond(confirmNode, { mfa: { method: "email" }, addMfa: { stepUpConfirmed: true } })).toBe(
      false,
    );
    // Code already in flight (re-pause on a wrong code) — never re-ask.
    expect(cond(confirmNode, { mfa: { method: "email" }, addMfa: {}, pin: "123456" })).toBe(false);
    // Step-up already verified.
    expect(
      cond(confirmNode, { mfa: { method: "email" }, addMfa: {}, otp: { verified: true } }),
    ).toBe(false);
  });

  it("schema: a consent-form cancel breaks BEFORE the pincode pair (declined code never sends)", () => {
    // `cancel` sets `aborted` with `mfa.method` still bound — the very next
    // node must be a `break` that fires on it, or the pair would dispatch the
    // code the user just declined in the same engine pass.
    const confirmIdx = loop.steps.indexOf(confirmNode);
    const next = loop.steps[confirmIdx + 1] as { break?: (ctx: AuthWfCtx) => boolean };
    expect(typeof next.break).toBe("function");
    expect(next.break!({ aborted: true })).toBe(true);
    expect(next.break!({})).toBe(false);
  });

  it("default pauses on the notice; Continue consents and falls through to the dispatch", async () => {
    const { wf } = makeStubFormWorkflow();
    // Continue submit = no action, empty input — the step resumes past
    // resolveInput and records consent. (The stub collapses pause + resume
    // into one call; the pause itself is the resolveInput contract.)
    const ctx: AuthWfCtx = { subject: "u1", mfa: { method: "email" }, addMfa: {} };
    await wf.manageStepUpConfirm(ctx);
    expect(wf.formBuilt).toBe(1);
    expect(ctx.addMfa?.stepUpConfirmed).toBe(true);
    expect(ctx.aborted).toBeUndefined();
    // Crucially: the consent step itself dispatched NOTHING.
    expect(wf.deliveries).toEqual([]);
    expect(ctx.pin).toBeUndefined();
  });

  it("cancel aborts with nothing dispatched and no consent recorded", async () => {
    const { wf } = makeStubFormWorkflow();
    wf.stubAction = "cancel";
    const ctx: AuthWfCtx = { subject: "u1", mfa: { method: "email" }, addMfa: {} };
    await wf.manageStepUpConfirm(ctx);
    expect(ctx.aborted).toBe(true);
    expect(ctx.addMfa?.stepUpConfirmed).toBeUndefined();
    expect(wf.deliveries).toEqual([]);
  });

  it("useDifferentMethod re-opens the picker (ignoreDefault + method cleared)", async () => {
    const { wf } = makeStubFormWorkflow();
    wf.stubAction = "useDifferentMethod";
    const ctx: AuthWfCtx = { subject: "u1", mfa: { method: "email" }, addMfa: {} };
    await wf.manageStepUpConfirm(ctx);
    expect(ctx.mfa?.method).toBeUndefined();
    expect(ctx.mfa?.ignoreDefault).toBe(true);
    expect(ctx.addMfa?.stepUpConfirmed).toBeUndefined();
    expect(ctx.aborted).toBeUndefined();
  });

  it("resolveStepUpConfirmBeforeSend=false opts out — consent auto-marked, no form built", async () => {
    class ZeroClickWorkflow extends StubFormWorkflow {
      protected override resolveStepUpConfirmBeforeSend(_ctx: AuthWfCtx): Promise<boolean> {
        return Promise.resolve(false); // async override — the step must await it
      }
    }
    const { users, auth, consentStore } = makeDeps();
    const wf = new ZeroClickWorkflow({}, users, auth, consentStore);
    const ctx: AuthWfCtx = { subject: "u1", mfa: { method: "email" }, addMfa: {} };
    await wf.manageStepUpConfirm(ctx);
    expect(wf.formBuilt).toBe(0);
    expect(ctx.addMfa?.stepUpConfirmed).toBe(true);
  });

  it("an explicit select-2fa pick records consent (no double pause)", async () => {
    const { wf } = makeStubFormWorkflow();
    wf.stubInput = { methodName: "email" };
    const ctx: AuthWfCtx = {
      subject: "u1",
      mfa: {
        enrolledMethods: [
          { kind: "email", methodName: "email", masked: "a***@x.co", isDefault: true },
          { kind: "totp", methodName: "totp", masked: "", isDefault: false },
        ],
      },
      addMfa: {},
    };
    await wf.select2fa(ctx);
    expect(ctx.mfa?.method).toBe("email");
    expect(ctx.addMfa?.stepUpConfirmed).toBe(true);
  });

  it("select-2fa does NOT touch consent on the login flow (no ctx.addMfa)", async () => {
    const { wf } = makeStubFormWorkflow();
    wf.stubInput = { methodName: "email" };
    const ctx: AuthWfCtx = {
      subject: "u1",
      mfa: {
        enrolledMethods: [
          { kind: "email", methodName: "email", masked: "a***@x.co", isDefault: true },
          { kind: "totp", methodName: "totp", masked: "", isDefault: false },
        ],
      },
    };
    await wf.select2fa(ctx);
    expect(ctx.mfa?.method).toBe("email");
    expect(ctx.addMfa).toBeUndefined();
  });
});

// ───────────────────────────────────────────────────────────────────────────
// Remove-last-factor dead-end (BUG-4 item 2) — an operation that can never
// succeed must not be offered, and if it arrives anyway it aborts to the
// finish terminal instead of pausing on a form whose only submit re-throws.
// ───────────────────────────────────────────────────────────────────────────

describe("Manage-MFA remove-last-factor dead-end (removeBlocked + abort-to-finish)", () => {
  const oneEmail = [
    { kind: "email" as const, methodName: "email", masked: "a***", isDefault: true },
  ];
  const emailPlusTotp = [
    { kind: "email" as const, methodName: "email", masked: "a***", isDefault: true },
    { kind: "totp" as const, methodName: "totp", masked: "", isDefault: false },
  ];

  it("manage-menu computes removeBlocked for the last factor under a required policy", async () => {
    const { wf } = makeStubFormWorkflow();
    wf.stubAction = "cancel"; // bail right after the flag is computed
    const ctx: AuthWfCtx = {
      subject: "u1",
      mfa: { enrolledMethods: oneEmail },
      mfaPolicy: { mode: "required", availableTransports: ["email", "totp"], issuer: "x" },
      addMfa: { candidates: ["totp"] },
    };
    await wf.manageMenu(ctx);
    expect(ctx.addMfa?.removeBlocked).toBe(true);
    // …and the projection ships it to the menu form (option filtering + hint).
    expect(wf.exposePopulatePublic(ctx)?.manage?.removeBlocked).toBe(true);
  });

  it("manage-menu leaves removeBlocked unset under optional policy or with >1 factors", async () => {
    const { wf } = makeStubFormWorkflow();
    wf.stubAction = "cancel";
    const optional: AuthWfCtx = {
      subject: "u1",
      mfa: { enrolledMethods: oneEmail },
      mfaPolicy: { mode: "optional", availableTransports: ["email", "totp"], issuer: "x" },
      addMfa: { candidates: ["totp"], removeBlocked: true }, // stale flag must be dropped
    };
    await wf.manageMenu(optional);
    expect(optional.addMfa?.removeBlocked).toBeUndefined();
    const twoFactors: AuthWfCtx = {
      subject: "u1",
      mfa: { enrolledMethods: emailPlusTotp },
      mfaPolicy: { mode: "required", availableTransports: ["email", "totp", "sms"], issuer: "x" },
      addMfa: { candidates: ["sms"] },
    };
    await wf.manageMenu(twoFactors);
    expect(twoFactors.addMfa?.removeBlocked).toBeUndefined();
  });

  it("manage-menu rejects a crafted remove of the blocked factor (option was filtered)", async () => {
    const { wf } = makeStubFormWorkflow();
    wf.stubInput = { operation: "remove:email" };
    const ctx: AuthWfCtx = {
      subject: "u1",
      mfa: { enrolledMethods: oneEmail },
      mfaPolicy: { mode: "required", availableTransports: ["email", "totp"], issuer: "x" },
      addMfa: { candidates: ["totp"] },
    };
    await expect(wf.manageMenu(ctx)).rejects.toMatchObject({
      formMessage: "You must keep at least one two-factor method.",
    });
    expect(ctx.addMfa?.action).toBeUndefined(); // never routed to confirm-remove-mfa
  });

  it("confirm-remove-mfa aborts to the finish terminal for the last required factor (no dead-end form)", async () => {
    const { wf, users } = makeStubFormWorkflow();
    const { id } = await users.createUser("last-factor", "pw");
    await users.addMfaMethod(id, { name: "email", value: "a@x.co", confirmed: true });
    const ctx: AuthWfCtx = {
      subject: id,
      mfa: { enrolledMethods: oneEmail },
      mfaPolicy: { mode: "required", availableTransports: ["email", "totp"], issuer: "x" },
      addMfa: { action: "remove", target: "email" },
    };
    await wf.confirmRemoveMfa(ctx);
    // No pause, no retryable error — straight to the cancelled-with-reason terminal.
    expect(wf.formBuilt).toBe(0);
    expect(ctx.aborted).toBe(true);
    expect(ctx.addMfa?.blocked).toBe("last-required-factor");
    // The factor survives untouched.
    const after = await users.getUser(id);
    expect(after.mfa.methods.find((m) => m.name === "email")).toMatchObject({ confirmed: true });
  });

  it("confirm-remove-mfa aborts likewise for a locked transport", async () => {
    const { wf } = makeStubFormWorkflow();
    const ctx: AuthWfCtx = {
      subject: "u1",
      mfa: { enrolledMethods: emailPlusTotp },
      mfaPolicy: { mode: "required", availableTransports: ["email", "totp"], issuer: "x" },
      addMfa: { action: "remove", target: "email", locked: ["email"] },
    };
    await wf.confirmRemoveMfa(ctx);
    expect(wf.formBuilt).toBe(0);
    expect(ctx.aborted).toBe(true);
    expect(ctx.addMfa?.blocked).toBe("method-locked");
  });

  it("a removable factor still pauses + removes exactly as before", async () => {
    const { wf, users } = makeStubFormWorkflow();
    const { id } = await users.createUser("two-factors", "pw");
    await users.addMfaMethod(id, { name: "email", value: "a@x.co", confirmed: true });
    await users.addMfaMethod(id, { name: "totp", value: "SECRET", confirmed: true });
    const ctx: AuthWfCtx = {
      subject: id,
      mfa: { enrolledMethods: emailPlusTotp },
      mfaPolicy: { mode: "required", availableTransports: ["email", "totp"], issuer: "x" },
      addMfa: { action: "remove", target: "email" },
    };
    await wf.confirmRemoveMfa(ctx);
    expect(ctx.addMfa?.removed).toBe("email");
    expect(ctx.addMfa?.blocked).toBeUndefined();
    const after = await users.getUser(id);
    expect(after.mfa.methods.find((m) => m.name === "email")).toBeUndefined();
    expect(after.mfa.methods.find((m) => m.name === "totp")).toMatchObject({ confirmed: true });
  });

  it("finish-add-mfa maps blocked reasons to specific copy (not the generic cancel)", () => {
    const wf = makeWorkflow();
    const lastFactor = wf.exposeAddMfaFinishEnvelope({
      aborted: true,
      addMfa: { blocked: "last-required-factor", action: "remove", target: "email" },
    });
    expect(lastFactor.data).toMatchObject({ added: false, reason: "last-required-factor" });
    expect(lastFactor.message?.text).toContain("at least one two-factor method");
    const locked = wf.exposeAddMfaFinishEnvelope({
      aborted: true,
      addMfa: { blocked: "method-locked", action: "remove", target: "email" },
    });
    expect(locked.data).toMatchObject({ added: false, reason: "method-locked" });
    // A successful removal still outranks any stale blocked flag…
    const removed = wf.exposeAddMfaFinishEnvelope({ addMfa: { removed: "email" } });
    expect(removed.data).toMatchObject({ removed: true, method: "email" });
    // …and a plain cancel keeps the generic copy.
    const cancelled = wf.exposeAddMfaFinishEnvelope({
      aborted: true,
      addMfa: { stepUpRequired: true },
    });
    expect(cancelled.data).toMatchObject({ added: false, reason: "cancelled" });
  });
});

// ───────────────────────────────────────────────────────────────────────────
// Enrolment address pinning + ctx-first validation (BUG-4 item 3)
// ───────────────────────────────────────────────────────────────────────────

describe("resolveEnrollAddress (pin / restrict the enrolment channel)", () => {
  it("default is 'collect' — the free-text form path is unchanged", async () => {
    const wf = makeWorkflow();
    expect(await settle(wf.exposeEnrollAddress({}, "email"))).toBe("collect");
    expect(await settle(wf.exposeEnrollAddress({}, "sms"))).toBe("collect");
  });

  it("a pinned address is staged (normalized) and the address form never renders", async () => {
    class PinningWorkflow extends StubFormWorkflow {
      protected override resolveEnrollAddress(
        _ctx: AuthWfCtx,
        method: MfaTransport,
      ): Promise<string> {
        // Async on purpose — record-based pins load the account row.
        return Promise.resolve(method === "email" ? "  Staff@Corp.Example " : "collect");
      }
    }
    const { users, auth, consentStore } = makeDeps();
    const wf = new PinningWorkflow({}, users, auth, consentStore);
    const ctx: AuthWfCtx = { subject: "u1", mfaEnroll: { method: "email", mode: "manage" } };
    await wf.enrollAddress(ctx);
    expect(ctx.mfaEnroll?.address).toBe("Staff@Corp.Example");
    expect(wf.formBuilt).toBe(0); // the user is never shown the free-text form
    expect(wf.deliveries).toEqual([]); // dispatch still belongs to enroll-send
  });

  it("a blank pin falls back to collect (consumer bug must not strand the trio)", async () => {
    class BlankPinWorkflow extends StubFormWorkflow {
      protected override resolveEnrollAddress(_ctx: AuthWfCtx, _m: MfaTransport): string {
        return "   ";
      }
    }
    const { users, auth, consentStore } = makeDeps();
    const wf = new BlankPinWorkflow({}, users, auth, consentStore);
    wf.stubInput = { address: "typed@x.co" };
    const ctx: AuthWfCtx = { subject: "u1", mfaEnroll: { method: "email" } };
    await wf.enrollAddress(ctx);
    expect(wf.formBuilt).toBe(1);
    expect(ctx.mfaEnroll?.address).toBe("typed@x.co");
  });

  it("validateMfaAddress is ctx-first + async-capable — record-based rules need no ctx-stash", async () => {
    class CorpOnlyWorkflow extends StubFormWorkflow {
      protected override async validateMfaAddress(
        ctx: AuthWfCtx,
        method: MfaTransport,
        value: string,
      ): Promise<string | undefined> {
        if (method === "email" && !value.trim().toLowerCase().endsWith("@corp.example")) {
          return "Use your corporate email address";
        }
        return super.validateMfaAddress(ctx, method, value);
      }
    }
    const { users, auth, consentStore } = makeDeps();
    const wf = new CorpOnlyWorkflow({}, users, auth, consentStore);
    wf.stubInput = { address: "user@gmail.com" };
    const rejected: AuthWfCtx = { subject: "u1", mfaEnroll: { method: "email" } };
    await expect(wf.enrollAddress(rejected)).rejects.toMatchObject({
      errors: { address: "Use your corporate email address" },
    });
    expect(rejected.mfaEnroll?.address).toBeUndefined();
    wf.stubInput = { address: "user@corp.example" };
    const accepted: AuthWfCtx = { subject: "u1", mfaEnroll: { method: "email" } };
    await wf.enrollAddress(accepted);
    expect(accepted.mfaEnroll?.address).toBe("user@corp.example");
  });
});

// ───────────────────────────────────────────────────────────────────────────
// TOTP account label (BUG-4 item 4) — the authenticator shows
// "issuer: account"; the account half must be human-readable, not the
// subject uuid, because it is baked into the otpauth URI forever.
// ───────────────────────────────────────────────────────────────────────────

describe("resolveTotpAccountLabel (authenticator account label)", () => {
  it("default prefers ctx.email, then the stored username, then the subject", async () => {
    const { wf, users } = makeWorkflowWithDeps();
    expect(await settle(wf.exposeTotpAccountLabel({ email: "inv@x.co", subject: "u-1" }))).toBe(
      "inv@x.co",
    );
    const { id } = await users.createUser("alice@corp.example", "pw");
    expect(await settle(wf.exposeTotpAccountLabel({ subject: id }))).toBe("alice@corp.example");
    expect(await settle(wf.exposeTotpAccountLabel({}))).toBe("");
  });

  it("enroll-pick-method bakes the label into the otpauth URI (auto-pick path)", async () => {
    const { wf, users } = makeStubFormWorkflow();
    const { id } = await users.createUser("alice@corp.example", "pw");
    const ctx: AuthWfCtx = {
      subject: id,
      mfaPolicy: { mode: "optional", availableTransports: ["totp"], issuer: "MyApp" },
    };
    await wf.enrollPickMethod(ctx);
    expect(ctx.mfaEnroll?.method).toBe("totp");
    expect(ctx.mfaEnroll?.uri).toContain("otpauth://totp/MyApp:alice%40corp.example?");
    expect(ctx.mfaEnroll?.uri).not.toContain(id);
  });

  it("enroll-totp-qr provisions with the same label (manage pre-seeded path)", async () => {
    const { wf, users } = makeStubFormWorkflow();
    const { id } = await users.createUser("bob@corp.example", "pw");
    const ctx: AuthWfCtx = {
      subject: id,
      mfaPolicy: { mode: "optional", availableTransports: ["totp", "email"], issuer: "MyApp" },
      mfaEnroll: { method: "totp", mode: "manage" },
    };
    await wf.enrollTotpQr(ctx);
    expect(ctx.mfaEnroll?.uri).toContain("MyApp:bob%40corp.example");
    expect(ctx.mfaEnroll?.qrSeen).toBe(true);
  });

  it("an override wins at both provisioning sites; blank falls back to the subject", async () => {
    class LabelledWorkflow extends StubFormWorkflow {
      public label = "Alice (Sales)";
      protected override resolveTotpAccountLabel(_ctx: AuthWfCtx): string {
        return this.label;
      }
    }
    const { users, auth, consentStore } = makeDeps();
    const wf = new LabelledWorkflow({}, users, auth, consentStore);
    const ctx: AuthWfCtx = {
      subject: "u-1",
      mfaPolicy: { mode: "optional", availableTransports: ["totp"], issuer: "MyApp" },
    };
    await wf.enrollPickMethod(ctx);
    expect(ctx.mfaEnroll?.uri).toContain(encodeURIComponent("Alice (Sales)"));
    // Blank label → the URI still carries SOME account discriminator.
    wf.label = "   ";
    const ctx2: AuthWfCtx = {
      subject: "u-2",
      mfaPolicy: { mode: "optional", availableTransports: ["totp"], issuer: "MyApp" },
    };
    await wf.enrollPickMethod(ctx2);
    expect(ctx2.mfaEnroll?.uri).toContain("MyApp:u-2?");
  });

  it("provisioning stays idempotent — a re-pause never rotates the staged secret", async () => {
    const { wf, users } = makeStubFormWorkflow();
    const { id } = await users.createUser("carol@corp.example", "pw");
    const ctx: AuthWfCtx = {
      subject: id,
      mfaPolicy: { mode: "optional", availableTransports: ["totp", "email"], issuer: "MyApp" },
      mfaEnroll: { method: "totp", mode: "manage" },
    };
    await wf.enrollTotpQr(ctx);
    const secret = ctx.mfaEnroll?.secret;
    const uri = ctx.mfaEnroll?.uri;
    delete ctx.mfaEnroll?.qrSeen;
    await wf.enrollTotpQr(ctx);
    expect(ctx.mfaEnroll?.secret).toBe(secret);
    expect(ctx.mfaEnroll?.uri).toBe(uri);
  });
});

// ───────────────────────────────────────────────────────────────────────────
// Consent-only authorize (silent session → consent) — AUTHZ_CONSENT work order.
// WHY: with `resolveAuthzReauthPolicy() → { mode: 'consent-only' }` a live
// browser session must land straight on the authorize-consent screen (no
// credentials form), while every probe failure — anonymous, stale, locked,
// deleted — falls back to the credentials path with zero behavioral change.
// The full happy path (session → consent → code → token) is exercised by the
// Playwright suite; here we pin the probe's decision table, the two schema
// gates it drives, and the public projection of the acting identity.
// ───────────────────────────────────────────────────────────────────────────

describe("Consent-only authorize (silent session → consent)", () => {
  const loginSchema = readSchemaFor("loginFlow");

  /** Auth context as the guard interceptor would stash it for a live session. */
  function liveSession(userId: string, sessionId?: string): AuthContext {
    return {
      userId,
      method: "token",
      credentialId: "cred-1",
      expiresAt: Date.now() + 60_000,
      ...(sessionId !== undefined && { sessionId }),
    };
  }

  /** Run the probe inside a test HTTP context carrying `auth` (or none). */
  function probe(
    wf: TestableAuthWorkflow,
    ctx: AuthWfCtx,
    policy: AuthzReauthPolicy,
    auth?: AuthContext,
  ): Promise<boolean> {
    const run = prepareTestHttpContext({ url: "/auth/trigger" });
    let result!: Promise<boolean>;
    run(() => {
      if (auth) setAuthContext(current(), auth);
      // `useAuth().getAuthContext()` is read synchronously before the first
      // await, so the probe promise can settle outside the context runner.
      result = wf.exposeProbeSilentAuthz(ctx, policy);
    });
    return result;
  }

  it("resolveAuthzReauthPolicy defaults to always-reauth (feature is opt-in)", async () => {
    const wf = makeWorkflow();
    expect(await settle(wf.exposeAuthzReauthPolicy({} as AuthWfCtx))).toEqual({
      mode: "always-reauth",
    });
  });

  it("credentials gate: skipped only when a subject is pre-bound (silent or SSO), never for anonymous authz starts", () => {
    const credentials = findNode(loginSchema, "credentials")!;
    // Anonymous plain login + anonymous authz start → form renders (unchanged).
    expect(evalCondition(credentials, {} as AuthWfCtx)).toBe(true);
    expect(evalCondition(credentials, { authz: { handle: "h" } } as AuthWfCtx)).toBe(true);
    // Silent bind → skipped; the `{ break: !ctx.subject }` gate still fails
    // closed for anonymous runs because the subject is what flips this.
    expect(
      evalCondition(credentials, {
        subject: "u-1",
        authz: { handle: "h", silent: true },
      } as AuthWfCtx),
    ).toBe(false);
    // Federated leg keeps its own skip.
    expect(evalCondition(credentials, { idpInbound: { state: "s" } } as AuthWfCtx)).toBe(false);
  });

  it("record-login gate: silent runs are not login events; fresh authz logins still record", () => {
    const recordLogin = findNode(loginSchema, "record-login")!;
    expect(evalCondition(recordLogin, { subject: "u-1" } as AuthWfCtx)).toBe(true);
    // Fresh credentials-based authorize → still stamps lastLogin + afterLogin.
    expect(
      evalCondition(recordLogin, { subject: "u-1", authz: { handle: "h" } } as AuthWfCtx),
    ).toBe(true);
    // Silent consent → no lastLogin stamp, no afterLogin fire.
    expect(
      evalCondition(recordLogin, {
        subject: "u-1",
        authz: { handle: "h", silent: true },
      } as AuthWfCtx),
    ).toBe(false);
  });

  it("probe binds subject + silent + signedInAs, pre-sets otp.verified, and seeds channel state", async () => {
    const { wf, users } = makeWorkflowWithDeps();
    const row = await users.createUser("alice", "pw");
    await users.activateAccount(row.id);
    await users.update(row.id, {
      mfa: {
        methods: [{ name: "email", confirmed: true, value: "alice@example.com" }],
        defaultMethod: "email",
        autoSend: false,
      },
    } as Partial<UserCredentials>);
    const ctx: AuthWfCtx = { authz: { handle: "h" } };
    const bound = await probe(wf, ctx, { mode: "consent-only" }, liveSession(row.id));
    expect(bound).toBe(true);
    expect(ctx.subject).toBe(row.id);
    expect(ctx.authz?.silent).toBe(true);
    expect(ctx.authz?.signedInAs).toBe("alice");
    // MFA loop skipped by default — the session proved its factors at login.
    expect(ctx.otp?.verified).toBe(true);
    // Channel state seeded from the row (same shape as the federated path) so
    // the shared enrolment / notice gates behave as after a fresh login.
    expect(ctx.channel?.emailConfirmed).toBe(true);
    expect(ctx.notice?.email).toBe("alice@example.com");
  });

  it("probe with requireMfa leaves otp unverified so the challenge loop still runs", async () => {
    const { wf, users } = makeWorkflowWithDeps();
    const row = await users.createUser("alice", "pw");
    await users.activateAccount(row.id);
    const ctx: AuthWfCtx = { authz: { handle: "h" } };
    const bound = await probe(
      wf,
      ctx,
      { mode: "consent-only", requireMfa: true },
      liveSession(row.id),
    );
    expect(bound).toBe(true);
    expect(ctx.subject).toBe(row.id);
    expect(ctx.otp?.verified).toBeUndefined();
  });

  it("probe falls through on: no session, deleted user, locked account, inactive account", async () => {
    const { wf, users } = makeWorkflowWithDeps();
    const policy: AuthzReauthPolicy = { mode: "consent-only" };

    // No auth context (anonymous / expired / garbage credential on the
    // @Public trigger route → guard stashed null) — the probe never throws.
    let ctx: AuthWfCtx = { authz: { handle: "h" } };
    expect(await probe(wf, ctx, policy)).toBe(false);
    expect(ctx.subject).toBeUndefined();
    expect(ctx.authz?.silent).toBeUndefined();

    // Session points at a row that no longer exists.
    ctx = { authz: { handle: "h" } };
    expect(await probe(wf, ctx, policy, liveSession("ghost"))).toBe(false);
    expect(ctx.subject).toBeUndefined();

    // ACCOUNT-STATE GATE runs BEFORE the bind (mirrors sso-callback): a
    // locked or deactivated account must fall back to credentials, where
    // `users.login` rejects it — never silently reach consent.
    const locked = await users.createUser("locked", "pw");
    await users.activateAccount(locked.id);
    await users.update(locked.id, {
      account: { ...locked.account, active: true, locked: true },
    } as Partial<UserCredentials>);
    ctx = { authz: { handle: "h" } };
    expect(await probe(wf, ctx, policy, liveSession(locked.id))).toBe(false);
    expect(ctx.subject).toBeUndefined();

    // `createUser` rows stay inactive until activated — exactly the state the
    // gate must reject.
    const inactive = await users.createUser("inactive", "pw");
    ctx = { authz: { handle: "h" } };
    expect(await probe(wf, ctx, policy, liveSession(inactive.id))).toBe(false);
    expect(ctx.subject).toBeUndefined();
  });

  it("maxSessionAgeMs: stale session origin (and origin-less legacy tokens) fall back; fresh origin binds", async () => {
    const users = new UserService(new UserStoreMemory());
    // Session ORIGIN minted 1h ago (injected clock), still live (2h ttl).
    const originAt = Date.now() - 60 * 60_000;
    const auth = new AuthCredential({
      store: new CredentialStoreMemory(),
      method: "token",
      accessTtl: 2 * 60 * 60_000,
      clock: { now: () => originAt },
    });
    const wf = new TestableAuthWorkflow({}, users, auth, new ConsentStore());
    const row = await users.createUser("alice", "pw");
    await users.activateAccount(row.id);
    await auth.issue(row.id);
    const [session] = await auth.listSessions(row.id);
    const sessionId = session.sessionId;

    // Ceiling below the origin age → stale → credentials.
    let ctx: AuthWfCtx = { authz: { handle: "h" } };
    expect(
      await probe(
        wf,
        ctx,
        { mode: "consent-only", maxSessionAgeMs: 30 * 60_000 },
        liveSession(row.id, sessionId),
      ),
    ).toBe(false);
    expect(ctx.subject).toBeUndefined();

    // Ceiling above the origin age → binds.
    ctx = { authz: { handle: "h" } };
    expect(
      await probe(
        wf,
        ctx,
        { mode: "consent-only", maxSessionAgeMs: 2 * 60 * 60_000 },
        liveSession(row.id, sessionId),
      ),
    ).toBe(true);
    expect(ctx.subject).toBe(row.id);

    // Legacy token without a sessionId — no provable origin → treated stale.
    ctx = { authz: { handle: "h" } };
    expect(
      await probe(
        wf,
        ctx,
        { mode: "consent-only", maxSessionAgeMs: 2 * 60 * 60_000 },
        liveSession(row.id),
      ),
    ).toBe(false);
    expect(ctx.subject).toBeUndefined();
  });

  it("projects signedInAs onto public.authz for the consent copy; silent stays server-only", () => {
    const wf = makeWorkflow();
    const pub = wf.exposePopulatePublic({
      subject: "u-1",
      authz: {
        handle: "server-only",
        silent: true,
        signedInAs: "alice",
        clientName: "Acme CLI",
      },
    });
    const projected = pub?.authz as Record<string, unknown> | undefined;
    expect(projected).toBeDefined();
    expect(projected?.signedInAs).toBe("alice");
    expect(projected?.clientName).toBe("Acme CLI");
    expect(projected?.handle).toBeUndefined();
    expect(projected?.silent).toBeUndefined();
  });
});
