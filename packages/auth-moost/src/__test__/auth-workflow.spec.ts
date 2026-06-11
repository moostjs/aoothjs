import { AuthCredential, CredentialStoreMemory } from "@aooth/auth";
import { type UserCredentials, UserService, UserStoreMemory } from "@aooth/user";
import { getMoostMate } from "moost";
import { describe, expect, it } from "vite-plus/test";

import { ConsentStore } from "../consent.store";
import type { AuthWfAltCredsPolicy, AuthWfCtx, MfaTransport } from "../workflow/auth-workflow.ctx";
import type { AuthDeliveryPayload } from "../workflow/auth-workflow";
import { AuthWorkflow } from "../workflow/auth-workflow";
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
  public exposeValidateMfaAddress = (m: MfaTransport, v: string) => this.validateMfaAddress(m, v);
  public exposeNormalizeMfaAddress = (m: MfaTransport, v: string) => this.normalizeMfaAddress(m, v);
  public exposeHandleEnrollExit = (ctx: AuthWfCtx, action: string | undefined) =>
    this.handleEnrollExit(ctx, action);
  public exposeOtpDisclosure = (ctx: AuthWfCtx, ch: "email" | "phone") =>
    this.resolveOtpDisclosure(ctx, ch);
  public exposeRiskStepUp = (ctx: AuthWfCtx) => this.resolveRiskStepUp(ctx);
  public exposeRecoveryUrl = (u: string | undefined, alt: AuthWfAltCredsPolicy) =>
    this.resolveRecoveryUrl(u, alt);
  public exposeAdminForm = (ctx: AuthWfCtx) => this.resolveAdminForm(ctx);
  public exposeDuplicateInviteCheck = (input: {
    email: string;
    existingUser: UserCredentials | null;
  }) => this.duplicateInviteCheck(input);
  public exposeAccept = (ctx: AuthWfCtx) => this.resolveAccept(ctx);
  public exposePostReset = (ctx: AuthWfCtx) => this.resolvePostReset(ctx);
  public exposeRecoveryAltActions = (ctx: AuthWfCtx) => this.resolveRecoveryAltActions(ctx);
  public exposePincodeForm = (ctx: AuthWfCtx) => this.resolvePincodeForm(ctx);
  public exposePincodeTarget = (ctx: AuthWfCtx) => this.resolvePincodeTarget(ctx);
  public exposeRecoveryDeliverySource = (ctx: AuthWfCtx) => this.resolveRecoveryDeliverySource(ctx);
  public exposeSelectRecoveryRegisteredMethod = (user: UserCredentials) =>
    this.selectRecoveryRegisteredMethod(user);
  public exposePincodeAltAction = (ctx: AuthWfCtx, a: string) =>
    this.resolvePincodeAltAction(ctx, a);
  public exposeRedirect = (ctx: AuthWfCtx) => this.resolveRedirect(ctx);
  public exposeClientIp = () => this.resolveClientIp();
  public exposeUserAgent = () => this.resolveUserAgent();
  public exposeIssueMetadata = (ctx: AuthWfCtx) => this.resolveIssueMetadata(ctx);
  public exposePopulatePublic = (ctx: AuthWfCtx) => {
    this.populatePublic(ctx);
    return ctx.public;
  };
  public exposeDeliver = (payload: AuthDeliveryPayload) => this.deliver(payload);
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

    // forms — defaulted to the bundled `forms.as` models so step bodies
    // (`useAtscriptWf(this.opts.forms.X)`) hit real annotated types out of
    // the box. Consumer override via `opts.forms.<field>` swaps any slot.
    // Pin a representative field-count + a key slot so a regression that
    // drops the default map is caught.
    expect(Object.keys(opts.forms).length).toBe(24);
    expect(opts.forms.loginCredentials).toBeTruthy();
    expect(opts.forms.recoveryEmailIdentifier).toBeTruthy();
    // Authorization-server consent gate (AUTH-SERVER.md §6).
    expect(opts.forms.authzConsent).toBeTruthy();
    // Manage-MFA additions: QR step + menu + remove-confirm + password re-auth.
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

  function readSchemaFor(method: string): SchemaNode[] {
    const meta = getMoostMate().read(AuthWorkflow.prototype as object, method) as
      | { wfSchema?: SchemaNode[] }
      | undefined;
    if (!meta?.wfSchema) throw new Error(`No wfSchema metadata on ${method}`);
    return meta.wfSchema;
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
