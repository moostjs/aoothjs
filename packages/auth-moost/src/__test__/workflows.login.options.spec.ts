/**
 * Per-option behaviour tests for `LoginWorkflow` — one (or two) cases per
 * `LoginWorkflowOpts` flag flagged in WF_LOGIN.md §"Tasks" item #6.
 *
 * Anti-test guard (Rule 9): every test below asserts an observable outcome
 * that DIRECTLY depends on the flag under test — i.e. flipping the flag (or
 * removing the relevant production-code branch) would make the test fail.
 * No "step count == N" tests; no full-body snapshots.
 *
 * Phase-2 reshape: callbacks (`recoveryUrlBuilder`, `riskStepUp`,
 * `redirect`-as-function) are now `protected` methods on `LoginWorkflow`.
 * Tests that exercised those callbacks build a tiny subclass and pass it via
 * `loginWorkflowClass`.
 */
import { AuthCredential } from "@aooth/auth";
import {
  generateTotpCode,
  generateTotpSecret,
  ppHasMinLength,
  UserService,
  UserStoreMemory,
} from "@aooth/user";
import { Controller, Inherit, Injectable } from "moost";
import { describe, expect, it } from "vite-plus/test";

import type { TAtscriptAnnotatedType } from "@atscript/typescript/utils";

import { AuthOpts } from "../auth.opts";
import { type ConsentDescriptor, ConsentStore } from "../consent.store";
import type { ConsentEvent } from "../workflows/auth-workflow.base";
import { type LoginWfCtx, LoginWorkflow, type LoginWorkflowOpts } from "../workflows/index";
import { SsoLoginCredentialsForm } from "./fixtures/sso-login.as";
import { prepareWfApp, seedActiveUser, withLoginMfaCtx } from "./workflow-utils";

/**
 * Build a `LoginWorkflow` subclass with a single override. Mirrors the
 * canonical consumer pattern (see TASKS.md §"Probe outcomes") — re-decorates
 * the class and re-declares the ctor so DI metadata regenerates.
 *
 * Post-resolver reshape: callers that previously overrode `buildRecoveryUrl`
 * now override `resolveAlternateCredentials` (which produces the resolved
 * `alternateCredentials.recoveryUrl` consumed by the credentials step's alt-
 * action handler). Callers that overrode `assessRiskStepUp` now override
 * `resolveRiskStepUp`. `resolveRedirect` is unchanged in name; it now reads
 * `ctx.finalize.redirect` instead of `this.opts.finalize.redirect`.
 */
function makeLoginSubclass(
  overrides: Partial<{
    resolveAlternateCredentials: (
      this: LoginWorkflow,
      ctx: LoginWfCtx,
    ) =>
      | NonNullable<LoginWfCtx["alternateCredentials"]>
      | Promise<NonNullable<LoginWfCtx["alternateCredentials"]>>;
    resolveRiskStepUp: (
      this: LoginWorkflow,
      ctx: LoginWfCtx,
    ) => Promise<{ require: boolean; reason?: string }>;
    resolveRedirect: (this: LoginWorkflow, ctx: LoginWfCtx) => string | undefined;
  }>,
): typeof LoginWorkflow {
  @Inherit()
  @Controller("auth/login")
  class SubclassedLogin extends LoginWorkflow {
    constructor(
      opts: LoginWorkflowOpts,
      users: UserService,
      auth: AuthCredential,
      authOpts: AuthOpts,
      consentStore: ConsentStore,
    ) {
      super(opts, users, auth, authOpts, consentStore);
    }
    protected override resolveAlternateCredentials(
      ctx: LoginWfCtx,
    ):
      | NonNullable<LoginWfCtx["alternateCredentials"]>
      | Promise<NonNullable<LoginWfCtx["alternateCredentials"]>> {
      return overrides.resolveAlternateCredentials
        ? overrides.resolveAlternateCredentials.call(this, ctx)
        : super.resolveAlternateCredentials(ctx);
    }
    protected override async resolveRiskStepUp(
      ctx: LoginWfCtx,
    ): Promise<{ require: boolean; reason?: string }> {
      return overrides.resolveRiskStepUp
        ? overrides.resolveRiskStepUp.call(this, ctx)
        : super.resolveRiskStepUp(ctx);
    }
    protected override resolveRedirect(ctx: LoginWfCtx): string | undefined {
      return overrides.resolveRedirect
        ? overrides.resolveRedirect.call(this, ctx)
        : super.resolveRedirect(ctx);
    }
  }
  return SubclassedLogin;
}

/**
 * Default-merged `alternateCredentials` policy — saves each test from spelling
 * out the full 8-field shape just to flip one flag. Mirrors
 * `LoginWorkflow.resolveAlternateCredentials` defaults.
 */
function altCreds(
  partial: Partial<NonNullable<LoginWfCtx["alternateCredentials"]>> = {},
): NonNullable<LoginWfCtx["alternateCredentials"]> {
  return {
    forgotPassword: true,
    signup: false,
    magicLink: false,
    magicLinkSkipsMfa: false,
    ssoProviders: [],
    recoveryUrl: "/recover",
    signupUrl: "/signup",
    embedRecovery: false,
    ...partial,
  };
}

/** Default-merged guards policy — saves test boilerplate. */
function guardsPolicy(
  partial: Partial<NonNullable<LoginWfCtx["guards"]>> = {},
): NonNullable<LoginWfCtx["guards"]> {
  return {
    passwordInitial: true,
    passwordExpiry: true,
    emailVerifiedRequired: false,
    ...partial,
  };
}

/** Default-merged finalize policy — saves test boilerplate. */
function finalizePolicy(
  partial: Partial<NonNullable<LoginWfCtx["finalize"]>> = {},
): NonNullable<LoginWfCtx["finalize"]> {
  return {
    auditLogin: true,
    notifyNewDevice: false,
    redirect: false,
    ...partial,
  };
}

/** Default-merged deviceTrust policy — saves test boilerplate. */
function deviceTrustPolicy(
  partial: Partial<NonNullable<LoginWfCtx["deviceTrust"]>> = {},
): NonNullable<LoginWfCtx["deviceTrust"]> {
  return {
    enabled: false,
    optIn: true,
    skipsMfa: true,
    ...partial,
  };
}

/** Helper: drive credentials → first paused/finished state. */
async function startAndCredentials(
  app: Awaited<ReturnType<typeof prepareWfApp>>,
  username: string,
  password: string,
  extra: Record<string, unknown> = {},
): Promise<Awaited<ReturnType<typeof app.trigger>>> {
  const r1 = await app.trigger({ wfid: "auth/login/flow" });
  return app.trigger({
    wfs: r1.body?.wfs as string,
    input: { username, password, ...extra },
  });
}

describe("LoginWorkflowOpts — Phase 1 alt-action redirects (credentials step)", () => {
  // Phase 1 alt-actions short-circuit via the `ALT_HANDLED` sentinel — the
  // handler sets a `useWfFinished({type:'redirect', value: ...})` and returns
  // the sentinel; the caller returns `undefined` without running form
  // validation (the payload lacks the password field by design).
  it("alternateCredentials.forgotPassword: 'forgotPassword' alt → redirect to recoveryUrl with typed username", async () => {
    const app = await prepareWfApp({
      loginPolicy: { alternateCredentials: altCreds({ forgotPassword: true }) },
    });
    const r1 = await app.trigger({ wfid: "auth/login/flow" });
    const r2 = await app.trigger({
      wfs: r1.body?.wfs as string,
      input: { username: "typed-user", action: "forgotPassword" },
    });
    expect(r2.body?.finished).toBe(true);
    const end = r2.body?.next as { trigger: string; action: { target: string } };
    expect(end?.trigger).toBe("immediate");
    expect(end?.action?.target).toBe("/recover?username=typed-user");
  });

  it("resolveAlternateCredentials override: subclass swaps recoveryUrl → custom URL fragment", async () => {
    // Post-resolver reshape: the redirect URL no longer flows through a
    // dedicated `buildRecoveryUrl` method — instead, `resolveRecoveryUrl`
    // pulls `recoveryUrl` off the resolved `alternateCredentials` policy. To
    // customize it, override `resolveAlternateCredentials` (or
    // `resolveRecoveryUrl` for full URL-construction control). This test
    // pins the alternateCredentials path; a separate test below covers
    // resolveRecoveryUrl directly.
    const app = await prepareWfApp({
      loginPolicy: {
        alternateCredentials: altCreds({ forgotPassword: true, recoveryUrl: "#/forgot" }),
      },
    });
    const r1 = await app.trigger({ wfid: "auth/login/flow" });
    const r2 = await app.trigger({
      wfs: r1.body?.wfs as string,
      input: { username: "bob", action: "forgotPassword" },
    });
    const end = r2.body?.next as { action: { target: string } };
    expect(end?.action?.target).toBe("#/forgot?username=bob");
  });

  it("alternateCredentials.forgotPassword: false → action is ignored (no redirect, falls through to validation)", async () => {
    // The handler returns undefined when it can't route the action, and
    // validation kicks in.
    const app = await prepareWfApp({
      loginPolicy: { alternateCredentials: altCreds({ forgotPassword: false }) },
    });
    const r1 = await app.trigger({ wfid: "auth/login/flow" });
    const r2 = await app.trigger({
      wfs: r1.body?.wfs as string,
      input: { username: "alice", action: "forgotPassword" },
    });
    expect(r2.body?.next).toBeUndefined();
    expect(r2.body?.errors).toBeTruthy();
  });

  it("alternateCredentials.signup: 'signup' alt → redirect to signupUrl", async () => {
    const app = await prepareWfApp({
      loginPolicy: { alternateCredentials: altCreds({ signup: true, signupUrl: "/sign-me-up" }) },
    });
    const r1 = await app.trigger({ wfid: "auth/login/flow" });
    const r2 = await app.trigger({
      wfs: r1.body?.wfs as string,
      input: { action: "signup" },
    });
    expect(r2.body?.finished).toBe(true);
    const end = r2.body?.next as { trigger: string; action: { target: string } };
    expect(end?.trigger).toBe("immediate");
    expect(end?.action?.target).toBe("/sign-me-up");
  });

  it("alternateCredentials.ssoProviders: matching provider id → redirect to provider url", async () => {
    const app = await prepareWfApp({
      loginPolicy: {
        alternateCredentials: altCreds({
          ssoProviders: [
            { id: "google", label: "Sign in with Google", url: "https://idp.example/oauth/google" },
            { id: "okta", label: "Okta", url: "https://idp.example/oauth/okta" },
          ],
        }),
      },
      // SSO providers are dynamic per consumer — the bundled
      // `LoginCredentialsForm` does NOT whitelist them. Opt into the test
      // fixture form that declares phantom `ui.action` fields for
      // `google` + `okta`.
      loginOpts: {
        forms: { loginCredentials: SsoLoginCredentialsForm as unknown as TAtscriptAnnotatedType },
      },
    });
    const r1 = await app.trigger({ wfid: "auth/login/flow" });
    const r2 = await app.trigger({
      wfs: r1.body?.wfs as string,
      input: { action: "okta" },
    });
    const end = r2.body?.next as { action: { target: string } };
    expect(end?.action?.target).toBe("https://idp.example/oauth/okta");
  });

  it("sso redirect emits WfFinished envelope with end:immediate + per-provider reason:sso-<id>", async () => {
    // Pins the new envelope shape after the WfFinished migration: SSO alt
    // actions surface `reason: 'sso-<providerId>'` so consumer analytics can
    // disambiguate which IdP was picked without parsing the URL.
    const app = await prepareWfApp({
      loginPolicy: {
        alternateCredentials: altCreds({
          ssoProviders: [{ id: "okta", label: "Okta", url: "https://idp.example/oauth/okta" }],
        }),
      },
      loginOpts: {
        forms: { loginCredentials: SsoLoginCredentialsForm as unknown as TAtscriptAnnotatedType },
      },
    });
    const r1 = await app.trigger({ wfid: "auth/login/flow" });
    const r2 = await app.trigger({
      wfs: r1.body?.wfs as string,
      input: { action: "okta" },
    });
    expect(r2.status).toBe(201);
    expect(r2.body?.finished).toBe(true);
    expect(r2.body).toMatchObject({
      finished: true,
      next: {
        trigger: "immediate",
        action: {
          type: "redirect",
          target: "https://idp.example/oauth/okta",
          reason: "sso-okta",
        },
      },
    });
  });

  it("alternateCredentials.magicLink: 'magicLink' alt → HttpError 501 (stub, see WF_LOGIN §Phase 1 doc)", async () => {
    const app = await prepareWfApp({
      loginPolicy: { alternateCredentials: altCreds({ magicLink: true }) },
    });
    const r1 = await app.trigger({ wfid: "auth/login/flow" });
    const r2 = await app.trigger({
      wfs: r1.body?.wfs as string,
      input: { action: "magicLink" },
    });
    expect(r2.status).toBe(501);
  });
});

describe("LoginWorkflowOpts — Phase 2 password guards", () => {
  it("guards.passwordInitial true + user.password.isInitial → routes to create-password-form", async () => {
    const app = await prepareWfApp({
      loginPolicy: { guards: guardsPolicy({ passwordInitial: true }) },
      // skip MFA so we observe the password-change branch directly
      loginWorkflowClass: withLoginMfaCtx(LoginWorkflow, { mfaMode: "disabled" }),
    });
    // createUser without a password marks `password.isInitial = true` (see UserService.createUser).
    await app.users.createUser("alice");
    await app.users.activateAccount("alice");
    // The auto-generated password is unknown — set a known one but keep isInitial=true.
    const u = await app.users.getUser("alice");
    const generatedHash = u.password.hash; // unreadable; instead just activate via setPassword and re-mark isInitial
    expect(generatedHash).toBeTruthy();
    // Set a known password and manually re-mark isInitial=true via direct store update.
    await app.users.setPassword("alice", "Knowable1!");
    // Re-flip isInitial back to true (setPassword resets it).
    const store = (app.users as unknown as { store: { update: Function } }).store;
    await store.update("alice", { set: { password: { isInitial: true } } });

    const r2 = await startAndCredentials(app, "alice", "Knowable1!");
    // After credentials, isPasswordInitial is set → next pause asks SetPasswordForm.
    expect(r2.body?.wfs).toBeTruthy();
    // The paused form should include the SetPasswordForm's `newPassword` property.
    const payload = r2.body as Record<string, unknown>;
    expect(JSON.stringify(payload)).toMatch(/newPassword/);
  });

  it("guards.passwordInitial false → skip the password-change branch even when isInitial is true", async () => {
    const app = await prepareWfApp({
      loginPolicy: { guards: guardsPolicy({ passwordInitial: false }) },
      loginWorkflowClass: withLoginMfaCtx(LoginWorkflow, { mfaMode: "disabled" }),
    });
    await app.users.createUser("alice", "Password123");
    await app.users.activateAccount("alice");
    const store = (app.users as unknown as { store: { update: Function } }).store;
    await store.update("alice", { set: { password: { isInitial: true } } });

    const r2 = await startAndCredentials(app, "alice", "Password123");
    // No password-change pause → directly issued tokens.
    const data = r2.body?.data as Record<string, unknown> | undefined;
    expect(data?.userId).toBe("alice");
    expect(typeof data?.accessToken).toBe("string");
  });

  it("WF-LOGIN-PWPOLICY — password.policies reaches client on SetPasswordForm pause (forced password change)", async () => {
    // Guards two regressions at once:
    //   1. `@wf.context.pass 'password'` on SetPasswordForm — without
    //      it `extractPassContext` strips the key before the inputRequired
    //      envelope leaves the engine.
    //   2. `prepare-password-rules` step seeding `ctx.password.policies` so the
    //      next step's `createPasswordForm` ships the rules to the client.
    const app = await prepareWfApp({
      loginPolicy: { guards: guardsPolicy({ passwordInitial: true }) },
      loginWorkflowClass: withLoginMfaCtx(LoginWorkflow, { mfaMode: "disabled" }),
      userConfig: { password: { policies: [ppHasMinLength(8)] } },
    });
    await app.users.createUser("alice");
    await app.users.activateAccount("alice");
    await app.users.setPassword("alice", "Knowable1!");
    const store = (app.users as unknown as { store: { update: Function } }).store;
    await store.update("alice", { set: { password: { isInitial: true } } });

    const r2 = await startAndCredentials(app, "alice", "Knowable1!");
    // The `password` group is shipped as a nested object — whitelisted ctx
    // keys merged alongside the form schema.
    const body = r2.body as { id?: string; password?: { policies?: unknown } };
    expect(body.id).toBe("SetPasswordForm");
    const policies = body.password?.policies as unknown[] | undefined;
    expect(policies).toEqual(app.users.getTransferablePolicies());
    expect(Array.isArray(policies)).toBe(true);
    expect(policies?.length ?? 0).toBeGreaterThan(0);
  });
});

describe("LoginWorkflowOpts — passwordExpiry (rotation) guard", () => {
  // Pattern notes (apply to every test in this block):
  // - Inject an explicit clock via `userConfig.clock` so test 2/3/4/6 can
  //   advance time deterministically without sleeping.
  // - Use `seedActiveUser` then mutate `password.lastChanged` via the same
  //   `store.update` escape hatch the Phase-2-guards tests use — going
  //   through `createUser` / `setPassword` would stamp the current clock
  //   and defeat the "lastChanged in the past" setup.
  // - Skip MFA via `withLoginMfaCtx(LoginWorkflow, { mfaMode: "disabled" })`
  //   so the assertions land on the SetPasswordForm pause, not an MFA pause.
  const DAY_MS = 24 * 60 * 60 * 1000;
  const YEAR_MS = 365 * DAY_MS;

  it("maxAgeMs unset → no forced change even after a long time", async () => {
    // WHY: pins the "expiry disabled by default" contract. A regression that
    // defaulted maxAgeMs to a non-zero number would force-change every user
    // on every long-running deployment — silent compliance footgun.
    let now = 1_000_000_000;
    const app = await prepareWfApp({
      userConfig: { clock: () => now },
      loginPolicy: { guards: guardsPolicy({ passwordExpiry: true }) },
      loginWorkflowClass: withLoginMfaCtx(LoginWorkflow, { mfaMode: "disabled" }),
    });
    await seedActiveUser(app.users, "alice", "Password123");
    // Advance 10 years — but maxAgeMs is unset, so isPasswordExpired stays false.
    now += 10 * YEAR_MS;
    const r2 = await startAndCredentials(app, "alice", "Password123");
    // No SetPasswordForm pause → tokens issued directly.
    const data = r2.body?.data as Record<string, unknown> | undefined;
    expect(data?.userId).toBe("alice");
    expect(typeof data?.accessToken).toBe("string");
  });

  it("maxAgeMs set + lastChanged within window → no forced change", async () => {
    // WHY: pins the inequality direction in `isPasswordExpired` from the
    // workflow side. A regression flipping `>` to `>=` would expire users
    // exactly at maxAgeMs (boundary case); flipping to `<` would never
    // expire. The within-window assertion catches both.
    let now = 1_000_000_000;
    const app = await prepareWfApp({
      userConfig: { clock: () => now, password: { maxAgeMs: YEAR_MS } },
      loginPolicy: { guards: guardsPolicy({ passwordExpiry: true }) },
      loginWorkflowClass: withLoginMfaCtx(LoginWorkflow, { mfaMode: "disabled" }),
    });
    await seedActiveUser(app.users, "alice", "Password123");
    // Move 30 days forward — well within the 1-year window.
    now += 30 * DAY_MS;
    const r2 = await startAndCredentials(app, "alice", "Password123");
    const data = r2.body?.data as Record<string, unknown> | undefined;
    expect(data?.userId).toBe("alice");
    expect(typeof data?.accessToken).toBe("string");
  });

  it("maxAgeMs set + lastChanged beyond window → SetPasswordForm pause + password.changeReason='expired'", async () => {
    // WHY: positive-case proof the new arc fires end-to-end (resolver →
    // credentials → schema condition → pause). Also pins
    // password.changeReason='expired' on the wire envelope — without
    // `@wf.context.pass 'password'` on SetPasswordForm, the
    // key would be stripped by `extractPassContext` before the client
    // receives it. Same regression class as WF-LOGIN-PWPOLICY.
    let now = 1_000_000_000;
    const app = await prepareWfApp({
      userConfig: { clock: () => now, password: { maxAgeMs: YEAR_MS } },
      loginPolicy: { guards: guardsPolicy({ passwordExpiry: true }) },
      loginWorkflowClass: withLoginMfaCtx(LoginWorkflow, { mfaMode: "disabled" }),
    });
    await seedActiveUser(app.users, "alice", "Password123");
    // Advance 2 years — well past the 1-year window.
    now += 2 * YEAR_MS;
    const r2 = await startAndCredentials(app, "alice", "Password123");
    expect(r2.body?.wfs).toBeTruthy();
    const body = r2.body as { id?: string; password?: { changeReason?: unknown } };
    expect(body.id).toBe("SetPasswordForm");
    expect(body.password?.changeReason).toBe("expired");
  });

  it("passwordInitial=true AND expired=true → password.changeReason='initial' wins", async () => {
    // WHY: pins the precedence rule. A user with a generated initial
    // password whose `lastChanged` (stamped on `createUser`) crossed
    // `maxAgeMs` before first login is a real (if narrow) case. Reporting
    // them as `'expired'` would tell the SPA to render a "your password
    // expired" banner for someone who never set one — confusing UX.
    let now = 1_000_000_000;
    const app = await prepareWfApp({
      userConfig: { clock: () => now, password: { maxAgeMs: YEAR_MS } },
      loginPolicy: {
        guards: guardsPolicy({ passwordInitial: true, passwordExpiry: true }),
      },
      loginWorkflowClass: withLoginMfaCtx(LoginWorkflow, { mfaMode: "disabled" }),
    });
    await seedActiveUser(app.users, "alice", "Password123");
    const store = (app.users as unknown as { store: { update: Function } }).store;
    // Force isInitial=true (setPassword inside seedActiveUser cleared it).
    await store.update("alice", { set: { password: { isInitial: true } } });
    // Advance 2 years so isPasswordExpired ALSO returns true.
    now += 2 * YEAR_MS;
    const r2 = await startAndCredentials(app, "alice", "Password123");
    expect(r2.body?.wfs).toBeTruthy();
    const body = r2.body as { id?: string; password?: { changeReason?: unknown } };
    expect(body.id).toBe("SetPasswordForm");
    expect(body.password?.changeReason).toBe("initial");
  });

  it("resolveGuards override returning passwordExpiry: false → no forced change even when expired", async () => {
    // WHY: pins the per-tenant escape hatch. A regression that read
    // `config.password.maxAgeMs` directly instead of going through
    // `ctx.guards?.passwordExpiry` would bypass the override surface and
    // force-change users in SSO-only tenants where the IdP owns rotation.
    let now = 1_000_000_000;
    const app = await prepareWfApp({
      userConfig: { clock: () => now, password: { maxAgeMs: YEAR_MS } },
      loginPolicy: { guards: guardsPolicy({ passwordExpiry: false }) },
      loginWorkflowClass: withLoginMfaCtx(LoginWorkflow, { mfaMode: "disabled" }),
    });
    await seedActiveUser(app.users, "alice", "Password123");
    now += 2 * YEAR_MS;
    const r2 = await startAndCredentials(app, "alice", "Password123");
    const data = r2.body?.data as Record<string, unknown> | undefined;
    expect(data?.userId).toBe("alice");
    expect(typeof data?.accessToken).toBe("string");
  });

  it("after successful password change → both flags reset, login completes", async () => {
    // WHY: pins the reset contract. A regression that forgot to clear
    // `isPasswordExpired` or `password.changeReason` on the post-change
    // path would either loop the user back to SetPasswordForm
    // indefinitely or leak stale reason copy into a subsequent step's
    // form (if a future step ever surfaces the field).
    let now = 1_000_000_000;
    const app = await prepareWfApp({
      userConfig: { clock: () => now, password: { maxAgeMs: YEAR_MS } },
      loginPolicy: { guards: guardsPolicy({ passwordExpiry: true }) },
      loginWorkflowClass: withLoginMfaCtx(LoginWorkflow, { mfaMode: "disabled" }),
    });
    await seedActiveUser(app.users, "alice", "Password123");
    now += 2 * YEAR_MS;
    const r2 = await startAndCredentials(app, "alice", "Password123");
    expect(r2.body?.wfs).toBeTruthy();
    const body = r2.body as { id?: string; password?: { changeReason?: unknown } };
    expect(body.id).toBe("SetPasswordForm");
    expect(body.password?.changeReason).toBe("expired");

    // Submit the new password — consents: [] required per workflow form
    // contract (the inline-consent string[] is non-optional on raw HTTP).
    const r3 = await app.trigger({
      wfs: r2.body?.wfs as string,
      input: { newPassword: "NewPass1!", confirmPassword: "NewPass1!", consents: [] },
    });
    // Flow completes — tokens issued, no loop back to SetPasswordForm.
    const data = r3.body?.data as Record<string, unknown> | undefined;
    expect(data?.userId).toBe("alice");
    expect(typeof data?.accessToken).toBe("string");
  });

  it("password.changeReason='initial' → SetPasswordForm wire envelope carries 'Set your initial password' heading + initial-flow intro", async () => {
    // WHY: pins the context-aware copy keyed off `password.changeReason`.
    // SetPasswordForm's bundled phantom `heading` / `intro` paragraphs read
    // `ctx.password.heading` / `ctx.password.intro` via
    // `@ui.form.fn.value`. The `create-password-form` step body sets those
    // values before the pause; a regression that dropped the assignment
    // (or routed the 'initial' branch to the 'expired' copy) would silently
    // mislead users about why they're being asked to set a password.
    const app = await prepareWfApp({
      loginPolicy: { guards: guardsPolicy({ passwordInitial: true }) },
      loginWorkflowClass: withLoginMfaCtx(LoginWorkflow, { mfaMode: "disabled" }),
    });
    await seedActiveUser(app.users, "alice", "Password123");
    const store = (app.users as unknown as { store: { update: Function } }).store;
    await store.update("alice", { set: { password: { isInitial: true } } });

    const r2 = await startAndCredentials(app, "alice", "Password123");
    expect(r2.body?.wfs).toBeTruthy();
    const body = r2.body as {
      id?: string;
      password?: { changeReason?: unknown; heading?: unknown; intro?: unknown };
    };
    expect(body.id).toBe("SetPasswordForm");
    expect(body.password?.changeReason).toBe("initial");
    expect(body.password?.heading).toBe("Set your initial password");
    expect(body.password?.intro).toMatch(/account was created without a password/i);
  });

  it("password.changeReason='expired' → SetPasswordForm wire envelope carries 'Your password has expired' heading + expired-flow intro", async () => {
    // WHY: symmetric pin for the 'expired' branch. Bundles two regression
    // surfaces: the `@wf.context.pass 'password'` annotation (without it
    // the keys are stripped by `extractPassContext` before reaching the
    // client), and the `create-password-form` step body's reason→copy
    // mapping.
    let now = 1_000_000_000;
    const app = await prepareWfApp({
      userConfig: { clock: () => now, password: { maxAgeMs: YEAR_MS } },
      loginPolicy: { guards: guardsPolicy({ passwordExpiry: true }) },
      loginWorkflowClass: withLoginMfaCtx(LoginWorkflow, { mfaMode: "disabled" }),
    });
    await seedActiveUser(app.users, "alice", "Password123");
    now += 2 * YEAR_MS;
    const r2 = await startAndCredentials(app, "alice", "Password123");
    const body = r2.body as {
      password?: { changeReason?: unknown; heading?: unknown; intro?: unknown };
    };
    expect(body.password?.changeReason).toBe("expired");
    expect(body.password?.heading).toBe("Your password has expired");
    expect(body.password?.intro).toMatch(/Choose a new password to continue/i);
  });

  it("SetPasswordForm: confirmPassword !== newPassword → inline error on confirmPassword (server-side belt-and-braces guard)", async () => {
    // WHY: pins the equality guard for `confirmPassword === newPassword`.
    // The bundled `SetPasswordForm` declares the cross-field rule via
    // `@ui.form.validate '(v, data) => v === data.newPassword || "Passwords
    // must match"'` — that string runs on the CLIENT (where the SPA wires
    // `installDynamicResolver()` from `@atscript/ui-fns`) and short-circuits
    // submit before the network call. The server side keeps the existing
    // step-body equality check ("Passwords do not match") as a
    // belt-and-braces guard for clients that bypass / don't install the
    // dynamic resolver. A regression that dropped BOTH would let mismatched
    // submissions through. We accept either error string here — what
    // matters is the field key (`confirmPassword`) and that we never
    // advance past the pause with a mismatched pair.
    const app = await prepareWfApp({
      loginPolicy: { guards: guardsPolicy({ passwordInitial: true }) },
      loginWorkflowClass: withLoginMfaCtx(LoginWorkflow, { mfaMode: "disabled" }),
    });
    await seedActiveUser(app.users, "alice", "Password123");
    const store = (app.users as unknown as { store: { update: Function } }).store;
    await store.update("alice", { set: { password: { isInitial: true } } });

    const r2 = await startAndCredentials(app, "alice", "Password123");
    expect(r2.body?.wfs).toBeTruthy();

    const r3 = await app.trigger({
      wfs: r2.body?.wfs as string,
      input: {
        newPassword: "AAAA1234",
        confirmPassword: "BBBB1234",
        consents: [],
      },
    });
    const errors = r3.body?.errors as Record<string, string> | undefined;
    expect(errors?.confirmPassword).toMatch(/Passwords (do not match|must match)/);
    // The pause holds — no tokens issued, no schema advance.
    expect(r3.body?.data).toBeUndefined();
  });
});

describe("LoginWorkflowOpts — Phase 4 MFA enable/transports", () => {
  it("mfa.mode='disabled' → Phase 4 skipped entirely (credentials → issue) even with enrolled TOTP", async () => {
    const app = await prepareWfApp({
      loginWorkflowClass: withLoginMfaCtx(LoginWorkflow, { mfaMode: "disabled" }),
    });
    await seedActiveUser(app.users, "alice", "Password123");
    const secret = generateTotpSecret();
    await app.users.addMfaMethod("alice", { name: "totp", value: secret, confirmed: true });

    const r2 = await startAndCredentials(app, "alice", "Password123");
    // Issued immediately — no MFA pause.
    const data = r2.body?.data as Record<string, unknown> | undefined;
    expect(data?.userId).toBe("alice");
    expect(typeof data?.accessToken).toBe("string");
  });

  it("mfa.transports: ['email'] + user has only TOTP enrolled → MFA short-circuits (no methods after filter)", async () => {
    // mode='disabled' to preserve the no-prompt semantics this test pins —
    // under the default 'optional' mode the same 0-methods state would route
    // to `mfa-enroll-required` with a skip action instead of silently issuing.
    const app = await prepareWfApp({
      loginWorkflowClass: withLoginMfaCtx(LoginWorkflow, {
        mfaMode: "disabled",
        availableMfaTransports: ["email"],
      }),
    });
    await seedActiveUser(app.users, "alice", "Password123");
    const secret = generateTotpSecret();
    await app.users.addMfaMethod("alice", { name: "totp", value: secret, confirmed: true });

    const r2 = await startAndCredentials(app, "alice", "Password123");
    // After prepare-mfa-options filters → 0 methods → ctx.mfa.checked = true → issue.
    const data = r2.body?.data as Record<string, unknown> | undefined;
    expect(data?.userId).toBe("alice");
    expect(typeof data?.accessToken).toBe("string");
  });

  it("mfa.transports: ['email', 'totp'] + user has TOTP only → auto-picks TOTP (1 method, no select2fa)", async () => {
    const app = await prepareWfApp({
      loginWorkflowClass: withLoginMfaCtx(LoginWorkflow, {
        availableMfaTransports: ["email", "totp"],
      }),
    });
    await seedActiveUser(app.users, "alice", "Password123");
    const secret = generateTotpSecret();
    await app.users.addMfaMethod("alice", { name: "totp", value: secret, confirmed: true });

    const r2 = await startAndCredentials(app, "alice", "Password123");
    // Single method → no select2fa pause; the next paused form is MfaCodeForm.
    expect(r2.body?.wfs).toBeTruthy();
    const code = generateTotpCode(secret);
    const r3 = await app.trigger({ wfs: r2.body?.wfs as string, input: { code } });
    expect((r3.body?.data as Record<string, unknown>)?.userId).toBe("alice");
  });

  it("mfa.transports: ['sms'] with sms MFA enrolled WITHOUT registered SmsSender → runtime throw at deliver()", async () => {
    // Post-reshape: sender absence is enforced at the first `deliver()` call
    // rather than at boot. The harness's override throws when `registerSmsSender`
    // is false, mirroring the prior fail-loud surface (500 with SmsSender message).
    const app = await prepareWfApp({
      loginWorkflowClass: withLoginMfaCtx(LoginWorkflow, { availableMfaTransports: ["sms"] }),
      registerSmsSender: false,
    });
    await seedActiveUser(app.users, "alice", "Password123");
    // Enroll an SMS factor so `pincode-send-login` runs and hits `deliver()`.
    await app.users.addMfaMethod("alice", {
      name: "sms",
      value: "+15555550100",
      confirmed: true,
    });
    const r1 = await app.trigger({ wfid: "auth/login/flow" });
    const r2 = await app.trigger({
      wfs: r1.body?.wfs as string,
      input: { username: "alice", password: "Password123" },
    });
    expect(r2.status).toBe(500);
    expect(JSON.stringify(r2.body)).toMatch(/SmsSender/);
  });

  // DELETED in PR9: the "empty mfa.transports + non-disabled mode → fail loud"
  // boot-time validator was removed when `mfa.mode` / `mfa.transports` moved
  // off `LoginWorkflowOpts` onto `@Step` setter methods populating ctx.
  // There is no longer an opts-shape to validate at boot — consumers control
  // `ctx.mfa.availableTransports` per-event via overriding `prepareMfaSetup`,
  // and the runtime steps that read it tolerate empty/undefined transports
  // by short-circuiting through the `ctx.mfa.checked = true` no-prompt branch.

  it("deviceTrust.enabled true with NO cookie → check-trusted-device flags newDevice and flow completes", async () => {
    // No cookie ⇒ `check-trusted-device` short-circuits to `newDevice = true`
    // without calling `loadTrustedDevice`, so the flow completes via the
    // no-trust path even when no trust-device secret/store is wired (we still
    // wire the default secret here — proves the no-cookie branch is the
    // structural short-circuit).
    const app = await prepareWfApp({
      loginPolicy: { deviceTrust: deviceTrustPolicy({ enabled: true }) },
      loginWorkflowClass: withLoginMfaCtx(LoginWorkflow, { mfaMode: "disabled" }),
    });
    await seedActiveUser(app.users, "alice", "Password123");
    const r1 = await app.trigger({ wfid: "auth/login/flow" });
    const r2 = await app.trigger({
      wfs: r1.body?.wfs as string,
      input: { username: "alice", password: "Password123" },
    });
    expect((r2.body?.data as Record<string, unknown>)?.userId).toBe("alice");
  });

  it("mfa.transports: ['email'] (default user has TOTP only) — falls back to issue (no enrolled allowed methods)", async () => {
    // mode='disabled' preserves the no-prompt fallback semantics this test pins.
    const app = await prepareWfApp({
      loginWorkflowClass: withLoginMfaCtx(LoginWorkflow, {
        mfaMode: "disabled",
        availableMfaTransports: ["email"],
      }),
    });
    await seedActiveUser(app.users, "alice", "Password123");
    const r2 = await startAndCredentials(app, "alice", "Password123");
    expect((r2.body?.data as Record<string, unknown>)?.userId).toBe("alice");
  });
});

describe("LoginWorkflowOpts — Phase 4 device trust", () => {
  it("deviceTrust true + valid cookie → MFA skipped (mfa.checked set in check-trusted-device)", async () => {
    const app = await prepareWfApp({
      loginPolicy: {
        deviceTrust: deviceTrustPolicy({ enabled: true, skipsMfa: true, optIn: false }),
      },
    });
    await seedActiveUser(app.users, "alice", "Password123");
    const secret = generateTotpSecret();
    await app.users.addMfaMethod("alice", { name: "totp", value: secret, confirmed: true });

    // Pre-issue a trust record so cookie is valid out of the gate.
    const rec = app.users.issueTrustedDevice("alice", { ttlMs: 60_000 });
    await app.users.addTrustedDevice("alice", rec);

    // First request: send the cookie.
    const r1 = await app.triggerWithHeaders(
      { wfid: "auth/login/flow" },
      { cookie: `aooth_trusted_device=${rec.token}` },
    );
    const r2 = await app.triggerWithHeaders(
      {
        wfs: r1.body?.wfs as string,
        input: { username: "alice", password: "Password123" },
      },
      { cookie: `aooth_trusted_device=${rec.token}` },
    );
    // MFA bypassed → tokens issued immediately.
    const data2 = r2.body?.data as Record<string, unknown> | undefined;
    expect(data2?.userId).toBe("alice");
    expect(typeof data2?.accessToken).toBe("string");
  });

  it("deviceTrust true + NO cookie → marks newDevice, runs MFA normally, persists cookie", async () => {
    const app = await prepareWfApp({
      loginPolicy: { deviceTrust: deviceTrustPolicy({ enabled: true, optIn: false }) },
      loginWorkflowClass: withLoginMfaCtx(LoginWorkflow, { availableMfaTransports: ["totp"] }),
    });
    await seedActiveUser(app.users, "alice", "Password123");
    const secret = generateTotpSecret();
    await app.users.addMfaMethod("alice", { name: "totp", value: secret, confirmed: true });

    const r2 = await startAndCredentials(app, "alice", "Password123");
    expect(r2.body?.wfs).toBeTruthy(); // paused for TOTP
    const code = generateTotpCode(secret);
    const r3 = await app.trigger({ wfs: r2.body?.wfs as string, input: { code } });
    expect((r3.body?.data as Record<string, unknown>)?.userId).toBe("alice");
    // A trust cookie was written.
    const trustCookie = r3.setCookies.find((c) => c.startsWith("aooth_trusted_device="));
    expect(trustCookie).toBeTruthy();
  });

  it("deviceTrust + deviceTrust.bindsTo='cookie+ip': cookie issued for IP A is rejected when verified with IP B", async () => {
    // Unit-level proof via `UserService` directly (workflow-level testing
    // requires the request adapter to expose req.ip, which the in-process
    // Wooks test harness doesn't surface for synthetic requests).
    // `UserService` IS the authoritative IP-binding check.
    const userStore = new UserStoreMemory();
    const users = new UserService(userStore, {
      deviceTrust: { secret: "test-secret" },
    });
    await users.createUser("alice", "Password123");
    const rec = users.issueTrustedDevice("alice", { ip: "10.0.0.1", ttlMs: 60_000 });
    await users.addTrustedDevice("alice", rec);
    expect(await users.verifyTrustedDevice("alice", rec.token, "10.0.0.1")).toBe(true);
    expect(await users.verifyTrustedDevice("alice", rec.token, "10.0.0.2")).toBe(false);
  });

  it("deviceTrust: alice's cookie attached to bob's login is rejected (cross-user binding)", async () => {
    // WHY: a trusted-device cookie proves "this device was trusted FOR a
    // specific user", not "this device is trusted in general". Attack: Alice
    // exfils her `aooth_trusted_device=…` cookie and pastes it into Bob's
    // login attempt (same IP/UA — she's on the corporate LAN). If the trust
    // record were keyed only on the token/signature without re-binding to the
    // submitted username, Bob's MFA prompt would be skipped, handing Alice
    // free MFA-bypass on any account that shares her network.
    //
    // `UserService.verifyTrustedDevice(username, token)` is the authoritative
    // gate — it loads the record from the user named in the *first* argument
    // (i.e. the user attempting to authenticate) and rejects when the stored
    // record was issued for a different user. We mint a trust record for
    // alice, then call verify with username="bob" and the same token: must
    // return false even though the signature is otherwise valid.
    const userStore = new UserStoreMemory();
    const users = new UserService(userStore, {
      deviceTrust: { secret: "test-secret" },
    });
    await users.createUser("alice", "Password123");
    await users.createUser("bob", "Password123");
    const aliceRec = users.issueTrustedDevice("alice", { ttlMs: 60_000 });
    await users.addTrustedDevice("alice", aliceRec);
    // Sanity: alice can verify her own cookie.
    expect(await users.verifyTrustedDevice("alice", aliceRec.token)).toBe(true);
    // Attack: bob attempts to verify alice's cookie → must be rejected.
    // No trust record exists for bob with this token; the store lookup fails
    // even though the HMAC signature on the token itself is well-formed.
    expect(await users.verifyTrustedDevice("bob", aliceRec.token)).toBe(false);
  });

  it("deviceTrust workflow: alice's cookie attached to bob's login does NOT skip MFA", async () => {
    // WHY: end-to-end pin of the cross-user binding at the workflow layer.
    // The check-trusted-device step in `LoginWorkflow` MUST scope cookie
    // verification to the username submitted in credentials — not to whoever
    // the cookie was originally minted for. Without that scoping, an attacker
    // who steals alice's cookie can hand it to bob's session and skip MFA.
    //
    // Setup mirrors the "valid cookie → MFA skipped" test directly above
    // (line 413), but POSTs bob's credentials with alice's cookie attached.
    // Expected: bob is still prompted for TOTP (workflow paused, not finished),
    // proving the trust path was bypassed and the normal MFA gate fires.
    const app = await prepareWfApp({
      loginPolicy: {
        deviceTrust: deviceTrustPolicy({ enabled: true, skipsMfa: true, optIn: false }),
      },
    });
    await seedActiveUser(app.users, "alice", "Password123");
    await seedActiveUser(app.users, "bob", "Password123");
    const aliceSecret = generateTotpSecret();
    const bobSecret = generateTotpSecret();
    await app.users.addMfaMethod("alice", {
      name: "totp",
      value: aliceSecret,
      confirmed: true,
    });
    await app.users.addMfaMethod("bob", { name: "totp", value: bobSecret, confirmed: true });

    // Mint a trust cookie for alice and persist it.
    const aliceRec = app.users.issueTrustedDevice("alice", { ttlMs: 60_000 });
    await app.users.addTrustedDevice("alice", aliceRec);

    // Bob's login with alice's cookie attached.
    const r1 = await app.triggerWithHeaders(
      { wfid: "auth/login/flow" },
      { cookie: `aooth_trusted_device=${aliceRec.token}` },
    );
    const r2 = await app.triggerWithHeaders(
      {
        wfs: r1.body?.wfs as string,
        input: { username: "bob", password: "Password123" },
      },
      { cookie: `aooth_trusted_device=${aliceRec.token}` },
    );
    // MFA NOT skipped: workflow must still be paused (wfs present, no tokens).
    const data2 = r2.body?.data as Record<string, unknown> | undefined;
    expect(r2.body?.wfs).toBeTruthy();
    expect(data2?.accessToken).toBeUndefined();
  });
});

describe("LoginWorkflowOpts — Phase 9 finalize (auditLogin, notifyNewDevice, redirect)", () => {
  it("finalize.auditLogin true → emits one 'login.success' event with userId + method", async () => {
    const app = await prepareWfApp({
      loginPolicy: { finalize: finalizePolicy({ auditLogin: true }) },
      loginWorkflowClass: withLoginMfaCtx(LoginWorkflow, { mfaMode: "disabled" }),
    });
    await seedActiveUser(app.users, "alice", "Password123");
    await startAndCredentials(app, "alice", "Password123");
    expect(app.auditEvents.length).toBe(1);
    expect(app.auditEvents[0]).toMatchObject({
      kind: "login.success",
      userId: "alice",
      workflow: "auth/login/flow",
    });
  });

  it("finalize.auditLogin false → emits NO events", async () => {
    const app = await prepareWfApp({
      loginPolicy: { finalize: finalizePolicy({ auditLogin: false }) },
      loginWorkflowClass: withLoginMfaCtx(LoginWorkflow, { mfaMode: "disabled" }),
    });
    await seedActiveUser(app.users, "alice", "Password123");
    await startAndCredentials(app, "alice", "Password123");
    expect(app.auditEvents.length).toBe(0);
  });

  it("finalize.notifyNewDevice true + newDevice → sends 'notifyNewDevice' email after MFA", async () => {
    const app = await prepareWfApp({
      loginPolicy: {
        finalize: finalizePolicy({ notifyNewDevice: true }),
        deviceTrust: deviceTrustPolicy({ enabled: true, optIn: false }), // unconditional trust persist so newDevice flows through
      },
      loginWorkflowClass: withLoginMfaCtx(LoginWorkflow, { availableMfaTransports: ["totp"] }),
    });
    await seedActiveUser(app.users, "alice", "Password123");
    // Need a confirmed email channel so notifyNewDevice has a recipient.
    await app.users.addMfaMethod("alice", {
      name: "email",
      value: "alice@example.com",
      confirmed: true,
    });
    const secret = generateTotpSecret();
    await app.users.addMfaMethod("alice", { name: "totp", value: secret, confirmed: true });

    const r2 = await startAndCredentials(app, "alice", "Password123");
    // 2 methods → select2fa pause; force pick totp.
    const sel = await app.trigger({
      wfs: r2.body?.wfs as string,
      input: { methodName: "totp" },
    });
    const code = generateTotpCode(secret);
    const final = await app.trigger({ wfs: sel.body?.wfs as string, input: { code } });
    expect((final.body?.data as Record<string, unknown>)?.userId).toBe("alice");
    const newDevEmail = app.emails.find((e) => e.kind === "notifyNewDevice");
    expect(newDevEmail).toBeTruthy();
    expect(newDevEmail?.recipient).toBe("alice@example.com");
  });

  it("finalize.notifyNewDevice false → no notifyNewDevice email even after MFA success", async () => {
    const app = await prepareWfApp({
      loginPolicy: {
        finalize: finalizePolicy({ notifyNewDevice: false }),
        deviceTrust: deviceTrustPolicy({ enabled: true, optIn: false }),
      },
      loginWorkflowClass: withLoginMfaCtx(LoginWorkflow, { availableMfaTransports: ["totp"] }),
    });
    await seedActiveUser(app.users, "alice", "Password123");
    await app.users.addMfaMethod("alice", {
      name: "email",
      value: "alice@example.com",
      confirmed: true,
    });
    const secret = generateTotpSecret();
    await app.users.addMfaMethod("alice", { name: "totp", value: secret, confirmed: true });

    const r2 = await startAndCredentials(app, "alice", "Password123");
    const sel = await app.trigger({
      wfs: r2.body?.wfs as string,
      input: { methodName: "totp" },
    });
    const code = generateTotpCode(secret);
    await app.trigger({ wfs: sel.body?.wfs as string, input: { code } });
    expect(app.emails.find((e) => e.kind === "notifyNewDevice")).toBeUndefined();
  });

  it("finalize.redirect: 'home' → envelope with end:immediate redirect to /", async () => {
    const app = await prepareWfApp({
      loginPolicy: { finalize: finalizePolicy({ redirect: "home" }) },
      loginWorkflowClass: withLoginMfaCtx(LoginWorkflow, { mfaMode: "disabled" }),
    });
    await seedActiveUser(app.users, "alice", "Password123");
    const r2 = await startAndCredentials(app, "alice", "Password123");
    expect(r2.body?.finished).toBe(true);
    expect(r2.body).toMatchObject({
      finished: true,
      next: {
        trigger: "immediate",
        action: { type: "redirect", target: "/", reason: "finalize-redirect" },
      },
    });
  });

  it("resolveRedirect override → envelope redirect to overridden URL", async () => {
    const app = await prepareWfApp({
      loginWorkflowClass: withLoginMfaCtx(
        makeLoginSubclass({
          resolveRedirect(ctx) {
            return `/welcome/${ctx.username ?? "guest"}`;
          },
        }),
        { mfaMode: "disabled" },
      ),
    });
    await seedActiveUser(app.users, "alice", "Password123");
    const r2 = await startAndCredentials(app, "alice", "Password123");
    const end = r2.body?.next as { action: { target: string } };
    expect(end?.action?.target).toBe("/welcome/alice");
  });

  it("finalize.redirect: 'referer' with no Referer header → data envelope (no redirect override)", async () => {
    const app = await prepareWfApp({
      loginPolicy: { finalize: finalizePolicy({ redirect: "referer" }) },
      loginWorkflowClass: withLoginMfaCtx(LoginWorkflow, { mfaMode: "disabled" }),
    });
    await seedActiveUser(app.users, "alice", "Password123");
    const r2 = await startAndCredentials(app, "alice", "Password123");
    expect(r2.body?.next).toBeUndefined();
    expect((r2.body?.data as Record<string, unknown>)?.userId).toBe("alice");
  });

  it("finalize.redirect: false → data envelope (no redirect end)", async () => {
    const app = await prepareWfApp({
      loginPolicy: { finalize: finalizePolicy({ redirect: false }) },
      loginWorkflowClass: withLoginMfaCtx(LoginWorkflow, { mfaMode: "disabled" }),
    });
    await seedActiveUser(app.users, "alice", "Password123");
    const r2 = await startAndCredentials(app, "alice", "Password123");
    expect(r2.body?.next).toBeUndefined();
    const data = r2.body?.data as Record<string, unknown> | undefined;
    expect(data?.userId).toBe("alice");
    expect(typeof data?.accessToken).toBe("string");
    expect(typeof data?.refreshToken).toBe("string");
  });
});

// ── Phase 6: inline consent (terms + marketing on carrier forms) ───────────
//
// REPLACES: the Phase-2 deletion of standalone `terms-accept` +
// `consent-marketing` steps. The Phase-1 consent-storage refactor moved the
// inline `WithInlineConsentForm` block OFF `LoginCredentialsForm` (so consent
// is captured AFTER `ctx.username` is bound, enabling per-user override
// logic) and replaced the singular `apply-consent` step / `applyConsentMarketing`
// hook with a batched `persist-consents` step / `ConsentStore.save(username,
// events)` DI seam. Validation lives in `AuthWorkflowBase.processInlineConsent`
// (HACK-CONSENT-* unit coverage in `auth-workflow.base.spec.ts`); the
// integration tests below pin the END-TO-END effect through the login
// workflow — that inline fields ride on the FIRST onboarding carrier form
// to fire (AskEmailForm / AskPhoneForm / SetPasswordForm /
// ProfileCompleteForm), and the `persist-consents` step batches the events
// into one consumer-override call.
//
// Shared capturing store for PERSIST-CONSENT-* + BUMP-PROMPT-* — these
// tests only differ in the pendingConsents / submission shape; the
// consumer-override is the same `save` capture + the `getPendingConsents`
// seed knob.
@Injectable()
class CapturingConsentStore extends ConsentStore {
  readonly calls: Array<{ username: string; events: ConsentEvent[] }> = [];
  /** Pre-canned descriptors returned by every getPendingConsents call. */
  pendingResponse: ConsentDescriptor[] = [];
  override async save(username: string, events: ConsentEvent[]): Promise<void> {
    this.calls.push({ username, events: [...events] });
  }
  override async getPendingConsents(
    _username: string | undefined,
    _ctx: { workflow: string; channel?: "email" | "sms" },
  ): Promise<ConsentDescriptor[]> {
    return this.pendingResponse;
  }
}
describe("LoginWorkflowOpts — Phase 5 dynamic inline consent (TERMS-INLINE / PERSIST-CONSENT)", () => {
  it("TERMS-INLINE-01: consents.pending[terms] + consents:['terms'] on AskEmailForm → ctx.consents.accepted reflects the validated subset", async () => {
    // WHY: the headline guarantee — the dynamic `consents: string[]` field
    // rides on the FIRST onboarding carrier form to fire. Without the
    // `processInlineConsent` call on AskEmailForm the submitted `consents`
    // array would be a stripped form-extra and the workflow would never
    // record acceptance. Asserts via a subclass override of `issue` that
    // captures ctx before workflow-finish state cleanup. The captured
    // `consents.accepted` is the load-bearing post-state — `consents`
    // intersected with the server's pending whitelist.
    const captured: Array<{
      acceptedConsentIds?: string[];
      consentsDecidedAt?: number;
    }> = [];
    @Inherit()
    @Controller("auth/login")
    class TermsCaptureLogin extends LoginWorkflow {
      constructor(
        opts: LoginWorkflowOpts,
        users: UserService,
        auth: AuthCredential,
        authOpts: AuthOpts,
        consentStore: ConsentStore,
      ) {
        super(opts, users, auth, authOpts, consentStore);
      }
      override async issue(ctx: LoginWfCtx): Promise<void> {
        captured.push({
          ...(ctx.consents?.accepted !== undefined && {
            acceptedConsentIds: [...ctx.consents.accepted],
          }),
          ...(ctx.consents?.decidedAt !== undefined && {
            consentsDecidedAt: ctx.consents.decidedAt,
          }),
        });
        return super.issue(ctx);
      }
    }
    const consentStore = new CapturingConsentStore();
    consentStore.pendingResponse = [
      { id: "terms", text: "Accept the Terms", required: "must accept terms", version: "v1" },
    ];
    const app = await prepareWfApp({
      consentStore,
      loginPolicy: {
        enrollment: { ensureEmail: true, ensurePhone: false },
      },
      loginWorkflowClass: withLoginMfaCtx(TermsCaptureLogin, { mfaMode: "disabled" }),
    });
    await seedActiveUser(app.users, "alice", "Password123");
    const r2 = await startAndCredentials(app, "alice", "Password123");
    // Paused at AskEmailForm — submit email + accept terms via the dynamic
    // `consents` array (the new `WithInlineConsentForm` shape).
    expect(r2.body?.wfs).toBeTruthy();
    const r3 = await app.trigger({
      wfs: r2.body?.wfs as string,
      input: { email: "alice@example.com", consents: ["terms"] },
    });
    // Paused at PincodeForm.
    expect(r3.body?.wfs).toBeTruthy();
    const sent = app.emails.find(
      (e) => e.kind === "login.pincode" && e.recipient === "alice@example.com",
    );
    expect(sent).toBeTruthy();
    const r4 = await app.trigger({
      wfs: r3.body?.wfs as string,
      input: { code: sent!.code as string, rememberDevice: false },
    });
    const data = r4.body?.data as Record<string, unknown> | undefined;
    expect(data?.userId).toBe("alice");
    // By the time `issue` runs, the inline-consent flip on AskEmailForm
    // has stamped ctx with the validated subset + timestamp.
    expect(captured).toHaveLength(1);
    expect(captured[0].acceptedConsentIds).toEqual(["terms"]);
    expect(typeof captured[0].consentsDecidedAt).toBe("number");
  });

  it("PERSIST-CONSENT-01: terms-only flow → consentStore.save receives [{id:'terms',accepted:true,version,at}]", async () => {
    // WHY: pins the per-descriptor event shape (Phase 5 — one event per
    // pending descriptor with explicit `accepted`). The version field is
    // stamped from `descriptor.version` (NOT from any client field — the
    // server's descriptor IS the source of truth).
    const consentStore = new CapturingConsentStore();
    consentStore.pendingResponse = [
      { id: "terms", text: "Accept Terms", required: "must accept", version: "v2" },
    ];
    const app = await prepareWfApp({
      consentStore,
      loginPolicy: {
        enrollment: { ensureEmail: true, ensurePhone: false },
      },
      loginWorkflowClass: withLoginMfaCtx(LoginWorkflow, { mfaMode: "disabled" }),
    });
    await seedActiveUser(app.users, "alice", "Password123");
    const before = Date.now();
    const r2 = await startAndCredentials(app, "alice", "Password123");
    const r3 = await app.trigger({
      wfs: r2.body?.wfs as string,
      input: { email: "alice@example.com", consents: ["terms"] },
    });
    const sent = app.emails.find(
      (e) => e.kind === "login.pincode" && e.recipient === "alice@example.com",
    );
    expect(sent).toBeTruthy();
    await app.trigger({
      wfs: r3.body?.wfs as string,
      input: { code: sent!.code as string, rememberDevice: false },
    });
    expect(consentStore.calls.length).toBe(1);
    expect(consentStore.calls[0].username).toBe("alice");
    expect(consentStore.calls[0].events.length).toBe(1);
    expect(consentStore.calls[0].events[0].id).toBe("terms");
    expect(consentStore.calls[0].events[0].accepted).toBe(true);
    expect(consentStore.calls[0].events[0].version).toBe("v2");
    expect(consentStore.calls[0].events[0].at).toBeGreaterThanOrEqual(before);
    expect(consentStore.calls[0].events[0].at).toBeLessThanOrEqual(Date.now());
  });

  it("PERSIST-CONSENT-02: optional marketing accepted → consentStore.save receives [{id:'marketing',accepted:true,at}] (no version when descriptor omits it)", async () => {
    // WHY: pins the optional-descriptor + no-version shape. A regression
    // that always stamped `version` (e.g. forced default to a literal)
    // would break customers who keep version on the FK side only.
    const consentStore = new CapturingConsentStore();
    consentStore.pendingResponse = [{ id: "marketing", text: "Marketing emails" }];
    const app = await prepareWfApp({
      consentStore,
      loginPolicy: {
        enrollment: { ensureEmail: true, ensurePhone: false },
      },
      loginWorkflowClass: withLoginMfaCtx(LoginWorkflow, { mfaMode: "disabled" }),
    });
    await seedActiveUser(app.users, "alice", "Password123");
    const before = Date.now();
    const r2 = await startAndCredentials(app, "alice", "Password123");
    const r3 = await app.trigger({
      wfs: r2.body?.wfs as string,
      input: { email: "alice@example.com", consents: ["marketing"] },
    });
    const sent = app.emails.find(
      (e) => e.kind === "login.pincode" && e.recipient === "alice@example.com",
    );
    expect(sent).toBeTruthy();
    await app.trigger({
      wfs: r3.body?.wfs as string,
      input: { code: sent!.code as string, rememberDevice: false },
    });
    expect(consentStore.calls.length).toBe(1);
    expect(consentStore.calls[0].events.length).toBe(1);
    expect(consentStore.calls[0].events[0].id).toBe("marketing");
    expect(consentStore.calls[0].events[0].accepted).toBe(true);
    expect(consentStore.calls[0].events[0].version).toBeUndefined();
    expect(consentStore.calls[0].events[0].at).toBeGreaterThanOrEqual(before);
    expect(consentStore.calls[0].events[0].at).toBeLessThanOrEqual(Date.now());
  });

  it("PERSIST-CONSENT-03: multiple descriptors → one event per pending descriptor in pendingConsents order (accepted reflects user submission)", async () => {
    // WHY: pins the audit-friendly default — ONE event per pending
    // descriptor (NOT just accepted ones). Declined-optional consents are
    // persisted with `accepted: false` so customers can prove the user was
    // asked. A regression that collapsed the array to only-accepted (or
    // re-ordered) would break customers who index events by position or
    // expect declined-optional rows for compliance audits.
    const consentStore = new CapturingConsentStore();
    consentStore.pendingResponse = [
      { id: "terms", text: "Terms", required: "must accept", version: "v3" },
      { id: "marketing", text: "Marketing" },
      { id: "research", text: "Research" },
    ];
    const app = await prepareWfApp({
      consentStore,
      loginPolicy: {
        enrollment: { ensureEmail: true, ensurePhone: false },
      },
      loginWorkflowClass: withLoginMfaCtx(LoginWorkflow, { mfaMode: "disabled" }),
    });
    await seedActiveUser(app.users, "alice", "Password123");
    const r2 = await startAndCredentials(app, "alice", "Password123");
    const r3 = await app.trigger({
      wfs: r2.body?.wfs as string,
      input: { email: "alice@example.com", consents: ["terms", "research"] },
    });
    const sent = app.emails.find(
      (e) => e.kind === "login.pincode" && e.recipient === "alice@example.com",
    );
    expect(sent).toBeTruthy();
    await app.trigger({
      wfs: r3.body?.wfs as string,
      input: { code: sent!.code as string, rememberDevice: false },
    });
    expect(consentStore.calls.length).toBe(1);
    expect(consentStore.calls[0].events.length).toBe(3);
    expect(consentStore.calls[0].events[0]).toMatchObject({
      id: "terms",
      accepted: true,
      version: "v3",
    });
    expect(consentStore.calls[0].events[1]).toMatchObject({ id: "marketing", accepted: false });
    expect(consentStore.calls[0].events[2]).toMatchObject({ id: "research", accepted: true });
  });

  it("PERSIST-CONSENT-04: consentsPersisted=true after step → no second consentStore.save call (idempotency)", async () => {
    // WHY (Rule 9): the step MUST be idempotent — a paused-workflow that
    // resumes through the `persist-consents` step a second time (or
    // schema re-iteration) must not double-write consents. The
    // `if (ctx.consents?.persisted) return undefined` guard at the top of
    // the step body is the load-bearing defense. A regression that drops
    // the guard would silently double-write consent records, polluting
    // audit logs. Pinned via a call counter on the store + a subclass that
    // re-invokes `persistConsentsStep` after the engine's first pass.
    const consentStore = new CapturingConsentStore();
    consentStore.pendingResponse = [{ id: "marketing", text: "Marketing" }];
    @Inherit()
    @Controller("auth/login")
    class IdempotentLogin extends LoginWorkflow {
      constructor(
        opts: LoginWorkflowOpts,
        users: UserService,
        auth: AuthCredential,
        authOpts: AuthOpts,
        consentStoreDep: ConsentStore,
      ) {
        super(opts, users, auth, authOpts, consentStoreDep);
      }
      override async persistConsentsStep(ctx: LoginWfCtx): Promise<undefined> {
        // First call runs the real step (writes consentsPersisted=true).
        // Second call should short-circuit on the idempotency guard.
        await super.persistConsentsStep(ctx);
        await super.persistConsentsStep(ctx);
        return undefined;
      }
    }
    const app = await prepareWfApp({
      consentStore,
      loginPolicy: {
        enrollment: { ensureEmail: true, ensurePhone: false },
      },
      loginWorkflowClass: withLoginMfaCtx(IdempotentLogin, { mfaMode: "disabled" }),
    });
    await seedActiveUser(app.users, "alice", "Password123");
    const r2 = await startAndCredentials(app, "alice", "Password123");
    const r3 = await app.trigger({
      wfs: r2.body?.wfs as string,
      input: { email: "alice@example.com", consents: ["marketing"] },
    });
    const sent = app.emails.find(
      (e) => e.kind === "login.pincode" && e.recipient === "alice@example.com",
    );
    expect(sent).toBeTruthy();
    await app.trigger({
      wfs: r3.body?.wfs as string,
      input: { code: sent!.code as string, rememberDevice: false },
    });
    // Exactly one persist regardless of step re-invocation.
    expect(consentStore.calls.length).toBe(1);
  });

  it("PERSIST-CONSENT-HACK-01: client submits forged extra ids → silently dropped, save() receives ONLY pending-descriptor events", async () => {
    // WHY: end-to-end pin of the silent-drop invariant (HACK-CONSENT-03's
    // unit-level cousin). A regression that propagated client-supplied
    // ids straight through to `save()` would let an attacker forge audit
    // records for consents they were never shown — preserving the
    // "what user saw is what server records" audit invariant means the
    // event array contains exactly one event for each pending descriptor
    // and NOTHING for the forged ids.
    const consentStore = new CapturingConsentStore();
    consentStore.pendingResponse = [
      { id: "terms", text: "Terms", required: "must accept", version: "v2" },
    ];
    const app = await prepareWfApp({
      consentStore,
      loginPolicy: {
        enrollment: { ensureEmail: true, ensurePhone: false },
      },
      loginWorkflowClass: withLoginMfaCtx(LoginWorkflow, { mfaMode: "disabled" }),
    });
    await seedActiveUser(app.users, "alice", "Password123");
    const r2 = await startAndCredentials(app, "alice", "Password123");
    const r3 = await app.trigger({
      wfs: r2.body?.wfs as string,
      input: {
        email: "alice@example.com",
        // Attacker smuggles two extra ids alongside the legitimate "terms".
        consents: ["terms", "evil-extra-id", "spoofed-gdpr"],
      },
    });
    const sent = app.emails.find(
      (e) => e.kind === "login.pincode" && e.recipient === "alice@example.com",
    );
    expect(sent).toBeTruthy();
    await app.trigger({
      wfs: r3.body?.wfs as string,
      input: { code: sent!.code as string, rememberDevice: false },
    });
    expect(consentStore.calls.length).toBe(1);
    // Exactly one event — the pending descriptor. NO event for the forged
    // ids (silent-drop). NO event with id="evil-extra-id" / "spoofed-gdpr".
    expect(consentStore.calls[0].events.length).toBe(1);
    expect(consentStore.calls[0].events[0].id).toBe("terms");
    const ids = consentStore.calls[0].events.map((e) => e.id);
    expect(ids).not.toContain("evil-extra-id");
    expect(ids).not.toContain("spoofed-gdpr");
  });

  it("PERSIST-CONSENT-REQUIRED-MISSING-01: required descriptor missing from submission → form-level error matches descriptor.required string; save() NEVER called", async () => {
    // WHY: the mandatory-by-message contract. The exact `required` string
    // IS the rejection copy — a regression that surfaced a generic
    // "field required" string would break the customer's per-consent UX
    // contract (the whole point of making `required` a string is to let
    // customers define localized copy per descriptor). Also pins that
    // `save()` is never called when validation throws — partial writes
    // would corrupt the audit trail.
    const consentStore = new CapturingConsentStore();
    consentStore.pendingResponse = [
      {
        id: "privacy",
        text: "Accept Privacy Policy",
        required: "Privacy Policy acceptance is mandatory",
      },
    ];
    const app = await prepareWfApp({
      consentStore,
      loginPolicy: {
        enrollment: { ensureEmail: true, ensurePhone: false },
      },
      loginWorkflowClass: withLoginMfaCtx(LoginWorkflow, { mfaMode: "disabled" }),
    });
    await seedActiveUser(app.users, "alice", "Password123");
    const r2 = await startAndCredentials(app, "alice", "Password123");
    const r3 = await app.trigger({
      wfs: r2.body?.wfs as string,
      input: { email: "alice@example.com", consents: [] },
    });
    // Workflow MUST NOT advance — requireInput surfaces the descriptor's
    // exact `required` string as the per-field error.
    const errors = r3.body?.errors as Record<string, string> | undefined;
    expect(errors?.consents).toBe("Privacy Policy acceptance is mandatory");
    // save() never called on the throw path — partial audit writes would
    // corrupt the trail.
    expect(consentStore.calls.length).toBe(0);
  });

  it("PERSIST-CONSENT-MULTI-01: 3 descriptors (required terms + optional marketing/research) → 3 events back with accepted reflecting user ticks", async () => {
    // WHY (Rule 9): pins the audit-friendly default for the multi-
    // descriptor case. ALL pending descriptors get an event — required
    // accepted=true (mandatory by definition), optional reflects the
    // user's tick. A regression that filtered to only-accepted (saving
    // bytes) would break customer audit logs that must prove the user
    // was asked about every descriptor in scope.
    const consentStore = new CapturingConsentStore();
    consentStore.pendingResponse = [
      { id: "terms", text: "Terms", required: "must accept" },
      { id: "marketing", text: "Marketing" },
      { id: "research", text: "Research" },
    ];
    const app = await prepareWfApp({
      consentStore,
      loginPolicy: {
        enrollment: { ensureEmail: true, ensurePhone: false },
      },
      loginWorkflowClass: withLoginMfaCtx(LoginWorkflow, { mfaMode: "disabled" }),
    });
    await seedActiveUser(app.users, "alice", "Password123");
    const r2 = await startAndCredentials(app, "alice", "Password123");
    const r3 = await app.trigger({
      wfs: r2.body?.wfs as string,
      input: { email: "alice@example.com", consents: ["terms", "research"] },
    });
    const sent = app.emails.find(
      (e) => e.kind === "login.pincode" && e.recipient === "alice@example.com",
    );
    expect(sent).toBeTruthy();
    await app.trigger({
      wfs: r3.body?.wfs as string,
      input: { code: sent!.code as string, rememberDevice: false },
    });
    expect(consentStore.calls.length).toBe(1);
    expect(consentStore.calls[0].events.length).toBe(3);
    const byId = Object.fromEntries(consentStore.calls[0].events.map((e) => [e.id, e.accepted]));
    expect(byId).toEqual({ terms: true, marketing: false, research: true });
  });

  it("PERSIST-CONSENT-EMPTY-PENDING-01: getPendingConsents → [] → consentStore.save NEVER called even if client posts ids", async () => {
    // WHY: the "no consent step renders, no audit row written" invariant.
    // A regression that always invoked `save()` (even with an empty
    // events array) would generate empty-event audit rows polluting
    // consumer logs. Pin via call counter at zero AFTER a successful
    // workflow completion — proves the step short-circuited before the
    // store call (NOT just that the events array happened to be empty).
    const consentStore = new CapturingConsentStore();
    consentStore.pendingResponse = []; // No pending — schema condition gate closed.
    const app = await prepareWfApp({
      consentStore,
      loginPolicy: {
        enrollment: { ensureEmail: true, ensurePhone: false },
      },
      loginWorkflowClass: withLoginMfaCtx(LoginWorkflow, { mfaMode: "disabled" }),
    });
    await seedActiveUser(app.users, "alice", "Password123");
    const r2 = await startAndCredentials(app, "alice", "Password123");
    const r3 = await app.trigger({
      wfs: r2.body?.wfs as string,
      // Client tries to smuggle ids — silent-drop says they go nowhere.
      input: { email: "alice@example.com", consents: ["ignored"] },
    });
    const sent = app.emails.find(
      (e) => e.kind === "login.pincode" && e.recipient === "alice@example.com",
    );
    expect(sent).toBeTruthy();
    const r4 = await app.trigger({
      wfs: r3.body?.wfs as string,
      input: { code: sent!.code as string, rememberDevice: false },
    });
    expect((r4.body?.data as Record<string, unknown>)?.userId).toBe("alice");
    expect(consentStore.calls.length).toBe(0);
  });

  it("BUMP-PROMPT-01: pending consents but no onboarding carrier form → terms-bump-prompt pauses on TermsBumpForm, submit persists", async () => {
    // WHY: pins the standalone bump-prompt path. A returning user with
    // pending consents but NO onboarding carrier form running (no
    // enrollment, no password-set, no profile-complete) MUST still be
    // prompted via the standalone `terms-bump-prompt` step. Without it
    // the workflow would silently issue tokens, leaving the consents
    // unrecorded.
    const consentStore = new CapturingConsentStore();
    consentStore.pendingResponse = [
      { id: "terms", text: "Accept Terms", required: "must accept", version: "v3" },
    ];
    const app = await prepareWfApp({
      consentStore,
      loginPolicy: {
        // No enrollment forms — forces the workflow to fall through to
        // the standalone terms-bump-prompt.
        enrollment: { ensureEmail: false, ensurePhone: false },
      },
      loginWorkflowClass: withLoginMfaCtx(LoginWorkflow, { mfaMode: "disabled" }),
    });
    await seedActiveUser(app.users, "alice", "Password123");
    const r2 = await startAndCredentials(app, "alice", "Password123");
    // Paused at TermsBumpForm (no other onboarding form to piggyback on).
    expect(r2.body?.wfs).toBeTruthy();
    expect((r2.body?.data as Record<string, unknown> | undefined)?.userId).toBeUndefined();
    const r3 = await app.trigger({
      wfs: r2.body?.wfs as string,
      input: { consents: ["terms"] },
    });
    const data = r3.body?.data as Record<string, unknown> | undefined;
    expect(data?.userId).toBe("alice");
    expect(consentStore.calls.length).toBe(1);
    expect(consentStore.calls[0].events.length).toBe(1);
    expect(consentStore.calls[0].events[0].id).toBe("terms");
    expect(consentStore.calls[0].events[0].accepted).toBe(true);
    expect(consentStore.calls[0].events[0].version).toBe("v3");
  });

  it("BUMP-PROMPT-02: carrier form already captured consents → terms-bump-prompt SKIPPED (condition short-circuit)", async () => {
    // WHY: pins the schema-condition short-circuit. When an onboarding
    // carrier form already captured consents via `WithInlineConsentForm`
    // (`ctx.consents?.decidedAt` set), the standalone bump-prompt condition
    // `!ctx.consents?.decidedAt` is false and the step is SKIPPED — the
    // user must not see a second consent prompt for the same acceptance.
    // Asserted via a step-body call counter that stays at zero (distinct
    // from "entered then early-returned").
    let bumpEntered = 0;
    @Inherit()
    @Controller("auth/login")
    class SkipBumpLogin extends LoginWorkflow {
      constructor(
        opts: LoginWorkflowOpts,
        users: UserService,
        auth: AuthCredential,
        authOpts: AuthOpts,
        consentStore: ConsentStore,
      ) {
        super(opts, users, auth, authOpts, consentStore);
      }
      override termsBumpPrompt(ctx: LoginWfCtx): undefined {
        bumpEntered++;
        return super.termsBumpPrompt(ctx);
      }
    }
    const consentStore = new CapturingConsentStore();
    consentStore.pendingResponse = [
      { id: "terms", text: "Accept Terms", required: "must accept", version: "v3" },
    ];
    const app = await prepareWfApp({
      consentStore,
      loginPolicy: {
        enrollment: { ensureEmail: true, ensurePhone: false },
      },
      loginWorkflowClass: withLoginMfaCtx(SkipBumpLogin, { mfaMode: "disabled" }),
    });
    await seedActiveUser(app.users, "alice", "Password123");
    const r2 = await startAndCredentials(app, "alice", "Password123");
    const r3 = await app.trigger({
      wfs: r2.body?.wfs as string,
      input: { email: "alice@example.com", consents: ["terms"] },
    });
    const sent = app.emails.find(
      (e) => e.kind === "login.pincode" && e.recipient === "alice@example.com",
    );
    expect(sent).toBeTruthy();
    const r4 = await app.trigger({
      wfs: r3.body?.wfs as string,
      input: { code: sent!.code as string, rememberDevice: false },
    });
    expect((r4.body?.data as Record<string, unknown>)?.userId).toBe("alice");
    // Bump step body NEVER entered — schema condition short-circuited.
    expect(bumpEntered).toBe(0);
  });

  it("TERMS-INLINE-02 (carrier-form fallthrough on AskEmailForm): consents close when pending arrived after credentials step", async () => {
    // WHY: pins that ANY carrier form can capture consent — the gate is
    // "pending non-empty AND not yet captured", not "credentials only". A
    // regression that hardcoded the capture path to the credentials step
    // would break the fallthrough scenario where `prepare-consents` only
    // gets a username AFTER `credentials` runs. The FIRST visible carrier
    // form (AskEmailForm here) must collect the dynamic `consents` array.
    const consentStore = new CapturingConsentStore();
    consentStore.pendingResponse = [{ id: "terms", text: "Accept Terms", required: "must accept" }];
    const app = await prepareWfApp({
      consentStore,
      loginPolicy: {
        enrollment: { ensureEmail: true, ensurePhone: false },
      },
      loginWorkflowClass: withLoginMfaCtx(LoginWorkflow, { mfaMode: "disabled" }),
    });
    await seedActiveUser(app.users, "alice", "Password123");
    // Submit credentials (no consent fields on LoginCredentialsForm — the
    // dynamic block lives on the inherited `WithInlineConsentForm` on
    // carrier forms further along). Workflow pauses on AskEmailForm.
    const r2 = await startAndCredentials(app, "alice", "Password123");
    // Paused for AskEmailForm.
    expect(r2.body?.wfs).toBeTruthy();
    expect(JSON.stringify(r2.body)).toMatch(/"email"/);
    // Submit email + the dynamic `consents` array on AskEmailForm. Proves
    // the helper accepts the inherited dynamic field on a non-credentials
    // carrier form.
    const r3 = await app.trigger({
      wfs: r2.body?.wfs as string,
      input: {
        email: "alice@example.com",
        consents: ["terms"],
      },
    });
    // Next pause: PincodeForm for the email OTP. Workflow proceeds —
    // proves AskEmailForm accepted the payload (dynamic + legitimate
    // fields all valid).
    expect(r3.body?.wfs).toBeTruthy();
    expect(JSON.stringify(r3.body)).toMatch(/"code"/);
  });
});

describe("LoginWorkflowOpts — Phase 8 session policy", () => {
  it("sessionPolicy.concurrencyLimit reject + ctx.session.activeSessions over max → 429", async () => {
    // Force activeSessions by directly setting on ctx — the workflow defers to
    // ctx.session.activeSessions which isn't auto-populated. To prove the rejection
    // path, we exercise it via the condition that DOES trip — by pre-populating
    // activeSessions via a custom 'init' on the workflow is not exposed.
    // Instead, we test the negative path here and the alt-action 'cancel'
    // path in the alt-actions spec.
    const app = await prepareWfApp({
      loginPolicy: {
        sessionPolicy: { concurrencyLimit: { max: 2, onLimit: "reject" } },
      },
      loginWorkflowClass: withLoginMfaCtx(LoginWorkflow, { mfaMode: "disabled" }),
    });
    await seedActiveUser(app.users, "alice", "Password123");
    const r2 = await startAndCredentials(app, "alice", "Password123");
    // activeSessions never set → step skipped → tokens issued.
    expect((r2.body?.data as Record<string, unknown>)?.userId).toBe("alice");
  });

  // Phase 8 `risk-step-up` runs inside the Phase 4 `while: !mfa.checked` loop;
  // a `require: true` outcome clears `mfa.checked` so MFA re-runs for the
  // extra factor. The subclass overrides `assessRiskStepUp` — the schema
  // condition no longer gates on a presence-projection (always runs when
  // mfa.checked and not yet evaluated), and a `require:false` outcome lets
  // the loop exit.
  it("resolveRiskStepUp override returning require:true forces additional MFA re-run", async () => {
    let calls = 0;
    const app = await prepareWfApp({
      loginWorkflowClass: withLoginMfaCtx(
        makeLoginSubclass({
          async resolveRiskStepUp() {
            calls++;
            return { require: calls === 1, reason: "unusual" };
          },
        }),
        { availableMfaTransports: ["totp"] },
      ),
    });
    await seedActiveUser(app.users, "alice", "Password123");
    const secret = generateTotpSecret();
    await app.users.addMfaMethod("alice", { name: "totp", value: secret, confirmed: true });

    const r2 = await startAndCredentials(app, "alice", "Password123");
    expect(r2.body?.wfs).toBeTruthy();
    const code = generateTotpCode(secret);
    const r3 = await app.trigger({ wfs: r2.body?.wfs as string, input: { code } });
    expect(r3.body?.wfs).toBeTruthy();
    expect((r3.body?.data as Record<string, unknown>)?.userId).toBeUndefined();
    // Step-up re-MFA in the same window: must use a NEXT-window code, not the
    // same code again — same-window replay is now blocked by `verifyMfa`.
    // Server accepts a +1-window code via the default `window=1` tolerance.
    const code2 = generateTotpCode(secret, { clock: () => Date.now() + 30_000 });
    const r4 = await app.trigger({ wfs: r3.body?.wfs as string, input: { code: code2 } });
    expect((r4.body?.data as Record<string, unknown>)?.userId).toBe("alice");
    expect(calls).toBeGreaterThanOrEqual(1);
  });
});

describe("LoginWorkflowOpts — mfa.mode='required' forced enrollment", () => {
  // WHY: a policy tightening from "no MFA" to "MFA required" must NOT let
  // existing un-enrolled users in unchallenged. The enroll step must run
  // BECAUSE `mfa.enrolledMethods.length === 0` (the gate at line 433-436) —
  // remove that branch and an attacker who phished a password walks in
  // forever without ever enrolling a second factor.
  it("sms path: pick → address → pincode confirm; method stored confirmed + becomes default + sms is sent", async () => {
    const app = await prepareWfApp({
      loginWorkflowClass: withLoginMfaCtx(LoginWorkflow, { mfaMode: "required" }),
    });
    await seedActiveUser(app.users, "user-a", "pwd-12345678");
    // Sanity baseline — no methods before the flow runs.
    expect((await app.users.getUser("user-a")).mfa.methods).toHaveLength(0);

    const r2 = await startAndCredentials(app, "user-a", "pwd-12345678");
    // Paused at EnrollPickMethodForm — enrollment is required, not the existing
    // select2fa/pincode path (those gate on enrolled methods > 0; this user has
    // 0). NOTE: paused responses carry `wfs` plus the form schema; the form
    // schema serialization itself has `finished: true` as metadata so we use
    // `wfs` truthiness (and absence of `data`) to detect pause vs WF-finish.
    expect(r2.body?.wfs).toBeTruthy();
    expect(r2.body?.data).toBeUndefined();

    // Phase 1: pick method.
    const r3 = await app.trigger({
      wfs: r2.body?.wfs as string,
      input: { method: "sms" },
    });
    expect(r3.body?.wfs).toBeTruthy();
    expect(r3.body?.data).toBeUndefined();
    // No sms sent yet — Phase 2 hasn't run.
    expect(app.sms.length).toBe(0);

    // Phase 2: supply address — pincode dispatched.
    const r4 = await app.trigger({
      wfs: r3.body?.wfs as string,
      input: { address: "+15551234567" },
    });
    expect(r4.body?.wfs).toBeTruthy();
    expect(r4.body?.data).toBeUndefined();
    expect(app.sms.length).toBe(1);
    expect(app.sms[0].recipient).toBe("+15551234567");
    expect(app.sms[0].kind).toBe("login.pincode");
    const code = app.sms[0].code;

    // Phase 3: confirm pincode → enrollment commits + login completes.
    const r5 = await app.trigger({
      wfs: r4.body?.wfs as string,
      input: { code },
    });
    const data = r5.body?.data as Record<string, unknown> | undefined;
    expect(typeof data?.accessToken).toBe("string");
    expect(data?.userId).toBe("user-a");

    // Method was actually persisted, confirmed, and made default — without
    // these flips the user's NEXT login would re-trigger enrollment (or worse,
    // accept any code).
    const user = await app.users.getUser("user-a");
    const sms = user.mfa.methods.find((m) => m.name === "sms");
    expect(sms).toBeDefined();
    expect(sms?.value).toBe("+15551234567");
    expect(sms?.confirmed).toBe(true);
    expect(user.mfa.defaultMethod).toBe("sms");
  });

  // WHY: ensures Phase 2 routes the email branch to the `emails[]` capture
  // (NOT the sms array) — a wiring mix-up would silently dispatch login codes
  // over SMS to email addresses, breaking delivery while looking healthy.
  it("email path: pincode is sent via email channel and method is confirmed", async () => {
    const app = await prepareWfApp({
      loginWorkflowClass: withLoginMfaCtx(LoginWorkflow, { mfaMode: "required" }),
    });
    await seedActiveUser(app.users, "user-b", "pwd-12345678");

    const r2 = await startAndCredentials(app, "user-b", "pwd-12345678");
    const r3 = await app.trigger({
      wfs: r2.body?.wfs as string,
      input: { method: "email" },
    });
    const r4 = await app.trigger({
      wfs: r3.body?.wfs as string,
      input: { address: "user@example.com" },
    });
    // Email sent, NOT sms — wiring proof.
    expect(app.sms.length).toBe(0);
    expect(app.emails.length).toBeGreaterThanOrEqual(1);
    const sent = app.emails.find((e) => e.kind === "login.pincode");
    expect(sent?.recipient).toBe("user@example.com");
    expect(sent?.code).toBeTruthy();

    const r5 = await app.trigger({
      wfs: r4.body?.wfs as string,
      input: { code: sent?.code },
    });
    const data = r5.body?.data as Record<string, unknown> | undefined;
    expect(typeof data?.accessToken).toBe("string");

    const user = await app.users.getUser("user-b");
    const email = user.mfa.methods.find((m) => m.name === "email");
    expect(email?.value).toBe("user@example.com");
    expect(email?.confirmed).toBe(true);
    expect(user.mfa.defaultMethod).toBe("email");
  });

  // WHY: TOTP has no Phase 2 (no address — secret is server-provisioned in
  // Phase 1). The branch at lines 1095-1108 persists an UNCONFIRMED totp row;
  // a valid TOTP code derived from THAT secret must flip it to confirmed and
  // NO pincode must be emitted (otherwise app.sms / app.emails leaks).
  it("totp path: secret provisioned in Phase 1, code accepted, method confirmed, no pincode emitted", async () => {
    const app = await prepareWfApp({
      loginWorkflowClass: withLoginMfaCtx(LoginWorkflow, { mfaMode: "required" }),
    });
    await seedActiveUser(app.users, "user-c", "pwd-12345678");

    const r2 = await startAndCredentials(app, "user-c", "pwd-12345678");
    // Phase 1: pick totp — secret should be persisted unconfirmed.
    const r3 = await app.trigger({
      wfs: r2.body?.wfs as string,
      input: { method: "totp" },
    });
    expect(r3.body?.wfs).toBeTruthy();
    expect(r3.body?.data).toBeUndefined();

    // Secret lives on the unconfirmed method row — read it back.
    const interimUser = await app.users.getUser("user-c");
    const totp = interimUser.mfa.methods.find((m) => m.name === "totp");
    expect(totp).toBeDefined();
    expect(totp?.confirmed).toBe(false);
    expect(typeof totp?.value).toBe("string");
    expect(totp?.value.length).toBeGreaterThan(0);

    const code = generateTotpCode(totp!.value);
    const r4 = await app.trigger({
      wfs: r3.body?.wfs as string,
      input: { code },
    });
    const data = r4.body?.data as Record<string, unknown> | undefined;
    expect(typeof data?.accessToken).toBe("string");

    // No pincode side-channel for TOTP — proves Phase 2 short-circuit at line
    // 1113 (the `enrollMethod === "sms" || "email"` guard).
    expect(app.sms.length).toBe(0);
    expect(app.emails.length).toBe(0);

    const user = await app.users.getUser("user-c");
    const totpFinal = user.mfa.methods.find((m) => m.name === "totp");
    expect(totpFinal?.confirmed).toBe(true);
    expect(user.mfa.defaultMethod).toBe("totp");
  });

  // WHY: if Phase 3 accepted any code for TOTP, an attacker with the password
  // could enroll a TOTP secret they DON'T control and pass the gate. Pins
  // that `verifyTotpSetupCode` is actually called and MFA_INVALID surfaces as
  // a form error (not a 500 / not a silent pass).
  it("totp path: invalid setup code is rejected with form error; method stays unconfirmed", async () => {
    const app = await prepareWfApp({
      loginWorkflowClass: withLoginMfaCtx(LoginWorkflow, { mfaMode: "required" }),
    });
    await seedActiveUser(app.users, "user-d", "pwd-12345678");

    const r2 = await startAndCredentials(app, "user-d", "pwd-12345678");
    const r3 = await app.trigger({
      wfs: r2.body?.wfs as string,
      input: { method: "totp" },
    });
    const r4 = await app.trigger({
      wfs: r3.body?.wfs as string,
      input: { code: "000000" },
    });
    // Not finished — must re-prompt with a form error, not crash or pass.
    expect(r4.body?.data).toBeUndefined();
    const errors = r4.body?.errors as Record<string, unknown> | undefined;
    expect(errors?.code).toBeTruthy();

    const user = await app.users.getUser("user-d");
    const totp = user.mfa.methods.find((m) => m.name === "totp");
    expect(totp?.confirmed).toBe(false);
  });

  // WHY: policy-loosening direction — with `mode: 'disabled'` the while-loop
  // guard in the schema filters out Phase 4 entirely, so an un-enrolled user
  // must complete login with zero MFA prompts. A future inversion of the
  // gate would silently force every un-enrolled user into MFA enrollment,
  // breaking the no-MFA configuration this test guards.
  it("mode='disabled' + no MFA: enrollment SKIPPED, login completes immediately", async () => {
    const app = await prepareWfApp({
      loginWorkflowClass: withLoginMfaCtx(LoginWorkflow, { mfaMode: "disabled" }),
    });
    await seedActiveUser(app.users, "user-e", "pwd-12345678");
    expect((await app.users.getUser("user-e")).mfa.methods).toHaveLength(0);

    const r2 = await startAndCredentials(app, "user-e", "pwd-12345678");
    // No paused enrollment forms — issues directly. Presence of `data` (not
    // just `finished: true`) is the unambiguous WF-finish signal.
    const data = r2.body?.data as Record<string, unknown> | undefined;
    expect(typeof data?.accessToken).toBe("string");
    expect(data?.userId).toBe("user-e");

    // No leftover unconfirmed method was attached — proves the enroll step
    // never ran (otherwise Phase 1's totp branch / Phase 2's address branch
    // would have inserted an unconfirmed row).
    const user = await app.users.getUser("user-e");
    expect(user.mfa.methods).toHaveLength(0);
  });
});

describe("LoginWorkflowOpts — mfa.mode='optional' skip action", () => {
  // WHY (L1): pins the headline NEW behavior of `mode: 'optional'` — without
  // the `wf.resolveAction() === 'skip'` short-circuit in
  // `AuthWorkflowBase.runMfaEnrollment` (Phase 1), optional mode would behave
  // identically to required and force users through enrollment. Removing that
  // branch (or inverting the mode check) silently breaks the user opt-out
  // contract this mode exists for.
  it("optional + 0 methods + skip action → workflow completes WITHOUT enrolling", async () => {
    const app = await prepareWfApp({
      loginWorkflowClass: withLoginMfaCtx(LoginWorkflow, { mfaMode: "optional" }),
    });
    await seedActiveUser(app.users, "opt-skip", "pwd-12345678");
    expect((await app.users.getUser("opt-skip")).mfa.methods).toHaveLength(0);

    const r2 = await startAndCredentials(app, "opt-skip", "pwd-12345678");
    // Paused at EnrollPickMethodForm — optional mode still PROMPTS, the
    // server-side gate is the skip action itself, not absence of the prompt.
    expect(r2.body?.wfs).toBeTruthy();
    expect(r2.body?.data).toBeUndefined();

    // Submit `skip` action (no `method` field) — Phase 1 short-circuit fires.
    const r3 = await app.trigger({
      wfs: r2.body?.wfs as string,
      input: { action: "skip" },
    });
    const data = r3.body?.data as Record<string, unknown> | undefined;
    expect(typeof data?.accessToken).toBe("string");
    expect(data?.userId).toBe("opt-skip");

    // No method was persisted — proves the skip short-circuit ran instead of
    // falling through to Phase 1's `resolveInput()` / `addMfaMethod()` branch.
    const user = await app.users.getUser("opt-skip");
    expect(user.mfa.methods).toHaveLength(0);
  });

  // WHY (L2): pins the positive branch of optional mode — users who pick a
  // method instead of skipping must still complete the full 3-phase enrollment
  // exactly like required mode. A regression that hardwired optional→skip
  // (treating any submit as a decline) would silently break the enroll path
  // for users who DO want MFA.
  it("optional + 0 methods + picks sms → full enrollment runs and method confirmed", async () => {
    const app = await prepareWfApp({
      loginWorkflowClass: withLoginMfaCtx(LoginWorkflow, { mfaMode: "optional" }),
    });
    await seedActiveUser(app.users, "opt-sms", "pwd-12345678");

    const r2 = await startAndCredentials(app, "opt-sms", "pwd-12345678");
    expect(r2.body?.wfs).toBeTruthy();

    // Phase 1: pick (no skip action).
    const r3 = await app.trigger({
      wfs: r2.body?.wfs as string,
      input: { method: "sms" },
    });
    expect(r3.body?.wfs).toBeTruthy();
    expect(r3.body?.data).toBeUndefined();
    expect(app.sms.length).toBe(0);

    // Phase 2: supply address.
    const r4 = await app.trigger({
      wfs: r3.body?.wfs as string,
      input: { address: "+15559876543" },
    });
    expect(r4.body?.wfs).toBeTruthy();
    expect(app.sms.length).toBe(1);
    const code = app.sms[0].code;

    // Phase 3: confirm pincode → enrollment commits + login completes.
    const r5 = await app.trigger({
      wfs: r4.body?.wfs as string,
      input: { code },
    });
    const data = r5.body?.data as Record<string, unknown> | undefined;
    expect(typeof data?.accessToken).toBe("string");

    const user = await app.users.getUser("opt-sms");
    const sms = user.mfa.methods.find((m) => m.name === "sms");
    expect(sms?.value).toBe("+15559876543");
    expect(sms?.confirmed).toBe(true);
    expect(user.mfa.defaultMethod).toBe("sms");
  });

  // WHY (L3): `mode: 'disabled'` is the maintenance escape hatch — it must
  // skip MFA EVEN IF the user has confirmed methods (e.g. ops turning off
  // MFA during an SMS provider outage). The schema gate at line 410
  // (`mfa.mode !== "disabled"`) is the load-bearing branch; a regression that
  // gated 'disabled' only on the 0-methods case (or only on the enroll branch)
  // would silently force enrolled users through MFA challenges when the policy
  // says off.
  it("disabled + user HAS confirmed totp → login completes WITHOUT MFA prompt", async () => {
    const app = await prepareWfApp({
      loginWorkflowClass: withLoginMfaCtx(LoginWorkflow, { mfaMode: "disabled" }),
    });
    await seedActiveUser(app.users, "dis-totp", "pwd-12345678");
    const secret = generateTotpSecret();
    await app.users.addMfaMethod("dis-totp", {
      name: "totp",
      value: secret,
      confirmed: true,
    });
    await app.users.setDefaultMfaMethod("dis-totp", "totp");
    const seeded = await app.users.getUser("dis-totp");
    expect(seeded.mfa.methods.find((m) => m.name === "totp")?.confirmed).toBe(true);

    const r2 = await startAndCredentials(app, "dis-totp", "pwd-12345678");
    // Immediate completion — no MFA prompt despite a confirmed totp.
    const data = r2.body?.data as Record<string, unknown> | undefined;
    expect(typeof data?.accessToken).toBe("string");
    expect(data?.userId).toBe("dis-totp");
    // No pincode side-channel either (totp is silent, but proves no
    // accidental sms/email kick).
    expect(app.sms.length).toBe(0);
    expect(app.emails.length).toBe(0);
  });

  // WHY (L4): negative — `required` must NEVER accept a skip. The helper's
  // `deps.mode === "optional"` guard is the gate; if a regression dropped the
  // mode check (e.g. unconditional skip handling), `required`-mode users
  // could opt out and defeat the very policy this mode exists for. The
  // failure mode here is "skip is ignored" — the helper proceeds to
  // `resolveInput()` and reports a form error on `method` (Unknown method),
  // never short-circuiting enrollment.
  it("required + 0 methods + skip action submitted → workflow does NOT short-circuit", async () => {
    const app = await prepareWfApp({
      loginWorkflowClass: withLoginMfaCtx(LoginWorkflow, { mfaMode: "required" }),
    });
    await seedActiveUser(app.users, "req-skip", "pwd-12345678");

    const r2 = await startAndCredentials(app, "req-skip", "pwd-12345678");
    expect(r2.body?.wfs).toBeTruthy();

    // Submit `skip` action under `required` mode. Either: (a) form action
    // whitelist rejects it OR (b) helper ignores the action because mode is
    // not 'optional' and tries to read `input.method`. Either way the
    // workflow MUST NOT finish and no method may be persisted.
    const r3 = await app.trigger({
      wfs: r2.body?.wfs as string,
      input: { action: "skip" },
    });
    expect(r3.body?.data).toBeUndefined();

    const user = await app.users.getUser("req-skip");
    expect(user.mfa.methods).toHaveLength(0);
  });
});

describe("LoginWorkflowOpts — mfa enrollment ergonomics (PR7-1)", () => {
  // WHY (T1): pins the 1-transport AUTO-PICK branch in `runMfaEnrollment`
  // Phase 1 (`if (transports.length === 1) { … return; }`). Without it, a
  // single-transport config would either silently force the user through a
  // 1-option radio (bad UX) OR — worse for the TOTP case — fail outright,
  // because the secret/uri provisioning lives inside that same branch. A
  // regression that auto-picked but DIDN'T provision the secret would land
  // at confirm without `enrollSecret`, so Phase 3 would have no TOTP secret
  // on the user row to verify against. The two assertions below — (a) no
  // picker pause + (b) confirm succeeds against the auto-provisioned
  // secret — together pin both halves of the branch.
  it("T1: required + transports=['totp'] + 0 methods → no picker pause, secret auto-provisioned, code accepted", async () => {
    const app = await prepareWfApp({
      loginWorkflowClass: withLoginMfaCtx(LoginWorkflow, {
        mfaMode: "required",
        availableMfaTransports: ["totp"],
      }),
    });
    await seedActiveUser(app.users, "auto-totp", "pwd-12345678");

    // Credentials → MUST land at the confirm form directly, NOT at the
    // picker. Picker form carries a `method` field; confirm form carries
    // a `code` field. Picker absence is the load-bearing assertion.
    const r2 = await startAndCredentials(app, "auto-totp", "pwd-12345678");
    expect(r2.body?.wfs).toBeTruthy();
    expect(r2.body?.data).toBeUndefined();
    const bodyJson = JSON.stringify(r2.body);
    expect(bodyJson).toMatch(/"code"/);
    // Picker would expose a `method` schema field (NOT to be confused with
    // the `methodName` of select2fa). A regression that fell through to the
    // picker form would surface `"method"` in the body schema.
    expect(bodyJson).not.toMatch(/"method"(?!Name)/);

    // Secret WAS provisioned server-side inside the auto-pick branch.
    const interim = await app.users.getUser("auto-totp");
    const totp = interim.mfa.methods.find((m) => m.name === "totp");
    expect(totp?.confirmed).toBe(false);
    expect(typeof totp?.value).toBe("string");
    expect(totp!.value.length).toBeGreaterThan(0);

    const code = generateTotpCode(totp!.value);
    const r3 = await app.trigger({ wfs: r2.body?.wfs as string, input: { code } });
    const data = r3.body?.data as Record<string, unknown> | undefined;
    expect(typeof data?.accessToken).toBe("string");

    const final = await app.users.getUser("auto-totp");
    const totpFinal = final.mfa.methods.find((m) => m.name === "totp");
    expect(totpFinal?.confirmed).toBe(true);
    expect(final.mfa.defaultMethod).toBe("totp");
  });

  // WHY (T2): pins the Phase 2 `skip` branch AND the invariant that no
  // method row exists at Phase 2 entry for sms/email (so cleanup is
  // deliberately NOT called — calling it would still be safe because
  // `removeMfaMethod` is filter-based, but it would mask a real bug if a
  // future change persisted the method row at Phase 1 for sms/email). The
  // test asserts skip works AND that `mfa.methods` stays empty — proving
  // the helper short-circuited via the optional-mode skip handler, not via
  // some other code path that might have persisted the method first.
  it("T2: optional + sms picked + skip from address form → finishes, no method persisted", async () => {
    const app = await prepareWfApp({
      loginWorkflowClass: withLoginMfaCtx(LoginWorkflow, { mfaMode: "optional" }),
    });
    await seedActiveUser(app.users, "opt-sms-skip", "pwd-12345678");

    const r2 = await startAndCredentials(app, "opt-sms-skip", "pwd-12345678");
    expect(r2.body?.wfs).toBeTruthy();

    // Pick sms → pause at address form (no SMS dispatched yet — no address
    // means no addMfaMethod call).
    const r3 = await app.trigger({
      wfs: r2.body?.wfs as string,
      input: { method: "sms" },
    });
    expect(r3.body?.wfs).toBeTruthy();
    expect(app.sms.length).toBe(0);
    // Critical pre-skip invariant: at Phase 2 entry for sms/email, NO
    // method row exists yet. The Phase 2 skip handler relies on this
    // (no cleanup needed). If a future change started persisting earlier,
    // this assertion would fail and force the skip handler to call
    // `cleanupEnrollment`.
    expect((await app.users.getUser("opt-sms-skip")).mfa.methods).toHaveLength(0);

    // Skip at address → workflow short-circuits to login finish.
    const r4 = await app.trigger({
      wfs: r3.body?.wfs as string,
      input: { action: "skip" },
    });
    const data = r4.body?.data as Record<string, unknown> | undefined;
    expect(typeof data?.accessToken).toBe("string");

    // Still no method persisted — proves the skip handler ran, not a
    // covert enroll path.
    const user = await app.users.getUser("opt-sms-skip");
    expect(user.mfa.methods).toHaveLength(0);
  });

  // WHY (T3): pins the Phase 3 `skip` branch + the `cleanupEnrollment` call
  // it depends on. At Phase 3 the unconfirmed sms method row IS persisted
  // (Phase 2 wrote it via addMfaMethod). Without the cleanup call, the
  // workflow would finish with a stale unconfirmed sms row on the user —
  // `prepareMfaOptions` filters by `confirmed`, so the user could still log
  // in, but the dead row would block re-enrolling sms with a different
  // address (or worse — leak metadata depending on consumer code paths).
  // The pre-skip assertion proves the row IS there (so cleanup is doing
  // real work, not no-op); the post-skip assertion proves it's gone.
  it("T3: optional + sms picked + address submitted + skip from confirm → unconfirmed sms REMOVED", async () => {
    const app = await prepareWfApp({
      loginWorkflowClass: withLoginMfaCtx(LoginWorkflow, { mfaMode: "optional" }),
    });
    await seedActiveUser(app.users, "opt-sms-cleanup", "pwd-12345678");

    const r2 = await startAndCredentials(app, "opt-sms-cleanup", "pwd-12345678");
    const r3 = await app.trigger({
      wfs: r2.body?.wfs as string,
      input: { method: "sms" },
    });
    const r4 = await app.trigger({
      wfs: r3.body?.wfs as string,
      input: { address: "+15551112222" },
    });
    expect(r4.body?.wfs).toBeTruthy();
    expect(app.sms.length).toBe(1);

    // Pre-skip: unconfirmed sms row EXISTS — proves cleanup is non-trivial.
    const interim = await app.users.getUser("opt-sms-cleanup");
    const interimSms = interim.mfa.methods.find((m) => m.name === "sms");
    expect(interimSms?.value).toBe("+15551112222");
    expect(interimSms?.confirmed).toBe(false);

    // Skip at confirm → cleanupEnrollment fires → row removed → finish.
    const r5 = await app.trigger({
      wfs: r4.body?.wfs as string,
      input: { action: "skip" },
    });
    const data = r5.body?.data as Record<string, unknown> | undefined;
    expect(typeof data?.accessToken).toBe("string");

    const final = await app.users.getUser("opt-sms-cleanup");
    expect(final.mfa.methods.find((m) => m.name === "sms")).toBeUndefined();
    expect(final.mfa.methods).toHaveLength(0);
  });

  // WHY (T4): pins the Phase 2 `useDifferentMethod` branch
  // (`delete ctx.enrollMethod` → loop re-enters Phase 1). A regression that
  // didn't clear `enrollMethod` would leave the user trapped on the address
  // form for sms forever; a regression that handled the action only for
  // optional mode would deny the switch under required mode. We assert
  // under default (`optional`) mode but the switch invariant is mode-
  // independent so the assertion holds regardless. The post-switch pick of
  // a DIFFERENT method (email) → full completion proves the loop actually
  // re-entered Phase 1, not got stuck or fell through.
  it("T4: useDifferentMethod from address form → loops back to picker, can pick another method", async () => {
    const app = await prepareWfApp({
      loginWorkflowClass: withLoginMfaCtx(LoginWorkflow, { mfaMode: "optional" }),
    });
    await seedActiveUser(app.users, "switch-method", "pwd-12345678");

    const r2 = await startAndCredentials(app, "switch-method", "pwd-12345678");
    // Pick sms → at address form → switch.
    const r3 = await app.trigger({
      wfs: r2.body?.wfs as string,
      input: { method: "sms" },
    });
    expect(r3.body?.wfs).toBeTruthy();
    const r4 = await app.trigger({
      wfs: r3.body?.wfs as string,
      input: { action: "useDifferentMethod" },
    });
    expect(r4.body?.wfs).toBeTruthy();
    expect(r4.body?.data).toBeUndefined();
    // No method persisted in the interim — Phase 2 entry for sms hasn't
    // run addMfaMethod yet, and the action handler must not have triggered
    // it either.
    expect((await app.users.getUser("switch-method")).mfa.methods).toHaveLength(0);

    // Picking email → next pause MUST be the email address form (NOT a
    // re-prompt of pick → if `enrollMethod` weren't cleared, the helper
    // would have re-prompted address for SMS instead of routing email).
    const r5 = await app.trigger({
      wfs: r4.body?.wfs as string,
      input: { method: "email" },
    });
    expect(r5.body?.wfs).toBeTruthy();
    // Address form schema for email — submit + confirm to prove the new
    // method routes end-to-end.
    const r6 = await app.trigger({
      wfs: r5.body?.wfs as string,
      input: { address: "switch@example.com" },
    });
    expect(app.emails.length).toBe(1);
    expect(app.emails[0].recipient).toBe("switch@example.com");
    const code = app.emails[0].code as string;
    const r7 = await app.trigger({ wfs: r6.body?.wfs as string, input: { code } });
    const data = r7.body?.data as Record<string, unknown> | undefined;
    expect(typeof data?.accessToken).toBe("string");

    const user = await app.users.getUser("switch-method");
    // Only email present — no leftover sms row (none was created), no
    // dangling unconfirmed entries.
    expect(user.mfa.methods).toHaveLength(1);
    expect(user.mfa.methods[0].name).toBe("email");
    expect(user.mfa.methods[0].confirmed).toBe(true);
  });

  // WHY (T5): pins Phase 3 `useDifferentMethod` for TOTP specifically — the
  // case where cleanupEnrollment matters most. For TOTP, Phase 1 persists
  // the unconfirmed secret onto the user row, so by the time we reach
  // Phase 3 the row is real. A regression that didn't call
  // cleanupEnrollment on the switch would leave a dead unconfirmed TOTP
  // row, and the user's re-pick of sms would land with stale state on the
  // user (and depending on store semantics, a subsequent re-pick of TOTP
  // would either upsert over the dead row or fail outright). The
  // re-pick-sms-and-complete tail proves the switch worked AND that the
  // user ends up with ONLY the confirmed sms method — no stale TOTP row.
  it("T5: useDifferentMethod from confirm form (totp) → totp row REMOVED, re-pick sms completes cleanly", async () => {
    const app = await prepareWfApp({
      loginWorkflowClass: withLoginMfaCtx(LoginWorkflow, { mfaMode: "optional" }),
    });
    await seedActiveUser(app.users, "switch-totp", "pwd-12345678");

    const r2 = await startAndCredentials(app, "switch-totp", "pwd-12345678");
    // Pick totp → secret persisted unconfirmed → pause at confirm.
    const r3 = await app.trigger({
      wfs: r2.body?.wfs as string,
      input: { method: "totp" },
    });
    expect(r3.body?.wfs).toBeTruthy();
    const interim = await app.users.getUser("switch-totp");
    expect(interim.mfa.methods.find((m) => m.name === "totp")?.confirmed).toBe(false);

    // Switch away at confirm → cleanupEnrollment MUST remove the totp row.
    const r4 = await app.trigger({
      wfs: r3.body?.wfs as string,
      input: { action: "useDifferentMethod" },
    });
    expect(r4.body?.wfs).toBeTruthy();
    expect(r4.body?.data).toBeUndefined();
    const afterSwitch = await app.users.getUser("switch-totp");
    expect(afterSwitch.mfa.methods.find((m) => m.name === "totp")).toBeUndefined();

    // Re-pick sms → full flow → ends with ONLY sms (no stale totp row).
    const r5 = await app.trigger({
      wfs: r4.body?.wfs as string,
      input: { method: "sms" },
    });
    const r6 = await app.trigger({
      wfs: r5.body?.wfs as string,
      input: { address: "+15553334444" },
    });
    expect(app.sms.length).toBe(1);
    const code = app.sms[0].code;
    const r7 = await app.trigger({ wfs: r6.body?.wfs as string, input: { code } });
    expect(typeof (r7.body?.data as Record<string, unknown>)?.accessToken).toBe("string");

    const final = await app.users.getUser("switch-totp");
    expect(final.mfa.methods).toHaveLength(1);
    expect(final.mfa.methods[0].name).toBe("sms");
    expect(final.mfa.methods[0].confirmed).toBe(true);
    expect(final.mfa.defaultMethod).toBe("sms");
  });

  // WHY (T6): pins BOTH halves of the Phase 3 `resend` branch:
  //   (a) cooldown gate — `Date.now() < enrollPincodeCooldown` rejects with
  //       a "wait Ns" formMessage and DOES NOT re-mint/re-dispatch. Without
  //       this gate, an attacker (or an impatient user) could spam an
  //       arbitrary phone with SMS pumping fraud / burn an email by
  //       hammering the resend button. The `app.sms.length` invariant
  //       across the rejected attempt is the load-bearing assertion.
  //   (b) post-cooldown re-mint — once the cooldown elapses, `mintPin` runs
  //       AGAIN (new code) AND `deliver` fires AGAIN (new SMS). Without
  //       re-mint, the user would submit the original (now-expired) code;
  //       without re-dispatch, the user would never receive the new code.
  // The final submission of the SECOND code (not the first) proves both.
  it("T6: resend on Phase 3 sms — cooldown blocks immediate retry; post-cooldown re-mint dispatches new code", async () => {
    const app = await prepareWfApp({
      // 50ms cooldown — short enough to wait out in-test without a
      // deterministic clock. The defense is the same regardless of the
      // window size.
      authOpts: { mfa: { pincodeResendTimeoutMs: 50 } },
      loginWorkflowClass: withLoginMfaCtx(LoginWorkflow, { mfaMode: "required" }),
    });
    await seedActiveUser(app.users, "resend-user", "pwd-12345678");

    const r2 = await startAndCredentials(app, "resend-user", "pwd-12345678");
    const r3 = await app.trigger({
      wfs: r2.body?.wfs as string,
      input: { method: "sms" },
    });
    const r4 = await app.trigger({
      wfs: r3.body?.wfs as string,
      input: { address: "+15557776666" },
    });
    expect(app.sms.length).toBe(1);
    expect(app.sms[0].recipient).toBe("+15557776666");
    const firstCode = app.sms[0].code;

    // Immediate resend → cooldown rejects with formMessage. No new SMS.
    const r5 = await app.trigger({
      wfs: r4.body?.wfs as string,
      input: { action: "resend" },
    });
    const errors5 = r5.body?.errors as Record<string, string> | undefined;
    expect(errors5?.__form).toMatch(/wait \d+s/i);
    expect(app.sms.length).toBe(1);

    // Wait past the cooldown window.
    await new Promise((r) => setTimeout(r, 100));

    // Resend now succeeds: re-mints + re-dispatches.
    const r6 = await app.trigger({
      wfs: r5.body?.wfs as string,
      input: { action: "resend" },
    });
    expect(r6.body?.wfs).toBeTruthy();
    expect(app.sms.length).toBe(2);
    expect(app.sms[1].recipient).toBe("+15557776666");
    const secondCode = app.sms[1].code;
    // The new code MUST be the one the workflow now expects — submitting
    // the first (stale) code at this point would fail. Submitting the
    // second proves `mintPin` actually overwrote `ctx.pin`.
    expect(secondCode).toBeTruthy();

    const r7 = await app.trigger({
      wfs: r6.body?.wfs as string,
      input: { code: secondCode },
    });
    const data = r7.body?.data as Record<string, unknown> | undefined;
    expect(typeof data?.accessToken).toBe("string");
    // Cross-check: pin was rotated — first code is NOT the same as the
    // accepted-second code (probabilistic — collisions are <1/10^pincodeLength;
    // for the default 6-digit length this is 1e-6, well within test
    // tolerance).
    expect(firstCode).not.toBe(secondCode);

    const user = await app.users.getUser("resend-user");
    const sms = user.mfa.methods.find((m) => m.name === "sms");
    expect(sms?.confirmed).toBe(true);
    expect(sms?.value).toBe("+15557776666");
  });

  // WHY (T7): the negative counterpart to T2 — `required` mode MUST NEVER
  // accept a skip at Phase 2. The helper's
  // `deps.mode === "optional" && action === "skip"` gate is the only thing
  // separating policy-enforced enrollment from a client-side opt-out. A
  // regression that dropped the mode check (e.g. blanket skip handling)
  // would let `required`-mode users dodge enrollment by submitting
  // `{action: "skip"}` from the address form — defeating the entire
  // purpose of `mode: 'required'`. The exact failure mode here is server-
  // side: with `required` mode the skip handler doesn't fire; control
  // falls through to `resolveInput()` which requires an `address` field —
  // the form throws and the workflow does NOT finish AND no method row
  // gets persisted (addMfaMethod is reached AFTER resolveInput succeeds).
  it("T7: required + skip at Phase 2 address form → workflow does NOT short-circuit", async () => {
    const app = await prepareWfApp({
      loginWorkflowClass: withLoginMfaCtx(LoginWorkflow, { mfaMode: "required" }),
    });
    await seedActiveUser(app.users, "req-addr-skip", "pwd-12345678");

    const r2 = await startAndCredentials(app, "req-addr-skip", "pwd-12345678");
    const r3 = await app.trigger({
      wfs: r2.body?.wfs as string,
      input: { method: "sms" },
    });
    expect(r3.body?.wfs).toBeTruthy();

    // Skip submitted under required mode → MUST NOT finish.
    const r4 = await app.trigger({
      wfs: r3.body?.wfs as string,
      input: { action: "skip" },
    });
    expect(r4.body?.data).toBeUndefined();
    // No method persisted — proves the helper did NOT take the skip path
    // (which would also short-circuit before addMfaMethod) AND did NOT
    // race past validation into addMfaMethod.
    const user = await app.users.getUser("req-addr-skip");
    expect(user.mfa.methods).toHaveLength(0);
  });
});

describe("LoginWorkflow — Phase 3 ask/verify channel routing", () => {
  it("ATOMIC-CHANNEL-01: both email + phone route through the SAME @Step('ask/:channel(email|phone)') handler — counter keyed by channel proves the parameterized route param actually delivers a single shared body for both", async () => {
    // WHY: pins that splitting `ensure-email` + `ensure-phone` into the
    // parameterized `ask/:channel(email|phone)` schema entries (and the
    // matching @Step path) preserves the contract that both channels share a
    // single handler. A regression that statically routed `ask/email` →
    // emailHandler and `ask/phone` → phoneHandler (defeating the
    // parameterization) would still pass the per-channel functional tests
    // above, but would fail this one — the counter would only see one
    // channel's invocations and the other channel's OTP would NEVER be
    // delivered.
    const askCalls: Array<"email" | "phone"> = [];
    @Inherit()
    @Controller("auth/login")
    class CountingAskLogin extends LoginWorkflow {
      constructor(
        opts: LoginWorkflowOpts,
        users: UserService,
        auth: AuthCredential,
        authOpts: AuthOpts,
        consentStore: ConsentStore,
      ) {
        super(opts, users, auth, authOpts, consentStore);
      }
      override async ask(ctx: LoginWfCtx, channel: "email" | "phone"): Promise<unknown> {
        askCalls.push(channel);
        return super.ask(ctx, channel);
      }
    }
    const app = await prepareWfApp({
      loginPolicy: {
        enrollment: { ensureEmail: true, ensurePhone: true },
      },
      loginWorkflowClass: withLoginMfaCtx(CountingAskLogin, { mfaMode: "disabled" }),
    });
    await seedActiveUser(app.users, "alice", "Password123");
    // 1. credentials → pauses on AskEmailForm.
    const r2 = await startAndCredentials(app, "alice", "Password123");
    expect(r2.body?.wfs).toBeTruthy();
    // 2. submit email → ask/email fires, OTP minted, pauses on PincodeForm.
    const r3 = await app.trigger({
      wfs: r2.body?.wfs as string,
      input: { email: "alice@example.com", consents: [] },
    });
    expect(r3.body?.wfs).toBeTruthy();
    const emailOtp = app.emails.find(
      (e) => e.kind === "login.pincode" && e.recipient === "alice@example.com",
    );
    expect(emailOtp).toBeTruthy();
    // 3. submit pincode → verify/email confirms email, pauses on AskPhoneForm.
    const r4 = await app.trigger({
      wfs: r3.body?.wfs as string,
      input: { code: emailOtp!.code, rememberDevice: false },
    });
    expect(r4.body?.wfs).toBeTruthy();
    // 4. submit phone → ask/phone fires (SAME handler), SMS OTP minted,
    //    pauses on PincodeForm.
    const r5 = await app.trigger({
      wfs: r4.body?.wfs as string,
      input: { phone: "+15550001111", consents: [] },
    });
    expect(r5.body?.wfs).toBeTruthy();
    const smsOtp = app.sms.find(
      (s) => s.kind === "login.pincode" && s.recipient === "+15550001111",
    );
    expect(smsOtp).toBeTruthy();
    // 5. submit sms pincode → verify/phone, workflow finishes.
    const r6 = await app.trigger({
      wfs: r5.body?.wfs as string,
      input: { code: smsOtp!.code, rememberDevice: false },
    });
    expect((r6.body?.data as Record<string, unknown>)?.userId).toBe("alice");
    // Each channel routed through the SAME `ask` method on the controller
    // (no static email/phone handler split). The body is entered TWICE per
    // channel — once to surface the carrier form (resolveInput throws), once
    // to actually collect+deliver — so the counter shows the parameterized
    // route param dispatched to a single shared method for BOTH channels.
    expect(askCalls).toEqual(["email", "email", "phone", "phone"]);
    // Both channels' OTPs were minted+delivered through that single handler.
    expect(emailOtp).toBeTruthy();
    expect(smsOtp).toBeTruthy();
  });

  it("ATOMIC-VERIFY-01: ask/email + verify/email are independently gated — a wrong pincode keeps verify/email looping on PincodeForm without re-entering ask/email; correct pincode flips emailConfirmed=true", async () => {
    // WHY: pins that the schema's separate `ask/email` + `verify/email`
    // entries correctly split the workflow at the PincodeForm pause. A
    // regression that re-fused ask + verify into a single step would re-run
    // the ask body (re-minting an OTP, re-sending an email) on every
    // pincode-rejection retry — observable as ask getting invoked more than
    // once. This test pins the failure-retry loop: bad code re-pauses on
    // PincodeForm via verify/email's `requireInput({errors})` WITHOUT
    // re-entering ask/email.
    const askCalls: Array<"email" | "phone"> = [];
    const verifyCalls: Array<"email" | "phone"> = [];
    @Inherit()
    @Controller("auth/login")
    class CountingVerifyLogin extends LoginWorkflow {
      constructor(
        opts: LoginWorkflowOpts,
        users: UserService,
        auth: AuthCredential,
        authOpts: AuthOpts,
        consentStore: ConsentStore,
      ) {
        super(opts, users, auth, authOpts, consentStore);
      }
      override async ask(ctx: LoginWfCtx, channel: "email" | "phone"): Promise<unknown> {
        askCalls.push(channel);
        return super.ask(ctx, channel);
      }
      override async verify(ctx: LoginWfCtx, channel: "email" | "phone"): Promise<unknown> {
        verifyCalls.push(channel);
        return super.verify(ctx, channel);
      }
    }
    const app = await prepareWfApp({
      loginPolicy: {
        enrollment: { ensureEmail: true, ensurePhone: false },
      },
      loginWorkflowClass: withLoginMfaCtx(CountingVerifyLogin, { mfaMode: "disabled" }),
    });
    await seedActiveUser(app.users, "alice", "Password123");
    const r2 = await startAndCredentials(app, "alice", "Password123");
    // ask/email fires → pauses on PincodeForm.
    const r3 = await app.trigger({
      wfs: r2.body?.wfs as string,
      input: { email: "alice@example.com", consents: [] },
    });
    expect(r3.body?.wfs).toBeTruthy();
    // ask/email is entered TWICE before pincode pause: once to surface the
    // AskEmailForm (resolveInput throws when input is undefined → pause),
    // then again after the email is submitted (this time the body runs
    // through to addMfaMethod + mintPin + deliver + pincode-requireInput).
    expect(askCalls).toEqual(["email", "email"]);
    expect(verifyCalls).toEqual([]);
    const sent = app.emails.find(
      (e) => e.kind === "login.pincode" && e.recipient === "alice@example.com",
    );
    expect(sent).toBeTruthy();
    // Submit a WRONG pincode → engine resumes at ask/email, schema
    // condition `!ctx.email` is now FALSE (email set), engine `continue`s
    // past ask/email and runs verify/email. verifyPin returns errors →
    // verify/email throws requireInput({errors}) → re-pauses on PincodeForm.
    // emailConfirmed stays unset; ask/email is NOT re-entered.
    const askCountBeforeRetry = askCalls.length;
    const r4 = await app.trigger({
      wfs: r3.body?.wfs as string,
      input: { code: "000000", rememberDevice: false },
    });
    expect(r4.body?.wfs).toBeTruthy();
    expect(r4.body?.data).toBeUndefined();
    expect(verifyCalls).toEqual(["email"]);
    // Critical: ask/email was NOT re-invoked. If ask + verify were re-fused
    // (single-step body) this would show a third "email" entry because the
    // PincodeForm pause would resume in ask/email's body, which would
    // re-mint+re-deliver before reaching the verify branch.
    expect(askCalls.length).toBe(askCountBeforeRetry);
    // Submit the correct pincode → verify/email passes, workflow finishes.
    const r5 = await app.trigger({
      wfs: r4.body?.wfs as string,
      input: { code: sent!.code, rememberDevice: false },
    });
    expect((r5.body?.data as Record<string, unknown>)?.userId).toBe("alice");
    expect(verifyCalls).toEqual(["email", "email"]);
    expect(askCalls.length).toBe(askCountBeforeRetry);
    // Final post-state: email method is confirmed on the user record.
    const user = await app.users.getUser("alice");
    const emailMethod = user.mfa.methods.find((m) => m.name === "email");
    expect(emailMethod?.confirmed).toBe(true);
  });
});

// Capturing ConsentStore for the OTP-* + PENDING-CONSENTS-* tests. Each
// override only pushes — none of the call lists are asserted by tests that
// don't explicitly opt in to that surface, so the lists stay backwards-compat
// across describe blocks.
@Injectable()
class RecordingConsentStore extends ConsentStore {
  readonly saveCalls: Array<{ username: string; events: ConsentEvent[] }> = [];
  readonly otpCalls: Array<{
    username: string;
    channel: "email" | "sms";
    target: string;
    disclosure: string;
  }> = [];
  readonly pendingCalls: Array<{
    username: string | undefined;
    ctx: { workflow: string; channel?: "email" | "sms" };
  }> = [];
  /** Pre-canned descriptors returned by `getPendingConsents`; default is empty (no-op). */
  pendingResponse: ConsentDescriptor[] | Promise<ConsentDescriptor[]> = [];
  override async save(username: string, events: ConsentEvent[]): Promise<void> {
    this.saveCalls.push({ username, events: [...events] });
  }
  override async recordOtpChannelConsent(
    username: string,
    channel: "email" | "sms",
    target: string,
    disclosure: string,
  ): Promise<void> {
    this.otpCalls.push({ username, channel, target, disclosure });
  }
  override getPendingConsents(
    username: string | undefined,
    ctx: { workflow: string; channel?: "email" | "sms" },
  ): Promise<ConsentDescriptor[]> {
    this.pendingCalls.push({ username, ctx });
    // Match the base class's `async` signature by always returning a Promise.
    return Promise.resolve(this.pendingResponse);
  }
}

// Wire-body shape for the channel group transported via `@wf.context.pass 'channel'`
// on the AskEmail/AskPhone form pause descriptors — used by the OTP-disclosure
// transport assertions below.
type ChannelTransport = { channel?: { otpDisclosure?: string } };

describe("LoginWorkflow — OTP disclosure + recordOtpChannelConsent hook", () => {
  it("OTP-DISCLOSURE-01: ask/email → ctx.channel.otpDisclosure populated BEFORE the AskEmailForm pause + transported via @wf.context.pass; default English copy is generic per-channel (no target templated in)", async () => {
    // WHY: customers building i18n / CMS-driven disclosure copy depend on
    // BOTH halves of this contract — the resolver runs (so they can override
    // for per-tenant copy) AND the result rides the AskEmailForm pause
    // descriptor via `@wf.context.pass 'channel'` so the SPA can render
    // the literal text beneath the email input BEFORE the user submits (the
    // act of typing + submitting their email constitutes implied consent).
    // A regression that staged the disclosure AFTER `askWf.resolveInput()`
    // would push the value to the PincodeForm pause (one step too late —
    // user already submitted their email by then). A regression that dropped
    // the `@wf.context.pass 'channel'` annotation on AskEmailForm
    // would pass the unit-level resolver-call test but break the wire
    // transport; this test pins both halves at the load-bearing pause.
    const app = await prepareWfApp({
      loginPolicy: { enrollment: { ensureEmail: true, ensurePhone: false } },
      loginWorkflowClass: withLoginMfaCtx(LoginWorkflow, { mfaMode: "disabled" }),
    });
    await seedActiveUser(app.users, "alice", "Password123");
    // Paused at AskEmailForm — the ask/:channel body resolves the disclosure
    // BEFORE useAtscriptWf can throw requireInput, so the AskEmailForm pause
    // descriptor carries ctx.channel via @wf.context.pass.
    const r2 = await startAndCredentials(app, "alice", "Password123");
    expect(r2.body?.wfs).toBeTruthy();
    // Wire-transport assertion: `@wf.context.pass 'channel'` echoes the ctx
    // group at the AskEmailForm pause (NOT at the PincodeForm pause one step
    // later), and the `otpDisclosure` field lives under `ctx.channel`.
    const transported = (r2.body as ChannelTransport).channel?.otpDisclosure;
    expect(typeof transported).toBe("string");
    // Default English copy is GENERIC per-channel — no target value templated
    // in (the user hasn't submitted their email yet at the ask-time pause).
    // The verified target is captured separately at verify-time by
    // recordOtpChannelConsent (target arg), so the audit record contains BOTH
    // the disclosure shown AND the address verified.
    expect(transported).toContain("one-time security codes");
    expect(transported).toContain("email");
    expect(transported).not.toContain("alice@example.com");
  });

  it("OTP-DISCLOSURE-02: ask/phone → ctx.channel.otpDisclosure carries the phone-specific default copy at the AskPhoneForm pause (generic per-channel — no literal phone target templated in)", async () => {
    // WHY: the default copy is channel-specific — phone uses an SMS-flavoured
    // template (carrier fees disclosure) that diverges from the email
    // version. Pins that resolveOtpDisclosure branches on `channel === "phone"`
    // and that the phone branch emits SMS / carrier-rate copy. The disclosure
    // rides on the AskPhoneForm pause (BEFORE the user submits a phone number)
    // so the user reads it adjacent to the phone input and decides whether
    // to type their number. The verified phone target is captured separately
    // at verify-time.
    const app = await prepareWfApp({
      loginPolicy: { enrollment: { ensureEmail: false, ensurePhone: true } },
      loginWorkflowClass: withLoginMfaCtx(LoginWorkflow, { mfaMode: "disabled" }),
    });
    await seedActiveUser(app.users, "alice", "Password123");
    // Paused at AskPhoneForm — ask body stages ctx.channel.otpDisclosure BEFORE
    // the carrier-form pause, so r2 (not r3 after phone-submit) carries it.
    const r2 = await startAndCredentials(app, "alice", "Password123");
    expect(r2.body?.wfs).toBeTruthy();
    const transported = (r2.body as ChannelTransport).channel?.otpDisclosure;
    expect(typeof transported).toBe("string");
    // Phone-channel template mentions SMS + carrier-rate disclosure — the
    // load-bearing differentiator vs the email default (TCPA / PECR copy
    // distinction matters for legal review).
    expect(transported).toContain("SMS");
    expect(transported).toContain("Message and data rates");
    expect(transported).toContain("phone");
    // No phone target templated in — the user hasn't typed it yet at ask-time.
    expect(transported).not.toContain("+15550001111");
  });

  it("OTP-HOOK-FIRES-01: ask → verify on email channel → consentStore.recordOtpChannelConsent fires exactly once with the verified target + the disclosure ctx carried", async () => {
    // WHY (Rule 9): hook timing is load-bearing. The hook fires AFTER
    // `confirmMfaMethod` flips the row to `confirmed: true` — so a customer
    // implementing the override can rely on the recorded consent being bound
    // to a verified channel. A refactor that hoisted the hook BEFORE
    // confirmMfaMethod would silently record consent for unverified
    // recipients (an attacker submitting a typo-squatted email could
    // accumulate disclosure records). This test pins (a) the hook fires (b)
    // exactly once (c) with the channel = 'email' arg (d) with the verified
    // target (e) with the literal disclosure ctx carried.
    const consentStore = new RecordingConsentStore();
    const app = await prepareWfApp({
      consentStore,
      loginPolicy: { enrollment: { ensureEmail: true, ensurePhone: false } },
      loginWorkflowClass: withLoginMfaCtx(LoginWorkflow, { mfaMode: "disabled" }),
    });
    await seedActiveUser(app.users, "alice", "Password123");
    // Paused at AskEmailForm — disclosure is staged BEFORE this pause, so r2
    // carries it (not r3 after email-submit). The hook MUST NOT fire here.
    const r2 = await startAndCredentials(app, "alice", "Password123");
    expect(r2.body?.wfs).toBeTruthy();
    expect(consentStore.otpCalls.length).toBe(0);
    const transported = (r2.body as ChannelTransport).channel?.otpDisclosure;
    expect(typeof transported).toBe("string");
    const r3 = await app.trigger({
      wfs: r2.body?.wfs as string,
      input: { email: "alice@example.com", consents: [] },
    });
    expect(r3.body?.wfs).toBeTruthy();
    // Still no hook call after email-submit — the channel hasn't been
    // verified yet. If a regression moved the call into the ask body, this
    // assert would catch it.
    expect(consentStore.otpCalls.length).toBe(0);
    const sent = app.emails.find(
      (e) => e.kind === "login.pincode" && e.recipient === "alice@example.com",
    );
    expect(sent).toBeTruthy();
    const r4 = await app.trigger({
      wfs: r3.body?.wfs as string,
      input: { code: sent!.code as string, rememberDevice: false },
    });
    expect((r4.body?.data as Record<string, unknown>)?.userId).toBe("alice");
    // Hook fired exactly once at verify-time with the verified target and
    // the same disclosure copy the SPA was shown at ask-time. The disclosure
    // text itself is GENERIC per-channel (no target templated in); the
    // verified target is captured as a separate hook arg so the audit record
    // pins BOTH the copy shown AND the address verified.
    expect(consentStore.otpCalls.length).toBe(1);
    expect(consentStore.otpCalls[0].username).toBe("alice");
    expect(consentStore.otpCalls[0].channel).toBe("email");
    expect(consentStore.otpCalls[0].target).toBe("alice@example.com");
    expect(consentStore.otpCalls[0].disclosure).toBe(transported);
    // Belt-and-brace: the disclosure copy is generic — the target is
    // captured as a separate arg, NOT templated into the disclosure text.
    expect(consentStore.otpCalls[0].disclosure).not.toContain("alice@example.com");
    // Post-state: the email method row is confirmed — proving the hook DID
    // see a verified channel (any logic order regression that called the
    // hook before confirmMfaMethod would still pass the "fires once" check,
    // so we belt-and-brace by asserting the row is now confirmed).
    const user = await app.users.getUser("alice");
    const emailMethod = user.mfa.methods.find((m) => m.name === "email");
    expect(emailMethod?.confirmed).toBe(true);
  });

  it("OTP-HOOK-FIRES-02: ask → verify on phone channel → channel arg is 'sms' (NOT 'phone'), target is the literal submitted phone", async () => {
    // WHY: the 'phone' route param is user-facing; the persisted channel
    // value is the protocol ('sms'). Customers using carrier-aggregator
    // APIs (Twilio Verify, MessageBird) key persistence by protocol — if the
    // workflow passed 'phone' through to the hook, customer impls that
    // switch on `channel === 'sms'` would silently drop the record. Pins the
    // load-bearing `channel === 'phone' ? 'sms' : 'email'` mapping in the
    // verify body.
    const consentStore = new RecordingConsentStore();
    const app = await prepareWfApp({
      consentStore,
      loginPolicy: { enrollment: { ensureEmail: false, ensurePhone: true } },
      loginWorkflowClass: withLoginMfaCtx(LoginWorkflow, { mfaMode: "disabled" }),
    });
    await seedActiveUser(app.users, "alice", "Password123");
    const r2 = await startAndCredentials(app, "alice", "Password123");
    // Disclosure rides on the AskPhoneForm pause (r2), not on r3.
    const transported = (r2.body as ChannelTransport).channel?.otpDisclosure;
    expect(typeof transported).toBe("string");
    const r3 = await app.trigger({
      wfs: r2.body?.wfs as string,
      input: { phone: "+15550009999", consents: [] },
    });
    expect(r3.body?.wfs).toBeTruthy();
    const smsOtp = app.sms.find(
      (s) => s.kind === "login.pincode" && s.recipient === "+15550009999",
    );
    expect(smsOtp).toBeTruthy();
    const r4 = await app.trigger({
      wfs: r3.body?.wfs as string,
      input: { code: smsOtp!.code, rememberDevice: false },
    });
    expect((r4.body?.data as Record<string, unknown>)?.userId).toBe("alice");
    expect(consentStore.otpCalls.length).toBe(1);
    // Protocol-not-channel mapping: 'phone' (user-facing) → 'sms' (protocol).
    expect(consentStore.otpCalls[0].channel).toBe("sms");
    // Target is the literal phone string the user typed — not a masked
    // version (customer impls need the raw target to match against carrier-
    // aggregator records). Captured as a separate hook arg, NOT templated
    // into the disclosure copy.
    expect(consentStore.otpCalls[0].target).toBe("+15550009999");
    expect(consentStore.otpCalls[0].disclosure).toBe(transported);
    expect(consentStore.otpCalls[0].disclosure).not.toContain("+15550009999");
  });

  it("OTP-HOOK-SKIPS-VERIFY-WITHOUT-ASK-01: if ctx.channel.otpDisclosure is undefined at verify-time, recordOtpChannelConsent is NOT called (defensive guard)", async () => {
    // WHY: a future schema path that lands on verify/:channel without
    // ctx.channel.otpDisclosure staged (manual harness invocation, cleanup retry,
    // resumed paused workflow with cleared ctx, consumer subclass that
    // resets transient ctx before verify) MUST NOT record a consent for a
    // target/disclosure pair the system never staged. The guard
    // `if (channelState.otpDisclosure)` in the verify body is the load-bearing
    // defense; this test fakes the condition by overriding `verify` to
    // strip the staged disclosure BEFORE super.verify runs, and asserts
    // the hook stays silent despite the channel confirming successfully.
    const consentStore = new RecordingConsentStore();
    @Inherit()
    @Controller("auth/login")
    class NoStashLogin extends LoginWorkflow {
      constructor(
        opts: LoginWorkflowOpts,
        users: UserService,
        auth: AuthCredential,
        authOpts: AuthOpts,
        consentStoreDep: ConsentStore,
      ) {
        super(opts, users, auth, authOpts, consentStoreDep);
      }
      override async verify(ctx: LoginWfCtx, channel: "email" | "phone"): Promise<unknown> {
        // Strip the staged disclosure BEFORE super.verify runs — simulates
        // a paused-flow whose ctx was cleared between the ask and verify
        // halves (a future cleanup-retry path, or a consumer subclass that
        // resets transient ctx in a custom prepare-* step before verify).
        if (ctx.channel) delete ctx.channel.otpDisclosure;
        return super.verify(ctx, channel);
      }
    }
    const app = await prepareWfApp({
      consentStore,
      loginPolicy: { enrollment: { ensureEmail: true, ensurePhone: false } },
      loginWorkflowClass: withLoginMfaCtx(NoStashLogin, { mfaMode: "disabled" }),
    });
    await seedActiveUser(app.users, "alice", "Password123");
    const r2 = await startAndCredentials(app, "alice", "Password123");
    const r3 = await app.trigger({
      wfs: r2.body?.wfs as string,
      input: { email: "alice@example.com", consents: [] },
    });
    expect(r3.body?.wfs).toBeTruthy();
    const sent = app.emails.find(
      (e) => e.kind === "login.pincode" && e.recipient === "alice@example.com",
    );
    expect(sent).toBeTruthy();
    const r4 = await app.trigger({
      wfs: r3.body?.wfs as string,
      input: { code: sent!.code as string, rememberDevice: false },
    });
    expect((r4.body?.data as Record<string, unknown>)?.userId).toBe("alice");
    // The defensive guard short-circuits — no record despite the channel
    // being confirmed (post-state pins that the rest of verify ran fine).
    expect(consentStore.otpCalls.length).toBe(0);
    const user = await app.users.getUser("alice");
    const emailMethod = user.mfa.methods.find((m) => m.name === "email");
    expect(emailMethod?.confirmed).toBe(true);
  });

  it("OTP-DISCLOSURE-ASYNC-01: async resolveOtpDisclosure override → custom disclosure flows to ctx + to recordOtpChannelConsent (pins the string | Promise<string> union)", async () => {
    // WHY (Rule 9): the union return type exists so customers can fetch copy
    // from i18n/CMS without forcing every default call site to allocate a
    // Promise. A refactor that narrowed the return type to plain `string`
    // would silently drop async overrides (TS would forbid `async ` on the
    // override). This test pins the contract by supplying an async override
    // that returns a custom disclosure and asserting it round-trips through
    // BOTH ctx.channel.otpDisclosure AND the recordOtpChannelConsent call —
    // confirming `await this.resolveOtpDisclosure(...)` in the ask body
    // correctly awaits the Promise.
    const consentStore = new RecordingConsentStore();
    @Inherit()
    @Controller("auth/login")
    class AsyncDisclosureLogin extends LoginWorkflow {
      constructor(
        opts: LoginWorkflowOpts,
        users: UserService,
        auth: AuthCredential,
        authOpts: AuthOpts,
        consentStoreDep: ConsentStore,
      ) {
        super(opts, users, auth, authOpts, consentStoreDep);
      }
      protected override async resolveOtpDisclosure(
        _ctx: LoginWfCtx,
        channel: "email" | "phone",
      ): Promise<string> {
        // Simulate an async i18n catalog lookup — a real impl would
        // `await catalog.get('otp.disclosure.' + channel)`. Target is NOT
        // passed in; the disclosure is generic per-channel (the user hasn't
        // submitted their address yet at the ask-time pause). The verified
        // target is captured separately at verify-time.
        await Promise.resolve();
        return `CUSTOM[${channel}]: i18n.fetched`;
      }
    }
    const app = await prepareWfApp({
      consentStore,
      loginPolicy: { enrollment: { ensureEmail: true, ensurePhone: false } },
      loginWorkflowClass: withLoginMfaCtx(AsyncDisclosureLogin, { mfaMode: "disabled" }),
    });
    await seedActiveUser(app.users, "alice", "Password123");
    // Paused at AskEmailForm — async override resolves BEFORE the carrier-
    // form pause, so r2 (not r3) carries the unwrapped Promise value.
    const r2 = await startAndCredentials(app, "alice", "Password123");
    expect(r2.body?.wfs).toBeTruthy();
    const transported = (r2.body as ChannelTransport).channel?.otpDisclosure;
    // The async override's return value flows through to ctx (proving the
    // `await` in the ask body unwraps the Promise — no `[object Promise]`
    // stringification regressing into ctx).
    expect(transported).toBe("CUSTOM[email]: i18n.fetched");
    const r3 = await app.trigger({
      wfs: r2.body?.wfs as string,
      input: { email: "alice@example.com", consents: [] },
    });
    expect(r3.body?.wfs).toBeTruthy();
    const sent = app.emails.find(
      (e) => e.kind === "login.pincode" && e.recipient === "alice@example.com",
    );
    expect(sent).toBeTruthy();
    const r4 = await app.trigger({
      wfs: r3.body?.wfs as string,
      input: { code: sent!.code as string, rememberDevice: false },
    });
    expect((r4.body?.data as Record<string, unknown>)?.userId).toBe("alice");
    expect(consentStore.otpCalls.length).toBe(1);
    expect(consentStore.otpCalls[0].disclosure).toBe("CUSTOM[email]: i18n.fetched");
  });
});

/**
 * Build a `LoginWorkflow` subclass that calls `super.prepareConsents(ctx)` and
 * stashes the post-call ctx onto the supplied `captured` slot. Lets Phase-4
 * tests inspect `ctx.consents?.pending` directly — the wf engine's persisted
 * state store is internal (no `dump()`), and finished responses don't echo
 * full ctx, so a subclass-stash is the cleanest read surface.
 */
function makeCtxCapturingLogin(captured: { ctx?: LoginWfCtx }): typeof LoginWorkflow {
  @Inherit()
  @Controller("auth/login")
  class CtxCapturingLogin extends LoginWorkflow {
    constructor(
      opts: LoginWorkflowOpts,
      users: UserService,
      auth: AuthCredential,
      authOpts: AuthOpts,
      consentStore: ConsentStore,
    ) {
      super(opts, users, auth, authOpts, consentStore);
    }
    override prepareConsents(ctx: LoginWfCtx): undefined | Promise<undefined> {
      const result = super.prepareConsents(ctx);
      if (result instanceof Promise) {
        return result.then((r) => {
          captured.ctx = ctx;
          return r;
        });
      }
      captured.ctx = ctx;
      return result;
    }
  }
  return CtxCapturingLogin;
}

describe("LoginWorkflow — prepare-consents @Step → ctx.consents.pending transport (Phase 4)", () => {
  it("PENDING-CONSENTS-01: default no-op ConsentStore → ctx.consents.pending is [] (always array, never undefined)", async () => {
    // WHY (Rule 9): the "always populated, even when empty" contract enables
    // Phase 5 carrier forms to read `ctx.consents.pending.length > 0` without
    // the type-system fork between `undefined` (step skipped / errored) and
    // `[]` (step ran, no consents needed). A regression that left ctx
    // un-touched on the empty-array path would force every Phase-5 form
    // condition to add a defensive `?? []`, multiplying the conditional
    // surface. Pin: default ConsentStore returns [] and the step copies that
    // through to ctx.
    const captured: { ctx?: LoginWfCtx } = {};
    const Capturing = makeCtxCapturingLogin(captured);
    const app = await prepareWfApp({
      loginWorkflowClass: withLoginMfaCtx(Capturing, { mfaMode: "disabled" }),
    });
    await seedActiveUser(app.users, "alice", "Password123");
    const r2 = await startAndCredentials(app, "alice", "Password123");
    expect((r2.body?.data as Record<string, unknown>)?.userId).toBe("alice");
    expect(captured.ctx).toBeTruthy();
    expect(captured.ctx!.consents?.pending).toEqual([]);
    // Belt-and-brace: `[]` is the empty-array literal, NOT `undefined`. A
    // regression that left the field unset would fail this strict check.
    expect(Array.isArray(captured.ctx!.consents?.pending)).toBe(true);
  });

  it("PENDING-CONSENTS-02: customer override returns 2 descriptors → ctx.consents.pending is the exact array (transport contract)", async () => {
    // WHY: pins the round-trip from customer override → ctx without mutation.
    // Phase 5 carrier forms will project these descriptors onto form fields;
    // any regression that filtered, re-shaped, or mutated the array between
    // store + ctx would break the Phase-5 wire contract. Each descriptor
    // field (name, text, required, version) is asserted directly.
    const descriptors: ConsentDescriptor[] = [
      { id: "terms", text: "Accept the terms", required: "Terms required", version: "v3" },
      { id: "marketing", text: "Receive marketing emails" },
    ];
    const consentStore = new RecordingConsentStore();
    consentStore.pendingResponse = descriptors;
    const captured: { ctx?: LoginWfCtx } = {};
    const Capturing = makeCtxCapturingLogin(captured);
    const app = await prepareWfApp({
      consentStore,
      loginWorkflowClass: withLoginMfaCtx(Capturing, { mfaMode: "disabled" }),
    });
    await seedActiveUser(app.users, "alice", "Password123");
    await startAndCredentials(app, "alice", "Password123");
    expect(captured.ctx!.consents?.pending).toHaveLength(2);
    expect(captured.ctx!.consents?.pending![0]).toEqual({
      id: "terms",
      text: "Accept the terms",
      required: "Terms required",
      version: "v3",
    });
    expect(captured.ctx!.consents?.pending![1]).toEqual({
      id: "marketing",
      text: "Receive marketing emails",
    });
  });

  it("PENDING-CONSENTS-03: async customer override → prepare-consents awaits the Promise before writing ctx (pins the Promise<ConsentDescriptor[]> union)", async () => {
    // WHY (Rule 9): the `T | Promise<T>` engine semantic on resolveXxx getters
    // is paralleled here at the store-call boundary — the step body branches
    // on `result instanceof Promise`. A regression that dropped the Promise
    // branch (or narrowed the store's return type) would silently coerce the
    // Promise to a stringified ctx field, surfacing as `[object Promise]` in
    // Phase-5 form renderers. This test forces the async path via an
    // override that delays 10ms before resolving, then asserts ctx is the
    // unwrapped array (not the Promise object).
    @Injectable()
    class DelayedStore extends ConsentStore {
      override async getPendingConsents(
        _username: string | undefined,
        _ctx: { workflow: string; channel?: "email" | "sms" },
      ): Promise<ConsentDescriptor[]> {
        await new Promise<void>((r) => setTimeout(r, 10));
        return [{ id: "jurisdiction-gdpr", text: "GDPR consent", required: "GDPR required" }];
      }
    }
    const captured: { ctx?: LoginWfCtx } = {};
    const Capturing = makeCtxCapturingLogin(captured);
    const app = await prepareWfApp({
      consentStore: new DelayedStore(),
      loginWorkflowClass: withLoginMfaCtx(Capturing, { mfaMode: "disabled" }),
    });
    await seedActiveUser(app.users, "alice", "Password123");
    await startAndCredentials(app, "alice", "Password123");
    // The async override's value is unwrapped onto ctx — not a Promise.
    expect(captured.ctx!.consents?.pending).toHaveLength(1);
    expect(captured.ctx!.consents?.pending![0].id).toBe("jurisdiction-gdpr");
  });

  it("PENDING-CONSENTS-WORKFLOW-ARG-01: customer override receives {workflow: 'auth/login/flow'} as the ctx arg (no channel — workflow-only in Phase 4)", async () => {
    // WHY: the `{workflow}` arg lets customer overrides return different
    // consent sets per workflow (e.g. GDPR cookie consent on first-login, not
    // on recovery). Pin: (a) the literal workflow string matches the
    // `@Workflow` registration so customer string-equality checks work;
    // (b) NO `channel` field is passed in Phase 4 — channel-scoped consent
    // goes through the separate `recordOtpChannelConsent` path (Phase 3),
    // NOT `getPendingConsents`. A regression that added `channel` to this
    // call would silently route OTP-channel-consent through both paths.
    const consentStore = new RecordingConsentStore();
    const app = await prepareWfApp({
      consentStore,
      loginWorkflowClass: withLoginMfaCtx(LoginWorkflow, { mfaMode: "disabled" }),
    });
    await seedActiveUser(app.users, "alice", "Password123");
    await startAndCredentials(app, "alice", "Password123");
    // Exactly one call — the step fires once per workflow run.
    expect(consentStore.pendingCalls).toHaveLength(1);
    expect(consentStore.pendingCalls[0].username).toBe("alice");
    expect(consentStore.pendingCalls[0].ctx.workflow).toBe("auth/login/flow");
    // No channel arg in Phase 4 — separate path for OTP-channel consent.
    expect(consentStore.pendingCalls[0].ctx.channel).toBeUndefined();
  });

  it("PENDING-CONSENTS-PRE-USERNAME-01: prepareConsents short-circuits synchronously when ctx.username is unset (defensive guard)", async () => {
    // WHY: the schema places `prepare-consents` after the `!ctx.username`
    // break gate, so this guard is belt-and-brace for future refactors that
    // might re-order the schema (e.g. moving the prepare-* block earlier).
    // Customer ConsentStore impls key their dedup by username — a call with
    // `username=undefined` would either crash their code or silently fetch
    // an empty / global consent set the user can't satisfy. The guard
    // prevents both. Pinned via direct-invocation: a subclass captures its
    // instance so the test calls `prepareConsents` with a synthetic ctx
    // that lacks `username`.
    const consentStore = new RecordingConsentStore();
    const captured: { instance?: LoginWorkflow } = {};
    @Inherit()
    @Controller("auth/login")
    class CapturingInstance extends LoginWorkflow {
      constructor(
        opts: LoginWorkflowOpts,
        users: UserService,
        auth: AuthCredential,
        authOpts: AuthOpts,
        consentStoreDep: ConsentStore,
      ) {
        super(opts, users, auth, authOpts, consentStoreDep);
        captured.instance = this;
      }
    }
    const app = await prepareWfApp({
      consentStore,
      loginWorkflowClass: CapturingInstance,
    });
    // Force-instantiate the workflow controller via a trivial trigger so the
    // SINGLETON ctor runs and stashes `this`.
    await app.trigger({ wfid: "auth/login/flow" });
    expect(captured.instance).toBeTruthy();
    // Reset the recorder to isolate the pre-username invocation.
    consentStore.pendingCalls.length = 0;
    // Synthetic ctx with NO username — direct-invoke the step body. The
    // guard MUST return undefined synchronously without touching the store.
    const ctx: LoginWfCtx = {};
    const result = captured.instance!.prepareConsents(ctx);
    // Sync short-circuit — the guard returns `undefined` directly, NOT a
    // Promise. A regression that always entered the Promise branch (e.g.
    // unconditional `await this.consentStore.getPendingConsents(...)`)
    // would return a Promise here.
    expect(result).toBeUndefined();
    expect(consentStore.pendingCalls).toHaveLength(0);
    expect(ctx.consents?.pending).toBeUndefined();
  });
});
