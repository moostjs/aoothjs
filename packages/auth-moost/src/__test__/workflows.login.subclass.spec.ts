/**
 * Consumer-subclass override coverage for `LoginWorkflow`.
 *
 * The Phase-2 reshape replaced eight injected callbacks with `protected`
 * methods that consumers override via `class MyLogin extends LoginWorkflow {}`.
 * The earlier `workflows.login.options.spec.ts` covers three of those
 * (`buildRecoveryUrl`, `assessRiskStepUp`, `resolveRedirect`) via a tightly
 * curated `makeLoginSubclass` helper.
 *
 * This file covers the rest — every additional override hook — plus a
 * standalone end-to-end smoke test that registers a consumer subclass
 * WITHOUT going through the helper (i.e. exercising the exact wire-up shape
 * documented in the class doc + WF_LOGIN.md). Each test asserts an
 * observable outcome that the default no-op implementation could not
 * produce.
 */
import { AuthCredential } from "@aooth/auth";
import { generateTotpCode, generateTotpSecret, UserService } from "@aooth/user";
import type { TAtscriptAnnotatedType } from "@atscript/typescript/utils";
import { Controller, Inherit } from "moost";
import { describe, expect, it } from "vite-plus/test";

import { ProfileCompleteForm } from "../atscript/models/forms.as";
import { type LoginWfCtx, LoginWorkflow, type LoginWorkflowOpts } from "../workflows/index";
import { prepareWfApp, seedActiveUser, withLoginMfaCtx } from "./workflow-utils";

// ── Subclass end-to-end smoke ────────────────────────────────────────────────
describe("LoginWorkflow subclass — end-to-end registration shape", () => {
  it("consumer subclass with @Inherit + @Controller + re-declared ctor → workflow registers and dispatches", async () => {
    // This is the literal subclass shape consumers paste into their app per
    // WF_LOGIN.md §"Consumer subclass pattern". A test that asserts the
    // workflow dispatches (no class-identity errors, no DI miss) under that
    // exact shape catches regressions in moost's @Inherit metadata handling.
    let credentialsRan = 0;
    @Inherit()
    @Controller()
    class MyLogin extends LoginWorkflow {
      constructor(opts: LoginWorkflowOpts, users: UserService, auth: AuthCredential) {
        super(opts, users, auth);
      }
      // Override an arbitrary protected method to prove the subclass body
      // actually runs on the dispatch path (i.e. the registered class is
      // ours, not the base).
      protected override async assessRiskStepUp(
        _ctx: LoginWfCtx,
      ): Promise<{ require: boolean; reason?: string }> {
        credentialsRan++;
        return { require: false };
      }
    }
    const app = await prepareWfApp({
      loginWorkflowClass: withLoginMfaCtx(MyLogin, { availableMfaTransports: ["totp"] }),
    });
    await seedActiveUser(app.users, "alice", "Password123");
    const secret = generateTotpSecret();
    await app.users.addMfaMethod("alice", { name: "totp", value: secret, confirmed: true });
    const r1 = await app.trigger({ wfid: "auth.login" });
    const r2 = await app.trigger({
      wfs: r1.body?.wfs as string,
      input: { username: "alice", password: "Password123" },
    });
    const code = generateTotpCode(secret);
    const r3 = await app.trigger({ wfs: r2.body?.wfs as string, input: { code } });
    expect((r3.body?.data as Record<string, unknown>)?.userId).toBe("alice");
    // The override ran — proves the subclass dispatched, not the base class
    // (whose body would still return require:false without bumping the
    // counter).
    expect(credentialsRan).toBeGreaterThanOrEqual(1);
  });
});

// ── applyProfile override ────────────────────────────────────────────────────
describe("LoginWorkflow subclass — applyProfile override", () => {
  it("override fires for profile-complete step (acceptance.profileCompleteRequired + ctx.profileMissingFields populated)", async () => {
    // The schema gates on `(ctx.profileMissingFields?.length ?? 0) > 0`.
    // Nothing in the base workflow populates that flag — by design, the
    // consumer either subclasses to populate it from their store, or wires
    // the step in via a feature flag. We populate it by overriding
    // `credentials` to inject a missing-fields marker after the base login
    // succeeds, then assert the consumer's `applyProfile` actually fires
    // with the submitted payload + the workflow's known username.
    const calls: Array<{ username: string; payload: Record<string, unknown> }> = [];
    @Inherit()
    @Controller()
    class ProfileLogin extends LoginWorkflow {
      constructor(opts: LoginWorkflowOpts, users: UserService, auth: AuthCredential) {
        super(opts, users, auth);
      }
      override async credentials(ctx: LoginWfCtx): Promise<unknown> {
        const out = await super.credentials(ctx);
        if (ctx.username) ctx.profileMissingFields = ["firstName"];
        return out;
      }
      protected override async applyProfile(
        username: string,
        payload: Record<string, unknown>,
      ): Promise<void> {
        calls.push({ username, payload });
      }
    }
    const app = await prepareWfApp({
      loginOpts: {
        acceptance: {
          profileCompleteRequired: true,
        },
        forms: {
          profileComplete: ProfileCompleteForm as unknown as TAtscriptAnnotatedType,
        },
      },
      loginWorkflowClass: withLoginMfaCtx(ProfileLogin, { mfaMode: "disabled" }),
    });
    await seedActiveUser(app.users, "alice", "Password123");
    const r1 = await app.trigger({ wfid: "auth.login" });
    const cred = await app.trigger({
      wfs: r1.body?.wfs as string,
      input: { username: "alice", password: "Password123" },
    });
    // Paused for ProfileCompleteForm.
    expect(cred.body?.wfs).toBeTruthy();
    expect(JSON.stringify(cred.body)).toMatch(/firstName/);
    const r3 = await app.trigger({
      wfs: cred.body?.wfs as string,
      input: { firstName: "Alice", lastName: "Doe" },
    });
    expect((r3.body?.data as Record<string, unknown>)?.userId).toBe("alice");
    // Consumer override ran with the submitted payload.
    expect(calls.length).toBe(1);
    expect(calls[0]).toMatchObject({
      username: "alice",
      payload: { firstName: "Alice", lastName: "Doe" },
    });
  });
});

// ── applyConsentMarketing override ──────────────────────────────────────────
describe("LoginWorkflow subclass — applyConsentMarketing override", () => {
  it("override fires when acceptance.consentMarketing is true with the submitted opt-in value", async () => {
    const captured: Array<{ username: string; optIn: boolean }> = [];
    @Inherit()
    @Controller()
    class ConsentLogin extends LoginWorkflow {
      constructor(opts: LoginWorkflowOpts, users: UserService, auth: AuthCredential) {
        super(opts, users, auth);
      }
      protected override async applyConsentMarketing(
        username: string,
        optIn: boolean,
      ): Promise<void> {
        captured.push({ username, optIn });
      }
    }
    const app = await prepareWfApp({
      loginOpts: {
        acceptance: { consentMarketing: true },
      },
      loginWorkflowClass: withLoginMfaCtx(ConsentLogin, { mfaMode: "disabled" }),
    });
    await seedActiveUser(app.users, "alice", "Password123");
    const r1 = await app.trigger({ wfid: "auth.login" });
    const cred = await app.trigger({
      wfs: r1.body?.wfs as string,
      input: { username: "alice", password: "Password123" },
    });
    expect(cred.body?.wfs).toBeTruthy();
    const r3 = await app.trigger({
      wfs: cred.body?.wfs as string,
      input: { optIn: true },
    });
    expect((r3.body?.data as Record<string, unknown>)?.userId).toBe("alice");
    expect(captured).toEqual([{ username: "alice", optIn: true }]);
  });
});

// ── loadTenants override ────────────────────────────────────────────────────
//
// NOTE on production wire-up gap (see findings in §"Production bugs found"):
// `tenant-select`'s schema condition gates on `ctx.availableTenants.length > 1`,
// but ONLY the step body lazily calls `loadTenants` to populate it — a
// chicken-and-egg that prevents the step from ever firing through default
// dispatch. The tests below seed `ctx.availableTenants` from a subclass
// `credentials` override so the gate passes, then assert (a) the override IS
// the source of truth for the validation set, and (b) the override is the
// hook the production wire-up will eventually call once the gap is fixed.
describe("LoginWorkflow subclass — loadTenants override", () => {
  it("multiContext.tenantSelect: tenants from override drive form validation (valid id → tokens)", async () => {
    @Inherit()
    @Controller()
    class TenantLogin extends LoginWorkflow {
      constructor(opts: LoginWorkflowOpts, users: UserService, auth: AuthCredential) {
        super(opts, users, auth);
      }
      override async credentials(ctx: LoginWfCtx): Promise<unknown> {
        const out = await super.credentials(ctx);
        if (ctx.username) ctx.availableTenants = await this.loadTenants(ctx.username);
        return out;
      }
      protected override async loadTenants(
        _username: string,
      ): Promise<Array<{ id: string; name: string }>> {
        return [
          { id: "t-acme", name: "Acme" },
          { id: "t-globex", name: "Globex" },
        ];
      }
    }
    const app = await prepareWfApp({
      loginOpts: { multiContext: { tenantSelect: true } },
      loginWorkflowClass: withLoginMfaCtx(TenantLogin, { mfaMode: "disabled" }),
    });
    await seedActiveUser(app.users, "alice", "Password123");
    const r1 = await app.trigger({ wfid: "auth.login" });
    const cred = await app.trigger({
      wfs: r1.body?.wfs as string,
      input: { username: "alice", password: "Password123" },
    });
    // Paused for TenantSelectForm — proves the override-supplied length>1 hit
    // the schema condition.
    expect(cred.body?.wfs).toBeTruthy();
    expect(JSON.stringify(cred.body)).toMatch(/tenantId/);
    const r3 = await app.trigger({
      wfs: cred.body?.wfs as string,
      input: { tenantId: "t-globex" },
    });
    // Tokens issued — proves the picked id was validated against the
    // override's return value (a bogus id would have produced a form error).
    expect((r3.body?.data as Record<string, unknown>)?.userId).toBe("alice");
  });

  it("multiContext.tenantSelect + bogus tenantId submission → form error 'Unknown tenant' (override's set IS authoritative)", async () => {
    @Inherit()
    @Controller()
    class TenantLogin extends LoginWorkflow {
      constructor(opts: LoginWorkflowOpts, users: UserService, auth: AuthCredential) {
        super(opts, users, auth);
      }
      override async credentials(ctx: LoginWfCtx): Promise<unknown> {
        const out = await super.credentials(ctx);
        if (ctx.username) ctx.availableTenants = await this.loadTenants(ctx.username);
        return out;
      }
      protected override async loadTenants(_username: string) {
        return [
          { id: "t-acme", name: "Acme" },
          { id: "t-globex", name: "Globex" },
        ];
      }
    }
    const app = await prepareWfApp({
      loginOpts: { multiContext: { tenantSelect: true } },
      loginWorkflowClass: withLoginMfaCtx(TenantLogin, { mfaMode: "disabled" }),
    });
    await seedActiveUser(app.users, "alice", "Password123");
    const r1 = await app.trigger({ wfid: "auth.login" });
    const cred = await app.trigger({
      wfs: r1.body?.wfs as string,
      input: { username: "alice", password: "Password123" },
    });
    const r3 = await app.trigger({
      wfs: cred.body?.wfs as string,
      input: { tenantId: "t-not-in-list" },
    });
    const errors = r3.body?.errors as Record<string, string> | undefined;
    expect(errors?.tenantId).toMatch(/Unknown tenant/);
  });
});

// ── loadPersonas override ───────────────────────────────────────────────────
//
// Same wire-up gap as `loadTenants` — see findings.
describe("LoginWorkflow subclass — loadPersonas override", () => {
  it("multiContext.personaSelect: personas from override drive form validation", async () => {
    @Inherit()
    @Controller()
    class PersonaLogin extends LoginWorkflow {
      constructor(opts: LoginWorkflowOpts, users: UserService, auth: AuthCredential) {
        super(opts, users, auth);
      }
      override async credentials(ctx: LoginWfCtx): Promise<unknown> {
        const out = await super.credentials(ctx);
        if (ctx.username) ctx.availablePersonas = await this.loadPersonas(ctx.username);
        return out;
      }
      protected override async loadPersonas(_username: string) {
        return [
          { id: "p-admin", label: "Admin" },
          { id: "p-viewer", label: "Viewer" },
        ];
      }
    }
    const app = await prepareWfApp({
      loginOpts: { multiContext: { personaSelect: true } },
      loginWorkflowClass: withLoginMfaCtx(PersonaLogin, { mfaMode: "disabled" }),
    });
    await seedActiveUser(app.users, "alice", "Password123");
    const r1 = await app.trigger({ wfid: "auth.login" });
    const cred = await app.trigger({
      wfs: r1.body?.wfs as string,
      input: { username: "alice", password: "Password123" },
    });
    expect(cred.body?.wfs).toBeTruthy();
    expect(JSON.stringify(cred.body)).toMatch(/personaId/);
    const r3 = await app.trigger({
      wfs: cred.body?.wfs as string,
      input: { personaId: "p-viewer" },
    });
    expect((r3.body?.data as Record<string, unknown>)?.userId).toBe("alice");
  });
});

// ── logoutOtherSessions override ────────────────────────────────────────────
describe("LoginWorkflow subclass — logoutOtherSessions override", () => {
  it("sessionPolicy.concurrencyLimit kickPrompt + 'logoutOthers' alt → override fires with username", async () => {
    // Nothing in the base workflow populates `ctx.activeSessions`, so we
    // subclass `credentials` to seed it past the threshold. The chain then
    // proceeds: pause at concurrency-limit form → consumer submits
    // `logoutOthers` → `logoutOtherSessions(username)` runs → flow completes
    // and tokens issue. Asserting the override received the right username
    // (and exactly one call) pins the wire-up.
    const calls: string[] = [];
    @Inherit()
    @Controller()
    class KickLogin extends LoginWorkflow {
      protected override async loadActiveSessions(_username: string): Promise<number> {
        return 9; // way past the max
      }
      protected override async logoutOtherSessions(username: string): Promise<void> {
        calls.push(username);
      }
    }
    const app = await prepareWfApp({
      loginOpts: {
        sessionPolicy: { concurrencyLimit: { max: 2, onLimit: "kickPrompt" } },
      },
      loginWorkflowClass: withLoginMfaCtx(KickLogin, { mfaMode: "disabled" }),
    });
    await seedActiveUser(app.users, "alice", "Password123");
    const r1 = await app.trigger({ wfid: "auth.login" });
    const cred = await app.trigger({
      wfs: r1.body?.wfs as string,
      input: { username: "alice", password: "Password123" },
    });
    // Paused for ConcurrencyLimitForm.
    expect(cred.body?.wfs).toBeTruthy();
    const r3 = await app.trigger({
      wfs: cred.body?.wfs as string,
      input: { action: "logoutOthers" },
    });
    expect((r3.body?.data as Record<string, unknown>)?.userId).toBe("alice");
    expect(calls).toEqual(["alice"]);
  });

  it("sessionPolicy.concurrencyLimit kickPrompt + 'cancel' alt → workflow aborts, override NOT called", async () => {
    const calls: string[] = [];
    @Inherit()
    @Controller()
    class KickLogin extends LoginWorkflow {
      protected override async loadActiveSessions(_username: string): Promise<number> {
        return 9;
      }
      protected override async logoutOtherSessions(username: string): Promise<void> {
        calls.push(username);
      }
    }
    const app = await prepareWfApp({
      loginOpts: {
        sessionPolicy: { concurrencyLimit: { max: 2, onLimit: "kickPrompt" } },
      },
      loginWorkflowClass: withLoginMfaCtx(KickLogin, { mfaMode: "disabled" }),
    });
    await seedActiveUser(app.users, "alice", "Password123");
    const r1 = await app.trigger({ wfid: "auth.login" });
    const cred = await app.trigger({
      wfs: r1.body?.wfs as string,
      input: { username: "alice", password: "Password123" },
    });
    const r3 = await app.trigger({
      wfs: cred.body?.wfs as string,
      input: { action: "cancel" },
    });
    expect(r3.body).toMatchObject({
      finished: true,
      aborted: true,
      reason: "sessionLimit",
      message: { level: "warn", text: "Concurrent session limit reached." },
    });
    // Override MUST NOT have fired on cancel.
    expect(calls).toEqual([]);
  });

  it("session-limit cancel emits WfFinished envelope with aborted+reason:sessionLimit + warn message", async () => {
    // Pins the WfFinished migration for the session-limit cancel path — the
    // structured `message` envelope is the new UI banner contract.
    @Inherit()
    @Controller()
    class KickLogin extends LoginWorkflow {
      protected override async loadActiveSessions(_username: string): Promise<number> {
        return 9;
      }
    }
    const app = await prepareWfApp({
      loginOpts: {
        sessionPolicy: { concurrencyLimit: { max: 2, onLimit: "kickPrompt" } },
      },
      loginWorkflowClass: withLoginMfaCtx(KickLogin, { mfaMode: "disabled" }),
    });
    await seedActiveUser(app.users, "alice", "Password123");
    const r1 = await app.trigger({ wfid: "auth.login" });
    const cred = await app.trigger({
      wfs: r1.body?.wfs as string,
      input: { username: "alice", password: "Password123" },
    });
    const r = await app.trigger({
      wfs: cred.body?.wfs as string,
      input: { action: "cancel" },
    });
    expect(r.status).toBe(201);
    expect(r.body).toMatchObject({
      finished: true,
      aborted: true,
      reason: "sessionLimit",
      message: { level: "warn", text: "Concurrent session limit reached." },
    });
  });
});

// ── Runtime fail-loud paths (post protected-method reshape) ─────────────────
//
// Pre-reshape these were boot-time checks against missing DI providers. The
// reshape moved sender wiring to `protected deliver()`; the default throws
// at the first dispatch. The harness's override throws when `registerEmailSender`
// is false, matching the prior fail-loud surface. We trigger the deliver()
// call by reaching a step that emits (email MFA pincode, notify-new-device).
describe("LoginWorkflow runtime fail-loud — deliver() not configured", () => {
  it("mfa email path + NO EmailSender registered → runtime throw (500 with 'EmailSender required')", async () => {
    const app = await prepareWfApp({
      loginWorkflowClass: withLoginMfaCtx(LoginWorkflow, {
        mfaMode: "optional",
        availableMfaTransports: ["email"],
      }),
      registerEmailSender: false,
    });
    await seedActiveUser(app.users, "alice", "Password123");
    // Enroll an email factor so `pincode-send-login` runs and hits `deliver()`.
    await app.users.addMfaMethod("alice", {
      name: "email",
      value: "alice@example.com",
      confirmed: true,
    });
    const r1 = await app.trigger({ wfid: "auth.login" });
    const r2 = await app.trigger({
      wfs: r1.body?.wfs as string,
      input: { username: "alice", password: "Password123" },
    });
    expect(r2.status).toBe(500);
    expect(JSON.stringify(r2.body)).toMatch(/EmailSender/);
  });

  it("finalize.notifyNewDevice + new device + NO EmailSender registered → runtime throw (500 with 'EmailSender required')", async () => {
    // Drive a TOTP-MFA login with deviceTrust enabled + no cookie so
    // `check-trusted-device` flags `newDevice`, MFA runs, deviceTrust persists,
    // then `notify-new-device` invokes `deliver()` — which throws because
    // EmailSender is not registered.
    const app = await prepareWfApp({
      loginOpts: {
        finalize: { notifyNewDevice: true },
        deviceTrust: { enabled: true, optIn: false },
      },
      loginWorkflowClass: withLoginMfaCtx(LoginWorkflow, { availableMfaTransports: ["totp"] }),
      registerEmailSender: false,
    });
    await seedActiveUser(app.users, "alice", "Password123");
    // Need an enrolled email so notifyNewDevice has a recipient (otherwise
    // the step returns undefined without calling deliver()).
    await app.users.addMfaMethod("alice", {
      name: "email",
      value: "alice@example.com",
      confirmed: true,
    });
    const secret = generateTotpSecret();
    await app.users.addMfaMethod("alice", {
      name: "totp",
      value: secret,
      confirmed: true,
    });
    const r1 = await app.trigger({ wfid: "auth.login" });
    const r2 = await app.trigger({
      wfs: r1.body?.wfs as string,
      input: { username: "alice", password: "Password123" },
    });
    // Two MFA methods → select2fa pauses; pick totp.
    const sel = await app.trigger({
      wfs: r2.body?.wfs as string,
      input: { methodName: "totp" },
    });
    const code = generateTotpCode(secret);
    const final = await app.trigger({ wfs: sel.body?.wfs as string, input: { code } });
    expect(final.status).toBe(500);
    expect(JSON.stringify(final.body)).toMatch(/EmailSender/);
  });
});
