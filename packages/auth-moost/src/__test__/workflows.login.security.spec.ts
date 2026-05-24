/**
 * SECURITY regression coverage for `LoginWorkflow` — audit hole #15.
 *
 * Two distinct attacker sinks are pinned here:
 *
 * **Sink A (`profile-complete` payload escalation).** The post-login
 * `profile-complete` step parses its form with `resolveInput({ partial: "deep" })`
 * which PRESERVES unknown extras. The default `applyProfile` body is a no-op,
 * but the contract says consumers override it to write into their user store
 * (e.g. via `users.update`). If the workflow handed the raw parsed payload to
 * `applyProfile`, a logged-in user could submit `{ firstName, roles: ['admin'],
 * password: { hash: 'pwned' } }` and self-promote / overwrite their password
 * via the routine post-login profile prompt — exactly the InviteWorkflow
 * scenario closed in audit hole #6, applied to the login flow. The defense
 * is the `stripReservedUserKeys()` call in `profileComplete` (NOT at the
 * `applyProfile` override seam) so consumer-replaced storage paths still
 * receive a sanitized payload.
 *
 * **Sink B (`@wf.context.pass` shadowing).** Forms in `forms.as` declare
 * `@wf.context.pass` for ctx keys that drive server-side decisions
 * (e.g. `Select2faForm` whitelists `mfaEnrolledMethods`, which the step
 * uses to validate the user's `methodName` pick). If a submitted form
 * payload could shadow those ctx keys, an attacker could spoof their
 * enrolled MFA methods. The defense lives at the form-parsing boundary —
 * `useAtscriptWf(form).resolveInput()` strips unknown extras when the form
 * schema does not declare them. Sink B's test pins that behavior as a
 * regression: a crafted Select2faForm payload containing a spoofed
 * `mfaEnrolledMethods` must NOT shadow the server-derived ctx value, and
 * therefore the `methodName` validation must still reject methods the
 * user has not actually enrolled.
 */
import { AuthCredential } from "@aooth/auth";
import { generateTotpSecret, UserService } from "@aooth/user";
import type { TAtscriptAnnotatedType } from "@atscript/typescript/utils";
import { Controller, Inherit } from "moost";
import { describe, expect, it } from "vite-plus/test";

import { ProfileWithRolesForm } from "./fixtures/profile-with-roles.as";
import { RESERVED_USER_KEYS } from "../workflows/auth-workflow.base";
import { type LoginWfCtx, LoginWorkflow, type LoginWorkflowOpts } from "../workflows/index";
import { prepareWfApp, seedActiveUser, withLoginMfaCtx } from "./workflow-utils";

// ── Sink A — profile-complete strip ─────────────────────────────────────────
describe("LoginWorkflow security — profile-complete payload escalation (audit #15 Sink A)", () => {
  it("accept-time profile payload CANNOT escalate roles / shadow server-managed fields", async () => {
    // WHY: a logged-in user reaching `profile-complete` could otherwise
    // submit `roles: ['admin']` (and the rest of the privileged top-level
    // UserCredentials keys) alongside legitimate fields. The default
    // `applyProfile` is a no-op, but ANY consumer override that deep-merges
    // the payload onto the user row (the documented pattern) would persist
    // the escalation. Mirrors the invite regression test (`workflows.invite.spec.ts:159`).
    //
    // The deliberately-vulnerable `ProfileWithRolesForm` fixture LEGITIMIZES
    // the privileged keys as accepted form fields, so the form validator
    // passes them through. Only the workflow's `stripReservedUserKeys()`
    // call in `profileComplete` can stop the escalation. Without that
    // strip, `seenAtHook[0]` would carry the spoofed bag and a
    // `users.update(username, payload)` override would persist them.
    const seenAtHook: Array<Record<string, unknown>> = [];

    @Inherit()
    @Controller()
    class ProfileLogin extends LoginWorkflow {
      constructor(opts: LoginWorkflowOpts, users: UserService, auth: AuthCredential) {
        super(opts, users, auth);
      }
      override async credentials(ctx: LoginWfCtx): Promise<unknown> {
        const out = await super.credentials(ctx);
        // Nothing in the base populates `profileMissingFields`; consumers
        // are expected to set it from their store. Forcing it here lets the
        // schema condition gate `profile-complete` on for the test.
        if (ctx.username) ctx.profileMissingFields = ["firstName"];
        return out;
      }
      // Capture what the workflow hands to `applyProfile` AND mutate the
      // user row the way a real consumer override would (`users.update`),
      // so the post-flow user-row assertions see the merged result.
      protected override async applyProfile(
        username: string,
        payload: Record<string, unknown>,
      ): Promise<void> {
        seenAtHook.push({ ...payload });
        await this.users.update(username, payload as Parameters<typeof this.users.update>[1]);
      }
    }

    const app = await prepareWfApp({
      loginOpts: {
        acceptance: { profileCompleteRequired: true },
        forms: {
          // `ProfileWithRolesForm` declares the privileged top-level keys
          // as accepted form fields, so the upstream atscript form validator
          // does NOT strip them. The strip we're testing is the workflow's
          // own `stripReservedUserKeys()` call.
          profileComplete: ProfileWithRolesForm as unknown as TAtscriptAnnotatedType,
        },
      },
      loginWorkflowClass: withLoginMfaCtx(ProfileLogin, { mfaMode: "disabled" }),
    });

    await seedActiveUser(app.users, "victim", "Password123");

    const r1 = await app.trigger({ wfid: "auth.login" });
    const cred = await app.trigger({
      wfs: r1.body?.wfs as string,
      input: { username: "victim", password: "Password123" },
    });
    expect(cred.body?.wfs).toBeTruthy();

    // Submit declared legitimate fields PLUS the attacker bag (all keys
    // are accepted by `ProfileWithRolesForm`).
    const r3 = await app.trigger({
      wfs: cred.body?.wfs as string,
      input: {
        firstName: "Pat",
        lastName: "Patel",
        // ── attacker-controlled extras (must all be stripped) ──────────
        roles: ["admin", "root"],
        password: { hash: "pwned" },
        passwordHistory: ["pwned"],
        account: { active: true, locked: true, pendingInvitation: true },
        mfa: { mode: "optional" },
        trustedDevices: ["attacker-device"],
        backupCodes: ["attacker-code"],
        version: 9999,
        id: "spoofed-id",
        username: "spoofed",
      },
    });
    expect((r3.body?.data as Record<string, unknown>)?.userId).toBe("victim");

    // The `applyProfile` hook MUST receive a payload with all
    // RESERVED_USER_KEYS removed (workflow-level enforcement — even though
    // the form schema declares them, the workflow does not let them through).
    // Iterate the shared set so this assertion auto-tracks future additions.
    expect(seenAtHook).toHaveLength(1);
    for (const key of RESERVED_USER_KEYS) {
      expect(seenAtHook[0]).not.toHaveProperty(key);
    }

    // Persisted user-row consequences of the strip.
    const user = (await app.users.getUser("victim")) as unknown as Record<string, unknown>;
    // 1) Roles NOT escalated.
    expect(user.roles ?? []).toEqual([]);
    // 2) Password NOT overwritten by the bag's 'pwned' hash.
    expect((user.password as { hash?: string }).hash).not.toBe("pwned");
    // 3) Account flags reflect post-login state (active), NOT the bag
    //    (which tried to lock + flip pendingInvitation).
    expect((user.account as { active?: boolean }).active).toBe(true);
    expect((user.account as { locked?: boolean }).locked).toBeFalsy();
    expect((user.account as { pendingInvitation?: boolean }).pendingInvitation).toBeFalsy();
    // 4) MFA + trustedDevices + backupCodes NOT shadowed.
    expect((user.mfa as { enabled?: boolean })?.enabled).toBeFalsy();
    expect(user.trustedDevices ?? []).toEqual([]);
    expect(user.backupCodes ?? []).toEqual([]);
    // 5) Legitimate profile fields still flowed through.
    expect(user.firstName).toBe("Pat");
    expect(user.lastName).toBe("Patel");
  });
});

// ── Sink B — @wf.context.pass shadowing ────────────────────────────────────
describe("LoginWorkflow security — @wf.context.pass key shadowing (audit #15 Sink B)", () => {
  it("Select2faForm: spoofed `mfaEnrolledMethods` in payload does NOT shadow server-derived ctx", async () => {
    // WHY: `Select2faForm` declares `@wf.context.pass 'mfaEnrolledMethods'`
    // so the client `@ui.form.fn.options` render fn can read the user's
    // enrolled methods from ctx. The matching server step
    // (`select2fa`) ALSO reads `ctx.mfaEnrolledMethods` — populated by
    // `prepareMfaOptions` from the user's real `users.mfa.methods` — to
    // validate the submitted `methodName`. If form payload keys could
    // promote into ctx, an attacker could:
    //
    //   POST { methodName: "spoofed", mfaEnrolledMethods: [{ methodName: "spoofed", kind: "weak" }] }
    //
    // and the step's `(ctx.mfaEnrolledMethods ?? []).find(...)` would
    // accept "spoofed" — defeating the MFA gate entirely. The defense
    // lives at the form-parsing boundary: `useAtscriptWf(form).resolveInput()`
    // strips unknown extras because `Select2faForm` does not declare
    // `mfaEnrolledMethods` as an INPUT field (only as a `@wf.context.pass`).
    //
    // This test pins that behaviour: when the spoofed key is submitted,
    // the step rejects "spoofed" with a `methodName` error AND the
    // workflow does NOT reach the issue/finish step. If the spoofed value
    // had shadowed ctx, the step would accept "spoofed" and proceed.

    const app = await prepareWfApp();
    await seedActiveUser(app.users, "alice", "Password123");
    // Enrol two methods so `select2fa` actually fires (the schema gates on
    // `mfaEnrolledMethods.length > 1`).
    await app.users.addMfaMethod("alice", {
      name: "email",
      value: "alice@example.com",
      confirmed: true,
    });
    const secret = generateTotpSecret();
    await app.users.addMfaMethod("alice", { name: "totp", value: secret, confirmed: true });

    const r1 = await app.trigger({ wfid: "auth.login" });
    const cred = await app.trigger({
      wfs: r1.body?.wfs as string,
      input: { username: "alice", password: "Password123" },
    });
    // 2 enrolled methods → paused on `select2fa`.
    expect(cred.body?.wfs).toBeTruthy();
    expect(JSON.stringify(cred.body)).toMatch(/methodName/);

    // Submit the attack payload: legitimate-looking `methodName` plus a
    // spoofed `mfaEnrolledMethods` array that would whitelist it.
    const sel = await app.trigger({
      wfs: cred.body?.wfs as string,
      input: {
        methodName: "spoofed",
        saveAsDefault: false,
        mfaEnrolledMethods: [{ methodName: "spoofed", kind: "weak" }],
      },
    });

    // The step rejected "spoofed" — proves ctx.mfaEnrolledMethods still
    // reflects ONLY the user's real enrollments (email + totp), not the
    // spoofed value the form payload tried to shadow it with.
    const errors = sel.body?.errors as Record<string, string> | undefined;
    expect(errors?.methodName).toBeTruthy();
    expect(errors?.methodName).toMatch(/unknown mfa method/i);
    // And the workflow did NOT finish — no auth tokens issued.
    expect((sel.body?.data as Record<string, unknown> | undefined)?.userId).toBeUndefined();
    // Belt-and-braces: the form parser re-echoes `mfaEnrolledMethods` from
    // ctx into the response (via `@wf.context.pass`). It MUST contain the
    // user's real methods (email + totp), NOT the attacker's spoofed
    // `[{ methodName: "spoofed", kind: "weak" }]` — proving the spoofed
    // payload key never reached ctx.
    const echoed = (sel.body as { mfaEnrolledMethods?: Array<{ methodName: string }> })
      ?.mfaEnrolledMethods;
    expect(echoed).toBeTruthy();
    expect(echoed?.map((m) => m.methodName).toSorted()).toEqual(["email", "totp"]);
  });
});
