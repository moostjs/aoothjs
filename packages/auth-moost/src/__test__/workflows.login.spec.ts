import { generateTotpCode, generateTotpSecret } from "@aooth/user";
import { describe, expect, it } from "vite-plus/test";

import { LoginWorkflow } from "../workflows/index";
import { prepareWfApp, seedActiveUser, withLoginMfaCtx } from "./workflow-utils";

/**
 * Wire trace for the login workflow:
 *
 * 1. `POST /wf/trigger { wfid: 'auth/login/flow' }`
 *    → step `credentials` returns `outletHttp(formSchema, ctx)` → HTTP outlet
 *      flattens to body = `{ ...formSchema, ...ctx, wfs: '<token>' }`.
 * 2. `POST /wf/trigger { wfs, input: { username, password } }`
 *    → step `credentials` validates; if MFA branch, pauses again with
 *      `MfaCodeForm`; otherwise the `issue` step `useWfFinished().set(...)`s
 *      the response → body = `<AuthLoginResponse>` with cookies set.
 * 3. (MFA only) `POST /wf/trigger { wfs, input: { code } }`
 *    → step `mfa` verifies, advances to `issue`.
 *
 * Body shape after a pause (`outletHttp`): `{ ...formSchema, wfs, errors? }`.
 * Body shape after finish: `<useWfFinished().set({ value }).value>`.
 */
describe("LoginWorkflow", () => {
  it("happy path: no MFA → finished with tokens + cookies", async () => {
    // mfa.mode='disabled' so the Phase-4 loop is filtered at the schema guard
    // and the un-enrolled user passes straight through to `issue`. The 3-state
    // opts default is `'optional'` which would otherwise prompt for enrollment
    // (with skip) for users with 0 methods.
    const app = await prepareWfApp({
      loginWorkflowClass: withLoginMfaCtx(LoginWorkflow, { mfaMode: "disabled" }),
    });
    await seedActiveUser(app.users, "alice", "Password123");

    const r1 = await app.trigger({ wfid: "auth/login/flow" });
    expect(r1.status).toBe(201);
    expect(typeof r1.body?.wfs).toBe("string");
    const wfs1 = r1.body?.wfs as string;

    const r2 = await app.trigger({
      wfs: wfs1,
      input: { username: "alice", password: "Password123" },
    });
    expect(r2.status).toBe(201);
    // Finished response — the issue step set the WfFinished envelope; domain
    // data lives under `.data`.
    const data = r2.body?.data as Record<string, unknown> | undefined;
    expect(r2.body?.finished).toBe(true);
    expect(data?.userId).toBe("alice");
    expect(typeof data?.accessToken).toBe("string");
    expect(typeof data?.refreshToken).toBe("string");
    // Cookies set
    expect(r2.setCookies.some((c) => c.startsWith("aooth_session="))).toBe(true);
    expect(r2.setCookies.some((c) => c.startsWith("aooth_refresh="))).toBe(true);
  });

  it("re-renders credentials form on bad password (no 401, no enumeration)", async () => {
    const app = await prepareWfApp();
    await seedActiveUser(app.users, "alice", "Password123");

    const r1 = await app.trigger({ wfid: "auth/login/flow" });
    const wfs1 = r1.body?.wfs as string;

    const r2 = await app.trigger({
      wfs: wfs1,
      input: { username: "alice", password: "WrongPass1" },
    });
    expect(r2.status).toBe(201);
    // Paused again (re-render of LoginCredentialsForm). Errors live next to
    // the form schema since the HTTP outlet spreads payload + context.
    const errors = r2.body?.errors as Record<string, string> | undefined;
    expect(errors).toMatchObject({ __form: "Invalid credentials" });
    expect(r2.body?.wfs).toBeTruthy();
  });

  it("re-renders credentials form on unknown user (no enumeration)", async () => {
    const app = await prepareWfApp();
    await seedActiveUser(app.users, "alice", "Password123");
    const r1 = await app.trigger({ wfid: "auth/login/flow" });
    const r2 = await app.trigger({
      wfs: r1.body?.wfs as string,
      input: { username: "ghost", password: "Password123" },
    });
    const errors = r2.body?.errors as Record<string, string> | undefined;
    expect(errors).toMatchObject({ __form: "Invalid credentials" });
  });

  it("re-renders credentials form with lock message on locked account", async () => {
    // WHY: locked account used to be HttpError(423) — that deleted the wf
    // state token (HandleStateStrategy.consume runs BEFORE the @Step body) and
    // the SPA's next submission got 410 Gone. The fix routes LOCKED through
    // `wf.requireInput({formMessage})` so the engine re-persists state under
    // a NEW token and the user can retry (e.g. after the lockout elapses)
    // without the SPA having to start over. The lock copy must surface on the
    // form-level `__form` slot so the SPA can render it adjacent to the
    // credentials inputs.
    const app = await prepareWfApp();
    await seedActiveUser(app.users, "alice", "Password123");
    await app.users.lockAccount("alice", "manual");

    const r1 = await app.trigger({ wfid: "auth/login/flow" });
    const r2 = await app.trigger({
      wfs: r1.body?.wfs as string,
      input: { username: "alice", password: "Password123" },
    });
    expect(r2.status).toBe(201);
    const errors = r2.body?.errors as Record<string, string> | undefined;
    expect(errors?.__form).toMatch(/locked/i);
    // WHY token-reuse: the engine re-persists state under THE SAME handle
    // on retriable errors (idempotent re-resume — see ../wooksjs WF_STRATEGY).
    // The URL token stays live across the lockout message so the user can
    // refresh/bookmark and retry once the lockout window expires without
    // restarting the flow.
    expect(r2.body?.wfs).toBeTruthy();
    expect(r2.body?.wfs).toBe(r1.body?.wfs);
  });

  it("re-renders form (no leak) on inactive account", async () => {
    const app = await prepareWfApp();
    // createUser without activateAccount → account.active === false
    await app.users.createUser("inactive_user", "Password123");

    const r1 = await app.trigger({ wfid: "auth/login/flow" });
    const r2 = await app.trigger({
      wfs: r1.body?.wfs as string,
      input: { username: "inactive_user", password: "Password123" },
    });
    expect(r2.status).toBe(201);
    const errors = r2.body?.errors as Record<string, string> | undefined;
    expect(errors).toMatchObject({ __form: "Invalid credentials" });
  });

  it("MFA branch: enter code → finish", async () => {
    const app = await prepareWfApp();
    await seedActiveUser(app.users, "alice", "Password123");
    const secret = generateTotpSecret();
    await app.users.addMfaMethod("alice", { name: "totp", value: secret, confirmed: true });

    const r1 = await app.trigger({ wfid: "auth/login/flow" });
    const r2 = await app.trigger({
      wfs: r1.body?.wfs as string,
      input: { username: "alice", password: "Password123" },
    });
    // After credentials with MFA enabled, paused for the MFA form.
    expect(r2.body?.wfs).toBeTruthy();
    const wfs2 = r2.body?.wfs as string;

    const code = generateTotpCode(secret);
    const r3 = await app.trigger({ wfs: wfs2, input: { code } });
    const data = r3.body?.data as Record<string, unknown> | undefined;
    expect(data?.userId).toBe("alice");
    expect(typeof data?.accessToken).toBe("string");
  });

  it("MFA branch: invalid code re-prompts, then retry with correct code succeeds (no 410 on retry)", async () => {
    // WHY: classic instance of the wf-state token bug — wrong MFA code used to
    // leak through paths that threw plain HttpError (e.g. INACTIVE → 401,
    // LOCKED → 423), eating the wf token on the throw and forcing the next
    // submission to 410 Gone. The fix routes invalid-code through
    // `wf.requireInput({errors:{code}})` so the engine re-persists state
    // under THE SAME handle AND re-renders the MFA form. This test pins
    // BOTH halves: the re-render carries `errors.code='Invalid code'` AND
    // the SAME wfs token (idempotent re-resume — keeps the URL token live
    // so the user can refresh / multi-tab without losing progress);
    // submitting the correct TOTP code on the same token finishes the
    // login (proves the workflow isn't terminally stuck).
    const app = await prepareWfApp();
    await seedActiveUser(app.users, "alice", "Password123");
    const secret = generateTotpSecret();
    await app.users.addMfaMethod("alice", { name: "totp", value: secret, confirmed: true });

    const r1 = await app.trigger({ wfid: "auth/login/flow" });
    const r2 = await app.trigger({
      wfs: r1.body?.wfs as string,
      input: { username: "alice", password: "Password123" },
    });
    const wfs2 = r2.body?.wfs as string;
    const r3 = await app.trigger({
      wfs: wfs2,
      input: { code: "000000" },
    });
    expect(r3.status).not.toBe(410);
    const errors = r3.body?.errors as Record<string, string> | undefined;
    expect(errors).toMatchObject({ code: "Invalid code" });
    // Token reused (idempotent re-resume) — same wfs.
    const wfs3 = r3.body?.wfs as string;
    expect(wfs3).toBeTruthy();
    expect(wfs3).toBe(wfs2);

    // Retry with a correct TOTP on the (still-live) token — login finishes.
    const code = generateTotpCode(secret);
    const r4 = await app.trigger({ wfs: wfs3, input: { code } });
    expect(r4.status).not.toBe(410);
    const data = r4.body?.data as Record<string, unknown> | undefined;
    expect(data?.userId).toBe("alice");
    expect(typeof data?.accessToken).toBe("string");
  });

  it("validates form input on missing fields", async () => {
    const app = await prepareWfApp();
    const r1 = await app.trigger({ wfid: "auth/login/flow" });
    const r2 = await app.trigger({
      wfs: r1.body?.wfs as string,
      input: { username: "", password: "" },
    });
    // The form-input validator fires errors.
    expect(r2.body?.errors).toBeTruthy();
  });
});
