import { afterEach, describe, expect, it } from "vite-plus/test";

import { AuthCredential, CredentialStoreMemory } from "@aooth/auth";
import { UserService, UserStoreMemory } from "@aooth/user";
import { setTranslator } from "moost";

import { ConsentStore } from "../consent.store";
import { withoutPublicProjection } from "../workflow/public-projection";
import { AuthWorkflow } from "../workflow/auth-workflow";
import type { AuthWfCtx } from "../workflow/auth-workflow.ctx";
import { inLocale, localizedHttpApp, type PreparedFlowApp, prepareFlowApp } from "./flow-utils";

// Texts are translated when a response is rendered, never into persisted
// workflow state: a flow opened in one language and resumed in another
// answers in the language of the request at hand.

const DE = {
  AOOTH_ACCOUNT_CREATED: "Dein Konto wurde erstellt.",
  SET_PASSWORD_INVITE_HEADING: "Willkommen — Passwort festlegen",
  SET_PASSWORD_INVITE_INTRO: "Wähle ein Passwort, um dein Konto zu aktivieren.",
  SET_PASSWORD_INITIAL_HEADING: "Lege dein erstes Passwort fest",
  SET_PASSWORD_INITIAL_INTRO: "Dein Konto hat noch kein Passwort.",
  CHANGE_PASSWORD_HEADING: "Passwort ändern",
  CHANGE_PASSWORD_INTRO: "Gib dein aktuelles Passwort ein und wähle ein neues.",
  INVALID_CREDENTIALS: "Ungültige Anmeldedaten",
  AOOTH_CODE_EXPIRED: "Code abgelaufen",
  AOOTH_ADDRESS_REQUIRED: "Pflichtfeld",
  AOOTH_INVALID_EMAIL_ADDRESS: "Gib eine gültige E-Mail-Adresse ein",
  MFA_METHOD_TOTP: "Authenticator-App",
  MFA_METHOD_REMOVED: "{method} entfernt.",
  OTP_DISCLOSURE_EMAIL: "Mit deiner E-Mail-Adresse willigst du ein, Codes per E-Mail zu erhalten.",
};
const de = { "accept-language": "de" };

/** No German text in any state the store persisted. */
function expectEnglishState(app: PreparedFlowApp): void {
  expect(app.savedStates.length).toBeGreaterThan(0);
  for (const state of app.savedStates) {
    // the rendered projection (`ctx.public`) is never persisted
    expect(state).toHaveProperty("context.subject");
    expect((state as { context?: object }).context).not.toHaveProperty("public");
  }
  const json = JSON.stringify(app.savedStates);
  for (const text of Object.values(DE)) expect(json).not.toContain(text);
}

afterEach(() => {
  setTranslator(undefined);
});

describe("persisted workflow state stays untranslated", () => {
  it("invite accept: opened in German, finished without a header → English confirmation", async () => {
    setTranslator({ en: {}, de: DE });
    const app = await prepareFlowApp({ httpApp: localizedHttpApp });
    const start = await app.start("auth/invite/start");
    await app.submit(start.body.wfs, { formData: { email: "new@x.test", roles: [] } });
    const opened = await app.submit(app.emails[0].token, {}, de);
    expect(opened.body.inputRequired.payload.id).toBe("SetPasswordForm");
    expect(opened.body.inputRequired.context.public.password).toMatchObject({
      heading: DE.SET_PASSWORD_INVITE_HEADING,
      intro: DE.SET_PASSWORD_INVITE_INTRO,
    });
    let res = await app.submit(opened.body.wfs, {
      formData: {
        newPassword: "Str0ng!Passw0rd",
        confirmPassword: "Str0ng!Passw0rd",
        consents: [],
      },
    });
    if (res.body.inputRequired?.payload?.id === "EnrollPickMethodForm") {
      res = await app.submit(res.body.wfs, { action: "skip" });
    }
    expect(res.body.message).toEqual({ level: "success", text: "Your account has been created." });
    expectEnglishState(app);
  });

  it("…and in German when the finishing request is German", async () => {
    setTranslator({ en: {}, de: DE });
    const app = await prepareFlowApp({ httpApp: localizedHttpApp });
    const start = await app.start("auth/invite/start");
    await app.submit(start.body.wfs, { formData: { email: "new@x.test", roles: [] } });
    const opened = await app.submit(app.emails[0].token, {});
    let res = await app.submit(
      opened.body.wfs,
      {
        formData: {
          newPassword: "Str0ng!Passw0rd",
          confirmPassword: "Str0ng!Passw0rd",
          consents: [],
        },
      },
      de,
    );
    if (res.body.inputRequired?.payload?.id === "EnrollPickMethodForm") {
      res = await app.submit(res.body.wfs, { action: "skip" }, de);
    }
    expect(res.body.message?.text).toBe(DE.AOOTH_ACCOUNT_CREATED);
    expectEnglishState(app);
  });

  it("sign-in with a forced password change: German screen, English state", async () => {
    setTranslator({ en: {}, de: DE });
    const app = await prepareFlowApp({ httpApp: localizedHttpApp });
    const id = await app.seedUser("alice", "Password123!");
    await app.users.update(id, { password: { isInitial: true } } as never);
    const start = await app.start("auth/login/flow", de);
    const wrong = await app.submit(
      start.body.wfs,
      { formData: { username: "alice", password: "nope" } },
      de,
    );
    expect(wrong.body.inputRequired.context.errors).toEqual({ __form: DE.INVALID_CREDENTIALS });
    const atForm = await app.submit(
      wrong.body.wfs,
      { formData: { username: "alice", password: "Password123!" } },
      de,
    );
    expect(atForm.body.inputRequired.context.public.password).toMatchObject({
      heading: DE.SET_PASSWORD_INITIAL_HEADING,
      intro: DE.SET_PASSWORD_INITIAL_INTRO,
    });
    // The same paused form, resumed without a header, renders English.
    const again = await app.submit(atForm.body.wfs, {
      formData: { newPassword: "Abc12345!x", confirmPassword: "different!1" },
    });
    expect(again.body.inputRequired.context.public.password.heading).toBe(
      "Set your initial password",
    );
    expectEnglishState(app);
  });

  it("change password: German heading and intro, English after a resume without a header", async () => {
    setTranslator({ en: {}, de: DE });
    const app = await prepareFlowApp({ httpApp: localizedHttpApp });
    const id = await app.seedUser("alice", "Password123!");
    const { accessToken } = await app.auth.issue(id);
    const headers = { ...de, authorization: `Bearer ${accessToken}` };
    const started = await app.post(
      "/auth/change-password",
      { wfid: "auth/change-password/flow" },
      headers,
    );
    expect(started.body.inputRequired.context.public.password).toMatchObject({
      heading: DE.CHANGE_PASSWORD_HEADING,
      intro: DE.CHANGE_PASSWORD_INTRO,
    });
    const en = await app.post(
      "/auth/change-password",
      { wfs: started.body.wfs, input: { formData: { currentPassword: "x" } } },
      { authorization: `Bearer ${accessToken}` },
    );
    // The heading comes from the state the resumed request reads: a code, not text.
    expect(en.body.inputRequired.context.public.password.heading).toBe("Change your password");
  });
});

describe("ctx.public: a per-response projection, stripped at persist time", () => {
  it("is an ordinary property of the live context", () => {
    const wf = new Exposed(
      {},
      new UserService(new UserStoreMemory()),
      new AuthCredential({ store: new CredentialStoreMemory() }),
      new ConsentStore(),
    );
    const ctx = { password: { headingCode: "CHANGE_PASSWORD_HEADING" } } as AuthWfCtx;
    wf.project(ctx);
    expect(Object.keys(ctx)).toContain("public");
    expect(JSON.parse(JSON.stringify(ctx)).public.password.heading).toBe("Change your password");
    // …stripped only as AuthWorkflow's projection: an app's own `public` key stays
    expect(withoutPublicProjection(ctx)).not.toHaveProperty("public");
    expect(withoutPublicProjection({ public: { mine: 1 } })).toEqual({ public: { mine: 1 } });
  });

  it("the app's beforePersist still runs, on store- and token-backed routes, without `public`", async () => {
    const seen: Array<{ schemaId: string; keys: string[] }> = [];
    const app = await prepareFlowApp({
      triggerHooks: {
        beforePersist: (state) => {
          seen.push({ schemaId: state.schemaId, keys: Object.keys(state.context as object) });
        },
      },
    });
    const id = await app.seedUser("alice", "Password123!");
    await app.users.update(id, { password: { isInitial: true } } as never);
    await app.login("alice", "Password123!");
    const { accessToken } = await app.auth.issue(id);
    await app.post(
      "/auth/change-password",
      { wfid: "auth/change-password/flow" },
      { authorization: `Bearer ${accessToken}` },
    );
    const flows = new Set(seen.map((s) => s.schemaId));
    expect([...flows].toSorted()).toEqual(["/auth/change-password/flow", "/auth/login/flow"]);
    for (const s of seen) expect(s.keys).not.toContain("public");
  });
});

class Exposed extends AuthWorkflow {
  project = (ctx: AuthWfCtx) => this.populatePublic(ctx);
  pin = (ctx: { pinNonce?: string; pinExpire?: number }, code: string) =>
    this.verifyPin(ctx, code, "", "target");
  address = (method: "email" | "sms", value: string) => this.validateMfaAddress({}, method, value);
  addMfaFinish = (ctx: AuthWfCtx) => this.buildAddMfaFinishEnvelope(ctx);
  disclosure = (channel: "email" | "phone") => this.resolveOtpDisclosure({}, channel);
}

describe("workflow texts that bypassed the catalogue", () => {
  const wf = new Exposed(
    {},
    new UserService(new UserStoreMemory()),
    new AuthCredential({ store: new CredentialStoreMemory() }),
    new ConsentStore(),
  );

  it("pincode, address checks, add-MFA finish and the OTP disclosure are translated", async () => {
    setTranslator({ en: {}, de: DE });
    await inLocale("de", async () => {
      expect(await wf.pin({}, "123456")).toEqual({ code: DE.AOOTH_CODE_EXPIRED });
      expect(wf.address("email", "")).toBe(DE.AOOTH_ADDRESS_REQUIRED);
      expect(wf.address("email", "nope")).toBe(DE.AOOTH_INVALID_EMAIL_ADDRESS);
      const removed = wf.addMfaFinish({ addMfa: { removed: "totp" } });
      expect(removed.message?.text).toBe("Authenticator-App entfernt.");
      expect(wf.disclosure("email")).toBe(DE.OTP_DISCLOSURE_EMAIL);
    });
    await inLocale("en", async () => {
      expect(await wf.pin({}, "123456")).toEqual({ code: "Code expired" });
      expect(wf.address("sms", "abc")).toBe("Enter a valid phone number");
      const removed = wf.addMfaFinish({ addMfa: { removed: "totp" } });
      expect(removed.message?.text).toBe("Authenticator app removed.");
    });
  });
});
