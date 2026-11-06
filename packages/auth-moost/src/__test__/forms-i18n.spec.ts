import { readFileSync } from "node:fs";

import { serializeFormSchema } from "@atscript/moost-wf";
import { compileFieldFn, compileTopFn } from "@atscript/ui-fns";
import { formatMessage, setTranslator, useTranslation } from "moost";
import { afterEach, beforeEach, describe, expect, it } from "vite-plus/test";

import {
  AuthorizeConsentForm,
  EnrollPickMethodForm,
  LoginCredentialsForm,
  ManageMfaForm,
  MfaCodeForm,
  RecoveryModeSelectForm,
  RemoveMfaConfirmForm,
  Select2faForm,
  SetPasswordForm,
  StepUpConfirmForm,
} from "../atscript/index";
import * as forms from "../atscript/index";
import { inLocale, localizedHttpApp, prepareFlowApp } from "./flow-utils";

// The bundled forms' expression texts go through `t(text, params)`: the server
// serves their translations in the form schema's `$i18n`, the browser's `t`
// reads them, and without a translation the English text is unchanged.

const DE: Record<string, string> = {
  Username: "Benutzername",
  "Forgot password?": "Passwort vergessen?",
  "Continue with {provider}": "Weiter mit {provider}",
  "Don’t have an account?": "Noch kein Konto?",
  "Code sent to {recipient}.": "Code an {recipient} gesendet.",
  "TOTP (Authenticator app)": "TOTP (Authenticator-App)",
  Email: "E-Mail",
  "Add {method}": "{method} hinzufügen",
  email: "E-Mail",
  "Magic link": "Magischer Link",
  PASSWORDS_DO_NOT_MATCH: "Die Passwörter stimmen nicht überein",
  MIN_LENGTH: "Mindestens {min} Zeichen",
  REQUIRED: "Darf nicht leer sein",
};

afterEach(() => {
  setTranslator(undefined);
});

// biome-ignore lint/suspicious/noExplicitAny: navigating atscript runtime metadata
type AnyForm = any;
const meta = (form: AnyForm, prop: string, key: string): unknown =>
  form.type.props.get(prop).metadata.get(key);
const fnAttr = (form: AnyForm, prop: string, name: string): string =>
  (meta(form, prop, "ui.form.fn.attr") as Array<{ name: string; fn: string }>).find(
    (a) => a.name === name,
  )!.fn;

/** The browser's `t`: a served translation by exact match, else the text; params filled. */
const tWith =
  (dict: Record<string, string>) =>
  (text: string, params?: Record<string, unknown>): string =>
    formatMessage(Object.hasOwn(dict, text) ? dict[text] : text, params);
const EN = tWith({});
const BROWSER_DE = tWith(DE);

/** Runs a field expression the way the browser does. */
const run = (src: string, context: unknown, t = EN) =>
  compileFieldFn(src)({ v: undefined, data: {}, context, entry: undefined, t } as never);
const field = (form: AnyForm, prop: string, key: string, context: unknown, t = EN) =>
  run(meta(form, prop, key) as string, context, t);

/** The serialized schema of `form`, as served in `locale`. */
const schemaIn = (locale: string, form: AnyForm) =>
  inLocale(locale, () => serializeFormSchema(form)) as { $i18n?: Record<string, string> };

describe("forms.as expression texts", () => {
  it("every t() text in forms.as is served in its form's $i18n — no registration needed", () => {
    // The server collects the string literals of text expressions, `fn.value`
    // (ui.paragraph notices) included: a translator that knows every text
    // must find each `t("…")` literal of forms.as in some form's `$i18n`.
    const source = readFileSync(new URL("../atscript/models/forms.as", import.meta.url), "utf8");
    const used = new Set([...source.matchAll(/\bt\("((?:[^"\\]|\\.)*)"/g)].map((m) => m[1]));
    expect(used.size).toBeGreaterThan(30);
    setTranslator((id, _p, { locale }) => (locale === "de" ? `«${id}»` : undefined), {
      locales: ["en", "de"],
    });
    const served = new Set<string>();
    for (const form of Object.values(forms)) {
      for (const id of Object.keys(schemaIn("de", form).$i18n ?? {})) served.add(id);
    }
    expect([...used].filter((text) => !served.has(text))).toEqual([]);
  });

  it("keep their English wording without a translation", () => {
    const sentTo = { public: { pincode: { sentTo: "a•••@x.test" } } };
    expect(field(MfaCodeForm, "transportHint", "ui.form.fn.value", sentTo)).toBe(
      "Code sent to a•••@x.test.",
    );
    expect(
      run(fnAttr(LoginCredentialsForm, "ssoProvider", "providers"), {
        public: { altActions: { ssoProviders: [{ id: "g", label: "Google" }] } },
      }),
    ).toEqual([{ id: "g", text: "Continue with Google", icon: undefined }]);
    const enrolled = {
      public: {
        mfa: {
          enrolledMethods: [
            { methodName: "totp", kind: "totp", masked: "" },
            { methodName: "email", kind: "email", masked: "ma•••@x.test" },
          ],
        },
        manage: { candidates: ["sms"] },
      },
    };
    expect(field(Select2faForm, "methodName", "ui.form.fn.options", enrolled)).toEqual([
      { key: "totp", label: "TOTP (Authenticator app)" },
      { key: "email", label: "Email (ma•••@x.test)" },
    ]);
    expect(field(ManageMfaForm, "operation", "ui.form.fn.options", enrolled)).toEqual([
      { key: "add:sms", label: "Add SMS" },
      { key: "replace:totp", label: "Change authenticator app" },
      { key: "remove:totp", label: "Remove authenticator app" },
      { key: "replace:email", label: "Change email (ma•••@x.test)" },
      { key: "remove:email", label: "Remove email" },
    ]);
    expect(
      field(EnrollPickMethodForm, "method", "ui.form.fn.options", {
        public: { mfaEnroll: { availableTransports: ["totp", "sms"] } },
      }),
    ).toEqual([
      { key: "totp", label: "Authenticator app (TOTP)" },
      { key: "sms", label: "SMS" },
    ]);
    expect(
      field(RemoveMfaConfirmForm, "notice", "ui.form.fn.value", {
        public: { mfaEnroll: { method: "sms" } },
      }),
    ).toBe("Remove SMS codes as a two-factor method? You can set it up again later.");
    expect(
      field(StepUpConfirmForm, "notice", "ui.form.fn.value", {
        public: { mfa: { method: "sms", enrolledMethods: [] } },
      }),
    ).toBe("To continue, we will send a verification code to your phone.");
    const authz = { clientName: "CLI", redirectHost: "127.0.0.1", scope: "openid" };
    expect(field(AuthorizeConsentForm, "notice", "ui.form.fn.value", { public: { authz } })).toBe(
      "“CLI” (127.0.0.1) wants to sign in to your account. It is requesting access to: openid. Authorize this only if you started it.",
    );
    expect(field(AuthorizeConsentForm, "notice", "ui.form.fn.value", { public: {} })).toBe(
      "A local application wants to sign in to your account. Authorize this only if you started it.",
    );
    expect(
      compileTopFn(SetPasswordForm.metadata.get("ui.form.fn.title") ?? "")({
        data: {},
        context: {},
        t: EN,
      }),
    ).toBe("Set your password");
  });

  it("read the served translations through t, params filled", () => {
    expect(
      field(
        MfaCodeForm,
        "transportHint",
        "ui.form.fn.value",
        { public: { pincode: { sentTo: "a•••@x.test" } } },
        BROWSER_DE,
      ),
    ).toBe("Code an a•••@x.test gesendet.");
    const enrolled = {
      public: {
        mfa: { enrolledMethods: [{ methodName: "email", kind: "email", masked: "m•@x" }] },
      },
    };
    expect(field(Select2faForm, "methodName", "ui.form.fn.options", enrolled, BROWSER_DE)).toEqual([
      { key: "email", label: "E-Mail (m•@x)" },
    ]);
    expect(
      field(
        ManageMfaForm,
        "operation",
        "ui.form.fn.options",
        { public: { manage: { candidates: ["email"] } } },
        BROWSER_DE,
      ),
    ).toEqual([{ key: "add:email", label: "E-Mail hinzufügen" }]);
  });
});

describe("forms served under a translator", () => {
  beforeEach(() => setTranslator({ en: {}, de: DE }));

  it("the MFA method picker's option texts ride $i18n (extracted from fn.options)", () => {
    expect(schemaIn("de", Select2faForm).$i18n).toMatchObject({
      "TOTP (Authenticator app)": "TOTP (Authenticator-App)",
      Email: "E-Mail",
    });
    // English: the source schema, no $i18n.
    expect(schemaIn("en", Select2faForm)).not.toHaveProperty("$i18n");
  });

  it("static option labels are translated in the schema, their values kept", () => {
    const schema = JSON.stringify(schemaIn("de", RecoveryModeSelectForm));
    expect(schema).toContain('"Magischer Link"');
    expect(schema).toContain('"magicLink"');
  });

  it("a ui.paragraph notice's t() text rides $i18n via fn.value extraction, not a registered catalogue", () => {
    expect(schemaIn("de", MfaCodeForm).$i18n).toMatchObject({
      "Code sent to {recipient}.": "Code an {recipient} gesendet.",
    });
    // Not a registered template: it reaches only the forms that use it.
    expect(inLocale("de", () => useTranslation()?.messages())).not.toHaveProperty([
      "Code sent to {recipient}.",
    ]);
  });

  it("the login form: label, action label, expression texts and validator templates in German", async () => {
    const app = await prepareFlowApp({ httpApp: localizedHttpApp });
    const de = await app.start("auth/login/flow", { "accept-language": "de" });
    const payload = de.body.inputRequired.payload;
    const json = JSON.stringify(payload);
    expect(json).toContain('"Benutzername"');
    expect(json).toContain('"Passwort vergessen?"');
    expect(payload.$i18n).toMatchObject({
      "Continue with {provider}": "Weiter mit {provider}",
      "Don’t have an account?": "Noch kein Konto?",
      MIN_LENGTH: "Mindestens {min} Zeichen",
      REQUIRED: "Darf nicht leer sein",
    });

    const en = await app.start("auth/login/flow", { "accept-language": "en" });
    expect(JSON.stringify(en.body.inputRequired.payload)).toContain('"Username"');
    expect(en.body.inputRequired.payload).not.toHaveProperty("$i18n");
  });
});

describe("workflow form validation under a translator", () => {
  it("a set-password minLength error is worded in the request's language", async () => {
    setTranslator({ en: {}, de: DE });
    const app = await prepareFlowApp({ httpApp: localizedHttpApp });
    const de = { "accept-language": "de" };
    const id = await app.seedUser("alice", "Password123!");
    await app.users.update(id, { password: { isInitial: true } } as never);
    const start = await app.start("auth/login/flow", de);
    const atForm = await app.submit(
      start.body.wfs,
      { formData: { username: "alice", password: "Password123!" } },
      de,
    );
    expect(atForm.body.inputRequired).toBeDefined();
    const short = await app.submit(
      atForm.body.wfs,
      { formData: { newPassword: "Ab1!", confirmPassword: "Ab1!", consents: [] } },
      de,
    );
    expect(short.body.inputRequired.context.errors).toMatchObject({
      newPassword: "Mindestens 8 Zeichen",
    });

    const mismatch = await app.submit(
      short.body.wfs,
      {
        formData: { newPassword: "NewPassword456!", confirmPassword: "Other456!xyz", consents: [] },
      },
      de,
    );
    // The workflow's own check (coded), translated; the public context ships
    // the same text for the form's client-side `@ui.form.validate`.
    expect(mismatch.body.inputRequired.context.errors).toMatchObject({
      confirmPassword: "Die Passwörter stimmen nicht überein",
    });
    expect(mismatch.body.inputRequired.context.public.messages).toEqual({
      PASSWORDS_DO_NOT_MATCH: "Die Passwörter stimmen nicht überein",
    });
  });
});
