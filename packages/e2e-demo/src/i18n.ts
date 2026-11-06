import { setTranslator } from "moost";

/**
 * The demo's translator: English (the default — the source texts as they
 * are) plus German for a representative set, so a request (or a browser) in
 * `de` gets German workflow forms, errors and `/meta` (test-e2e/i18n.spec.ts).
 * `MoostHttp` negotiates each request's locale against `en` / `de`.
 *
 * Ids are codes for coded messages (aooth catalogues, validator messages,
 * `UI_*` component texts) and the English text itself for model and form
 * texts (`@meta.label`, action labels, the forms' `t("…")` expression texts).
 */
export function installDemoTranslator(): void {
  setTranslator({
    en: {},
    de: {
      // aooth message codes (AOOTH_MESSAGES, AOOTH_HTTP_MESSAGES, USER_AUTH_ERROR_MESSAGES)
      INVALID_CREDENTIALS: "Ungültige Anmeldedaten",
      NOT_AUTHENTICATED: "Nicht angemeldet",
      PASSWORDS_DO_NOT_MATCH: "Die Passwörter stimmen nicht überein",
      LOCKED: "Konto gesperrt",
      // validator messages (atscript VALIDATOR_MESSAGES)
      REQUIRED: "Darf nicht leer sein",
      MIN_LENGTH: "Mindestens {min} Zeichen",
      MAX_LENGTH: "Höchstens {max} Zeichen",
      // built-in UI texts (atscript-ui AS_UI_MESSAGES)
      UI_YES: "Ja",
      UI_NO: "Nein",
      // form texts — static annotations
      "Sign in": "Anmelden",
      Username: "Benutzername",
      Password: "Passwort",
      "Forgot password?": "Passwort vergessen?",
      "Sign up": "Registrieren",
      "Sign in with a magic link": "Mit einem magischen Link anmelden",
      "Verify your identity": "Identität bestätigen",
      Verify: "Bestätigen",
      "Verification code": "Bestätigungscode",
      // form texts — the forms' expressions (`t("…")`, served with each form)
      "Don’t have an account?": "Noch kein Konto?",
      "Continue with {provider}": "Weiter mit {provider}",
      "Code sent to {recipient}.": "Code an {recipient} gesendet.",
      "Enter your verification code.": "Gib deinen Bestätigungscode ein.",
      "TOTP (Authenticator app)": "TOTP (Authenticator-App)",
      Email: "E-Mail",
      "Passwords must match": "Die Passwörter müssen übereinstimmen",
      // a data model text (/meta option label; the value stays `open`)
      open: "offen",
    },
  });
}
