import { setTranslator } from "moost";

/**
 * The demo's translator: English (the default — the catalogue texts as they
 * are) plus a few German texts, so a request with `Accept-Language: de` gets
 * a German workflow form error and a German error body
 * (test-e2e/i18n.spec.ts). The codes come from `AOOTH_MESSAGES` and
 * `AOOTH_HTTP_MESSAGES`; `MoostHttp` negotiates the locale and translates
 * error bodies by code.
 */
export function installDemoTranslator(): void {
  setTranslator({
    en: {},
    de: {
      INVALID_CREDENTIALS: "Ungültige Anmeldedaten",
      NOT_AUTHENTICATED: "Nicht angemeldet",
    },
  });
}
