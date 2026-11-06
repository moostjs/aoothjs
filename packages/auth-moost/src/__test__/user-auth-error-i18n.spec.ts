import { afterEach, beforeEach, describe, expect, it } from "vite-plus/test";

import { UserAuthError, USER_AUTH_ERROR_MESSAGES } from "@aooth/user";
import { setTranslator, useTranslation } from "moost";

import { userAuthErrorToHttp } from "../user-errors";
import { inLocale } from "./flow-utils";

// `UserAuthError` texts are a coded catalogue (codes = error types), registered
// by auth-moost: a translator translates them by type and `$i18n` serves them.

// `NOT_FOUND` is a shared generic id (atscript-db's errors use it too): neutral wording.
const DE = { LOCKED: "Konto gesperrt", NOT_FOUND: "Nicht gefunden" };

/** The HTTP body of `e`, answered in `locale`. */
const body = (e: UserAuthError, locale = "de") =>
  inLocale(locale, () => userAuthErrorToHttp(e).body);

afterEach(() => {
  setTranslator(undefined);
});

describe("USER_AUTH_ERROR_MESSAGES", () => {
  beforeEach(() => setTranslator({ en: {}, de: DE }));

  it("is registered with moost by auth-moost (served translated in $i18n)", () => {
    const messages = inLocale("de", () => useTranslation()?.messages());
    expect(messages).toMatchObject(DE);
    // Untranslated codes are not listed: the client keeps their English.
    expect(messages).not.toHaveProperty("CAS_EXHAUSTED");
  });

  it("a UserAuthError answers in the request's language, its type the code", () => {
    expect(body(new UserAuthError("LOCKED"))).toMatchObject({
      code: "LOCKED",
      message: "Konto gesperrt",
    });
    // No translation for the type: the English default message.
    expect(body(new UserAuthError("CAS_EXHAUSTED")).message).toBe(
      USER_AUTH_ERROR_MESSAGES.CAS_EXHAUSTED,
    );
    expect(body(new UserAuthError("LOCKED"), "en").message).toBe("Account is locked");
  });
});
