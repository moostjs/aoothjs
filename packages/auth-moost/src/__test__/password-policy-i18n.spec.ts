import { afterEach, describe, expect, it } from "vite-plus/test";

import { ppHasMinLength, ppHasNumber, UserAuthError } from "@aooth/user";
import { setTranslator, useTranslation } from "moost";

import { userAuthErrorToHttp } from "../user-errors";
import { inLocale, localizedHttpApp, prepareFlowApp } from "./flow-utils";

// Password policies carry PP_* codes: their texts are translated by code in
// the request's language, the English (plural-correct) text the fallback.

const DE = {
  PP_MIN_LENGTH: "Das Passwort muss mindestens {min} Zeichen lang sein",
  PP_MIN_LENGTH_DESCRIPTION: "Mindestens {min} Zeichen",
  SET_PASSWORD_INITIAL_HEADING: "Lege dein erstes Passwort fest",
};

afterEach(() => {
  setTranslator(undefined);
});

describe("PP_* codes", () => {
  it("are registered with moost by auth-moost", () => {
    setTranslator({ en: {}, de: DE });
    expect(inLocale("de", () => useTranslation()?.messages())).toMatchObject({
      PP_MIN_LENGTH: "Das Passwort muss mindestens {min} Zeichen lang sein",
    });
  });

  it("the set-password form ships translated policies and a translated failure", async () => {
    setTranslator({ en: {}, de: DE });
    const app = await prepareFlowApp({
      httpApp: localizedHttpApp,
      userConfig: { password: { policies: [ppHasMinLength(12), ppHasNumber(1)] } },
    });
    const de = { "accept-language": "de" };
    const id = await app.seedUser("alice", "Password123!xx");
    await app.users.update(id, { password: { isInitial: true } } as never);
    const start = await app.start("auth/login/flow", de);
    const atForm = await app.submit(
      start.body.wfs,
      { formData: { username: "alice", password: "Password123!xx" } },
      de,
    );
    const pub = atForm.body.inputRequired.context.public;
    expect(pub.password.heading).toBe("Lege dein erstes Passwort fest");
    expect(pub.password.policies).toMatchObject([
      {
        code: "PP_MIN_LENGTH",
        params: { min: 12 },
        description: "Mindestens 12 Zeichen",
        errorMessage: "Das Passwort muss mindestens 12 Zeichen lang sein",
      },
      // Untranslated: the English text (singular here).
      { code: "PP_NUMBER", description: "At least 1 number" },
    ]);

    const short = await app.submit(
      atForm.body.wfs,
      { formData: { newPassword: "short123", confirmPassword: "short123", consents: [] } },
      de,
    );
    expect(short.body.inputRequired.context.errors).toEqual({
      newPassword: "Das Passwort muss mindestens 12 Zeichen lang sein",
    });
  });

  it("userAuthErrorToHttp translates a POLICY_VIOLATION per failed policy", () => {
    setTranslator({ en: {}, de: DE });
    const policies = [
      {
        description: "Minimum length 12",
        passed: false,
        errorMessage: "Password must be at least 12 characters long",
        code: "PP_MIN_LENGTH",
        params: { min: 12 },
      },
      {
        description: "Custom",
        passed: false,
        errorMessage: "Must not contain the username",
      },
    ];
    const err = new UserAuthError(
      "POLICY_VIOLATION",
      "Password must be at least 12 characters long; Must not contain the username",
      { policies },
    );
    expect(inLocale("de", () => userAuthErrorToHttp(err)).body).toMatchObject({
      code: "POLICY_VIOLATION",
      message: "Das Passwort muss mindestens 12 Zeichen lang sein; Must not contain the username",
      params: { policies },
    });
    // Without a translation: the English message, unchanged.
    expect(inLocale("en", () => userAuthErrorToHttp(err)).body.message).toBe(err.message);
  });

  it("a hand-thrown POLICY_VIOLATION keeps its own message when nothing is translated", () => {
    setTranslator({ en: {}, de: DE });
    const err = new UserAuthError("POLICY_VIOLATION", "Pick a stronger password", {
      policies: [
        { description: "Custom", passed: false, errorMessage: "Must not be a dictionary word" },
      ],
    });
    expect(inLocale("de", () => userAuthErrorToHttp(err)).body.message).toBe(
      "Pick a stronger password",
    );
  });
});
