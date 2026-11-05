import { afterEach, describe, expect, it } from "vite-plus/test";

import { AuthCredential, CredentialStoreMemory } from "@aooth/auth";
import { UserService, UserStoreMemory } from "@aooth/user";
import { setTranslator, useTranslation } from "moost";

import { ConsentStore } from "../consent.store";
import { AOOTH_MESSAGES, resolveAoothMessage } from "../workflow/auth-messages";
import { AuthWorkflow, buildInviteAlreadyAcceptedEnvelope } from "../workflow/auth-workflow";
import type { AuthWfCtx } from "../workflow/auth-workflow.ctx";
import { inLocale, localizedHttpApp, prepareFlowApp } from "./flow-utils";

// The message chain: `messages` (app override) → moost translator → English.

const DE = {
  INVALID_CODE: "Ungültiger Code",
  RESEND_WAIT: "Bitte {seconds}s warten.",
  INVALID_CREDENTIALS: "Ungültige Anmeldedaten",
  USER_ALREADY_EXISTS: "Benutzer existiert bereits",
  INVITE_ALREADY_ACCEPTED: "Einladung bereits angenommen.",
};

afterEach(() => {
  setTranslator(undefined);
});

describe("AOOTH_MESSAGES registration", () => {
  it("is registered with moost on import (served translated by useTranslation().messages())", () => {
    setTranslator({ en: {}, de: DE });
    const messages = inLocale("de", () => useTranslation()?.messages());
    expect(messages).toMatchObject({
      INVALID_CODE: "Ungültiger Code",
      RESEND_WAIT: "Bitte {seconds}s warten.",
    });
    // Untranslated codes are not listed (their English template is served by the client).
    expect(messages).not.toHaveProperty("GO_NOW");
  });
});

describe("resolveAoothMessage chain", () => {
  it("translates by code in the event's locale, filling params", () => {
    setTranslator({ en: {}, de: DE });
    inLocale("de", () => {
      expect(resolveAoothMessage("INVALID_CODE")).toBe("Ungültiger Code");
      expect(resolveAoothMessage("RESEND_WAIT", { seconds: 7 })).toBe("Bitte 7s warten.");
      // No translation for the code → the English template, filled.
      expect(resolveAoothMessage("RESEND_WAIT_ANOTHER", { seconds: 3 })).toBe(
        "Please wait 3s before requesting another code",
      );
    });
    inLocale("en", () => expect(resolveAoothMessage("INVALID_CODE")).toBe("Invalid code"));
  });

  it("the app's messages option wins over the translator", () => {
    setTranslator({ en: {}, de: DE });
    inLocale("de", () => {
      expect(resolveAoothMessage("INVALID_CODE", {}, { INVALID_CODE: "Code falsch" })).toBe(
        "Code falsch",
      );
      expect(resolveAoothMessage("INVALID_CODE", {}, () => "vom Resolver")).toBe("vom Resolver");
      // A resolver returning undefined falls through to the translator.
      expect(resolveAoothMessage("INVALID_CODE", {}, () => undefined)).toBe("Ungültiger Code");
      // A map without the code falls through too.
      expect(resolveAoothMessage("INVALID_CODE", {}, { GO_NOW: "Los" })).toBe("Ungültiger Code");
    });
  });

  it("outside an event (or without a translator) it is the English template", () => {
    setTranslator({ en: {}, de: DE });
    expect(resolveAoothMessage("INVALID_CODE")).toBe(AOOTH_MESSAGES.INVALID_CODE);
    setTranslator(undefined);
    inLocale("de", () => expect(resolveAoothMessage("INVALID_CODE")).toBe("Invalid code"));
  });

  it("the invite-already-accepted envelope is translated too", () => {
    setTranslator({ en: {}, de: DE });
    const env = inLocale("de", () =>
      buildInviteAlreadyAcceptedEnvelope({ loginUrl: "/login", alreadyAcceptedRedirectUrl: "" }),
    );
    expect(env.message?.text).toBe("Einladung bereits angenommen.");
  });
});

describe("AuthWorkflow under Accept-Language", () => {
  it("a failed sign-in answers in the request's language", async () => {
    setTranslator({ en: {}, de: DE });
    const app = await prepareFlowApp({ httpApp: localizedHttpApp });
    await app.seedUser("alice", "Password123!");
    const de = { "accept-language": "de-DE,de;q=0.9" };
    const start = await app.start("auth/login/flow", de);
    const res = await app.submit(
      start.body.wfs,
      { formData: { username: "alice", password: "nope" } },
      de,
    );
    expect(res.body.inputRequired.context.errors).toEqual({ __form: "Ungültige Anmeldedaten" });

    const enStart = await app.start("auth/login/flow");
    const en = await app.submit(enStart.body.wfs, {
      formData: { username: "alice", password: "nope" },
    });
    expect(en.body.inputRequired.context.errors).toEqual({ __form: "Invalid credentials" });
  });

  it("a coded HttpError carries code and params, its text in the event's language", async () => {
    setTranslator({ en: {}, de: DE });
    const users = new UserService(new UserStoreMemory());
    const flow = new AuthWorkflow(
      {},
      users,
      new AuthCredential({ store: new CredentialStoreMemory() }),
      new ConsentStore(),
    );
    await users.createUser("taken@x.test", "Password123!");
    const ctx = { email: "taken@x.test", admin: { userExtras: {} } } as AuthWfCtx;
    const err = await inLocale("de", () => flow.createUser(ctx).catch((e: unknown) => e));
    expect((err as { body: unknown }).body).toMatchObject({
      statusCode: 409,
      message: "Benutzer existiert bereits",
      code: "USER_ALREADY_EXISTS",
    });
  });
});
