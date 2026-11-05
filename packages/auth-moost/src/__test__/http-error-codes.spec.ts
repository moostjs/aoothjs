import { afterEach, describe, expect, it } from "vite-plus/test";

import { RATE_LIMIT_MESSAGES } from "@aooth/auth";
import { setTranslator, useTranslation } from "moost";

import { AOOTH_HTTP_MESSAGES } from "../http-messages";
import { inLocale, localizedHttpApp, prepareFlowApp } from "./flow-utils";

// Every 4xx auth-moost answers carries a `code` (+ `params`), so an error-body
// translator can translate it by code.

afterEach(() => {
  setTranslator(undefined);
});

describe("coded HttpErrors", () => {
  it("the guard, refresh and status routes answer coded 401s", async () => {
    const app = await prepareFlowApp();
    const guarded = await app.post("/auth/add-mfa", {});
    expect(guarded.status).toBe(401);
    expect(guarded.body).toMatchObject({ code: "AUTH_REQUIRED", message: "Unauthorized" });

    const invalid = await app.post("/auth/add-mfa", {}, { authorization: "Bearer nope" });
    expect(invalid.body).toMatchObject({
      code: "CREDENTIAL_INVALID",
      message: "Invalid credential",
    });

    const status = await app.get("/auth/status");
    expect(status.status).toBe(401);
    expect(status.body).toMatchObject({ code: "NOT_AUTHENTICATED", message: "Not authenticated" });

    const refresh = await app.post("/auth/refresh", {});
    expect(refresh.status).toBe(401);
    expect(refresh.body).toMatchObject({
      code: "MISSING_REFRESH_TOKEN",
      message: AOOTH_HTTP_MESSAGES.MISSING_REFRESH_TOKEN,
    });

    const bad = await app.post("/auth/refresh", { refreshToken: "nope" });
    expect(bad.body).toMatchObject({ code: "INVALID_REFRESH_TOKEN" });
  });

  it("a workflow outside the trigger's allow list is a coded 403 with params", async () => {
    const app = await prepareFlowApp();
    const res = await app.start("auth/not-a-flow");
    expect(res.status).toBe(403);
    expect(res.body).toMatchObject({
      code: "WORKFLOW_NOT_ALLOWED",
      params: { workflow: "auth/not-a-flow" },
      message: "Workflow 'auth/not-a-flow' is not allowed",
    });
  });

  it("an error-body translator translates them by code, filling params", async () => {
    setTranslator({
      en: {},
      de: {
        NOT_AUTHENTICATED: "Nicht angemeldet",
        WORKFLOW_NOT_ALLOWED: "Workflow '{workflow}' ist nicht erlaubt",
      },
    });
    const app = await prepareFlowApp({ httpApp: localizedHttpApp });
    const de = { "accept-language": "de" };
    expect((await app.get("/auth/status", de)).body).toMatchObject({
      code: "NOT_AUTHENTICATED",
      message: "Nicht angemeldet",
    });
    expect((await app.start("auth/x", de)).body).toMatchObject({
      code: "WORKFLOW_NOT_ALLOWED",
      message: "Workflow 'auth/x' ist nicht erlaubt",
    });
    // No Accept-Language → the default (first) locale, English.
    expect((await app.get("/auth/status")).body.message).toBe("Not authenticated");
  });
});

describe("RATE_LIMITED", () => {
  it("is registered once, from @aooth/auth's RATE_LIMIT_MESSAGES (not the HTTP catalogue)", () => {
    expect(AOOTH_HTTP_MESSAGES).not.toHaveProperty("RATE_LIMITED");
    setTranslator({ en: { RATE_LIMITED: RATE_LIMIT_MESSAGES.RATE_LIMITED }, de: {} });
    const messages = inLocale("en", () => useTranslation()?.messages());
    // a translation identical to the template is not listed; the registry has the template
    expect(messages).toEqual({});
    setTranslator({ en: {}, de: { RATE_LIMITED: "Zu viele Anfragen ({retryAfter}s)" } });
    const de = inLocale("de", () => useTranslation()?.messages());
    expect(de).toMatchObject({ RATE_LIMITED: "Zu viele Anfragen ({retryAfter}s)" });
  });
});
