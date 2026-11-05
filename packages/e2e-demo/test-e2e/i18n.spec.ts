import { expect, test } from "@playwright/test";

import { uniqueEmail } from "./harness";

/**
 * The Accept-Language path end to end: the demo registers a translator
 * (src/i18n.ts — English default + a few German texts). `MoostHttp`
 * negotiates each request's locale against it; the auth workflow resolves
 * its texts through the translator and error bodies are translated by code.
 * No reset needed: a sign-in with a fresh unknown handle touches no seeded data.
 */
test.describe("Accept-Language: de", () => {
  test("I18N-01: a workflow form error in German (English without the header)", async ({
    request,
  }) => {
    const signIn = async (headers: Record<string, string>) => {
      const start = await request.post("/auth/trigger", {
        headers,
        data: { wfid: "auth/login/flow" },
      });
      expect(start.status()).toBe(201);
      const { wfs } = (await start.json()) as { wfs: string };
      const res = await request.post("/auth/trigger", {
        headers,
        // a fresh unknown handle each time: repeated misses would lock it (uniform lockout)
        data: { wfs, input: { formData: { username: uniqueEmail("i18n"), password: "wrong" } } },
      });
      const body = (await res.json()) as { inputRequired: { context: { errors: unknown } } };
      return body.inputRequired.context.errors;
    };
    expect(await signIn({ "Accept-Language": "de-DE,de;q=0.9,en;q=0.5" })).toEqual({
      __form: "Ungültige Anmeldedaten",
    });
    expect(await signIn({})).toEqual({ __form: "Invalid credentials" });
  });

  test("I18N-02: an error body translated by its code", async ({ request }) => {
    const de = await request.get("/auth/status", { headers: { "Accept-Language": "de" } });
    expect(de.status()).toBe(401);
    expect(await de.json()).toMatchObject({
      code: "NOT_AUTHENTICATED",
      message: "Nicht angemeldet",
    });
    expect(de.headers()["vary"]?.toLowerCase()).toContain("accept-language");

    const en = await request.get("/auth/status");
    expect(await en.json()).toMatchObject({
      code: "NOT_AUTHENTICATED",
      message: "Not authenticated",
    });
  });
});
