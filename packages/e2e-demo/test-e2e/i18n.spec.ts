import { expect, test } from "@playwright/test";

import {
  bearerAuth,
  fillField,
  mintToken,
  resetApp,
  submitForm,
  uniqueEmail,
  USERS,
  waitForFormInput,
  wfUrl,
} from "./harness";

/**
 * The Accept-Language path end to end: the demo registers a translator
 * (src/i18n.ts — English default + a few German texts). `MoostHttp`
 * negotiates each request's locale against it; the auth workflow resolves
 * its texts through the translator and error bodies are translated by code.
 * Most tests need no reset: a sign-in with a fresh unknown handle touches no
 * seeded data, and the `/meta` read uses a minted token of a seeded user.
 * I18N-06 signs a seeded MFA user in, so it resets the demo first.
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

test.describe("Client locale de (?lang=de)", () => {
  test("I18N-03: the login form in German — label, expression text, validator message, error", async ({
    page,
  }) => {
    // The browser itself stays English: `provideAsLocale` (App.vue) sends the
    // app's locale as Accept-Language and merges the served `$i18n`.
    await page.goto(`${wfUrl("auth/login/flow")}&lang=de`);
    await waitForFormInput(page, "username");
    const signIn = page.getByRole("button", { name: "Anmelden", exact: true });

    // a static form text (@meta.label), translated by the server
    await expect(page.getByText("Benutzername", { exact: true })).toBeVisible();
    await expect(signIn).toBeVisible();
    // expression texts: t("Continue with {provider}", …) and t("Don’t have an account?")
    await expect(page.getByRole("button", { name: "Weiter mit Google" })).toBeVisible();
    await expect(page.getByText("Noch kein Konto?")).toBeVisible();

    // a validator message, checked in the browser from the served templates
    await signIn.click();
    await expect(page.getByText("Darf nicht leer sein").first()).toBeVisible();

    // a server error, by code
    await fillField(page, "username", uniqueEmail("i18n-ui"));
    await fillField(page, "password", "wrong");
    await signIn.click();
    await expect(page.getByText("Ungültige Anmeldedaten")).toBeVisible();
  });

  test("I18N-06: MFA method options and the code-sent hint in German", async ({
    page,
    request,
  }) => {
    await resetApp(request); // signs a seeded user in: start from the seed
    await page.goto(`${wfUrl("auth/login/flow", "mfa-full")}&lang=de`);
    await fillField(page, "username", USERS.multi_mfa.username);
    await fillField(page, "password", USERS.multi_mfa.password);
    await page.getByRole("button", { name: "Anmelden", exact: true }).click();
    await waitForFormInput(page, "code");
    await page.getByRole("button", { name: "Use a different method" }).click();

    // fn.options labels built with t(…) — the method selector
    await waitForFormInput(page, "methodName");
    await expect(page.getByRole("radio", { name: "TOTP (Authenticator-App)" })).toBeVisible();
    await expect(page.getByRole("radio", { name: /^E-Mail \(.+\)$/ })).toBeVisible();

    // a ui.paragraph notice: t("Code sent to {recipient}.", …)
    await fillField(page, "methodName", "email");
    await submitForm(page);
    await waitForFormInput(page, "code");
    await expect(page.getByText(/^Code an .+ gesendet\.$/)).toBeVisible();
  });

  test("I18N-04: without a language the login form stays English", async ({ page }) => {
    await page.goto(wfUrl("auth/login/flow"));
    await waitForFormInput(page, "username");
    await expect(page.getByText("Username", { exact: true })).toBeVisible();
    await expect(page.getByRole("button", { name: "Continue with Google" })).toBeVisible();
    await expect(page.getByText("Don’t have an account?")).toBeVisible();
  });
});

test.describe("/meta under Accept-Language: de", () => {
  test("I18N-05: /tasks/meta carries $i18n and translated option labels", async ({ request }) => {
    const token = await mintToken(request, "t1_dave");
    const de = await request.get("/tasks/meta", {
      headers: { ...bearerAuth(token), "Accept-Language": "de" },
    });
    expect(de.status()).toBe(200);
    expect(de.headers()["vary"]?.toLowerCase()).toContain("accept-language");
    const body = (await de.json()) as { type: { $i18n?: Record<string, unknown> } };
    // flat `{ [id]: text }`: the registered templates (validator, aooth) translated
    expect(body.type.$i18n).toMatchObject({
      REQUIRED: "Darf nicht leer sein",
      MAX_LENGTH: "Höchstens {max} Zeichen",
      LOCKED: "Konto gesperrt", // USER_AUTH_ERROR_MESSAGES
    });
    const text = JSON.stringify(body);
    expect(text).toContain('"offen"'); // the `open` option's label
    expect(text).toContain('"open"'); // its value is kept

    const en = await request.get("/tasks/meta", { headers: bearerAuth(token) });
    expect(((await en.json()) as { type: object }).type).not.toHaveProperty("$i18n");
  });
});
