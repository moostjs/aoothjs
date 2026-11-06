/**
 * Magic links against the REAL stack (durable AsWfStore, email outlet, test
 * mailbox):
 *   ML-LOGIN-01 — a user without MFA is signed in by the link; the link is single use.
 *                 Opening a link shows "Continue as …" and does not use it up.
 *   ML-LOGIN-02 — the link is the first factor only: an MFA user is challenged after the click.
 *   ML-LOGIN-03 — unknown / locked / pending identifiers get the requester's same answer, nothing is sent.
 *   ML-LOGIN-04 — the emailed link resumes in the SPA and signs in (browser).
 *   ML-RECOVERY-01 — a recovery link leads to the password step; the reset works; single use.
 *   ML-RECOVERY-02 — an unknown identifier gets the same answer, nothing is sent.
 *   ML-RECOVERY-03 — 'choice': the same picker for known and unknown identifiers.
 *   ML-RECOVERY-04 — the emailed recovery link opens the password form in the SPA (browser).
 */
import { type APIRequestContext, expect, test } from "@playwright/test";

import {
  fillField,
  getEmails,
  readFinishEnvelope,
  resetApp,
  rewriteToBaseUrl,
  submitForm,
  USERS,
  waitForEmail,
  waitForFormInput,
} from "./harness";

const ALICE_EMAIL = "alice@acme.test";
const HENRY_EMAIL = "henry@acme.test";
const NEW_PASSWORD = "NewPassword2!";

const variant = (name: string) => ({ "x-wf-variant": name });

/** The trigger's answer, as far as these tests read it. */
interface TriggerBody {
  wfs?: string;
  finished?: boolean;
  inputRequired?: unknown;
  data?: { accessToken?: string };
}

async function trigger(
  request: APIRequestContext,
  data: Record<string, unknown>,
  headers: Record<string, string>,
) {
  const res = await request.post("/auth/trigger", { data, headers });
  return { status: res.status(), body: (await res.json()) as TriggerBody };
}

/** Login → `magicLink` alt-action → submit `identifier`; returns the requester's answer. */
async function requestSignInLink(request: APIRequestContext, identifier: string, v: string) {
  const headers = variant(v);
  const start = await trigger(request, { wfid: "auth/login/flow" }, headers);
  const form = await trigger(
    request,
    { wfs: start.body.wfs, input: { action: "magicLink" } },
    headers,
  );
  expect(form.body.inputRequired, JSON.stringify(form.body)).toBeDefined();
  return trigger(request, { wfs: form.body.wfs, input: { formData: { identifier } } }, headers);
}

/** Recovery → submit `email`; returns the requester's answer. */
async function requestRecovery(request: APIRequestContext, email: string, v: string) {
  const headers = variant(v);
  const start = await trigger(request, { wfid: "auth/recovery/flow" }, headers);
  return trigger(request, { wfs: start.body.wfs, input: { formData: { email } } }, headers);
}

const linkToken = (url: string | undefined) => new URL(url!).searchParams.get("wfs")!;

/**
 * Open the emailed link ("Continue as …" — the link is not used up yet) and
 * continue (it is used up).
 */
async function useLink(request: APIRequestContext, token: string, v: string) {
  const landing = await trigger(request, { wfs: token }, variant(v));
  expect(landing.body.inputRequired, JSON.stringify(landing.body)).toBeDefined();
  expect(landing.body.wfs, "opening the link does not use it up").toBe(token);
  return trigger(request, { wfs: landing.body.wfs, input: { formData: {} } }, variant(v));
}

test.describe("magic-link sign-in", () => {
  test.beforeEach(async ({ request }) => {
    await resetApp(request);
  });

  test("ML-LOGIN-01: a user without MFA is signed in by the link, once", async ({ request }) => {
    await request.post(`/__test/verified-email/${USERS.alice.username}`);
    const sent = await requestSignInLink(request, USERS.alice.username, "magic-link");
    expect(sent.status).toBe(201);
    expect(sent.body).toEqual({ sent: true, outlet: "email" });

    const mail = await waitForEmail(request, (e) => e.kind === "login.magicLink");
    expect(mail.recipient).toBe(ALICE_EMAIL);
    expect(mail.url).toContain("/login?wfs=magic-link.");

    const token = linkToken(mail.url);
    const done = await useLink(request, token, "magic-link");
    expect(done.body.finished, JSON.stringify(done.body)).toBe(true);
    const status = await request.get("/auth/status", {
      headers: { Authorization: `Bearer ${done.body.data?.accessToken}` },
    });
    expect(status.status()).toBe(200);

    const again = await trigger(request, { wfs: token }, variant("magic-link"));
    expect(again.status).toBe(410);
  });

  test("ML-LOGIN-02: the link is the first factor only — an MFA user is challenged", async ({
    request,
  }) => {
    // henry: email MFA confirmed on henry@acme.test (a proven inbox).
    await requestSignInLink(request, USERS.henry.username, "magic-link-mfa");
    const mail = await waitForEmail(request, (e) => e.kind === "login.magicLink");
    expect(mail.recipient).toBe(HENRY_EMAIL);

    const clicked = await useLink(request, linkToken(mail.url), "magic-link-mfa");
    expect(clicked.body.finished, JSON.stringify(clicked.body)).toBeUndefined();
    expect(clicked.body.inputRequired).toBeDefined();
    expect(JSON.stringify(clicked.body)).not.toContain("accessToken");

    const code = await waitForEmail(request, (e) => e.kind !== "login.magicLink" && !!e.code);
    const done = await trigger(
      request,
      { wfs: clicked.body.wfs, input: { formData: { code: code.code, rememberDevice: false } } },
      variant("magic-link-mfa"),
    );
    expect(done.body.finished, JSON.stringify(done.body)).toBe(true);
    expect(done.body.data?.accessToken).toBeTruthy();
  });

  test("ML-LOGIN-03: unknown, locked and pending identifiers get the same answer; nothing is sent", async ({
    request,
  }) => {
    await request.post(`/__test/verified-email/${USERS.alice.username}`);
    const known = await requestSignInLink(request, USERS.alice.username, "magic-link");
    for (const who of ["nobody-here", USERS.locked.username, USERS.pending.username]) {
      const res = await requestSignInLink(request, who, "magic-link");
      expect(res.status).toBe(known.status);
      expect(res.body).toEqual(known.body);
    }
    const links = (await getEmails(request)).filter((e) => e.kind === "login.magicLink");
    expect(links.map((e) => e.recipient)).toEqual([ALICE_EMAIL]);
  });

  test("ML-LOGIN-04: the emailed link resumes in the SPA and signs in", async ({
    page,
    request,
    baseURL,
  }) => {
    await request.post(`/__test/verified-email/${USERS.alice.username}`);
    await requestSignInLink(request, USERS.alice.username, "magic-link");
    const mail = await waitForEmail(request, (e) => e.kind === "login.magicLink");
    await page.goto(rewriteToBaseUrl(mail.url!, baseURL));
    // The landing step names the account; continuing uses the link up.
    await expect(page.getByText("Continue as a***e@acme.test.")).toBeVisible();
    await submitForm(page);
    await expect(page.getByText("Workflow finished.")).toBeVisible();
    const envelope = (await readFinishEnvelope(page)) as { data?: { accessToken?: string } };
    expect(envelope.data?.accessToken).toBeTruthy();
  });
});

test.describe("recovery by magic link", () => {
  test.beforeEach(async ({ request }) => {
    await resetApp(request);
  });

  test("ML-RECOVERY-01: the link leads to the password step; the reset works; single use", async ({
    request,
  }) => {
    const sent = await requestRecovery(request, ALICE_EMAIL, "recovery-magic-link");
    expect(sent.body).toEqual({ sent: true, outlet: "email" });
    const mail = await waitForEmail(request, (e) => e.kind === "recovery.magicLink");
    expect(mail.recipient).toBe(ALICE_EMAIL);
    expect(mail.url).toContain("/recover?wfs=magic-link.");
    expect(mail.code).toBeUndefined();

    const token = linkToken(mail.url);
    const atPassword = await useLink(request, token, "recovery-magic-link");
    expect(JSON.stringify(atPassword.body.inputRequired)).toContain("newPassword");
    const done = await trigger(
      request,
      {
        wfs: atPassword.body.wfs,
        input: {
          formData: { newPassword: NEW_PASSWORD, confirmPassword: NEW_PASSWORD, consents: [] },
        },
      },
      variant("recovery-magic-link"),
    );
    expect(done.body.finished, JSON.stringify(done.body)).toBe(true);
    expect(done.body.data?.accessToken).toBeFalsy();

    // The new password signs in; the link is spent.
    const login = await trigger(request, { wfid: "auth/login/flow" }, variant("minimal"));
    const signedIn = await trigger(
      request,
      {
        wfs: login.body.wfs,
        input: { formData: { username: USERS.alice.username, password: NEW_PASSWORD } },
      },
      variant("minimal"),
    );
    expect(signedIn.body.finished, JSON.stringify(signedIn.body)).toBe(true);
    expect((await trigger(request, { wfs: token }, variant("recovery-magic-link"))).status).toBe(
      410,
    );
  });

  test("ML-RECOVERY-02: an unknown identifier gets the same answer; nothing is sent", async ({
    request,
  }) => {
    const known = await requestRecovery(request, ALICE_EMAIL, "recovery-magic-link");
    const unknown = await requestRecovery(request, "nobody@acme.test", "recovery-magic-link");
    expect(unknown.status).toBe(known.status);
    expect(unknown.body).toEqual(known.body);
    const links = (await getEmails(request)).filter((e) => e.kind === "recovery.magicLink");
    expect(links.map((e) => e.recipient)).toEqual([ALICE_EMAIL]);
  });

  test("ML-RECOVERY-03: 'choice' shows the same picker for known and unknown identifiers", async ({
    request,
  }) => {
    const known = await requestRecovery(request, ALICE_EMAIL, "recovery-choice");
    const unknown = await requestRecovery(request, "nobody@acme.test", "recovery-choice");
    expect(known.body.inputRequired).toBeDefined();
    expect(unknown.body.inputRequired).toEqual(known.body.inputRequired);
    const picked = await trigger(
      request,
      { wfs: known.body.wfs, input: { formData: { mode: "magicLink" } } },
      variant("recovery-choice"),
    );
    expect(picked.body).toEqual({ sent: true, outlet: "email" });
    const mail = await waitForEmail(request, (e) => e.kind === "recovery.magicLink");
    expect(mail.recipient).toBe(ALICE_EMAIL);
  });

  test("ML-RECOVERY-04: the emailed link opens the password form in the SPA", async ({
    page,
    request,
    baseURL,
  }) => {
    await requestRecovery(request, ALICE_EMAIL, "recovery-magic-link");
    const mail = await waitForEmail(request, (e) => e.kind === "recovery.magicLink");
    await page.goto(rewriteToBaseUrl(mail.url!, baseURL));
    await expect(page.getByText("Continue as a***e@acme.test.")).toBeVisible();
    await submitForm(page);
    await waitForFormInput(page, "newPassword", 15_000);
    await fillField(page, "newPassword", NEW_PASSWORD);
    await fillField(page, "confirmPassword", NEW_PASSWORD);
    await submitForm(page);
    await expect(page.getByText("Workflow finished.")).toBeVisible();
  });
});

test.describe("magic links in the shared wf-state table", () => {
  test.beforeEach(async ({ request }) => {
    await resetApp(request);
  });

  // WHY: the demo keeps magic links in the same table as the durable `store`
  // state; a link's (hashed) key read from that table must not open as a
  // `store.` token.
  for (const [purpose, v] of [
    ["recovery", "recovery-magic-link"],
    ["login", "magic-link"],
  ] as const) {
    test(`ML-SHARED-${purpose}: a ${purpose} link's stored key is not a usable token, and the link survives`, async ({
      request,
    }) => {
      await request.post(`/__test/verified-email/${USERS.alice.username}`);
      if (purpose === "recovery") await requestRecovery(request, ALICE_EMAIL, v);
      else await requestSignInLink(request, USERS.alice.username, v);
      const mail = await waitForEmail(request, (e) => e.kind === `${purpose}.magicLink`);
      const { handles } = (await (await request.get("/__test/wf-states/handles")).json()) as {
        handles: string[];
      };
      const key = handles.find((h) => h.startsWith("wfh1_"));
      expect(key, "the link sits in the shared table, hashed").toBeTruthy();
      const attack = await trigger(request, { wfs: `store.${key}` }, variant(v));
      expect(attack.status).toBe(410);
      expect(attack.body.inputRequired).toBeUndefined();
      const used = await useLink(request, linkToken(mail.url), v);
      expect(used.status).toBe(201);
    });
  }
});
