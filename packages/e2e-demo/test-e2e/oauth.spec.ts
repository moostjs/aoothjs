/**
 * Federated login (OAuth2 / OIDC) e2e — drives the full browser bounce through
 * the test-only fake IdP:
 *
 *   "Sign in with Google" (top-level nav) → GET /auth/oauth/google/start
 *     → 302 → GET /__fake-idp/authorize  (mints a code, registers the profile)
 *     → 302 → GET /auth/oauth/google/callback?code&state  (SPA bridge page)
 *     → POST /auth/trigger { wfid: auth/oauth/flow, input.formData: { code, state } }
 *     → oauth-exchange (verify state + CSRF + PKCE txn + ID token) → login tail
 *     → finish { data.accessToken, userId }
 *
 * The PKCE verifier never leaves the server; only the single-use `code` rides
 * through the browser. Asserts the first login CREATES the account and a second
 * login with the same provider `subject` LINKS to the SAME user.
 */
import { expect, test } from "@playwright/test";

import { resetApp } from "./harness";

interface OAuthFinish {
  finished?: boolean;
  data?: { accessToken?: string; userId?: string };
}

/** Drive one full OAuth round-trip via the home-page button; return the finish envelope. */
async function signInWithGoogle(page: import("@playwright/test").Page): Promise<OAuthFinish> {
  const triggerResp = page.waitForResponse(
    (r) => r.url().includes("/auth/trigger") && r.request().method() === "POST",
    { timeout: 15_000 },
  );
  // `page.goto` follows the 302 chain (start → fake-idp → callback) and resolves
  // on the SPA callback page, which auto-starts the oauth flow via /auth/trigger.
  await page.goto("/auth/oauth/google/start");
  const resp = await triggerResp;
  return (await resp.json()) as OAuthFinish;
}

test.beforeEach(async ({ request }) => {
  await resetApp(request);
});

test.describe("OAuth / federated login", () => {
  test("OAUTH-001: first federated login creates the account and issues a session", async ({
    page,
  }) => {
    const envelope = await signInWithGoogle(page);

    expect(envelope.finished, "oauth flow finished").toBe(true);
    expect(typeof envelope.data?.accessToken, "issued an access token").toBe("string");
    expect((envelope.data?.accessToken ?? "").length).toBeGreaterThan(0);
    expect(envelope.data?.userId, "carries the resolved user id").toBeTruthy();

    // The bridge page navigates home after stashing the token.
    await expect(page).toHaveURL(/\/$|\/\?/, { timeout: 10_000 });

    // The issued token authenticates a real session.
    const token = envelope.data!.accessToken!;
    const status = await page.request.get("/auth/status", {
      headers: { authorization: `Bearer ${token}` },
    });
    expect(status.status()).toBe(200);
    const ctx = (await status.json()) as { userId?: string };
    expect(ctx.userId).toBe(envelope.data?.userId);
  });

  test("OAUTH-002: second login with the same provider subject links to the SAME user", async ({
    page,
  }) => {
    const first = await signInWithGoogle(page);
    expect(first.data?.userId, "first login created/linked a user").toBeTruthy();

    // Second round trip — same fake-IdP default subject → `resolveUser` finds the
    // existing `(google, sub)` link → `linked` → same account (no duplicate).
    const second = await signInWithGoogle(page);
    expect(second.finished).toBe(true);
    expect(typeof second.data?.accessToken).toBe("string");
    expect(second.data?.userId, "linked to the same user, not a new one").toBe(first.data?.userId);
  });
});
