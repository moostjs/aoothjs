import { expect, test } from "@playwright/test";

import { loginViaUi, resetApp, USERS } from "./harness";

// WHY: the demo runs `rotation: 'always'` on a stateful (atscript-db) credential
// store — the exact shape that, pre-fix, turned a benign concurrent refresh into
// a "token theft" response and logged the user out of every device. These tests
// pin the two refresh-layer guarantees against the REAL stack:
//   RF-001 — a concurrent refresh within the grace window both succeeds; no theft.
//   RF-002 — the refresh cookie is scoped to AuthController's resolved route.

interface SessionRow {
  sessionId: string;
  current?: boolean;
}

function setCookies(headers: { name: string; value: string }[]): string[] {
  return headers.filter((h) => h.name.toLowerCase() === "set-cookie").map((h) => h.value);
}

test.describe("Refresh & rotation (auth.refresh)", () => {
  test.beforeEach(async ({ request }) => {
    await resetApp(request);
  });

  test("RF-001: concurrent refresh within grace both succeed — no theft logout", async ({
    page,
  }) => {
    await loginViaUi(page, USERS.alice);

    // Two tabs / parallel XHRs present the SAME refresh cookie at once — both
    // fire before either response rotates the jar. Pre-fix the second was
    // mistaken for a replayed (consumed) token → REFRESH_REUSE_DETECTED →
    // revokeAllForUser → 401 everywhere. With the store-backed grace window
    // both land inside grace and succeed.
    const [a, b] = await Promise.all([
      page.request.post("/auth/refresh", { data: {} }),
      page.request.post("/auth/refresh", { data: {} }),
    ]);
    expect(a.status()).toBe(201);
    expect(b.status()).toBe(201);

    // The user is NOT logged out everywhere: still authenticated, still exactly
    // one session (no theft revoke fired).
    expect((await page.request.get("/auth/status")).status()).toBe(200);
    const sessions = (await (await page.request.get("/auth/sessions")).json()) as SessionRow[];
    expect(sessions).toHaveLength(1);
    expect(sessions[0].current).toBe(true);
  });

  test("RF-002: the refresh cookie is scoped to the resolved /auth/refresh route", async ({
    page,
  }) => {
    await loginViaUi(page, USERS.alice);

    const res = await page.request.post("/auth/refresh", { data: {} });
    expect(res.status()).toBe(201);

    // AuthController is mounted at the root here, so the auto-derived path equals
    // the default `/auth/refresh` — the cookie must carry exactly that Path so
    // it keeps travelling only to the refresh endpoint. (The under-a-prefix
    // derivation, e.g. `/api/auth/refresh`, is covered by the auth-moost
    // integration spec, which can mount the controller under a prefix.)
    const refreshCookie = setCookies(res.headersArray()).find((c) =>
      c.startsWith("aooth_refresh="),
    );
    expect(refreshCookie).toBeDefined();
    expect(refreshCookie).toMatch(/;\s*Path=\/auth\/refresh(;|$)/i);
  });
});
