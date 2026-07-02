/**
 * RL.spec.md acceptance — HTTP rate limiting against the REAL stack:
 *   RL-001 — public IP-keyed route: full 429 contract (draft RateLimit-*
 *            headers on every response, Retry-After + templated message on
 *            rejection), and `/__test/reset` restores the budget.
 *   RL-002 — guarded user-keyed route: one budget per user id, independent
 *            across users; anonymous callers are 401'd by the auth guard
 *            (never mistaken for a rate-limit rejection).
 *   RL-003 — undecorated routes are untouched (no default rules configured).
 */
import { expect, test } from "@playwright/test";

import { bearerAuth as auth, mintToken, resetApp, USERS } from "./harness";

test.describe("RL: HTTP rate limiting (@RateLimit)", () => {
  test.beforeEach(async ({ request }) => {
    await resetApp(request);
  });

  test("RL-001: public IP-keyed route — headers on success, 429 + Retry-After + message, reset restores budget", async ({
    request,
  }) => {
    // /rl-demo/ping declares `3/1m | Demo limit hit, wait {{delta}}`.
    for (let i = 1; i <= 3; i++) {
      const res = await request.get("/rl-demo/ping");
      expect(res.status()).toBe(200);
      const headers = res.headers();
      expect(headers["ratelimit-limit"]).toBe("3");
      expect(headers["ratelimit-remaining"]).toBe(String(3 - i));
      expect(Number(headers["ratelimit-reset"])).toBeGreaterThan(0);
      expect(headers["ratelimit-policy"]).toBe("3;w=60");
    }

    const rejected = await request.get("/rl-demo/ping");
    expect(rejected.status()).toBe(429);
    const headers = rejected.headers();
    expect(headers["ratelimit-remaining"]).toBe("0");
    const retryAfter = Number(headers["retry-after"]);
    expect(retryAfter).toBeGreaterThan(0);
    expect(retryAfter).toBeLessThanOrEqual(60);
    expect(await rejected.text()).toContain("Demo limit hit, wait");

    // The test-harness reset wipes counters — budget restored.
    await resetApp(request);
    expect((await request.get("/rl-demo/ping")).status()).toBe(200);
  });

  test("RL-002: guarded user-keyed route — per-user budgets, anonymous is 401 not 429", async ({
    request,
  }) => {
    // /rl-demo/quota declares `2/1m` with `key: 'user'`.
    const alice = await mintToken(request, USERS.alice.username);
    const bob = await mintToken(request, USERS.bob.username);

    for (let i = 0; i < 2; i++) {
      const res = await request.get("/rl-demo/quota", { headers: auth(alice) });
      expect(res.status()).toBe(200);
    }
    const rejected = await request.get("/rl-demo/quota", { headers: auth(alice) });
    expect(rejected.status()).toBe(429);

    // Bob's budget is untouched by alice exhausting hers.
    const other = await request.get("/rl-demo/quota", { headers: auth(bob) });
    expect(other.status()).toBe(200);
    expect((await other.json()) as { userId: string }).toHaveProperty("userId");

    // No token: the guard rejects BEFORE the post-guard rate-limit phase.
    const anonymous = await request.get("/rl-demo/quota");
    expect(anonymous.status()).toBe(401);
  });

  test("RL-003: undecorated routes carry no rate-limit headers (no app-wide defaults)", async ({
    request,
  }) => {
    const res = await request.get("/__test/emails");
    expect(res.status()).toBe(200);
    expect(res.headers()["ratelimit-limit"]).toBeUndefined();
    expect(res.headers()["ratelimit-policy"]).toBeUndefined();
  });
});
