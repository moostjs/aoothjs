import { type APIRequestContext, expect, test } from "@playwright/test";

import { bearerAuth as auth, mintToken, resetApp, USERS } from "./harness";

/**
 * End-to-end proof of the credential → ARBAC attenuation bridge: a down-scoped
 * token (the credential's TYPED `@arbac.attenuate.*` root fields, minted via the
 * test-only `/__test/token-attenuated` endpoint) authorizes for strictly LESS
 * than its owning user — restrict-only, enforced by the real auth guard + ARBAC
 * interceptor + DB-controller scope application against SQLite.
 *
 * `t1_alice` holds `["member", "viewer"]` in tenant A: member grants the
 * `tasks/new` write + tenant-scoped reads; viewer is read-only.
 */
const ALICE = USERS.alice.username;

function mint(
  request: APIRequestContext,
  claims: { roles?: string[]; attrs?: Record<string, unknown> },
): Promise<string> {
  return mintToken(request, ALICE, claims);
}

test.describe("ARBAC-ATTN: credential-claims → ARBAC attenuation (down-scoped tokens)", () => {
  test.beforeEach(async ({ request }) => {
    await resetApp(request);
  });

  test("ARBAC-ATTN-001: a tenant-attenuated token is clipped to zero rows the owner can read", async ({
    request,
  }) => {
    const full = await mint(request, {});
    // attrs narrow the scope predicate to a foreign tenant; the conjunction
    // with the owner's tenant filter is unsatisfiable → the credential can
    // never see the owner's rows (the attr-widen clip).
    const otherTenant = await mint(request, { attrs: { tenantId: "tenant-zzz-nonexistent" } });

    const fullRes = await request.get("/tasks/query", { headers: auth(full) });
    expect(fullRes.status()).toBe(200);
    expect(((await fullRes.json()) as unknown[]).length).toBeGreaterThan(0);

    const otherRes = await request.get("/tasks/query", { headers: auth(otherTenant) });
    expect(otherRes.status()).toBe(200);
    expect(((await otherRes.json()) as unknown[]).length).toBe(0);
  });

  test("ARBAC-ATTN-002: roles:[] (deny-all) is forbidden from reading", async ({ request }) => {
    const denyAll = await mint(request, { roles: [] });
    const res = await request.get("/tasks/query", { headers: auth(denyAll) });
    expect(res.status()).toBe(403);
  });

  test("ARBAC-ATTN-003: a viewer-attenuated token is denied a write the full token is allowed", async ({
    request,
  }) => {
    const full = await mint(request, {});
    const viewer = await mint(request, { roles: ["viewer"] });

    // viewer (read-only) drops the `member` write grant → denied at the ARBAC
    // guard (the allow-AND outcome intersection).
    const viewerRes = await request.post("/tasks/actions/new", { headers: auth(viewer), data: {} });
    expect(viewerRes.status()).toBe(403);

    // the full token retains member authority → allowed past the guard (the
    // empty body 400s on form validation, but it is NOT a 403).
    const fullRes = await request.post("/tasks/actions/new", { headers: auth(full), data: {} });
    expect(fullRes.status()).not.toBe(403);
  });

  test("ARBAC-ATTN-004: a normal (un-attenuated) token keeps full user authority", async ({
    request,
  }) => {
    const full = await mint(request, {});
    const res = await request.get("/tasks/query", { headers: auth(full) });
    expect(res.status()).toBe(200);
    expect(((await res.json()) as unknown[]).length).toBeGreaterThan(0);
  });
});
