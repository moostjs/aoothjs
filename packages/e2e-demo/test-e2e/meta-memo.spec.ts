import { type APIRequestContext, expect, test } from "@playwright/test";

import { bearerAuth, lazySuiteTokens, mintToken } from "./harness";

/**
 * `/meta` is pruned per principal; the ARBAC overlay memoizes the pruning by
 * the evaluated decisions (and a layer may answer `If-None-Match` with 304).
 * One "browser" carries its last ETag across logins: a role switch must
 * always get the new role's body, never the previous one's.
 * `t1_dave` = admin, `t1_eve` = viewer (no `internalNotes`), `t1_alice` =
 * member+viewer (attenuable to `viewer`; `member` alone already covers her
 * full /tasks surface).
 */
/** A cookie-jar-like client: carries the last ETag as If-None-Match. */
function jar(request: APIRequestContext) {
  let etag: string | undefined;
  let last = "";
  return async (token: string): Promise<string> => {
    const res = await request.get("/tasks/meta", {
      headers: { ...bearerAuth(token), ...(etag ? { "If-None-Match": etag } : {}) },
    });
    if (res.status() === 304) {
      // Only ever right when the bytes are the ones this client holds.
      expect(res.headers().etag).toBe(etag);
      return last;
    }
    expect(res.status()).toBe(200);
    etag = res.headers().etag;
    last = await res.text();
    return last;
  };
}
const fields = (body: string) => Object.keys((JSON.parse(body) as { fields: object }).fields);

test.describe("META-MEMO: /meta never crosses principals", () => {
  const tokenFor = lazySuiteTokens();

  test("META-MEMO-001: admin → viewer → admin in one jar", async ({ request }) => {
    const get = jar(request);
    const admin = await tokenFor(request, "t1_dave");
    const viewer = await tokenFor(request, "t1_eve");
    const a1 = await get(admin);
    expect(await get(admin)).toBe(a1);
    const v = await get(viewer);
    expect(v).not.toBe(a1);
    expect(fields(a1)).toContain("internalNotes");
    expect(fields(v)).not.toContain("internalNotes");
    expect(await get(viewer)).toBe(v);
    expect(await get(admin)).toBe(a1);
  });

  test("META-MEMO-002: full vs attenuated credential of one user", async ({ request }) => {
    const get = jar(request);
    const full = await tokenFor(request, "t1_alice");
    const narrowed = await mintToken(request, "t1_alice", { roles: ["viewer"] });
    const f1 = await get(full);
    const n1 = await get(narrowed);
    expect(n1).not.toBe(f1);
    expect(await get(full)).toBe(f1);
    expect(await get(narrowed)).toBe(n1);
  });

  test("META-MEMO-003: a re-login with the same role gets the same body", async ({ request }) => {
    const get = jar(request);
    const first = await get(await tokenFor(request, "t1_dave"));
    const relogin = await mintToken(request, "t1_dave");
    expect(await get(relogin)).toBe(first);
  });
});
