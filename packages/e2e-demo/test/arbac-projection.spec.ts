import { afterAll, beforeAll, describe, expect, it } from "vite-plus/test";

import { buildTestApp, loginAndFetch, type TestApp } from "./harness";

interface UserRow {
  id?: string;
  username?: string;
  email?: string;
  departmentId?: string;
  password?: unknown;
  mfa?: unknown;
  account?: unknown;
  secretNotes?: unknown;
}

const SENSITIVE_USER_KEYS = ["password", "mfa", "account", "secretNotes", "email"] as const;
const VIEWER_ALLOWED = ["id", "username", "departmentId"] as const;

function expectViewerProjection(rows: Array<Record<string, unknown>>): void {
  for (const row of rows) {
    const keys = Object.keys(row);
    for (const k of SENSITIVE_USER_KEYS) {
      expect(keys.includes(k)).toBe(false);
    }
    for (const k of keys) {
      expect(VIEWER_ALLOWED).toContain(k);
    }
  }
}

describe("PROJ — field-level projection", () => {
  let app: TestApp;

  beforeAll(async () => {
    app = await buildTestApp();
  });
  afterAll(async () => {
    await app.close();
  });

  it("PROJ-01 — viewer-only role hides password/mfa/account/secretNotes/email on /users/query", async () => {
    const { fetch } = await loginAndFetch(app, app.fixtures.users.t1_eve);
    const res = await fetch("/users/query");
    expect(res.status).toBe(200);
    const rows = (await res.json()) as Array<Record<string, unknown>>;
    expect(rows.length).toBeGreaterThan(0);
    expectViewerProjection(rows);
  });

  it("PROJ-02 — $select cannot escape projection (viewer requesting password,mfa)", async () => {
    const { fetch } = await loginAndFetch(app, app.fixtures.users.t1_eve);
    const res = await fetch("/users/query?$select=password,mfa");
    if (res.status === 400) {
      // Acceptable per story: server may reject the request outright.
      return;
    }
    expect(res.status).toBe(200);
    const rows = (await res.json()) as Array<Record<string, unknown>>;
    for (const row of rows) {
      const keys = Object.keys(row);
      expect(keys.includes("password")).toBe(false);
      expect(keys.includes("mfa")).toBe(false);
      expect(keys.includes("account")).toBe(false);
      expect(keys.includes("secretNotes")).toBe(false);
    }
  });

  it("PROJ-03 — multi-role union widens but never exceeds total schema (alice member+viewer)", async () => {
    const { fetch } = await loginAndFetch(app, app.fixtures.users.t1_alice);
    const res = await fetch("/users/query");
    expect(res.status).toBe(200);
    const rows = (await res.json()) as UserRow[];
    expect(rows.length).toBeGreaterThan(0);

    // member.PROJ_USER_MEMBER ∪ viewer.PROJ_USER_VIEWER (both include-mode) =
    // {id, username, email, departmentId}. Email is the union-only field.
    const allowed = new Set(["id", "username", "email", "departmentId"]);
    let sawEmail = false;
    for (const row of rows as Array<Record<string, unknown>>) {
      const keys = Object.keys(row);
      for (const k of keys) expect(allowed.has(k)).toBe(true);
      for (const k of SENSITIVE_USER_KEYS) {
        if (k === "email") continue;
        expect(keys.includes(k)).toBe(false);
      }
      if (Object.hasOwn(row, "email")) sawEmail = true;
    }
    expect(sawEmail).toBe(true);
  });

  it("PROJ-04 — $with whitelist gates expansion + per-relation projection masks expanded rows + parent projection survives", async () => {
    // Load-bearing assertion: expanded comment rows must honor
    // viewer.tasks.with.comments.projection — proves arbac-moost pipes the
    // per-relation projection into the relation loader, not just the parent.
    const { fetch } = await loginAndFetch(app, app.fixtures.users.t1_eve);
    const allowed = await fetch("/tasks/query?$with=comments");
    expect(allowed.status).toBe(200);
    const rows = (await allowed.json()) as Array<{
      internalNotes?: unknown;
      comments?: Array<Record<string, unknown>>;
    }>;
    expect(rows.length).toBeGreaterThan(0);
    for (const r of rows) expect(Object.hasOwn(r, "internalNotes")).toBe(false);
    const expanded = rows.flatMap((r) => r.comments ?? []);
    expect(expanded.length).toBeGreaterThan(0);
    for (const c of expanded) expect(Object.hasOwn(c, "tenantId")).toBe(false);

    const rejected = await fetch("/tasks/query?$with=project");
    expect(rejected.status).toBe(403);
  });

  it("PROJ-04b — user $select on $with-relation intersects with child role projection (cannot escape exclusion)", async () => {
    // PROJ-04 proves the default case: with no user-supplied $select on the
    // `comments` relation, viewer.tasks.with.comments.projection
    // (= PROJ_COMMENT_VIEWER = { tenantId: 0 }) masks tenantId on expanded rows.
    //
    // This pins the adversarial case: when the user explicitly asks the
    // server for tenantId via `$with=comments($select=...,tenantId,...)`,
    // the child role projection STILL wins. `applyArbacRelationScopes` calls
    // `applyArbacProjection(normalizeSelect(entry.controls.$select), subScopes)`,
    // which routes through `restrictProjection(desired, accessControl)` — an
    // intersection, not a union. User $select cannot widen the role grant.
    //
    // Crucial: include-mode `$select` ∩ exclude-mode `{tenantId: 0}` → include-mode
    // result with `tenantId` dropped (see restrictProjection's
    // include/exclude branch). So `body` + `authorUsername` survive (proving
    // intersection actually applied) and `tenantId` is gone (proving role wins).
    //
    // `taskId` is included in the user $select because the relation loader
    // needs the FK column to attach child rows back to parent tasks — strip it
    // and comments expansion comes back as `[]` for every task. Orthogonal to
    // the projection-intersection invariant under test.
    const { fetch } = await loginAndFetch(app, app.fixtures.users.t1_eve);
    const res = await fetch(
      "/tasks/query?$with=comments($select=tenantId,body,authorUsername,taskId)",
    );
    expect(res.status).toBe(200);
    const rows = (await res.json()) as Array<{
      comments?: Array<Record<string, unknown>>;
    }>;
    const expanded = rows.flatMap((r) => r.comments ?? []);
    expect(expanded.length).toBeGreaterThan(0);

    let sawBody = false;
    for (const c of expanded) {
      // Role child projection beats user-supplied $select — tenantId stays out
      // even though the user explicitly named it.
      expect(Object.hasOwn(c, "tenantId")).toBe(false);
      if (Object.hasOwn(c, "body")) sawBody = true;
    }
    // At least one comment must carry `body` — proves the user $select was
    // honored where it didn't conflict (so the empty-tenantId result isn't
    // just an empty projection swallowing every field).
    expect(sawBody).toBe(true);
  });

  it("PROJ-05 — /one honors projection (viewer fetching a known user by id)", async () => {
    const { fetch } = await loginAndFetch(app, app.fixtures.users.t1_eve);
    const targetId = app.fixtures.users.t1_dave.id;
    const res = await fetch(`/users/one/${targetId}`);
    expect(res.status).toBe(200);
    const row = (await res.json()) as Record<string, unknown>;
    expectViewerProjection([row]);
    expect(row.id).toBe(targetId);
    expect(row.username).toBe("t1_dave");
  });

  it("PROJ-06 — additive union semantics: superadmin sees all; alice sees only the union of include keys", async () => {
    const targetId = app.fixtures.users.t1_dave.id;

    const { fetch: supFetch } = await loginAndFetch(app, app.fixtures.users._super);
    const supRes = await supFetch(`/users/one/${targetId}`);
    expect(supRes.status).toBe(200);
    const supRow = (await supRes.json()) as Record<string, unknown>;
    const supKeys = new Set(Object.keys(supRow));
    // _super has no projection — the universe; sensitive keys MUST be present.
    expect(supKeys.has("password")).toBe(true);
    expect(supKeys.has("mfa")).toBe(true);
    expect(supKeys.has("account")).toBe(true);

    const { fetch: aliceFetch } = await loginAndFetch(app, app.fixtures.users.t1_alice);
    const aRes = await aliceFetch(`/users/one/${targetId}`);
    expect(aRes.status).toBe(200);
    const aRow = (await aRes.json()) as Record<string, unknown>;
    const aKeys = new Set(Object.keys(aRow));

    // member ∪ viewer (both include-mode) = {id, username, email, departmentId}.
    // Per `unionProjections`: all-include input → include-mode result with the
    // union of keys; sensitive keys absent in BOTH stay denied.
    expect(aKeys.has("password")).toBe(false);
    expect(aKeys.has("mfa")).toBe(false);
    expect(aKeys.has("account")).toBe(false);
    expect(aKeys.has("secretNotes")).toBe(false);

    // Same row id, identical underlying record — the diff is purely projection.
    expect(aRow.id).toBe(supRow.id);
    expect(aRow.username).toBe(supRow.username);
  });
});
