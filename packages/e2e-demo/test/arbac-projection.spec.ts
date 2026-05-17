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

  it("PROJ-04 — $with whitelist gates relation expansion + parent projection survives", async () => {
    // Viewer's tasks scope sets controls.$with = ['comments'] so the relation
    // graph can be drilled exactly one hop. Asserts:
    //   1. `?$with=comments` is allowed and produces expanded child arrays
    //   2. parent rows still honor PROJ_TASK_VIEWER (no `internalNotes`)
    //   3. unwhitelisted relations (e.g. `?$with=project`) are rejected
    // KNOWN GAP: arbac-moost does not yet pipe the joined resource's own
    // projection through the $with expansion — expanded comment rows
    // currently carry `tenantId` even though the standalone /comments
    // query masks it. Tracked separately; per-relation projection masking
    // would belong in arbac-moost, not the demo fixtures.
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

    const rejected = await fetch("/tasks/query?$with=project");
    expect(rejected.status).toBe(403);
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
