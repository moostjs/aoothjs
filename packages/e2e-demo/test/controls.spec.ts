import { afterAll, beforeAll, describe, expect, it } from "vite-plus/test";

import { buildTestApp, expectAllInTenant, type TestApp } from "./harness";

interface TaskRow {
  id?: string;
  tenantId?: string;
  title?: string;
  status?: "open" | "in_progress" | "done";
  createdAt?: number;
  internalNotes?: string;
  priority?: "low" | "medium" | "high";
  description?: string;
}

describe("CTRL — Uniquery $controls (read-only as t1_dave / admin)", () => {
  let app: TestApp;
  let daveFetch: ReturnType<TestApp["authedFetch"]>;
  let aliceFetch: ReturnType<TestApp["authedFetch"]>;
  let tenantA: string;
  let tenantB: string;

  beforeAll(async () => {
    app = await buildTestApp();
    daveFetch = app.authedFetch((await app.loginAs(app.fixtures.users.t1_dave)).accessToken);
    aliceFetch = app.authedFetch((await app.loginAs(app.fixtures.users.t1_alice)).accessToken);
    tenantA = app.fixtures.tenants["tenant-a"];
    tenantB = app.fixtures.tenants["tenant-b"];
  });

  afterAll(async () => {
    await app.close();
  });

  it("CTRL-05 — $with=comments expansion against declared nav prop", async () => {
    const res = await daveFetch("/tasks/query?$with=comments&$limit=5");
    expect(res.status).toBe(200);
    const rows = (await res.json()) as (TaskRow & { comments?: unknown[] })[];
    expectAllInTenant(rows, tenantA);
    const withComments = rows.find((r) => Array.isArray(r.comments) && r.comments.length > 0);
    expect(withComments).toBeDefined();
  });

  describe("CTRL-07 — scope holds across operator forms", () => {
    // Per-operator semantics belong to @uniqu/core; here we only assert that
    // aoothjs's tenant scope is preserved no matter which operator form the
    // user supplies (no operator escapes scope).
    it("$eq (status=open) — all returned rows are tenant-scoped", async () => {
      const res = await daveFetch("/tasks/query?status=open");
      expect(res.status).toBe(200);
      const rows = (await res.json()) as TaskRow[];
      expectAllInTenant(rows, tenantA);
    });

    it("$ne (status!=done) — all returned rows are tenant-scoped", async () => {
      const res = await daveFetch("/tasks/query?status!=done");
      expect(res.status).toBe(200);
      const rows = (await res.json()) as TaskRow[];
      expectAllInTenant(rows, tenantA);
    });

    it("$in (status{open,done}) — all returned rows are tenant-scoped", async () => {
      const res = await daveFetch("/tasks/query?status{open,done}");
      expect(res.status).toBe(200);
      const rows = (await res.json()) as TaskRow[];
      expectAllInTenant(rows, tenantA);
    });

    it("$nin (status!{done}) — all returned rows are tenant-scoped", async () => {
      const res = await daveFetch("/tasks/query?status!{done}");
      expect(res.status).toBe(200);
      const rows = (await res.json()) as TaskRow[];
      expectAllInTenant(rows, tenantA);
    });

    it("$gt / $gte / $lt / $lte (createdAt range) — all returned rows are tenant-scoped", async () => {
      const all = await daveFetch("/tasks/query?$select=id,createdAt&$sort=createdAt");
      const allRows = (await all.json()) as TaskRow[];
      const median = allRows[Math.floor(allRows.length / 2)].createdAt as number;

      const gt = await daveFetch(`/tasks/query?createdAt>${median}`);
      const gtRows = (await gt.json()) as TaskRow[];
      for (const r of gtRows) expect(r.tenantId).toBe(tenantA);

      const gte = await daveFetch(`/tasks/query?createdAt>=${median}`);
      const gteRows = (await gte.json()) as TaskRow[];
      for (const r of gteRows) expect(r.tenantId).toBe(tenantA);

      const lt = await daveFetch(`/tasks/query?createdAt<${median}`);
      const ltRows = (await lt.json()) as TaskRow[];
      for (const r of ltRows) expect(r.tenantId).toBe(tenantA);

      const lte = await daveFetch(`/tasks/query?createdAt<=${median}`);
      const lteRows = (await lte.json()) as TaskRow[];
      for (const r of lteRows) expect(r.tenantId).toBe(tenantA);
    });

    it("$regex (title~=/^Task 1$/) — all returned rows are tenant-scoped", async () => {
      const pattern = encodeURIComponent("/^Task 1$/");
      const res = await daveFetch(`/tasks/query?title~=${pattern}`);
      expect(res.status).toBe(200);
      const rows = (await res.json()) as TaskRow[];
      for (const r of rows) expect(r.tenantId).toBe(tenantA);
    });
  });

  it("CTRL-08 — $or in user filter is ANDed with scope", async () => {
    // SPEC: tenant scope (`tenantId=A`) must hold even when the user supplies a
    // top-level logical operator. `^` is OR in @uniqu/url syntax.
    const res = await daveFetch("/tasks/query?status=open^status=in_progress");
    expect(res.status).toBe(200);
    const rows = (await res.json()) as TaskRow[];
    expect(rows.length).toBe(15);
    for (const r of rows) expect(["open", "in_progress"]).toContain(r.status as string);
    expectAllInTenant(rows, tenantA);

    // Adversarial $or: alice tries to OR-in tenant B. Scope's tenantId=A must
    // AND on top — zero tenant-B rows allowed. UUIDs are single-quoted so
    // @uniqu/url's lexer accepts the `-`.
    const qa = encodeURIComponent(`'${tenantA}'`);
    const qb = encodeURIComponent(`'${tenantB}'`);
    const sneaky = await aliceFetch(`/tasks/query?tenantId=${qa}^tenantId=${qb}`);
    expect(sneaky.status).toBe(200);
    const sneakyRows = (await sneaky.json()) as TaskRow[];
    expectAllInTenant(sneakyRows, tenantA);

    const negated = await daveFetch("/tasks/query?!(status=done)");
    expect(negated.status).toBe(200);
    const negatedRows = (await negated.json()) as TaskRow[];
    for (const r of negatedRows) expect(r.status).not.toBe("done");
    expectAllInTenant(negatedRows, tenantA);
  });
});
