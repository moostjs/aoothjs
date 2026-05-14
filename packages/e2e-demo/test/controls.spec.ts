import { afterAll, beforeAll, describe, expect, it } from "vite-plus/test"

import { buildTestApp, expectAllInTenant, installDyeStubs, type TestApp } from "./harness"

installDyeStubs()

interface TaskRow {
  id?: string
  tenantId?: string
  title?: string
  status?: "open" | "in_progress" | "done"
  createdAt?: number
  internalNotes?: string
  priority?: "low" | "medium" | "high"
  description?: string
}

describe("CTRL — Uniquery $controls (read-only as t1_dave / admin)", () => {
  let app: TestApp
  let daveFetch: ReturnType<TestApp["authedFetch"]>
  let aliceFetch: ReturnType<TestApp["authedFetch"]>
  let tenantA: string
  let tenantB: string

  beforeAll(async () => {
    app = await buildTestApp()
    daveFetch = app.authedFetch((await app.loginAs(app.fixtures.users.t1_dave)).accessToken)
    aliceFetch = app.authedFetch((await app.loginAs(app.fixtures.users.t1_alice)).accessToken)
    tenantA = app.fixtures.tenants["tenant-a"]
    tenantB = app.fixtures.tenants["tenant-b"]
  })

  afterAll(async () => {
    await app.close()
  })

  it.skip(
    "CTRL-05 — $with=comments expansion (gap: nav props blocked by moost-db typing)",
    () => {
      // $with relation expansion against an actually-declared nav prop. Skipped
      // because moost-db@0.1.75's `@TableController` typing rejects tables
      // with non-empty NavType (variance issue). FK constraints landed in
      // Phase 2 but the nav props (`@db.rel.to`/`@db.rel.from`) were dropped
      // to keep the controllers compiling. Re-enable when moost-db typing
      // accepts wider tables.
    },
  )

  describe("CTRL-07 — scope holds across operator forms", () => {
    // Per-operator semantics belong to @uniqu/core; here we only assert that
    // aoothjs's tenant scope is preserved no matter which operator form the
    // user supplies (no operator escapes scope).
    it("$eq (status=open) — all returned rows are tenant-scoped", async () => {
      const res = await daveFetch("/tasks/query?status=open")
      expect(res.status).toBe(200)
      const rows = (await res.json()) as TaskRow[]
      expectAllInTenant(rows, tenantA)
    })

    it("$ne (status!=done) — all returned rows are tenant-scoped", async () => {
      const res = await daveFetch("/tasks/query?status!=done")
      expect(res.status).toBe(200)
      const rows = (await res.json()) as TaskRow[]
      expectAllInTenant(rows, tenantA)
    })

    it("$in (status{open,done}) — all returned rows are tenant-scoped", async () => {
      const res = await daveFetch("/tasks/query?status{open,done}")
      expect(res.status).toBe(200)
      const rows = (await res.json()) as TaskRow[]
      expectAllInTenant(rows, tenantA)
    })

    it("$nin (status!{done}) — all returned rows are tenant-scoped", async () => {
      const res = await daveFetch("/tasks/query?status!{done}")
      expect(res.status).toBe(200)
      const rows = (await res.json()) as TaskRow[]
      expectAllInTenant(rows, tenantA)
    })

    it("$gt / $gte / $lt / $lte (createdAt range) — all returned rows are tenant-scoped", async () => {
      const all = await daveFetch("/tasks/query?$select=id,createdAt&$sort=createdAt")
      const allRows = (await all.json()) as TaskRow[]
      const median = allRows[Math.floor(allRows.length / 2)].createdAt as number

      const gt = await daveFetch(`/tasks/query?createdAt>${median}`)
      const gtRows = (await gt.json()) as TaskRow[]
      for (const r of gtRows) expect(r.tenantId).toBe(tenantA)

      const gte = await daveFetch(`/tasks/query?createdAt>=${median}`)
      const gteRows = (await gte.json()) as TaskRow[]
      for (const r of gteRows) expect(r.tenantId).toBe(tenantA)

      const lt = await daveFetch(`/tasks/query?createdAt<${median}`)
      const ltRows = (await lt.json()) as TaskRow[]
      for (const r of ltRows) expect(r.tenantId).toBe(tenantA)

      const lte = await daveFetch(`/tasks/query?createdAt<=${median}`)
      const lteRows = (await lte.json()) as TaskRow[]
      for (const r of lteRows) expect(r.tenantId).toBe(tenantA)
    })

    it("$regex (title~=/^Task 1$/) — all returned rows are tenant-scoped", async () => {
      const pattern = encodeURIComponent("/^Task 1$/")
      const res = await daveFetch(`/tasks/query?title~=${pattern}`)
      expect(res.status).toBe(200)
      const rows = (await res.json()) as TaskRow[]
      for (const r of rows) expect(r.tenantId).toBe(tenantA)
    })
  })

  it("CTRL-08 — $or in user filter is ANDed with scope (BUG-SHAPE: walkFilter drops sibling fields)", async () => {
    // SPEC: tenant scope (`tenantId=A` for dave/alice) must hold even when the
    // user supplies a top-level `$or`. `^` is OR in @uniqu/url syntax, so
    // `status=open^status=in_progress` parses to `{ $or: [{status:'open'},
    // {status:'in_progress'}] }`.
    //
    // CURRENT BEHAVIOR (bug): `AsArbacDbController.transformFilter` merges the
    // scope filter and the user filter via object spread —
    //   `{...{tenantId: 'A'}, ...{$or: [...]}}` → `{tenantId: 'A', $or: [...]}`
    // — which would be a correct AND in MongoDB-style filters, BUT
    // `@uniqu/core`'s `walkFilter` short-circuits on top-level `$or` (and
    // `$and`/`$not`): when ANY logical key is present, sibling field keys are
    // SILENTLY DROPPED. So the SQL adapter compiles WHERE `status='open' OR
    // status='in_progress'` with NO tenant predicate → tenant-B rows leak.
    //
    // Fix would be in arbac-moost: wrap as `{$and: [scopeFilter, userFilter]}`
    // (or have @uniqu/core's walker visit sibling fields alongside logical
    // operators).
    const res = await daveFetch("/tasks/query?status=open^status=in_progress")
    expect(res.status).toBe(200)
    const rows = (await res.json()) as TaskRow[]
    expect(rows.length).toBe(15)
    for (const r of rows) expect(["open", "in_progress"]).toContain(r.status as string)
    expectAllInTenant(rows, tenantA)

    // Adversarial $or: alice (member+viewer in tenant A) tries to OR-in tenant B.
    // Scope's tenantId=A filter MUST AND on top — zero tenant-B rows allowed.
    const sneaky = await aliceFetch(
      `/tasks/query?tenantId=${encodeURIComponent(tenantA)}^tenantId=${encodeURIComponent(tenantB)}`,
    )
    expect(sneaky.status).toBe(200)
    const sneakyRows = (await sneaky.json()) as TaskRow[]
    expectAllInTenant(sneakyRows, tenantA)

    // $not (negation) form via !(...) — single top-level operator works because
    // there are no sibling keys for the walker to drop.
    const negated = await daveFetch("/tasks/query?!(status=done)")
    expect(negated.status).toBe(200)
    const negatedRows = (await negated.json()) as TaskRow[]
    for (const r of negatedRows) expect(r.status).not.toBe("done")
    expectAllInTenant(negatedRows, tenantA)
  })
})
