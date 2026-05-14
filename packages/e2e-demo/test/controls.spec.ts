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

interface PagesEnvelope<T> {
  data: T[]
  page: number
  itemsPerPage: number
  pages: number
  count: number
}

describe("CTRL — Uniquery $controls (read-only as t1_dave / admin)", () => {
  let app: TestApp
  let daveFetch: ReturnType<TestApp["authedFetch"]>
  let aliceFetch: ReturnType<TestApp["authedFetch"]>
  let tenantA: string
  let tenantB: string
  let tenantATotal: number

  beforeAll(async () => {
    app = await buildTestApp()
    daveFetch = app.authedFetch((await app.loginAs(app.fixtures.users.t1_dave)).accessToken)
    aliceFetch = app.authedFetch((await app.loginAs(app.fixtures.users.t1_alice)).accessToken)
    tenantA = app.fixtures.tenants["tenant-a"]
    tenantB = app.fixtures.tenants["tenant-b"]
    tenantATotal = app.fixtures.tasks.tenantA.length
  })

  afterAll(async () => {
    await app.close()
  })

  it("CTRL-01 — $select=id,title returns rows projected to those fields only", async () => {
    const res = await daveFetch("/tasks/query?$select=id,title")
    expect(res.status).toBe(200)
    const rows = (await res.json()) as TaskRow[]
    expect(rows.length).toBeGreaterThan(0)
    for (const row of rows) {
      expect(Object.keys(row).toSorted()).toEqual(["id", "title"])
    }
  })

  it("CTRL-02 — $sort/$order=-createdAt orders DESC by createdAt", async () => {
    const res = await daveFetch("/tasks/query?$select=id,createdAt&$sort=-createdAt")
    expect(res.status).toBe(200)
    const rows = (await res.json()) as TaskRow[]
    expect(rows.length).toBeGreaterThan(1)
    for (let i = 1; i < rows.length; i++) {
      const prev = rows[i - 1].createdAt as number
      const curr = rows[i].createdAt as number
      expect(prev).toBeGreaterThanOrEqual(curr)
    }
  })

  it("CTRL-03 — $skip=5&$limit=5 returns exactly 5 rows offset by 5", async () => {
    const all = await daveFetch("/tasks/query?$select=id&$sort=id")
    expect(all.status).toBe(200)
    const allRows = (await all.json()) as TaskRow[]
    expect(allRows.length).toBe(tenantATotal)

    const slice = await daveFetch("/tasks/query?$select=id&$sort=id&$skip=5&$limit=5")
    expect(slice.status).toBe(200)
    const sliceRows = (await slice.json()) as TaskRow[]
    expect(sliceRows.length).toBe(5)
    expect(sliceRows.map((r) => r.id)).toEqual(allRows.slice(5, 10).map((r) => r.id))
  })

  it("CTRL-04 — /query?$count returns a bare number (not an array)", async () => {
    const res = await daveFetch("/tasks/query?$count")
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(typeof body).toBe("number")
    expect(body).toBe(tenantATotal)
  })

  it.skip(
    "CTRL-05 — $with=comments expansion (gap: Comment.taskId is not declared as @db.rel.* to Task)",
    () => {
      // Per spec: skip when relations aren't declared. Task.id <-> Comment.taskId
      // has no @db.rel.FK / @db.rel.* annotation in the .as models, so the
      // moost-db relation graph is empty and $with=comments is a no-op (or 400).
      // Same skip rationale as PROJ-04.
    },
  )

  it("CTRL-06 — $groupBy=status with count(*) aggregate returns scoped per-status counts", async () => {
    // Admin (t1_dave) has full tenant-A read scope: 10 open / 5 in_progress / 5 done.
    const res = await daveFetch("/tasks/query?$groupBy=status&$select=status,count(*):count")
    expect(res.status).toBe(200)
    const rows = (await res.json()) as Array<{ status: string; count: number }>
    expect(rows.length).toBe(3)
    const byStatus = Object.fromEntries(rows.map((r) => [r.status, Number(r.count)]))
    expect(byStatus).toEqual({ open: 10, in_progress: 5, done: 5 })

    // Scope intersection: t2_olivia (admin of tenant B) sees the full tenant-B
    // breakdown, never tenant A's rows. Using olivia (admin) rather than oscar
    // (member) keeps the assertion precise — member's per-row scope additionally
    // narrows by creator/assignee, which would shrink the aggregate counts.
    const oliviaFetch = app.authedFetch((await app.loginAs(app.fixtures.users.t2_olivia)).accessToken)
    const bRes = await oliviaFetch("/tasks/query?$groupBy=status&$select=status,count(*):count")
    expect(bRes.status).toBe(200)
    const bRows = (await bRes.json()) as Array<{ status: string; count: number }>
    const bByStatus = Object.fromEntries(bRows.map((r) => [r.status, Number(r.count)]))
    expect(bByStatus).toEqual({ open: 10, in_progress: 5, done: 5 })
    const totalB = (bByStatus.open ?? 0) + (bByStatus.in_progress ?? 0) + (bByStatus.done ?? 0)
    expect(totalB).toBe(app.fixtures.tasks.tenantB.length)
  })

  describe("CTRL-07 — comparison operators each work AND keep scope intersection", () => {
    it("$eq (status=open) returns only open tasks within tenant scope", async () => {
      const res = await daveFetch("/tasks/query?status=open")
      expect(res.status).toBe(200)
      const rows = (await res.json()) as TaskRow[]
      expect(rows.length).toBe(10)
      for (const r of rows) expect(r.status).toBe("open")
      expectAllInTenant(rows, tenantA)
    })

    it("$ne (status!=done) excludes done while scope holds", async () => {
      const res = await daveFetch("/tasks/query?status!=done")
      expect(res.status).toBe(200)
      const rows = (await res.json()) as TaskRow[]
      expect(rows.length).toBe(15)
      for (const r of rows) expect(r.status).not.toBe("done")
      expectAllInTenant(rows, tenantA)
    })

    it("$in (status{open,done}) returns matching enum values only", async () => {
      const res = await daveFetch("/tasks/query?status{open,done}")
      expect(res.status).toBe(200)
      const rows = (await res.json()) as TaskRow[]
      expect(rows.length).toBe(15)
      for (const r of rows) expect(["open", "done"]).toContain(r.status as string)
      expectAllInTenant(rows, tenantA)
    })

    it("$nin (status!{done}) excludes the listed values", async () => {
      const res = await daveFetch("/tasks/query?status!{done}")
      expect(res.status).toBe(200)
      const rows = (await res.json()) as TaskRow[]
      expect(rows.length).toBe(15)
      for (const r of rows) expect(r.status).not.toBe("done")
      expectAllInTenant(rows, tenantA)
    })

    it("$gt / $gte / $lt / $lte (createdAt range) filter numeric ranges", async () => {
      const all = await daveFetch("/tasks/query?$select=id,createdAt&$sort=createdAt")
      const allRows = (await all.json()) as TaskRow[]
      expect(allRows.length).toBe(tenantATotal)
      const median = allRows[Math.floor(allRows.length / 2)].createdAt as number

      const gt = await daveFetch(`/tasks/query?createdAt>${median}`)
      const gtRows = (await gt.json()) as TaskRow[]
      for (const r of gtRows) {
        expect((r.createdAt as number) > median).toBe(true)
        expect(r.tenantId).toBe(tenantA)
      }

      const gte = await daveFetch(`/tasks/query?createdAt>=${median}`)
      const gteRows = (await gte.json()) as TaskRow[]
      expect(gteRows.length).toBeGreaterThanOrEqual(gtRows.length)
      for (const r of gteRows) expect((r.createdAt as number) >= median).toBe(true)

      const lt = await daveFetch(`/tasks/query?createdAt<${median}`)
      const ltRows = (await lt.json()) as TaskRow[]
      for (const r of ltRows) expect((r.createdAt as number) < median).toBe(true)

      const lte = await daveFetch(`/tasks/query?createdAt<=${median}`)
      const lteRows = (await lte.json()) as TaskRow[]
      expect(lteRows.length).toBeGreaterThanOrEqual(ltRows.length)
    })

    it("$regex (title~=/^Task 1$/) matches the regex within scope", async () => {
      // The seed produces 'Task 1', 'Task 2', ..., 'Task 20'. /^Task 1$/ pins to
      // exactly "Task 1" — one row in tenant A.
      const pattern = encodeURIComponent("/^Task 1$/")
      const res = await daveFetch(`/tasks/query?title~=${pattern}`)
      expect(res.status).toBe(200)
      const rows = (await res.json()) as TaskRow[]
      expect(rows.length).toBe(1)
      expect(rows[0].title).toBe("Task 1")
      expect(rows[0].tenantId).toBe(tenantA)
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

  describe("CTRL-09 — pagination bounds", () => {
    it("$skip=-1 is rejected (validator requires min 0)", async () => {
      expect((await daveFetch("/tasks/query?$skip=-1")).status).toBe(400)
    })

    it("$limit=-1 is rejected (validator requires min 0)", async () => {
      expect((await daveFetch("/tasks/query?$limit=-1")).status).toBe(400)
    })

    it("$limit=99999 is passed through (no server cap; default fallback is 1000 only when omitted)", async () => {
      const res = await daveFetch("/tasks/query?$limit=99999")
      expect(res.status).toBe(200)
      const rows = (await res.json()) as TaskRow[]
      expect(rows.length).toBe(tenantATotal)
    })

    it("$skip=10000 (out of range) returns an empty array", async () => {
      const res = await daveFetch("/tasks/query?$skip=10000")
      expect(res.status).toBe(200)
      const rows = (await res.json()) as TaskRow[]
      expect(rows).toEqual([])
    })
  })

  it("CTRL-10 — /pages count reflects total in-scope rows, not the page slice", async () => {
    // /pages uses $page / $size (not $skip / $limit) and ALWAYS returns count
    // in its envelope — `$count` is not a valid PagesControlsDto property. With
    // page=2, size=5 the response skips the first 5 rows; the returned `count`
    // must still be the full tenant-A total (20), not 5 and not 15.
    const res = await daveFetch("/tasks/pages?$page=2&$size=5")
    expect(res.status).toBe(200)
    const body = (await res.json()) as PagesEnvelope<TaskRow>
    expect(body.count).toBe(tenantATotal)
    expect(body.itemsPerPage).toBe(5)
    expect(body.page).toBe(2)
    expect(body.pages).toBe(Math.ceil(tenantATotal / 5))
    expect(body.data.length).toBe(5)
    expectAllInTenant(body.data, tenantA)
  })
})
