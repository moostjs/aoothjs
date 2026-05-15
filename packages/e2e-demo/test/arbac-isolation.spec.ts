import { afterAll, beforeAll, describe, expect, it } from "vite-plus/test"

import {
  buildTestApp,
  dbFindOne,
  expectAllInTenant,
  installDyeStubs,
  loginAndFetch,
  type TestApp,
} from "./harness"

installDyeStubs()

interface TaskRow {
  id: string
  tenantId: string
  title: string
  internalNotes?: string
}

describe("ISO — read-only tenant isolation", () => {
  let app: TestApp

  beforeAll(async () => {
    app = await buildTestApp()
  })
  afterAll(async () => {
    await app.close()
  })

  it("ISO-01 — list scoped to caller's tenant (alice → A; oscar → B)", async () => {
    const tenantA = app.fixtures.tenants["tenant-a"]
    const tenantB = app.fixtures.tenants["tenant-b"]

    const { fetch: aliceFetch } = await loginAndFetch(app, app.fixtures.users.t1_alice)
    const aRes = await aliceFetch("/tasks/query")
    expect(aRes.status).toBe(200)
    const aRows = (await aRes.json()) as TaskRow[]
    expect(aRows.length).toBeGreaterThan(0)
    expectAllInTenant(aRows, tenantA)

    const { fetch: oscarFetch } = await loginAndFetch(app, app.fixtures.users.t2_oscar)
    const bRes = await oscarFetch("/tasks/query")
    expect(bRes.status).toBe(200)
    const bRows = (await bRes.json()) as TaskRow[]
    expect(bRows.length).toBeGreaterThan(0)
    expectAllInTenant(bRows, tenantB)
  })

  it("ISO-02 — single-record fetch across tenant returns 404", async () => {
    const { fetch } = await loginAndFetch(app, app.fixtures.users.t1_alice)
    const tB = app.fixtures.tasks.tenantB[0]
    const res = await fetch(`/tasks/one/${tB}`)
    expect(res.status).toBe(404)
  })

  it("ISO-03 — composite-key /one fetch scope-gated (cross-tenant id → 404)", async () => {
    // The seed's document model does not declare a composite unique index, so
    // we exercise the same `getOneComposite` route via the primary-key form
    // (`?id=<id>`). This still goes through `transformOne` (the scope filter),
    // which is what ISO-03 verifies.
    const { fetch } = await loginAndFetch(app, app.fixtures.users.t1_alice)
    const docB = app.fixtures.documents.tenantB[0]
    const res = await fetch(`/documents/one?id=${docB}`)
    expect(res.status).toBe(404)
  })

  it("ISO-04 — pagination count respects scope (alice sees only tenant-A tasks)", async () => {
    const { fetch } = await loginAndFetch(app, app.fixtures.users.t1_alice)
    const cnt = await fetch("/tasks/query?$count=true")
    expect(cnt.status).toBe(200)
    const total = (await cnt.json()) as number
    expect(total).toBe(app.fixtures.tasks.tenantA.length)

    const pages = await fetch("/tasks/pages")
    expect(pages.status).toBe(200)
    const pBody = (await pages.json()) as { count: number; data: TaskRow[] }
    expect(pBody.count).toBe(app.fixtures.tasks.tenantA.length)
    expectAllInTenant(pBody.data, app.fixtures.tenants["tenant-a"])
  })

  it("ISO-08 — superadmin sees rows from every tenant", async () => {
    const { fetch } = await loginAndFetch(app, app.fixtures.users._super)
    const res = await fetch("/tasks/query")
    expect(res.status).toBe(200)
    const rows = (await res.json()) as TaskRow[]
    const tenantIds = new Set(rows.map((r) => r.tenantId))
    expect(tenantIds.has(app.fixtures.tenants["tenant-a"])).toBe(true)
    expect(tenantIds.has(app.fixtures.tenants["tenant-b"])).toBe(true)
    expect(rows.length).toBe(
      app.fixtures.tasks.tenantA.length + app.fixtures.tasks.tenantB.length,
    )
  })

  it.skip("ISO-09 — tenant cascade deletion is OUT OF SCOPE for ARBAC (documentation story)", () => {
    // ARBAC governs access control, not relational integrity / cascade
    // deletes. There is no behavior to assert — this story exists in the
    // catalog to make the scope boundary explicit.
  })
})

describe("ISO — write isolation (mutations; isolated app per test)", () => {
  let app: TestApp

  beforeAll(async () => {
    app = await buildTestApp()
  })
  afterAll(async () => {
    await app.close()
  })

  it("ISO-05 — PATCH cross-tenant by id MUST NOT modify (scope ANDed with body.id)", async () => {
    const tenantB = app.fixtures.tenants["tenant-b"]
    const tB = app.fixtures.tasks.tenantB[0]

    const before = (await dbFindOne(app, "tasks", { id: tB })) as TaskRow
    expect(before.tenantId).toBe(tenantB)
    const originalTitle = before.title

    const { fetch } = await loginAndFetch(app, app.fixtures.users.t1_dave)
    const res = await fetch("/tasks", {
      method: "PATCH",
      json: { id: tB, title: "ISO-05-pwned" },
    })

    const after = (await dbFindOne(app, "tasks", { id: tB })) as TaskRow

    // SPEC: scope filter is ANDed with body.id; tenant-A admin cannot touch
    // tenant-B rows. The PATCH is rejected with 404 (out of scope).
    expect(res.status).toBe(404)
    expect(after.tenantId).toBe(tenantB)
    expect(after.title).toBe(originalTitle)
  })

  it("ISO-06 — DELETE cross-tenant by id MUST NOT delete (scope gates delete)", async () => {
    const tB = app.fixtures.tasks.tenantB[1]

    const before = await dbFindOne(app, "tasks", { id: tB })
    expect(before).toBeTruthy()

    const { fetch } = await loginAndFetch(app, app.fixtures.users.t1_dave)
    const res = await fetch(`/tasks/${tB}`, { method: "DELETE" })

    // SPEC: scope gates delete by tenant. Out-of-scope id rejected with 404.
    expect(res.status).toBe(404)
    const after = await dbFindOne(app, "tasks", { id: tB })
    expect(after).toBeTruthy()
  })

  it("ISO-07a — actions/new ignores body.tenantId; scope.set forces caller's tenant", async () => {
    const tenantA = app.fixtures.tenants["tenant-a"]
    const tenantB = app.fixtures.tenants["tenant-b"]
    const { fetch } = await loginAndFetch(app, app.fixtures.users.t1_alice)

    const res = await fetch("/tasks/actions/new", {
      method: "POST",
      json: {
        input: {
          projectId: app.fixtures.projects["proj-a-1"],
          title: "ISO-07a alice-new",
          tenantId: tenantB,
        },
      },
    })
    expect([200, 201]).toContain(res.status)
    const body = (await res.json()) as { insertedId: string }
    const row = (await dbFindOne(app, "tasks", { id: body.insertedId })) as TaskRow
    expect(row.tenantId).toBe(tenantA)
  })

  it("ISO-07b — bare POST /tasks ignores body.tenantId; scope.set forces caller's tenant", async () => {
    const tenantA = app.fixtures.tenants["tenant-a"]
    const tenantB = app.fixtures.tenants["tenant-b"]
    const { fetch } = await loginAndFetch(app, app.fixtures.users.t1_dave)

    const res = await fetch("/tasks", {
      method: "POST",
      json: {
        projectId: app.fixtures.projects["proj-a-1"],
        title: "ISO-07b dave-bare",
        creatorUsername: "t1_dave",
        status: "open",
        tenantId: tenantB,
      },
    })
    expect([200, 201]).toContain(res.status)
    const body = (await res.json()) as { insertedId: string }
    const row = (await dbFindOne(app, "tasks", { id: body.insertedId })) as TaskRow
    expect(row.tenantId).toBe(tenantA)
  })
})
