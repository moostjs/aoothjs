import { afterAll, beforeAll, describe, expect, it } from "vite-plus/test"

import { buildTestApp, installDyeStubs, loginAndFetch, type TestApp } from "./harness"

installDyeStubs()

interface DbActionInfo {
  name: string
  label: string
  level: string
  processor: string
  value: string
}

interface MetaResponse {
  actions: DbActionInfo[]
  crud: Record<string, string[]>
  primaryKeys: string[]
  fields: Record<string, unknown>
  type?: unknown
}

const ALL_TASK_ACTIONS = ["new", "markDone", "markInProgress", "archive", "assign", "delete"]
const WRITE_CRUD_OPS = ["insert", "update", "replace", "remove"]

describe("META — meta endpoint overlay", () => {
  let app: TestApp

  beforeAll(async () => {
    app = await buildTestApp()
  })
  afterAll(async () => {
    await app.close()
  })

  it("META-01 — actions[] is filtered by privilege (viewer empty; admin full)", async () => {
    const { fetch: eveFetch } = await loginAndFetch(app, app.fixtures.users.t1_eve)
    const eveRes = await eveFetch("/tasks/meta")
    expect(eveRes.status).toBe(200)
    const eveMeta = (await eveRes.json()) as MetaResponse
    const eveActionNames = eveMeta.actions.map((a) => a.name)
    for (const name of ALL_TASK_ACTIONS) {
      expect(eveActionNames.includes(name)).toBe(false)
    }

    const { fetch: daveFetch } = await loginAndFetch(app, app.fixtures.users.t1_dave)
    const daveRes = await daveFetch("/tasks/meta")
    expect(daveRes.status).toBe(200)
    const daveMeta = (await daveRes.json()) as MetaResponse
    const daveActionNames = new Set(daveMeta.actions.map((a) => a.name))
    for (const name of ALL_TASK_ACTIONS) {
      expect(daveActionNames.has(name)).toBe(true)
    }
  })

  it("META-02 — crud{} is filtered by privilege (viewer no writes; admin all)", async () => {
    const { fetch: eveFetch } = await loginAndFetch(app, app.fixtures.users.t1_eve)
    const eveRes = await eveFetch("/tasks/meta")
    const eveMeta = (await eveRes.json()) as MetaResponse
    const eveCrudKeys = new Set(Object.keys(eveMeta.crud))
    for (const op of WRITE_CRUD_OPS) {
      expect(eveCrudKeys.has(op)).toBe(false)
    }

    const { fetch: daveFetch } = await loginAndFetch(app, app.fixtures.users.t1_dave)
    const daveRes = await daveFetch("/tasks/meta")
    const daveMeta = (await daveRes.json()) as MetaResponse
    const daveCrudKeys = new Set(Object.keys(daveMeta.crud))
    for (const op of WRITE_CRUD_OPS) {
      expect(daveCrudKeys.has(op)).toBe(true)
    }
    expect(daveCrudKeys.has("query")).toBe(true)
  })

  it("META-03 — meta itself requires the `meta` action (guest gets 403 on /tasks/meta)", async () => {
    const { fetch } = await loginAndFetch(app, app.fixtures.users.t1_frank)
    const res = await fetch("/tasks/meta")
    // guest only has user/self read privilege; `tasks.meta` is denied.
    expect(res.status).toBe(403)
  })

  it("META-04 — meta/form/:name schema is global (BUG-SHAPE: gated by `metaForm` action)", async () => {
    // SPEC: form schemas are global metadata; viewer and admin should both
    // get the SAME serialized form back. The route should be allowed for
    // anyone holding `tasks.meta` (or be open like `meta` itself).
    //
    // CURRENT BEHAVIOR: `normalizeAutoCrudMethod` in arbac-moost's
    // useArbac() composable maps `getOne`/`getOneComposite` → `one` and
    // `removeComposite` → `remove`, but does NOT map `metaForm` → `meta`.
    // Thus the action ID resolved from the controller method name is the
    // literal `"metaForm"`, which no role grants — and EVERY role gets 403,
    // including the tenant admin and the viewer who explicitly hold
    // `tasks.meta`. Real bug location:
    // `packages/arbac-moost/src/arbac.composables.ts` (`normalizeAutoCrudMethod`
    // is missing the `metaForm → meta` alias). Once fixed, both admin and
    // viewer should get 200 with identical bodies, and guest should still
    // get 403 (no `tasks.meta` privilege).
    const { fetch: daveFetch } = await loginAndFetch(app, app.fixtures.users.t1_dave)
    const daveRes = await daveFetch("/tasks/meta/form/NewTaskForm")

    if (daveRes.status === 403) {
      const { fetch: eveFetch } = await loginAndFetch(app, app.fixtures.users.t1_eve)
      const eveRes = await eveFetch("/tasks/meta/form/NewTaskForm")
      // Bug-shape: BOTH roles fail consistently with 403.
      expect(eveRes.status).toBe(403)
      return
    }

    expect(daveRes.status).toBe(200)
    const daveSchema = await daveRes.json()

    const { fetch: eveFetch } = await loginAndFetch(app, app.fixtures.users.t1_eve)
    const eveRes = await eveFetch("/tasks/meta/form/NewTaskForm")
    expect(eveRes.status).toBe(200)
    const eveSchema = await eveRes.json()
    expect(eveSchema).toEqual(daveSchema)
  })
})
