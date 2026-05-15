import { afterAll, beforeAll, describe, expect, it } from "vite-plus/test";

import { buildTestApp, loginAndFetch, type TestApp } from "./harness";

interface DbActionInfo {
  name: string;
  label: string;
  level: string;
  processor: string;
  value: string;
}

interface MetaResponse {
  actions: DbActionInfo[];
  crud: Record<string, string[]>;
  primaryKeys: string[];
  fields: Record<string, unknown>;
  type?: unknown;
}

const ALL_TASK_ACTIONS = ["new", "markDone", "markInProgress", "archive", "assign", "delete"];
const WRITE_CRUD_OPS = ["insert", "update", "replace", "remove"];

describe("META — meta endpoint overlay", () => {
  let app: TestApp;

  beforeAll(async () => {
    app = await buildTestApp();
  });
  afterAll(async () => {
    await app.close();
  });

  it("META-01 — actions[] is filtered by privilege (viewer empty; admin full)", async () => {
    const { fetch: eveFetch } = await loginAndFetch(app, app.fixtures.users.t1_eve);
    const eveRes = await eveFetch("/tasks/meta");
    expect(eveRes.status).toBe(200);
    const eveMeta = (await eveRes.json()) as MetaResponse;
    const eveActionNames = new Set(eveMeta.actions.map((a) => a.name));
    for (const name of ALL_TASK_ACTIONS) {
      expect(eveActionNames.has(name)).toBe(false);
    }

    const { fetch: daveFetch } = await loginAndFetch(app, app.fixtures.users.t1_dave);
    const daveRes = await daveFetch("/tasks/meta");
    expect(daveRes.status).toBe(200);
    const daveMeta = (await daveRes.json()) as MetaResponse;
    const daveActionNames = new Set(daveMeta.actions.map((a) => a.name));
    for (const name of ALL_TASK_ACTIONS) {
      expect(daveActionNames.has(name)).toBe(true);
    }
  });

  it("META-02 — crud{} is filtered by privilege (viewer no writes; admin all)", async () => {
    const { fetch: eveFetch } = await loginAndFetch(app, app.fixtures.users.t1_eve);
    const eveRes = await eveFetch("/tasks/meta");
    const eveMeta = (await eveRes.json()) as MetaResponse;
    const eveCrudKeys = new Set(Object.keys(eveMeta.crud));
    for (const op of WRITE_CRUD_OPS) {
      expect(eveCrudKeys.has(op)).toBe(false);
    }

    const { fetch: daveFetch } = await loginAndFetch(app, app.fixtures.users.t1_dave);
    const daveRes = await daveFetch("/tasks/meta");
    const daveMeta = (await daveRes.json()) as MetaResponse;
    const daveCrudKeys = new Set(Object.keys(daveMeta.crud));
    for (const op of WRITE_CRUD_OPS) {
      expect(daveCrudKeys.has(op)).toBe(true);
    }
    expect(daveCrudKeys.has("query")).toBe(true);
  });

  it("META-03 — meta itself requires the `meta` action (guest gets 403 on /tasks/meta)", async () => {
    const { fetch } = await loginAndFetch(app, app.fixtures.users.t1_frank);
    const res = await fetch("/tasks/meta");
    // guest only has user/self read privilege; `tasks.meta` is denied.
    expect(res.status).toBe(403);
  });

  it("META-04 — meta/form/:name schema is reachable for any role holding `meta`", async () => {
    // SPEC: form schemas are global metadata served via `metaForm`, which is
    // included in `allowTableRead`. Both admin and viewer hold `tasks.metaForm`
    // and must get identical bodies.
    const { fetch: daveFetch } = await loginAndFetch(app, app.fixtures.users.t1_dave);
    const daveRes = await daveFetch("/tasks/meta/form/NewTaskForm");
    expect(daveRes.status).toBe(200);
    const daveSchema = await daveRes.json();

    const { fetch: eveFetch } = await loginAndFetch(app, app.fixtures.users.t1_eve);
    const eveRes = await eveFetch("/tasks/meta/form/NewTaskForm");
    expect(eveRes.status).toBe(200);
    const eveSchema = await eveRes.json();
    expect(eveSchema).toEqual(daveSchema);
  });
});
