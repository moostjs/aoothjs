// "View as" attenuation (`allowUnheldRoles`): a credential may claim roles
// its user does not hold — the claimed roles are evaluated as given, then
// CONJOINED with the user's full authority exactly like any attenuation, so
// the preview can never widen beyond the user (rows, projection, controls,
// actions). Without the flag, unheld roles are dropped (unchanged).
import { allowTableOps, allowTableRead, allowTableWrite, defineRole } from "@aooth/arbac";
import { TableController } from "@atscript/moost-db";
import type { MoostHttp } from "@moostjs/event-http";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vite-plus/test";

import { ArbacResource } from "../../arbac.decorator";
import type { AoothArbacClaims } from "../../attenuation";
import { type ArbacDbScope, AsArbacDbController } from "../as-arbac-db-controller";
import { RpTask } from "./fixtures/rel-fixtures.as";
import { boot, createSpace, type Harness, seed, send } from "./relations-harness";

const roles = [
  // Unscoped full access.
  defineRole<object, ArbacDbScope>().id("admin").use(allowTableWrite("tasks")).build(),
  // The previewed role: tenant-a rows, no profile column, no $with, read only.
  defineRole<object, ArbacDbScope>()
    .id("reader")
    .use(
      allowTableRead("tasks", {
        scope: () => ({
          filter: { tenant: "a" },
          projection: { profile: 0 },
          controls: { $with: false },
        }),
      }),
    )
    .build(),
  // A previewed role WIDER than the clerk below: tenant-a rows + every write op.
  defineRole<object, ArbacDbScope>()
    .id("editor")
    .use(allowTableWrite("tasks", { scope: () => ({ filter: { tenant: "a" } }) }))
    .build(),
  // A narrow user: own rows only, title hidden, no $sort, read only.
  defineRole<object, ArbacDbScope>()
    .id("clerk")
    .use(
      allowTableOps("tasks", ["read"], {
        scope: () => ({
          filter: { ownerId: 1 },
          projection: { title: 0 },
          controls: { $sort: false },
        }),
      }),
    )
    .build(),
];

@TableController(RpTask, "tasks")
@ArbacResource("tasks")
class TasksController extends AsArbacDbController<typeof RpTask> {}

let h: Harness;
let http: MoostHttp;
async function bootAs(userRoles: string[], attenuation: AoothArbacClaims | undefined) {
  const booted = await boot(roles, [TasksController], userRoles);
  booted.user.attenuation = attenuation;
  http = booted.http;
}

const get = (path: string) => send(http, "GET", path);
const ids = (rows: Array<{ id: number }>) => rows.map((r) => r.id).toSorted((a, b) => a - b);
const NEW_TASK = { id: 9, title: "n", tenant: "a" };

beforeAll(async () => {
  h = await createSpace();
});
afterAll(() => h.close());
beforeEach(() => seed(h));

describe("allowUnheldRoles — admin previews a role it does not hold", () => {
  it("sees exactly the previewed role's surface", async () => {
    await bootAs(["admin"], { roles: ["reader"], allowUnheldRoles: true });
    const q = await get("/tasks/query");
    expect(q.status).toBe(200);
    expect(ids(q.body)).toEqual([1, 3]);
    for (const row of q.body) expect(row).not.toHaveProperty("profile");
    expect((await get("/tasks/one/2")).status).toBe(404);
    expect((await get("/tasks/query?$with=owner")).status).toBe(403);
    expect((await send(http, "POST", "/tasks", NEW_TASK)).status).toBe(403);
    const meta = (await get("/tasks/meta")).body;
    expect(Object.keys(meta.crud)).not.toContain("insert");
    expect(Object.keys(meta.crud)).toContain("one");
  });

  it("without the flag the unheld role is dropped (unchanged: deny-all)", async () => {
    await bootAs(["admin"], { roles: ["reader"] });
    expect((await get("/tasks/query")).status).toBe(403);
  });

  it("the admin's own authority is untouched without attenuation", async () => {
    await bootAs(["admin"], undefined);
    expect(ids((await get("/tasks/query")).body)).toEqual([1, 2, 3]);
  });
});

describe("allowUnheldRoles never widens beyond the user", () => {
  it("a narrow user previewing a wider role stays clipped to its own scope", async () => {
    await bootAs(["clerk"], { roles: ["editor"], allowUnheldRoles: true });
    const q = await get("/tasks/query");
    expect(q.status).toBe(200);
    // Rows: clerk (ownerId 1) ∧ editor (tenant a) — never editor's [1, 3].
    expect(ids(q.body)).toEqual([1]);
    // Projection: the clerk's hidden title stays hidden.
    for (const row of q.body) expect(row).not.toHaveProperty("title");
    expect((await get("/tasks/query?$select=title")).status).toBe(400);
    // Controls: the clerk's $sort gate still applies.
    expect((await get("/tasks/query?$sort=id")).status).toBe(403);
    // Actions: the clerk cannot write, whatever the previewed role allows.
    expect((await send(http, "POST", "/tasks", NEW_TASK)).status).toBe(403);
    const meta = (await get("/tasks/meta")).body;
    expect(Object.keys(meta.crud)).not.toContain("insert");
    expect(Object.keys(meta.crud)).not.toContain("remove");
  });

  it("previewing a role the user already holds behaves like plain attenuation", async () => {
    await bootAs(["clerk", "editor"], { roles: ["clerk"], allowUnheldRoles: true });
    expect(ids((await get("/tasks/query")).body)).toEqual([1]);
    expect((await send(http, "POST", "/tasks", NEW_TASK)).status).toBe(403);
  });
});
