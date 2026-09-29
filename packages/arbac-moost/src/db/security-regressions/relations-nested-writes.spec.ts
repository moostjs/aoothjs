// Nested writes through navigation props (P2): 403 unless the write scopes'
// `nestedWrites` list the relation; once opted in, atscript-db's nested
// writer keeps every nested write inside THIS parent. The basic 403 / opt-in
// / union cases live in write-scope.integration.spec.ts — this pins the VIA
// and depth-2 shapes, the `set` / `allowedFields` roles, and the nested-writer
// integrity rules with the relation opted in.
import { allowTableWrite, defineRole } from "@aooth/arbac";
import { TableController } from "@atscript/moost-db";
import type { MoostHttp } from "@moostjs/event-http";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vite-plus/test";

import { ArbacResource } from "../../arbac.decorator";
import { type ArbacDbScope, AsArbacDbController } from "../as-arbac-db-controller";
import {
  RpNote,
  RpOrg,
  RpProject,
  RpTag,
  RpTask,
  RpTaskTag,
  RpUser,
} from "./fixtures/rel-fixtures.as";
import { all, boot, createSpace, type Harness, one, seed, send } from "./relations-harness";

const role = (id: string, extra: ArbacDbScope = {}, projects: ArbacDbScope = extra) =>
  defineRole<object, ArbacDbScope>()
    .id(id)
    .use(allowTableWrite("tasks", { scope: () => ({ filter: { tenant: "a" }, ...extra }) }))
    .use(allowTableWrite("projects", { scope: () => ({ filter: { tenant: "a" }, ...projects }) }))
    .build();

const ROLES = [
  role("writer"),
  role("with-set", { set: { tenant: "a" } }),
  role("whitelisted", { allowedFields: ["title", "tenant"] }),
  role("nested", { nestedWrites: ["owner", "tags"] }, { nestedWrites: ["notes"] }),
];

@TableController(RpTask, "tasks")
@ArbacResource("tasks")
class TasksController extends AsArbacDbController<typeof RpTask> {}

@TableController(RpProject, "projects")
@ArbacResource("projects")
class ProjectsController extends AsArbacDbController<typeof RpProject> {}

let h: Harness;
let http: MoostHttp;
let user: { roles: string[] };
beforeAll(async () => {
  h = await createSpace();
});
afterAll(() => h.close());
beforeEach(async () => {
  await seed(h);
  ({ http, user } = await boot(ROLES, [TasksController, ProjectsController], ["writer"]));
});

/** Every row of every table the nested writes could reach. */
const snapshot = async () => {
  const tables = { RpOrg, RpUser, RpTag, RpTask, RpTaskTag, RpProject, RpNote };
  const out: Record<string, unknown> = {};
  for (const [name, t] of Object.entries(tables)) out[name] = await all(h, t);
  return out;
};

describe("nested writes are forbidden unless the scope lists the relation", () => {
  it.each<[role: string, method: string, path: string, rel: string, body: unknown]>([
    [
      "writer",
      "POST",
      "/tasks",
      "owner",
      {
        id: 12,
        title: "t",
        tenant: "a",
        owner: {
          id: 61,
          name: "m",
          tenant: "b",
          salary: 1,
          org: { id: 70, name: "evil", tenant: "b", budget: 1 },
        },
      },
    ],
    [
      "writer",
      "POST",
      "/tasks",
      "tags",
      { id: 13, title: "t", tenant: "a", tags: [{ id: 2 }, { name: "new", tenant: "b" }] },
    ],
    ["writer", "PATCH", "/tasks", "tags", { id: 1, tags: { $update: [{ id: 2, name: "pwned" }] } }],
    ["writer", "PATCH", "/tasks", "tags", { id: 1, tags: { $insert: [{ id: 2 }] } }],
    [
      "writer",
      "PUT",
      "/tasks",
      "tags",
      { id: 1, title: "t", tenant: "a", tags: [{ id: 2, name: "overwritten", tenant: "a" }] },
    ],
    [
      "writer",
      "PUT",
      "/tasks",
      "owner",
      {
        id: 1,
        title: "t",
        tenant: "a",
        owner: { id: 2, name: "overwritten", tenant: "a", salary: 0 },
      },
    ],
    [
      "writer",
      "PATCH",
      "/projects",
      "notes",
      { id: 1, notes: { $upsert: [{ id: 2, body: "x", tenant: "b" }] } },
    ],
    [
      "writer",
      "PATCH",
      "/projects",
      "notes",
      { id: 1, notes: { $replace: [{ id: 2, body: "x", tenant: "a" }] } },
    ],
    ["writer", "PATCH", "/projects", "notes", { id: 1, notes: { $remove: [{ id: 1 }] } }],
    // A `set` overlay never reaches nested rows — the nav key is refused outright.
    [
      "with-set",
      "POST",
      "/projects",
      "notes",
      { id: 14, title: "p", tenant: "b", notes: [{ id: 51, body: "x", tenant: "b" }] },
    ],
    // An `allowedFields` whitelist no longer silently strips nav keys: they are refused.
    [
      "whitelisted",
      "POST",
      "/tasks",
      "owner",
      { id: 15, title: "t", tenant: "a", owner: { id: 62, name: "m", tenant: "b", salary: 1 } },
    ],
    ["whitelisted", "PATCH", "/tasks", "owner", { id: 3, title: "ok", owner: { salary: 0 } }],
  ])("%s: %s %s through %s → 403, nothing written", async (roleId, method, path, rel, body) => {
    user.roles = [roleId];
    const before = await snapshot();
    const res = await send(http, method, path, body);
    expect(res.status, JSON.stringify(res.body)).toBe(403);
    expect(res.body.message).toBe(`Nested writes through "${rel}" are not allowed`);
    expect(await snapshot()).toEqual(before);
  });
});

describe("with nestedWrites opted in, nested writes stay inside this parent", () => {
  beforeEach(() => {
    user.roles = ["nested"];
  });

  const rejectsUnchanged = async (method: string, path: string, body: unknown) => {
    const before = await snapshot();
    const res = await send(http, method, path, body);
    expect(res.status, JSON.stringify(res.body)).toBe(409);
    expect(res.body.message).toMatch(/record \[2\] is not (a child of|linked to) this record/);
    expect(await snapshot()).toEqual(before);
  };

  it("FROM $update of another parent's child → rejected, parent write rolled back", async () => {
    await rejectsUnchanged("PATCH", "/projects", {
      id: 1,
      title: "changed",
      notes: { $update: [{ id: 2, body: "stolen" }] },
    });
  });

  it("FROM $upsert by another parent's child PK → rejected, not re-parented", async () => {
    await rejectsUnchanged("PATCH", "/projects", {
      id: 1,
      notes: { $upsert: [{ id: 2, body: "stolen", tenant: "b" }] },
    });
  });

  it("FROM $replace naming another parent's child → rejected, own children not deleted", async () => {
    await rejectsUnchanged("PATCH", "/projects", {
      id: 1,
      notes: { $replace: [{ id: 2, body: "replaced", tenant: "a" }] },
    });
    expect(await one(h, RpNote, { id: 1 })).toMatchObject({ projectId: 1 });
  });

  it("PUT with a plain FROM array naming another parent's child → rejected", async () => {
    await rejectsUnchanged("PUT", "/projects", {
      id: 1,
      title: "p",
      tenant: "a",
      notes: [{ id: 2, body: "mine now", tenant: "a" }],
    });
  });

  it("FROM $remove is parent-scoped: another parent's child survives", async () => {
    const res = await send(http, "PATCH", "/projects", { id: 1, notes: { $remove: [{ id: 2 }] } });
    expect(res.status, JSON.stringify(res.body)).toBeLessThan(300);
    expect(await one(h, RpNote, { id: 2 })).toMatchObject({ projectId: 2, body: "nB" });
  });

  it("FROM $update of this parent's own child passes", async () => {
    const res = await send(http, "PATCH", "/projects", {
      id: 1,
      notes: { $update: [{ id: 1, body: "edited" }] },
    });
    expect(res.status, JSON.stringify(res.body)).toBeLessThan(300);
    expect(await one(h, RpNote, { id: 1 })).toMatchObject({ body: "edited", projectId: 1 });
  });

  it("VIA $update of a target not linked to this parent → rejected", async () => {
    await rejectsUnchanged("PATCH", "/tasks", {
      id: 1,
      tags: { $update: [{ id: 2, name: "pwned" }] },
    });
  });

  it("VIA $update of a linked target passes", async () => {
    const res = await send(http, "PATCH", "/tasks", {
      id: 1,
      tags: { $update: [{ id: 1, name: "renamed" }] },
    });
    expect(res.status, JSON.stringify(res.body)).toBeLessThan(300);
    expect(await one(h, RpTag, { id: 1 })).toMatchObject({ name: "renamed" });
  });

  it("TO patch that changes the FK and carries the nested object → 400, nothing written", async () => {
    const before = await snapshot();
    const res = await send(http, "PATCH", "/tasks", {
      id: 1,
      ownerId: 2,
      owner: { password: "attacker-chosen" },
    });
    expect(res.status, JSON.stringify(res.body)).toBe(400);
    expect(res.body.message).toMatch(/^Cannot change 'ownerId' and patch relation 'owner'/);
    expect(await snapshot()).toEqual(before);
    expect(await one(h, RpTask, { id: 1 })).toMatchObject({ ownerId: 1 });
  });

  it("TO patch updates the row the STORED FK references", async () => {
    const res = await send(http, "PATCH", "/tasks", { id: 1, owner: { name: "alice2" } });
    expect(res.status, JSON.stringify(res.body)).toBeLessThan(300);
    expect(await one(h, RpUser, { id: 1 })).toMatchObject({ name: "alice2" });
    expect(await one(h, RpUser, { id: 2 })).toMatchObject({ name: "bob" });
  });

  it.each<[string, unknown]>([
    ["out-of-scope", { id: 2, notes: { $update: [{ id: 2, body: "x" }] } }],
    ["missing", { id: 99, notes: { $insert: [{ id: 60, body: "x", tenant: "a" }] } }],
  ])("a PATCH of an %s parent → 404, nested phase skipped", async (_n, body) => {
    const before = await snapshot();
    const res = await send(http, "PATCH", "/projects", body);
    expect(res.status, JSON.stringify(res.body)).toBe(404);
    expect(await snapshot()).toEqual(before);
  });
});
