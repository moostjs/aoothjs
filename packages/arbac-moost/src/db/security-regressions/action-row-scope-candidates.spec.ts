// Candidate-aware `actionRowScope` (moost-db 0.1.147): the hook now receives
// the candidate rows (`ctx`). The ARBAC grant filter stays candidate-free —
// several grants union, attenuation intersects — and the app ANDs its own
// candidate-bounded filter on top (here: `resolve` only on issues whose
// TICKET belongs to the caller's team). Every surface — `$actions`,
// `GET /meta/actions`, the action gate — applies grant ∧ bound; nothing the
// app adds can widen the grant.
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vite-plus/test";

import {
  actionsById,
  bootIssues,
  caller,
  createIssueSpace,
  type IssueSpace,
  scopeCalls,
} from "./issue-actions-harness";

let space: IssueSpace;
beforeAll(async () => {
  space = await createIssueSpace();
});
afterAll(() => space.close());
beforeEach(() => space.seed());

// Team a: 1, 3, 4 (4 closed). Team b: 2, 5. Region eu: 1, 2, 4; us: 3, 5.

describe("mixed roles: a read-everything role + a region action role", () => {
  it("$actions: resolve only on the team's rows of the region, close on the region", async () => {
    const { get } = await bootIssues(["lead", "triage-eu"]);
    const r = await get("/issues/query?$actions=true&$sort=id");
    expect(r.status, JSON.stringify(r.body)).toBe(200);
    expect(actionsById(r.body)).toEqual({
      1: ["close", "resolve"],
      2: ["close"], // other team: no resolve
      3: [], // other region
      4: ["resolve"], // close disabled (already closed)
      5: [],
    });
    expect(r.body[3].$disabledReasons).toEqual({ close: "Already closed" });
    // The hook saw the page's rows, once, as one evaluation.
    expect(scopeCalls).toEqual([{ purpose: "rows", ids: [1, 2, 3, 4, 5] }]);
  });

  it("the candidates are bounded by the page", async () => {
    const { get } = await bootIssues(["lead", "triage-eu"]);
    await get("/issues/query?$actions=true&$sort=id&$limit=2");
    expect(scopeCalls).toEqual([{ purpose: "rows", ids: [1, 2] }]);
  });

  it("GET /meta/actions/:id answers per row (one candidate)", async () => {
    const { get } = await bootIssues(["lead", "triage-eu"]);
    expect((await get("/issues/meta/actions/1")).body.actions.toSorted()).toEqual([
      "close",
      "resolve",
    ]);
    expect((await get("/issues/meta/actions/2")).body).toEqual({ actions: ["close"] });
    expect(scopeCalls.map((c) => c.purpose)).toEqual(["available", "available"]);
    expect(scopeCalls.map((c) => c.ids)).toEqual([[1], [2]]);
  });

  it("an other-team id is refused like a missing one and stays untouched", async () => {
    const { send } = await bootIssues(["lead", "triage-eu"]);
    const foreign = await send("POST", "/issues/actions/resolve", { ids: { id: 2 } });
    const missing = await send("POST", "/issues/actions/resolve", { ids: { id: 99 } });
    expect(foreign.status).toBe(404);
    expect(foreign.body).toEqual(missing.body);
    const ok = await send("POST", "/issues/actions/resolve", { ids: { id: 1 } });
    expect(ok.status, JSON.stringify(ok.body)).toBe(201);
    expect(ok.body).toEqual({ resolved: 1 });
    expect(await space.statuses()).toMatchObject({ 1: "resolved", 2: "open" });
    expect(scopeCalls.filter((c) => c.purpose === "execute").map((c) => c.ids)).toEqual([[2], [1]]);
  });

  it("the read grant adds nothing: no action grant → no actions anywhere", async () => {
    const { get, send } = await bootIssues(["lead"]);
    const r = await get("/issues/query?$actions=true&$sort=id");
    expect(Object.values(actionsById(r.body)).flat()).toEqual([]);
    expect((await get("/issues/meta/actions/1")).status).toBe(403);
    expect((await send("POST", "/issues/actions/resolve", { ids: { id: 1 } })).status).toBe(403);
    expect((await space.statuses())[1]).toBe("open");
  });

  it("a different caller team flips the bound, never the grant", async () => {
    caller.team = "b";
    const { get } = await bootIssues(["lead", "triage-eu"]);
    expect(actionsById((await get("/issues/query?$actions=true&$sort=id")).body)).toEqual({
      1: ["close"],
      2: ["close", "resolve"],
      3: [],
      4: [],
      5: [], // team b, but outside the region grant
    });
  });
});

describe("action-only caller (action grant, no read grant)", () => {
  it("runs in-scope ids and is refused other-team / other-region ids", async () => {
    const { get, send } = await bootIssues(["triage-eu"]);
    expect((await get("/issues/query")).status).toBe(403);
    expect((await get("/issues/one/1")).status).toBe(403);
    expect((await send("POST", "/issues/actions/resolve", { ids: { id: 2 } })).status).toBe(404);
    expect((await send("POST", "/issues/actions/resolve", { ids: { id: 3 } })).status).toBe(404);
    expect((await send("POST", "/issues/actions/resolve", { ids: { id: 1 } })).status).toBe(201);
    // 'rows' level: an out-of-region id fails the whole request, nothing runs.
    const mixed = await send("POST", "/issues/actions/close", { ids: [{ id: 2 }, { id: 3 }] });
    expect(mixed.status).toBe(409);
    expect(await space.statuses()).toMatchObject({ 1: "resolved", 2: "open", 3: "open" });
    const both = await send("POST", "/issues/actions/close", { ids: [{ id: 1 }, { id: 2 }] });
    expect(both.status, JSON.stringify(both.body)).toBe(201);
    expect(both.body).toEqual({ closed: [1, 2] });
    expect(await space.statuses()).toMatchObject({ 1: "closed", 2: "closed", 3: "open" });
  });

  it("the availability route answers without a read grant, per row", async () => {
    const { get } = await bootIssues(["triage-eu"]);
    expect((await get("/issues/meta/actions/1")).body.actions.toSorted()).toEqual([
      "close",
      "resolve",
    ]);
    expect((await get("/issues/meta/actions/2")).body).toEqual({ actions: ["close"] });
    expect((await get("/issues/meta/actions/3")).body).toEqual({ actions: [] });
    expect((await get("/issues/meta/actions?id=2")).body).toEqual({ actions: ["close"] });
    expect((await get("/issues/meta/actions/99")).body).toEqual({ actions: [] });
  });
});

describe("several grants union, attenuation intersects — the bound is ANDed on top", () => {
  it("two region grants: both regions, still only the caller's team for resolve", async () => {
    const { get, send } = await bootIssues(["triage-eu", "triage-us"]);
    expect((await get("/issues/meta/actions/3")).body.actions.toSorted()).toEqual([
      "close",
      "resolve",
    ]);
    expect((await get("/issues/meta/actions/5")).body).toEqual({ actions: ["close"] });
    expect((await send("POST", "/issues/actions/resolve", { ids: { id: 5 } })).status).toBe(404);
    expect((await send("POST", "/issues/actions/resolve", { ids: { id: 3 } })).status).toBe(201);
    expect(await space.statuses()).toMatchObject({ 3: "resolved", 5: "open" });
  });

  it("a credential attenuated to one role narrows to its region", async () => {
    const { get, send, user } = await bootIssues(["lead", "triage-eu", "triage-us"]);
    user.attenuation = { roles: ["lead", "triage-eu"] };
    expect((await get("/issues/meta/actions/3")).body).toEqual({ actions: [] });
    expect(actionsById((await get("/issues/query?$actions=true&$sort=id")).body)).toEqual({
      1: ["close", "resolve"],
      2: ["close"],
      3: [],
      4: ["resolve"],
      5: [],
    });
    expect((await send("POST", "/issues/actions/resolve", { ids: { id: 3 } })).status).toBe(404);
    expect((await send("POST", "/issues/actions/close", { ids: [{ id: 5 }] })).status).toBe(409);
    expect(await space.statuses()).toMatchObject({ 3: "open", 5: "open" });
  });
});
