// View-delegated row actions (`@DbActionsFrom`, moost-db 0.1.147): the board
// VIEW lists the issue controller's actions on its rows. Every delegated
// verdict is the SOURCE's — evaluated as the issues controller, under the
// caller's grants on `issues` (and the app's candidate bound) — never under
// the view's grants, and executing always goes through the source's route.
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vite-plus/test";

import { controllerMethodIndex } from "../meta-projection";
import {
  actionsById,
  bootIssues,
  createIssueSpace,
  IssuesController,
  type IssueSpace,
} from "./issue-actions-harness";

let space: IssueSpace;
beforeAll(async () => {
  space = await createIssueSpace();
});
afterAll(() => space.close());
beforeEach(() => space.seed());

// Team a: 1, 3, 4 (4 closed). Team b: 2, 5. Region eu: 1, 2, 4; us: 3, 5.

const metaActions = (body: { actions: Array<{ name: string }> }) =>
  body.actions.map((a) => a.name).toSorted();

describe("$actions on the view's rows follow the source grants", () => {
  it("view read + source action grant: only the source's in-scope rows carry them", async () => {
    const { get } = await bootIssues(["board-reader", "triage-eu"]);
    const rows = await get("/board/query?$actions=true&$sort=id");
    expect(rows.status, JSON.stringify(rows.body)).toBe(200);
    expect(actionsById(rows.body)).toEqual({
      1: ["close", "resolve"],
      2: ["close"], // the source's team bound applies
      3: [],
      4: ["resolve"],
      5: [],
    });
    expect(rows.body[3].$disabledReasons).toEqual({ close: "Already closed" });
    // The same verdicts the source gives for the same rows.
    for (const id of [1, 2, 3, 4, 5]) {
      const source = await get(`/issues/meta/actions/${id}`);
      const view = await get(`/board/meta/actions?id=${id}`);
      expect(view.body, String(id)).toEqual(source.body);
    }
  });

  it("no source grant → no delegated action anywhere; executing is refused", async () => {
    const { get, send } = await bootIssues(["board-reader"]);
    const rows = await get("/board/query?$actions=true&$sort=id");
    expect(rows.status).toBe(200);
    expect(Object.values(actionsById(rows.body)).flat()).toEqual([]);
    expect(metaActions((await get("/board/meta")).body)).toEqual([]);
    // The view's read grant does not run the source's action.
    expect((await send("POST", "/issues/actions/resolve", { ids: { id: 1 } })).status).toBe(403);
    expect((await send("POST", "/issues/actions/close", { ids: [{ id: 1 }] })).status).toBe(403);
    expect((await space.statuses())[1]).toBe("open");
  });

  it("a grant on the VIEW's resource under the same action names leaks nothing", async () => {
    const { get, send } = await bootIssues(["board-reader", "board-closer"]);
    const rows = await get("/board/query?$actions=true&$sort=id");
    expect(Object.values(actionsById(rows.body)).flat()).toEqual([]);
    expect(metaActions((await get("/board/meta")).body)).toEqual([]);
    expect((await get("/board/meta/actions?id=1")).body).toEqual({ actions: [] });
    const run = await send("POST", "/board/delegated-actions/close", { query: { q: "" } });
    expect(run.status).toBe(403);
    expect((await send("POST", "/issues/actions/close", { ids: [{ id: 1 }] })).status).toBe(403);
    expect((await space.statuses())[1]).toBe("open");
  });

  it("the view's read scope bounds which rows (and so which source ids) are seen", async () => {
    const { get } = await bootIssues(["reader-eu", "triage-eu", "triage-us"]);
    const rows = await get("/board/query?$actions=true&$sort=id");
    expect(Object.keys(actionsById(rows.body))).toEqual(["1", "2", "4"]);
  });
});

describe("/meta of the view", () => {
  it("lists the delegated actions the source grants, with owner / idMap / queryTarget", async () => {
    const { get } = await bootIssues(["board-reader", "triage-eu"]);
    const meta = (await get("/board/meta")).body;
    const close = meta.actions.find((a: { name: string }) => a.name === "close");
    expect(close).toMatchObject({
      owner: "/issues",
      value: "/issues/actions/close",
      idMap: { id: "id" },
      queryTarget: { maxRows: 50, url: "/board/delegated-actions/close" },
    });
    expect(close).not.toHaveProperty("disabled");
    expect(metaActions(meta)).toEqual(["close", "resolve"]);
  });

  it("a source grant on one action lists only that one", async () => {
    const { get } = await bootIssues(["board-reader", "closer"]);
    expect(metaActions((await get("/board/meta")).body)).toEqual(["close"]);
  });
});

describe("GET /meta/actions on the view (renamed to the source id)", () => {
  it("a source grant without any view grant still answers — the source's verdict", async () => {
    const { get } = await bootIssues(["triage-eu"]);
    expect((await get("/board/query")).status).toBe(403);
    expect((await get("/board/meta/actions?id=1")).body.actions.toSorted()).toEqual([
      "close",
      "resolve",
    ]);
    expect((await get("/board/meta/actions?id=2")).body).toEqual({ actions: ["close"] });
    expect((await get("/board/meta/actions?id=3")).body).toEqual({ actions: [] });
    expect((await get("/board/meta/actions?id=4")).body).toEqual({
      actions: ["resolve"],
      disabledReasons: { close: "Already closed" },
    });
  });

  it("no grant anywhere: nothing is listed", async () => {
    const { get } = await bootIssues([]);
    const r = await get("/board/meta/actions?id=1");
    expect(r.body).toEqual({ actions: [] });
  });

  it("holds without the global authorize interceptor too", async () => {
    const { get } = await bootIssues(["board-reader"], { authorize: false });
    expect((await get("/board/meta/actions?id=1")).body).toEqual({ actions: [] });
    const rows = await get("/board/query?$actions=true&$sort=id");
    expect(rows.status).toBe(200);
    expect(Object.values(actionsById(rows.body)).flat()).toEqual([]);
  });
});

describe("controllerMethodIndex reads the given instance, not the event's controller", () => {
  it("indexes a controller's @DbAction methods outside any event", () => {
    const index = controllerMethodIndex(Object.create(IssuesController.prototype));
    expect(index.actionMethods.get("close")).toEqual(["close"]);
    expect(index.actionMethods.get("resolve")).toEqual(["resolve"]);
  });
});
