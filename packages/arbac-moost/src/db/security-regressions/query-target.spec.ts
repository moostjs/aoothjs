// Query targets (moost-db 0.1.147): an action body `{ query }` runs the action
// on "every row matching the query". Under ARBAC the target reaches only rows
// the caller can BOTH act on (the action grant, as the row overlay) and LIST
// (the read grant — moost-db re-checks the query as a READ of the controller,
// whose `prepareRequest` resolves the caller's read scopes); an action-only
// caller is refused (403) — it targets rows by id. A view's delegated query
// target is a read of the VIEW, after the source lists the action for the
// caller; the source's route re-authorizes every batch.
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vite-plus/test";

import { bootIssues, createIssueSpace, type IssueSpace } from "./issue-actions-harness";

let space: IssueSpace;
beforeAll(async () => {
  space = await createIssueSpace();
});
afterAll(() => space.close());
beforeEach(() => space.seed());

// Team a: 1, 3, 4 (4 closed). Team b: 2, 5. Region eu: 1, 2, 4; us: 3, 5.

const target = (q: string, extra: Record<string, unknown> = {}) => ({ query: { q, ...extra } });
const closedIds = async () =>
  Object.entries(await space.statuses())
    .filter(([, s]) => s === "closed")
    .map(([id]) => Number(id));

describe("own query targets: read ∧ action", () => {
  it("a region reader with a global action grant targets only the region", async () => {
    const { send } = await bootIssues(["reader-eu", "closer"]);
    const dry = await send("POST", "/issues/actions/close", target("", { dryRun: true }));
    expect(dry.status, JSON.stringify(dry.body)).toBe(201);
    expect(dry.body).toEqual({ matched: 3 });
    const run = await send("POST", "/issues/actions/close", target("status=open"));
    expect(run.status, JSON.stringify(run.body)).toBe(201);
    expect(run.body).toEqual({ closed: [1, 2] });
    expect(await closedIds()).toEqual([1, 2, 4]);
  });

  it("a reader of everything with a region action grant targets only that region", async () => {
    const { send } = await bootIssues(["lead", "triage-eu"]);
    const dry = await send("POST", "/issues/actions/close", target("", { dryRun: true }));
    expect(dry.body).toEqual({ matched: 3 });
    // Nothing matches: the handler never runs.
    expect(
      (await send("POST", "/issues/actions/close", target("status=open&region=us"))).body,
    ).toEqual({ matched: 0, processed: 0, skipped: [], failed: [] });
    expect(await closedIds()).toEqual([4]);
  });

  it("action-only caller: 403 (dry run included), nothing written", async () => {
    const { send } = await bootIssues(["triage-eu"]);
    const dry = await send("POST", "/issues/actions/close", target("", { dryRun: true }));
    expect(dry.status).toBe(403);
    const run = await send("POST", "/issues/actions/close", target("status=open"));
    expect(run.status).toBe(403);
    expect(await closedIds()).toEqual([4]);
    // By id it still works.
    const byId = await send("POST", "/issues/actions/close", { ids: [{ id: 1 }] });
    expect(byId.status).toBe(201);
  });

  it("an attenuated credential narrows what matches", async () => {
    const { send, user } = await bootIssues(["lead", "reader-eu", "closer"]);
    const dry = () => send("POST", "/issues/actions/close", target("", { dryRun: true }));
    expect((await dry()).body).toEqual({ matched: 5 });
    user.attenuation = { roles: ["reader-eu", "closer"] };
    expect((await dry()).body).toEqual({ matched: 3 });
  });

  it("the target filter is judged by READ visibility: a field the reader sees may filter the target", async () => {
    // `lead` reads `secret`; the action grant hiding it does not matter — the caller can read it anyway.
    const { send } = await bootIssues(["lead", "closer-nosecret"]);
    const r = await send("POST", "/issues/actions/close", target("secret='s1'", { dryRun: true }));
    expect(r.status, JSON.stringify(r.body)).toBe(201);
    const ok = await send("POST", "/issues/actions/close", target("title='alpha one'"));
    expect(ok.status, JSON.stringify(ok.body)).toBe(201);
    expect(await closedIds()).toEqual([1, 4]);
  });
});

describe("delegated query targets (POST /board/delegated-actions/:name)", () => {
  it("the view's rows, run through the source route per batch — out-of-grant rows skipped", async () => {
    const { send } = await bootIssues(["board-reader", "triage-eu"]);
    const r = await send("POST", "/board/delegated-actions/close", target("status=open"));
    expect(r.status, JSON.stringify(r.body)).toBe(201);
    expect(r.body).toEqual({
      matched: 4,
      processed: 2,
      skipped: [{ id: { id: 3 } }, { id: { id: 5 } }],
      failed: [],
    });
    expect(await closedIds()).toEqual([1, 2, 4]);
  });

  it("the view's read scope bounds the target; the source's disabled rule still applies", async () => {
    const { send } = await bootIssues(["reader-eu", "closer"]);
    const dry = await send("POST", "/board/delegated-actions/close", target("", { dryRun: true }));
    expect(dry.body).toEqual({ matched: 3 });
    const r = await send("POST", "/board/delegated-actions/close", target(""));
    expect(r.body).toEqual({
      matched: 3,
      processed: 2,
      skipped: [{ id: { id: 4 }, reason: "Already closed" }],
      failed: [],
    });
    expect(await closedIds()).toEqual([1, 2, 4]);
  });

  it("the view's read grant alone runs nothing (403, dry runs included)", async () => {
    const { send } = await bootIssues(["board-reader"]);
    const dry = await send("POST", "/board/delegated-actions/close", target("", { dryRun: true }));
    expect(dry.status).toBe(403);
    const r = await send("POST", "/board/delegated-actions/close", target(""));
    expect(r.status).toBe(403);
    expect(await closedIds()).toEqual([4]);
  });

  it("holds without the global authorize interceptor", async () => {
    let app = await bootIssues(["board-reader"], { authorize: false });
    expect((await app.send("POST", "/board/delegated-actions/close", target(""))).status).toBe(403);
    expect(await closedIds()).toEqual([4]);
    app = await bootIssues(["board-reader", "triage-eu"], { authorize: false });
    const r = await app.send("POST", "/board/delegated-actions/close", target("status=open"));
    expect(r.body).toMatchObject({ matched: 4, processed: 2 });
    expect(await closedIds()).toEqual([1, 2, 4]);
  });

  it("scopes the view's request cached never stand in for the source's grant", async () => {
    for (const authorize of [false, true]) {
      const { send } = await bootIssues(["board-reader"], { authorize });
      const r = await send("POST", "/board-cached/delegated-actions/close", target(""));
      expect(r.status, `authorize: ${authorize}`).toBe(403);
      expect(await closedIds()).toEqual([4]);
    }
  });

  it("the source grant without the view read grant: 403 (the route is a read of the view)", async () => {
    const { send } = await bootIssues(["triage-eu"]);
    const r = await send("POST", "/board/delegated-actions/close", target(""));
    expect(r.status).toBe(403);
    expect(await closedIds()).toEqual([4]);
  });
});
