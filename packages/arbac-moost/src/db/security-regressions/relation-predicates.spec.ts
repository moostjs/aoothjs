// Relational filter predicates (`ticket=$some(…)` / `$none`, moost-db 0.1.147)
// under ARBAC. Server side, a scope `filter` (or a custom field's `rowFilter`)
// may use a predicate freely — it is the rule itself, on reads, `$actions`,
// the action gate and query targets alike. Client side, a predicate on a
// relation is allowed exactly when `$with` of it is (same visibility, same
// `controls.$with` gate), and its operand is conjoined with the related rows
// the caller may see there — so a hidden related row never makes `$some`
// true nor `$none` false.
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vite-plus/test";

import { listFieldRule } from "../../__testing__/scope-fields";
import {
  actionsById,
  bootIssues,
  createIssueSpace,
  type IssueApp,
  type IssueSpace,
} from "./issue-actions-harness";

let space: IssueSpace;
beforeAll(async () => {
  space = await createIssueSpace();
});
afterAll(() => space.close());
beforeEach(() => space.seed());

// Teams: a "Alpha", b "Beta". Tickets: T1 (a, open), T2 (b, open), T3 (a, closed).
// Issues: 1 (T1, eu), 2 (T2, eu), 3 (T3, us), 4 (T1, eu, closed), 5 (T2, us).

const ids = (body: unknown) =>
  (body as Array<{ id: number }>).map((r) => r.id).toSorted((a, b) => a - b);
const query = async (app: IssueApp, q: string) => {
  const r = await app.get(`/issues/query?${q}`);
  expect(r.status, `${q}: ${JSON.stringify(r.body)}`).toBe(200);
  return ids(r.body);
};

/** Ticket keys a `/tickets/query` answers. */
const ticketKeys = async (app: IssueApp, q: string) =>
  ((await app.get(`/tickets/query?${q}&$sort=key`)).body as Array<{ key: string }>).map(
    (t) => t.key,
  );

/** Issue id → the key of its joined `ticket` (null when not loaded). */
const ticketOf = (body: unknown) =>
  Object.fromEntries(
    (body as Array<{ id: number; ticket?: { key: string } | null }>).map((r) => [
      r.id,
      r.ticket?.key ?? null,
    ]),
  );

/** `ticketTeams` → `{ ticket: { $some: { teamId: { $in } } } }` (union `$or`, attenuation intersects). */
const TICKET_TEAMS = {
  ticketTeams: {
    ...listFieldRule("ticketTeams"),
    rowFilter: (teams: unknown) => ({ ticket: { $some: { teamId: { $in: teams as string[] } } } }),
  },
};

describe("server scopes with relational predicates (issue → ticket team / status)", () => {
  it("an action grant on open team-a tickets: $actions, refusals and execution", async () => {
    const app = await bootIssues(["lead", "closer-open-a"]);
    const r = await app.get("/issues/query?$actions=true&$sort=id");
    expect(actionsById(r.body)).toEqual({ 1: ["close"], 2: [], 3: [], 4: [], 5: [] });
    expect((await app.get("/issues/meta/actions/1")).body).toEqual({ actions: ["close"] });
    expect((await app.get("/issues/meta/actions/2")).body).toEqual({ actions: [] });

    const foreign = await app.send("POST", "/issues/actions/close", { ids: [{ id: 2 }] });
    expect(foreign.status).toBe(409);
    const ok = await app.send("POST", "/issues/actions/close", { ids: [{ id: 1 }] });
    expect(ok.status, JSON.stringify(ok.body)).toBe(201);
    expect(await space.statuses()).toMatchObject({ 1: "closed", 2: "open" });
  });

  it("a query target reaches only the relational grant's rows", async () => {
    const app = await bootIssues(["lead", "closer-open-a"]);
    const dry = await app.send("POST", "/issues/actions/close", { query: { q: "", dryRun: true } });
    expect(dry.body).toEqual({ matched: 2 }); // issues 1 and 4
    const r = await app.send("POST", "/issues/actions/close", { query: { q: "status=open" } });
    expect(r.body).toEqual({ closed: [1] });
    expect(await space.statuses()).toEqual({
      1: "closed",
      2: "open",
      3: "open",
      4: "closed",
      5: "open",
    });
  });

  it("a predicate rowFilter of a custom field: unions across roles, attenuation intersects", async () => {
    const boot = (roles: string[]) => bootIssues(roles, { fields: TICKET_TEAMS });
    expect(await query(await boot(["reader-ta"]), "")).toEqual([1, 3, 4]);
    expect(await query(await boot(["reader-tb"]), "")).toEqual([2, 5]);
    const both = await boot(["reader-ta", "reader-tb"]);
    expect(await query(both, "")).toEqual([1, 2, 3, 4, 5]);
    both.user.attenuation = { roles: ["reader-tb"] };
    expect(await query(both, "")).toEqual([2, 5]);
    // Rows are bounded, not hidden by name: the ticket itself stays unknown
    // without a tickets grant.
    expect((await both.get("/issues/query?ticket=$some()")).status).toBe(400);
  });

  it("a predicate on a relation not opted in to client predicates works server-side", async () => {
    const app = await bootIssues(["lead", "tickets-alpha"]);
    expect(await ticketKeys(app, "")).toEqual(["T1", "T3"]);
    // The same relation in a client predicate is refused (opt-in).
    const client = await app.get("/tickets/query?team=$some(name=Alpha)");
    expect(client.status).toBe(400);
  });
});

describe("client predicates follow the $with relation policy", () => {
  it("no grant on the related table → unknown, exactly like $with", async () => {
    const app = await bootIssues(["lead"]);
    for (const q of ["ticket=$some(status=open)", "ticket=$none()", "$with=ticket"]) {
      expect((await app.get(`/issues/query?${q}`)).status, q).toBe(400);
    }
  });

  it("the caller's own ticket grant bounds the operand — hidden tickets never answer", async () => {
    const all = await bootIssues(["lead", "tickets-all"]);
    expect(await query(all, "ticket=$some(status=open)")).toEqual([1, 2, 4, 5]);
    expect(await query(all, "ticket=$none(status=open)")).toEqual([3]);

    const teamA = await bootIssues(["lead", "tickets-a"]);
    expect(await query(teamA, "ticket=$some(status=open)")).toEqual([1, 4]);
    expect(await query(teamA, "ticket=$none(status=open)")).toEqual([2, 3, 5]);
    // T2 (team b) is hidden: changing it changes nothing.
    await space.setStatus("T2", "closed");
    expect(await query(teamA, "ticket=$none(status=open)")).toEqual([2, 3, 5]);
    expect(await query(teamA, "ticket=$some()")).toEqual([1, 3, 4]);
  });

  it("a declared with.ticket sub-scope governs the operand", async () => {
    const app = await bootIssues(["lead-with-a"]);
    expect(await query(app, "ticket=$some(status=open)")).toEqual([1, 4]);
    expect(await query(app, "ticket=$none()")).toEqual([2, 5]);
  });

  it("controls.$with: false refuses predicates as it refuses $with (403)", async () => {
    const app = await bootIssues(["lead-nojoin", "tickets-all"]);
    expect((await app.get("/issues/query?ticket=$some()")).status).toBe(403);
    expect((await app.get("/issues/query?$with=ticket")).status).toBe(403);
    expect(await query(app, "status=open")).toEqual([1, 2, 3, 5]);
  });

  it("a from-relation operand is bounded by the caller's grant on the related table", async () => {
    await space.setStatus(3, "closed");
    const lead = await bootIssues(["lead", "tickets-all"]);
    const q = "issues=$some(status=closed)";
    expect(await ticketKeys(lead, q)).toEqual(["T1", "T3"]);
    // Issue 3 (region us) is hidden from an eu reader.
    expect(await ticketKeys(await bootIssues(["reader-eu", "tickets-all"]), q)).toEqual(["T1"]);
  });

  it("a nested predicate on a relation not opted in is refused", async () => {
    const app = await bootIssues(["lead", "tickets-all", "teams-all"]);
    const r = await app.get("/issues/query?ticket=$some(team=$some(name=Alpha))");
    expect(r.status).toBe(400);
    expect(r.body.message).toContain("@db.rel.filterable");
  });
});

describe("query targets", () => {
  // The relation policy is resolved for read requests only — a predicate in a
  // target's `q` fails closed (see the upstream note in the docs).
  it("a client predicate in a query target runs under the read-side relation policy", async () => {
    // Read grant on tickets: the predicate counts and acts like on /query.
    const app = await bootIssues(["lead", "tickets-all", "closer"]);
    const dry = await app.send("POST", "/issues/actions/close", {
      query: { q: "ticket=$some(status=open)", dryRun: true },
    });
    expect(dry.status, JSON.stringify(dry.body)).toBe(201);
    expect(dry.body).toEqual({ matched: 4 });
    const r = await app.send("POST", "/issues/actions/close", {
      query: { q: "status=open&ticket=$some(status=open)" },
    });
    expect(r.status, JSON.stringify(r.body)).toBe(201);
    expect(await space.statuses()).toEqual({
      1: "closed",
      2: "closed",
      3: "open",
      4: "closed",
      5: "closed",
    });
  });

  it("without a read grant on the related table the predicate is an unknown field (400), nothing runs", async () => {
    const app = await bootIssues(["lead", "closer"]);
    const r = await app.send("POST", "/issues/actions/close", {
      query: { q: "ticket=$some(status=open)" },
    });
    expect(r.status).toBe(400);
    expect(r.body).toMatchObject({ errors: [{ path: "ticket" }] });
    expect(await space.statuses()).toMatchObject({ 1: "open", 2: "open", 3: "open", 5: "open" });
  });
});

describe("$with sub-filters: server scopes pass, client predicates are gated and overlaid", () => {
  it("a server scope predicate on a non-filterable relation applies to a plain $with", async () => {
    const app = await bootIssues(["lead", "tickets-alpha"]);
    const r = await app.get("/issues/query?$with=ticket&$sort=id");
    expect(r.status, JSON.stringify(r.body)).toBe(200);
    expect(ticketOf(r.body)).toEqual({ 1: "T1", 2: null, 3: "T3", 4: "T1", 5: null });
    // A client predicate on that relation inside the same entry is gated.
    expect((await app.get("/issues/query?$with=ticket(team=$some(name=Alpha))")).status).toBe(400);
  });

  it("a client predicate inside a $with entry is overlaid at its path", async () => {
    await space.setStatus(5, "closed"); // T2's only closed issue — region us
    const q = "/issues/query?$with=ticket(issues=$some(status=closed))&$sort=id";
    const lead = await bootIssues(["lead", "tickets-all"]);
    expect(ticketOf((await lead.get(q)).body)).toMatchObject({ 1: "T1", 2: "T2", 4: "T1" });
    // An eu reader cannot see issue 5: T2 has no VISIBLE closed issue.
    const eu = await bootIssues(["reader-eu", "tickets-all"]);
    const r = await eu.get(q);
    expect(r.status, JSON.stringify(r.body)).toBe(200);
    expect(ticketOf(r.body)).toEqual({ 1: "T1", 2: null, 4: "T1" });
    // With the server scope on the same entry, both apply.
    const alpha = await bootIssues(["lead", "tickets-alpha"]);
    expect(ticketOf((await alpha.get(q)).body)).toEqual({
      1: "T1",
      2: null,
      3: null,
      4: "T1",
      5: null,
    });
  });
});
