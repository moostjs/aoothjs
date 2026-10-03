// Shared harness for the row-action regressions over moost-db 0.1.147
// (candidate-aware `actionRowScope`, `@DbActionsFrom` view delegation, query
// targets) and the relational filter predicates: one SQLite space with
// issues → tickets → teams (a ticket's team owns its issues) and a board view
// over issues ⋈ tickets, reseeded per test.
//
// The ARBAC grants scope issues by `region` (an issue column). On top, the
// app bounds `resolve` to the caller's team — a RELATED table's column — by
// composing a candidate-bounded filter onto the grant (`conjoinScopeFilters`).
import { allowTableAction, allowTableRead, conjoinScopeFilters, defineRole } from "@aooth/arbac";
import type { TScopeFieldRules } from "@aooth/arbac";
import type { TArbacRole } from "@aooth/arbac-core";
import { DbSpace } from "@atscript/db";
import { SchemaSync } from "@atscript/db/sync";
import { BetterSqlite3Driver, SqliteAdapter } from "@atscript/db-sqlite";
import {
  clearDbSpaces,
  DbAction,
  DbActionID,
  DbActionIDs,
  DbActionsFrom,
  provideDbSpace,
  ReadableController,
  TableController,
} from "@atscript/moost-db";
import type { TDbActionScopeContext, TDbRequestContext } from "@atscript/moost-db";
import { Post } from "@moostjs/event-http";
import { clearGlobalWooks, getMoostInfact } from "moost";

import { bootArbacHttp } from "../../__testing__/arbac-http";
import { request, type TestResponse } from "../../__testing__/http";
import { FakeUserProvider } from "../../__testing__/user-provider";
import { useArbac } from "../../arbac.composables";
import { ArbacResource } from "../../arbac.decorator";
import { MoostArbac } from "../../moost-arbac";
import { type ArbacDbScope, AsArbacDbController } from "../as-arbac-db-controller";
import { AsArbacDbReadableController } from "../as-arbac-db-readable-controller";
import { requireRequestScopes } from "../request-scopes";
import { IaIssue, IaIssueBoard, IaTeam, IaTicket } from "./fixtures/issue-actions.as";

const scope = (s: ArbacDbScope) => (): ArbacDbScope => s;
const region = (r: string) => scope({ filter: { region: r } });

/** An app scope field: the TICKET teams an issue grant is bounded to (a relational row filter). */
type IssueScope = ArbacDbScope & { ticketTeams?: string[] };

const ROLES: TArbacRole<object, ArbacDbScope>[] = [
  // Reads every issue and the whole board; may run no action.
  defineRole<object, ArbacDbScope>()
    .id("lead")
    .use(allowTableRead("issues"), allowTableRead("board"))
    .build(),
  // Action-only: close / resolve on region "eu" issues, no read grant.
  defineRole<object, ArbacDbScope>()
    .id("triage-eu")
    .use(allowTableAction("issues", ["close", "resolve"], { scope: region("eu") }))
    .build(),
  defineRole<object, ArbacDbScope>()
    .id("triage-us")
    .use(allowTableAction("issues", ["close", "resolve"], { scope: region("us") }))
    .build(),
  // Reads region "eu" only (issues and board).
  defineRole<object, ArbacDbScope>()
    .id("reader-eu")
    .use(
      allowTableRead("issues", { scope: region("eu") }),
      allowTableRead("board", { scope: region("eu") }),
    )
    .build(),
  // `close` on every issue (no row restriction).
  defineRole<object, ArbacDbScope>()
    .id("closer")
    .use(allowTableAction("issues", ["close"]))
    .build(),
  // `close` on every issue, its rows seen without `secret`.
  defineRole<object, ArbacDbScope>()
    .id("closer-nosecret")
    .use(allowTableAction("issues", ["close"], { scope: () => ({ projection: { secret: 0 } }) }))
    .build(),
  // The board view only.
  defineRole<object, ArbacDbScope>().id("board-reader").use(allowTableRead("board")).build(),
  // Grants on the VIEW's resource under the source's action names.
  defineRole<object, ArbacDbScope>()
    .id("board-closer")
    .use(allowTableAction("board", ["close", "resolve"]))
    .build(),
  // ── Relational predicates ──
  defineRole<object, ArbacDbScope>().id("tickets-all").use(allowTableRead("tickets")).build(),
  defineRole<object, ArbacDbScope>()
    .id("tickets-a")
    .use(allowTableRead("tickets", { scope: scope({ filter: { teamId: "a" } }) }))
    .build(),
  // Tickets of the team NAMED "Alpha" — a server predicate on `team`, which
  // is not opted in to client predicates.
  defineRole<object, ArbacDbScope>()
    .id("tickets-alpha")
    .use(
      allowTableRead("tickets", {
        scope: scope({ filter: { team: { $some: { name: "Alpha" } } } }),
      }),
    )
    .build(),
  defineRole<object, ArbacDbScope>().id("teams-all").use(allowTableRead("teams")).build(),
  // Every issue; their ticket joins under a DECLARED sub-scope (team a).
  defineRole<object, ArbacDbScope>()
    .id("lead-with-a")
    .use(
      allowTableRead("issues", { scope: scope({ with: { ticket: { filter: { teamId: "a" } } } }) }),
    )
    .build(),
  // Every issue, no `$with` control.
  defineRole<object, ArbacDbScope>()
    .id("lead-nojoin")
    .use(allowTableRead("issues", { scope: scope({ controls: { $with: false } }) }))
    .build(),
  // `close` on issues whose ticket is team a AND open — a relational grant.
  defineRole<object, ArbacDbScope>()
    .id("closer-open-a")
    .use(
      allowTableAction("issues", ["close"], {
        scope: scope({ filter: { ticket: { $some: { teamId: "a", status: "open" } } } }),
      }),
    )
    .build(),
  // Issues of the ticket teams in the caller's `ticketTeams` scope field.
  defineRole<object, IssueScope>()
    .id("reader-ta")
    .use(allowTableRead("issues", { scope: () => ({ ticketTeams: ["a"] }) }))
    .build(),
  defineRole<object, IssueScope>()
    .id("reader-tb")
    .use(allowTableRead("issues", { scope: () => ({ ticketTeams: ["b"] }) }))
    .build(),
];

/** The caller's team, as the app knows it (the `resolve` bound). */
export const caller = { team: "a" };

/** What `actionRowScope("resolve", ctx)` was asked about, per call. */
export const scopeCalls: Array<{ purpose: string; ids: unknown[] }> = [];

let tickets: { findMany: (q: unknown) => Promise<Array<{ key: string }>> } | undefined;

@TableController(IaIssue as never, "issues")
@ArbacResource("issues")
export class IssuesController extends AsArbacDbController<typeof IaIssue> {
  /** The ARBAC grant, ANDed with the app's candidate-bounded team filter for `resolve`. */
  protected async actionRowScope(
    name: string,
    ctx?: TDbActionScopeContext,
  ): Promise<Record<string, unknown> | undefined> {
    const grant = await super.actionRowScope(name, ctx);
    if (name !== "resolve" || !ctx) return grant;
    scopeCalls.push({ purpose: ctx.purpose, ids: ctx.ids.map((i) => i.id) });
    const issues = await ctx.loadRows(["ticketKey"]);
    const own = await tickets!.findMany({
      filter: {
        key: { $in: [...new Set(issues.map((i) => i.ticketKey))] },
        teamId: caller.team,
      },
      controls: { $select: ["key"] },
    });
    return conjoinScopeFilters(grant, { ticketKey: { $in: own.map((t) => t.key) } });
  }

  @Post("actions/resolve")
  @DbAction("resolve", { label: "Resolve" })
  async resolve(@DbActionID() id: { id: number }) {
    await (this.table as any).updateOne({ id: id.id, status: "resolved" });
    return { resolved: id.id };
  }

  @Post("actions/close")
  @DbAction("close", {
    label: "Close",
    requiredFields: ["status"],
    disabled: (rows: Array<{ status?: string }>) =>
      rows.map((r) => (r.status === "closed" ? "Already closed" : false)),
    queryTarget: { maxRows: 50, batchSize: 2 },
  })
  async close(@DbActionIDs() ids: Array<{ id: number }>) {
    for (const { id } of ids) await (this.table as any).updateOne({ id, status: "closed" });
    return { closed: ids.map((i) => i.id) };
  }
}

@TableController(IaTicket as never, "tickets")
@ArbacResource("tickets")
class TicketsController extends AsArbacDbController<typeof IaTicket> {}

@TableController(IaTeam as never, "teams")
@ArbacResource("teams")
class TeamsController extends AsArbacDbController<typeof IaTeam> {}

/** The board view: lists the issue actions of its rows (`id` ← `IaIssue.id`). */
@ReadableController(IaIssueBoard as never, "board")
@ArbacResource("board")
@DbActionsFrom(() => IssuesController)
class BoardController extends AsArbacDbReadableController {}

/**
 * The same board, but its own requests also cache their (read) scopes in the
 * ARBAC scopes slot — app code may do that. A source batch running inside
 * the request must still never take them as its own grant.
 */
@ReadableController(IaIssueBoard as never, "board-cached")
@ArbacResource("board")
@DbActionsFrom(() => IssuesController)
class CachingBoardController extends AsArbacDbReadableController {
  protected async prepareRequest(ctx: TDbRequestContext): Promise<void> {
    await super.prepareRequest(ctx);
    useArbac().setScopes(requireRequestScopes());
  }
}

const TEAMS = [
  { id: "a", name: "Alpha" },
  { id: "b", name: "Beta" },
];

const TICKETS = [
  { key: "T1", teamId: "a", status: "open" },
  { key: "T2", teamId: "b", status: "open" },
  { key: "T3", teamId: "a", status: "closed" },
];

// Team a: 1, 3, 4. Team b: 2, 5. Region eu: 1, 2, 4. Issue 4 is closed.
// Open tickets: T1 (issues 1, 4), T2 (issues 2, 5).
const ISSUES = [
  { id: 1, ticketKey: "T1", region: "eu", status: "open", title: "alpha one", secret: "s1" },
  { id: 2, ticketKey: "T2", region: "eu", status: "open", title: "alpha two", secret: "s2" },
  { id: 3, ticketKey: "T3", region: "us", status: "open", title: "beta three", secret: "s3" },
  { id: 4, ticketKey: "T1", region: "eu", status: "closed", title: "beta four", secret: "s4" },
  { id: 5, ticketKey: "T2", region: "us", status: "open", title: "gamma five", secret: "s5" },
];

export interface IssueSpace {
  /** Wipe + seed. */
  seed: () => Promise<void>;
  /** Raw status per issue id, bypassing every controller. */
  statuses: () => Promise<Record<number, string>>;
  /** Set a status directly (no controller): an issue by id, or a ticket by key. */
  setStatus: (id: number | string, status: string) => Promise<void>;
  close: () => void;
}

export async function createIssueSpace(): Promise<IssueSpace> {
  const driver = new BetterSqlite3Driver(":memory:");
  const space = new DbSpace(() => new SqliteAdapter(driver));
  await new SchemaSync(space).run([IaTeam, IaTicket, IaIssue, IaIssueBoard] as never);
  provideDbSpace(space);
  const issueTable = space.getTable(IaIssue as never) as any;
  const ticketTable = space.getTable(IaTicket as never) as any;
  const teamTable = space.getTable(IaTeam as never) as any;
  tickets = ticketTable;
  return {
    async seed() {
      driver.exec(`DELETE FROM "ia_issues"`);
      driver.exec(`DELETE FROM "ia_tickets"`);
      driver.exec(`DELETE FROM "ia_teams"`);
      await teamTable.insertMany(structuredClone(TEAMS));
      await ticketTable.insertMany(structuredClone(TICKETS));
      await issueTable.insertMany(structuredClone(ISSUES));
      scopeCalls.length = 0;
      caller.team = "a";
    },
    async statuses() {
      const rows = (await issueTable.findMany({ filter: {}, controls: {} })) as Array<{
        id: number;
        status: string;
      }>;
      return Object.fromEntries(rows.map((r) => [r.id, r.status]));
    },
    async setStatus(id, status) {
      if (typeof id === "number") await issueTable.updateOne({ id, status });
      else await ticketTable.updateOne({ key: id, status });
    },
    close() {
      clearDbSpaces();
      driver.close();
    },
  };
}

export interface IssueApp {
  user: FakeUserProvider;
  send: (method: string, path: string, body?: unknown) => Promise<TestResponse>;
  get: (path: string) => Promise<TestResponse>;
}

/**
 * Boot the issue + board controllers for a caller holding `roles` — with the
 * global authorize interceptor unless `authorize: false` (the ARBAC DB
 * controllers' `prepareRequest` must then hold on its own).
 */
export async function bootIssues(
  roles: string[],
  opts: { authorize?: boolean; fields?: TScopeFieldRules<ArbacDbScope> } = {},
): Promise<IssueApp> {
  clearGlobalWooks();
  // Fresh controller singletons: a delegating view runs its source's route
  // through ITS app (`this.app`), which must be this boot's.
  getMoostInfact()._cleanup();
  const arbac = new MoostArbac<object, ArbacDbScope>();
  for (const r of ROLES) arbac.registerRole(r);
  if (opts.fields) arbac.registerScopeFields(opts.fields);
  const user = new FakeUserProvider("u1", roles);
  const http = await bootArbacHttp({
    arbac,
    user,
    controllers: [
      IssuesController,
      TicketsController,
      TeamsController,
      BoardController,
      CachingBoardController,
    ],
    authorize: opts.authorize ?? true,
  });
  const send = (method: string, path: string, body?: unknown) => request(http, method, path, body);
  return { user, send, get: (path) => send("GET", path) };
}

/** Row id → its `$actions` (sorted) from a `$actions=true` read. */
export function actionsById(body: unknown): Record<number, string[]> {
  return Object.fromEntries(
    (body as Array<{ id: number; $actions?: string[] }>).map((r) => [
      r.id,
      (r.$actions ?? []).toSorted(),
    ]),
  );
}
