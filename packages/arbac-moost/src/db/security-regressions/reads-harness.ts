// Shared harness for the reads-*.spec.ts security regressions: one space
// (SQLite by default, or the memory adapter) holding the read fixtures, ARBAC
// controllers over the table + views, a plain moost-db controller as the
// no-ARBAC baseline, and a per-test single-role boot.

import { DbSpace } from "@atscript/db";
import { SchemaSync } from "@atscript/db/sync";
import { BetterSqlite3Driver, SqliteAdapter } from "@atscript/db-sqlite";
import {
  AsDbController,
  clearDbSpaces,
  provideDbSpace,
  ReadableController,
  TableController,
} from "@atscript/moost-db";
import { MoostHttp } from "@moostjs/event-http";
import { clearGlobalWooks, Moost } from "moost";

import { bootArbacHttp } from "../../__testing__/arbac-http";
import { loadMemoryAdapter, readerRole } from "../../__testing__/http";
import { FakeUserProvider } from "../../__testing__/user-provider";
import { ArbacResource } from "../../arbac.decorator";
import { MoostArbac } from "../../moost-arbac";
import { type ArbacDbScope, AsArbacDbController } from "../as-arbac-db-controller";
import { AsArbacDbReadableController } from "../as-arbac-db-readable-controller";
import {
  ReadAccount,
  ReadAccountView,
  ReadDept,
  ReadStaff,
  ReadViewOverView,
} from "./fixtures/read-fixtures.as";

@TableController(ReadAccount as never, "read-accounts")
@ArbacResource("accounts")
class AccountsController extends AsArbacDbController {}

@ReadableController(ReadAccountView as never, "read-account-view")
@ArbacResource("account-view")
class AccountViewController extends AsArbacDbReadableController {}

@ReadableController(ReadStaff as never, "read-staff")
@ArbacResource("staff")
class StaffController extends AsArbacDbReadableController {}

@ReadableController(ReadViewOverView as never, "read-vov")
@ArbacResource("vov")
class VovController extends AsArbacDbReadableController {}

@TableController(ReadDept as never, "read-depts")
@ArbacResource("depts")
class DeptsController extends AsArbacDbController {}

export const ACCOUNTS = [
  {
    id: 1,
    owner: "u1",
    status: "open",
    title: "alpha",
    secretNote: "zebra launch codes",
    salary: 100,
    hiredAt: Date.UTC(2024, 0, 15),
    deptId: 1,
    pin: "1111",
    settings: { apiKey: "KEY-AAA", theme: "dark", public: "p1" },
    home: [-122.42, 37.77] as [number, number],
  },
  {
    id: 2,
    owner: "u1",
    status: "open",
    title: "beta",
    secretNote: "nothing here",
    salary: 900,
    hiredAt: Date.UTC(2025, 5, 15),
    deptId: 1,
    managerId: 1,
    pin: "2222",
    settings: { apiKey: "KEY-BBB", theme: "light", public: "p2" },
    home: [2.35, 48.85] as [number, number],
  },
  {
    id: 3,
    owner: "u2",
    status: "done",
    title: "gamma",
    secretNote: "zebra again",
    salary: 5000,
    hiredAt: Date.UTC(2025, 7, 1),
    deptId: 2,
    managerId: 1,
    pin: "3333",
    settings: { apiKey: "KEY-CCC", theme: "dark", public: "p3" },
    home: [13.4, 52.52] as [number, number],
  },
];

let driver: BetterSqlite3Driver | undefined;

export async function setupSpace(kind: "sqlite" | "memory" = "sqlite"): Promise<void> {
  let space: DbSpace;
  if (kind === "memory") {
    const MemoryAdapter = await loadMemoryAdapter();
    space = new DbSpace(() => new MemoryAdapter());
  } else {
    const sqlite = new BetterSqlite3Driver(":memory:");
    driver = sqlite;
    space = new DbSpace(() => new SqliteAdapter(sqlite));
  }
  await new SchemaSync(space).run([
    ReadDept,
    ReadAccount,
    ReadAccountView,
    ReadStaff,
    ReadViewOverView,
  ] as never);
  await space.getTable(ReadDept as never).insertMany([
    { id: 1, name: "eng", budget: 111, secretCode: "xylophone" },
    { id: 2, name: "ops", budget: 222, secretCode: "quartz" },
  ] as never);
  await space.getTable(ReadAccount as never).insertMany(ACCOUNTS as never);
  provideDbSpace(space);
}

export function teardownSpace(): void {
  clearDbSpaces();
  driver?.close();
  driver = undefined;
}

export type Get = (path: string) => Promise<{ status: number; body: any; text: string }>;

/**
 * Boot an app whose single role grants `allowTableRead(resource)` with the
 * given scope for each entry (`undefined` = unscoped).
 */
function wrap(http: MoostHttp): Get {
  return async (path) => {
    const res = await http.request(path);
    const text = await res!.text();
    let body: unknown = text;
    try {
      body = JSON.parse(text);
    } catch {
      // keep text
    }
    return { status: res!.status, body, text };
  };
}

export async function bootWith(grants: Record<string, ArbacDbScope | undefined>): Promise<Get> {
  clearGlobalWooks();
  const arbac = new MoostArbac<object, ArbacDbScope>();
  arbac.registerRole(readerRole("reader", grants));
  const http = await bootArbacHttp({
    arbac,
    user: new FakeUserProvider("u1", ["reader"]),
    controllers: [
      AccountsController,
      AccountViewController,
      StaffController,
      VovController,
      DeptsController,
    ],
    authorize: true,
  });
  return wrap(http);
}

/**
 * Boot a plain moost-db app (no ARBAC at all) serving `ReadAccount` under
 * `/plain-accounts` — the baseline for seals that must hold without a
 * permission layer. The controller class is declared here, lazily, because
 * `@TableController` stamps its path on the shared `ReadAccount` type.
 */
export async function bootPlain(): Promise<Get> {
  clearGlobalWooks();
  @TableController(ReadAccount as never, "plain-accounts")
  class PlainAccountsController extends AsDbController {}
  const app = new Moost();
  const http = new MoostHttp();
  app.adapter(http);
  app.registerControllers(PlainAccountsController);
  await app.init();
  return wrap(http);
}

export const ids = (body: unknown): number[] => (body as Array<{ id: number }>).map((r) => r.id);
