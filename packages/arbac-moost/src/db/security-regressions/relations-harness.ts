// Shared harness for the relations-* security regressions: one in-memory
// SQLite space, reseeded per test, HTTP via bootArbacHttp with the authorize
// interceptor. Tenant "a" is the caller's, tenant "b" someone else's.
import type { TScopeFieldRules } from "@aooth/arbac";
import type { TArbacRole } from "@aooth/arbac-core";
import { DbSpace } from "@atscript/db";
import { BetterSqlite3Driver, SqliteAdapter } from "@atscript/db-sqlite";
import { clearDbSpaces, provideDbSpace } from "@atscript/moost-db";
import type { MoostHttp } from "@moostjs/event-http";
import { clearGlobalWooks } from "moost";

import { bootArbacHttp } from "../../__testing__/arbac-http";
import { request } from "../../__testing__/http";
import { FakeUserProvider } from "../../__testing__/user-provider";
import { MoostArbac } from "../../moost-arbac";
import type { ArbacDbScope } from "../as-arbac-db-controller";
import {
  RpNote,
  RpOrg,
  RpProject,
  RpSlug,
  RpTag,
  RpTask,
  RpTaskTag,
  RpUser,
} from "./fixtures/rel-fixtures.as";

const TYPES = [RpOrg, RpUser, RpTag, RpTask, RpTaskTag, RpSlug, RpProject, RpNote] as const;

export interface Harness {
  driver: BetterSqlite3Driver;
  table: (t: unknown) => any;
  close: () => void;
}

export async function createSpace(): Promise<Harness> {
  const driver = new BetterSqlite3Driver(":memory:");
  const space = new DbSpace(() => new SqliteAdapter(driver));
  for (const t of TYPES) await space.getTable(t as never).ensureTable();
  provideDbSpace(space);
  return {
    driver,
    table: (t) => space.getTable(t as never) as any,
    close: () => {
      clearDbSpaces();
      driver.close();
    },
  };
}

/** Wipe + seed (children first on wipe, parents first on insert). */
export async function seed(h: Harness): Promise<void> {
  for (const t of [...TYPES].toReversed()) {
    h.driver.exec(`DELETE FROM "${(h.table(t) as { tableName: string }).tableName}"`);
  }
  await h.table(RpOrg).insertMany([
    { id: 1, name: "orgA", tenant: "a", budget: 100 },
    { id: 2, name: "orgB", tenant: "b", budget: 999999 },
  ]);
  await h.table(RpUser).insertMany([
    { id: 1, name: "alice", tenant: "a", salary: 10, password: "pw-alice", orgId: 1 },
    { id: 2, name: "bob", tenant: "b", salary: 777777, password: "pw-bob", orgId: 2 },
  ]);
  await h.table(RpTag).insertMany([
    { id: 1, name: "tagA", tenant: "a" },
    { id: 2, name: "tagB", tenant: "b" },
  ]);
  await h.table(RpTask).insertMany([
    { id: 1, title: "taskA", tenant: "a", ownerId: 1, profile: { name: "pa", tenant: "a" } },
    { id: 2, title: "taskB", tenant: "b", ownerId: 2, profile: { name: "pb", tenant: "b" } },
    // In scope, but owned by a foreign-tenant user.
    { id: 3, title: "taskA2", tenant: "a", ownerId: 2 },
  ]);
  await h.table(RpTaskTag).insertMany([
    { taskId: 1, tagId: 1 },
    { taskId: 2, tagId: 2 },
  ]);
  await h.table(RpProject).insertMany([
    { id: 1, title: "pA", tenant: "a" },
    { id: 2, title: "pB", tenant: "b" },
  ]);
  await h.table(RpNote).insertMany([
    { id: 1, body: "nA", tenant: "a", projectId: 1 },
    { id: 2, body: "nB", tenant: "b", projectId: 2 },
  ]);
  // The out-of-scope row goes in FIRST (lower rowid): its unique slug equals
  // the in-scope row's primary key, so a scalar "abc" names both rows.
  await h.table(RpSlug).insertMany([
    { id: "zz-b", slug: "abc", tenant: "b", title: "B-row" },
    { id: "abc", slug: "a-own", tenant: "a", title: "A-row" },
  ]);
}

/**
 * Boot an ARBAC HTTP app over the harness space: `roles` registered, the
 * caller `u1` holding `roleIds` (with `attrs`), optional custom scope field
 * rules. The returned `user` takes a per-test `attenuation`.
 */
export async function boot<A extends object = object, S extends object = ArbacDbScope>(
  roles: Array<TArbacRole<A, S>>,
  controllers: Parameters<typeof bootArbacHttp>[0]["controllers"],
  roleIds: string[],
  opts: { attrs?: A; fields?: TScopeFieldRules<S> } = {},
): Promise<{ http: MoostHttp; user: FakeUserProvider<A>; arbac: MoostArbac<A, S> }> {
  clearGlobalWooks();
  const arbac = new MoostArbac<A, S>();
  for (const r of roles) arbac.registerRole(r);
  if (opts.fields) arbac.registerScopeFields(opts.fields);
  const user = new FakeUserProvider<A>("u1", roleIds, opts.attrs);
  const http = await bootArbacHttp({ arbac, user, controllers, authorize: true });
  return { http, user, arbac };
}

export async function send(
  http: MoostHttp,
  method: string,
  path: string,
  body?: unknown,
): Promise<{ status: number; body: any }> {
  return request(http, method, path, body);
}

/** Raw DB read, bypassing every controller. */
export const one = (h: Harness, t: unknown, filter: Record<string, unknown>) =>
  h.table(t).findOne({ filter, controls: {} });

export const all = (h: Harness, t: unknown, filter: Record<string, unknown> = {}) =>
  h.table(t).findMany({ filter, controls: {} }) as Promise<Array<Record<string, any>>>;
