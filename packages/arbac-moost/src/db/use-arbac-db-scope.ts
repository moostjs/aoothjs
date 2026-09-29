import { conjoinScopeFilters, effectiveScope } from "@aooth/arbac";
import type { TScopeFilter } from "@aooth/arbac";
import type {
  TDbRemoveGuardContext,
  TDbWriteGuardContext,
  TDeleteOptions,
  TRowResolveOptions,
  TWriteOptions,
} from "@atscript/db";
import { HttpError } from "@moostjs/event-http";

import type { ArbacDbScope } from "./as-arbac-db-controller";
import { navFieldsOf } from "./helpers";
import { isScopedFieldVisible, resolveRequestScopes } from "./request-scopes";
import type { VisibilityTableSource } from "./visibility";
import {
  assertIdFiltersInScope,
  assertNestedWritesAllowed,
  checkArbacWrite,
  guardArbacRemove,
  guardArbacWrite,
} from "./write-policy";
import type { ArbacWriteTable } from "./write-policy";
import { assertRefsInScope } from "./write-refs";
import type { RefTableSource } from "./write-refs";

/**
 * The slice of an atscript-db table {@link ArbacDbScopeHelpers.assertRowsInScope}
 * needs — satisfied by `AtscriptDbTable` / a controller's `this.table`.
 */
export interface ArbacScopedTable extends VisibilityTableSource {
  resolveRowFilter(id: unknown, opts?: TRowResolveOptions): Promise<object | null | undefined>;
  count(query: { filter: TScopeFilter; controls?: Record<string, never> }): Promise<number>;
}

/**
 * The table surface {@link ArbacDbScopeHelpers.writeOptions} /
 * {@link ArbacDbScopeHelpers.removeOptions} guard — satisfied by
 * `AtscriptDbTable` / a controller's `this.table`.
 *
 * @since 0.1.72
 */
export type ArbacGuardedTable = ArbacScopedTable & ArbacWriteTable & RefTableSource;

/** The current event's merged ARBAC DB scope — returned by {@link useArbacDbScope}. */
export interface ArbacDbScopeHelpers<T = unknown> {
  /** The evaluated scopes (one per matching rule; one composite when attenuated). */
  scopes: ArbacDbScope<T>[];
  /**
   * Union of the scopes' row filters CONJOINED (`$and`) with `extra` — never
   * spread, so `extra` can only narrow. `{}` when unrestricted.
   */
  filter(extra?: TScopeFilter): TScopeFilter;
  /** Merged `set` overrides (later scopes win) — overlay them on inserted / updated data. */
  set(): Record<string, unknown>;
  /**
   * Union of the scopes' effective WITH CHECK filters (`check`, defaulting to
   * `filter`; `{}` = none) — what a written row must match. `{}` when unrestricted.
   */
  check(): TScopeFilter;
  /**
   * 404 `Not found` unless every id resolves (PK first, else a visible unique
   * key — exactly one row per id) to a row inside the scope filter. Duplicate
   * ids count once.
   */
  assertRowsInScope(table: ArbacScopedTable, ids: readonly unknown[]): Promise<void>;
  /**
   * `checkRefs` for rows a handler is about to insert: 403 `Referenced row
   * "<field>" is outside your scope` unless every foreign key the scopes
   * enforce (see {@link ArbacDbScope.checkRefs}, union rule included)
   * references a row the caller can read on the target table. Null / absent
   * FKs pass. The same check the ARBAC DB controllers run on their CRUD writes.
   *
   * @since 0.1.72
   */
  assertRefsInScope(
    table: RefTableSource,
    rows: ReadonlyArray<Record<string, unknown>>,
  ): Promise<void>;
  /**
   * `TWriteOptions` for `table.insertOne/Many`, `replaceOne` / `bulkReplace`,
   * `updateOne` / `bulkUpdate` in a handler: the same in-transaction
   * enforcement the ARBAC DB controllers' CRUD writes get — nested writes
   * (`nestedWrites`, 403), USING (pre-image in scope, 404), `checkRefs` (403)
   * and WITH CHECK (403, rolled back). `allowedFields` / `set` are not applied
   * — overlay {@link set} yourself.
   *
   * @since 0.1.72
   */
  writeOptions<Row extends object = Record<string, unknown>>(
    table: ArbacGuardedTable,
  ): TWriteOptions<Row>;
  /**
   * `TDeleteOptions` for `table.deleteOne` in a handler: the id is pinned
   * among in-scope rows and the row must match the scope filter (else 404) —
   * the ARBAC DB controllers' `DELETE` enforcement.
   *
   * @since 0.1.72
   */
  removeOptions<Row extends object = Record<string, unknown>>(
    table: ArbacGuardedTable,
  ): TDeleteOptions<Row>;
}

/**
 * The current event's merged ARBAC DB scope, for custom routes and
 * `@DbAction` handlers that query the table directly. Resolves the event's
 * scopes once (the ones the authorize interceptor cached, else an ARBAC
 * evaluation of the current resource/action) — a deny, or an allowed
 * evaluation with no scope left, throws 403.
 *
 * @example
 * ```ts
 * const scope = await useArbacDbScope<typeof Task>();
 * await scope.assertRowsInScope(this.table, [id]);
 * await this.table.updateMany(scope.filter({ id }), { ...patch, ...scope.set() });
 * // A handler-side insert with the CRUD endpoints' write enforcement.
 * await this.table.insertOne({ ...row, ...scope.set() }, scope.writeOptions(this.table));
 * ```
 */
// `T` only types the returned scopes (a caller-side witness, like `useArbac().evaluate`).
// oxlint-disable-next-line typescript/no-unnecessary-type-parameters
export async function useArbacDbScope<T = unknown>(): Promise<ArbacDbScopeHelpers<T>> {
  const scopes = await resolveRequestScopes();
  const eff = effectiveScope(scopes);
  // A unique key over a scope-hidden column is no identification — the same
  // rule the ARBAC controllers apply through `hasField`.
  const visibleOn = (table: VisibilityTableSource) => (path: string) =>
    isScopedFieldVisible(scopes, path, table);

  return {
    scopes: scopes as ArbacDbScope<T>[],
    filter: (extra) => conjoinScopeFilters(eff.filter, extra) ?? {},
    set: () => ({ ...eff.set }),
    check: () => eff.check ?? {},
    async assertRowsInScope(table, ids) {
      const isFieldVisible = visibleOn(table);
      const scope = eff.filter;
      const idFilters = await Promise.all(
        ids.map(async (id) => {
          const f = await table.resolveRowFilter(id, { isFieldVisible, scope });
          if (!f) throw new HttpError(404, "Not found");
          return f;
        }),
      );
      await assertIdFiltersInScope(table, idFilters, eff.filter);
    },
    assertRefsInScope: (table, rows) =>
      assertRefsInScope(
        {
          action: "insertMany",
          rows: [...rows],
          expectedVersions: [],
          current: async () => null,
          currentAll: async () => rows.map(() => null),
          filterFor: () => null,
        },
        scopes,
        table,
      ),
    writeOptions: <Row extends object>(table: ArbacGuardedTable): TWriteOptions<Row> => ({
      isFieldVisible: visibleOn(table),
      guard: async (ctx) => {
        const rows = ctx as unknown as TDbWriteGuardContext;
        assertNestedWritesAllowed(rows.rows, scopes, navFieldsOf(table));
        await guardArbacWrite(rows, scopes, table, table);
      },
      check: (ctx) => checkArbacWrite(ctx, scopes),
    }),
    removeOptions: <Row extends object>(table: ArbacGuardedTable): TDeleteOptions<Row> => ({
      isFieldVisible: visibleOn(table),
      ...(eff.filter ? { scope: eff.filter } : {}),
      guard: (ctx) => guardArbacRemove(ctx as TDbRemoveGuardContext, scopes, table),
    }),
  };
}
