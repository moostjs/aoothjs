import { effectiveScope, stableKey } from "@aooth/arbac";
import type { TScopeFilter } from "@aooth/arbac";
import type {
  TDbRemoveGuardContext,
  TDbWriteCheckContext,
  TDbWriteGuardContext,
} from "@atscript/db";
import { HttpError } from "@moostjs/event-http";

import type { ArbacDbScope } from "./as-arbac-db-controller";
import { hasPreImage, isPatchAction } from "./helpers";
import {
  checkFields,
  compileScopeCheck,
  patchPostImage,
  UnsupportedCheckError,
} from "./write-check";
import { assertRefsInScope } from "./write-refs";
import type { RefTableSource } from "./write-refs";

const OUT_OF_SCOPE = "Row outside your write scope";

/**
 * Nested writes through nav props are denied unless a write scope opts the
 * relation in via `nestedWrites` (an unrestricted scope does not). A dotted
 * key whose head is a nav prop counts as that relation.
 */
export function assertNestedWritesAllowed(
  data: unknown,
  scopes: readonly ArbacDbScope[],
  navFields: ReadonlySet<string>,
): void {
  if (navFields.size === 0) return;
  const rows = Array.isArray(data) ? data : [data];
  for (const row of rows) {
    if (!row || typeof row !== "object") continue;
    for (const key of Object.keys(row)) {
      const dot = key.indexOf(".");
      const rel = dot === -1 ? key : key.slice(0, dot);
      if (navFields.has(rel) && !effectiveScope(scopes).nestedWrites.has(rel)) {
        throw new HttpError(403, `Nested writes through "${rel}" are not allowed`);
      }
    }
  }
}

/** The table surface the write guards need (`AtscriptDbTable` satisfies it). */
export interface ArbacWriteTable {
  count(query: { filter: TScopeFilter; controls?: Record<string, never> }): Promise<number>;
  getAdapter(): { isInTransaction(): boolean };
}

/**
 * Every exact id filter (one row each, duplicates counted once) must match
 * a row inside `filter` — ONE count; else the same 404 a missing row gets
 * (no existence leak).
 */
export async function assertIdFiltersInScope(
  table: Pick<ArbacWriteTable, "count">,
  idFilters: ReadonlyArray<object>,
  filter: TScopeFilter | undefined,
): Promise<void> {
  const unique = new Map<string, object>();
  for (const f of idFilters) unique.set(stableKey(f), f);
  if (unique.size === 0) return;
  const ids = [...unique.values()];
  const idFilter = (ids.length === 1 ? ids[0] : { $or: ids }) as TScopeFilter;
  const n = await table.count({
    filter: filter ? { $and: [idFilter, filter] } : idFilter,
    controls: {},
  });
  if (n < ids.length) throw new HttpError(404, "Not found");
}

/**
 * WITH CHECK before the write (adapters without real transactions): insert /
 * replace rows are full rows, evaluated as-is; an update patch is evaluated
 * over its pre-image when every check-referenced field is untouched or a
 * plain scalar SET. Anything the in-memory evaluator cannot decide (an
 * unsupported operator, an operator / nested patch over a checked field, a
 * missing pre-image) is rejected — fail closed.
 */
export async function assertCheckBeforeWrite(
  ctx: TDbWriteGuardContext,
  check: TScopeFilter,
): Promise<void> {
  let predicate: (row: Record<string, unknown>) => boolean;
  try {
    predicate = compileScopeCheck(check);
  } catch (error) {
    if (error instanceof UnsupportedCheckError) throw new HttpError(403, OUT_OF_SCOPE);
    throw error;
  }
  const fields = isPatchAction(ctx.action) ? checkFields(check) : undefined;
  const images = fields
    ? (await ctx.currentAll()).map((current, i) =>
        current ? patchPostImage(current, ctx.rows[i], fields) : undefined,
      )
    : ctx.rows;
  for (const image of images) {
    if (!image || !predicate(image)) throw new HttpError(403, OUT_OF_SCOPE);
  }
}

/** WITH CHECK after the write (inside the transaction — a throw rolls back). */
export async function assertWrittenRowsInCheck(
  ctx: TDbWriteCheckContext,
  check: TScopeFilter,
): Promise<void> {
  if (ctx.filters.length === 0) return;
  const written = ctx.filters.length === 1 ? ctx.filters[0] : { $or: [...ctx.filters] };
  const n = await ctx.count({ $and: [written, check] });
  if (n !== ctx.filters.length) throw new HttpError(403, OUT_OF_SCOPE);
}

/**
 * The in-transaction write guard of the ARBAC DB layer — the body of
 * `AsArbacDbController.guardWrite` and of `useArbacDbScope().writeOptions()`'s
 * `guard`:
 *
 * - USING — every update / replace target (the exact record filter the
 *   write uses) must match the scope filter — one count, no pre-image read
 *   (missing or out of scope → 404);
 * - `checkRefs` — every enforced FK the write sets must reference rows the
 *   caller can read on the target table (→ 403);
 * - WITH CHECK when the adapter cannot roll back — validated here, before
 *   the write (see {@link checkArbacWrite} for the transactional path).
 */
export async function guardArbacWrite(
  ctx: TDbWriteGuardContext,
  scopes: readonly ArbacDbScope[],
  table: ArbacWriteTable,
  refs: RefTableSource,
): Promise<void> {
  const eff = effectiveScope(scopes);
  if (eff.filter && hasPreImage(ctx.action)) {
    const targets = ctx.rows.map((_row, i) => {
      const filter = ctx.filterFor(i);
      if (!filter) throw new HttpError(404, "Not found");
      return filter;
    });
    await assertIdFiltersInScope(table, targets, eff.filter);
  }
  await assertRefsInScope(ctx, scopes, refs);
  if (eff.check && !table.getAdapter().isInTransaction()) {
    await assertCheckBeforeWrite(ctx, eff.check);
  }
}

/**
 * WITH CHECK after the write, inside its transaction: every written row must
 * match the scopes' `check` (default `filter`) — else 403 and the write rolls
 * back. Non-transactional adapters were checked in {@link guardArbacWrite}.
 */
export async function checkArbacWrite(
  ctx: TDbWriteCheckContext,
  scopes: readonly ArbacDbScope[],
): Promise<void> {
  if (!ctx.transactional) return;
  const check = effectiveScope(scopes).check;
  if (check) await assertWrittenRowsInCheck(ctx, check);
}

/** USING for deletes: the exact row the delete targets must match the scope filter (else 404). */
export async function guardArbacRemove(
  ctx: TDbRemoveGuardContext,
  scopes: readonly ArbacDbScope[],
  table: Pick<ArbacWriteTable, "count">,
): Promise<void> {
  const filter = effectiveScope(scopes).filter;
  if (!filter) return;
  const n = await table.count({
    filter: { $and: [ctx.filter as TScopeFilter, filter] },
    controls: {},
  });
  if (n === 0) throw new HttpError(404, "Not found");
}
