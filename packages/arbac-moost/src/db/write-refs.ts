import { effectiveScope, intersectEnabled, stableKey } from "@aooth/arbac";
import type { TScopeFilter } from "@aooth/arbac";
import { getPath } from "@atscript/db";
import type { TDbWriteGuardContext } from "@atscript/db";
import { HttpError } from "@moostjs/event-http";

import type { ArbacDbScope } from "./as-arbac-db-controller";
import { getOrCreate, isPatchAction, isScalar } from "./helpers";
import { evaluateTypeRead } from "./relation-policy";

/*
 * `checkRefs` — FK target checks (opt-in per write scope, since 0.1.72).
 *
 * A write that SETS a foreign key must reference a row the caller can READ on
 * the target table (its own `query` grant there, through the target's
 * registered ARBAC DB controller): otherwise a scoped writer could attach its
 * row to another tenant's parent, which the parent-table's scope never sees.
 */

/** A `@db.rel.FK` entry as atscript-db's readable exposes it. */
export interface RefForeignKey {
  readonly fields: readonly string[];
  readonly targetFields: readonly string[];
  readonly targetTable?: string;
  readonly alias?: string;
  readonly targetTypeRef?: () => unknown;
}

/** The table surface `checkRefs` resolves names against (`AtscriptDbReadable` satisfies it). */
export interface RefTableSource {
  readonly foreignKeys?: ReadonlyMap<string, RefForeignKey>;
  /** The FK a TO relation is backed by (atscript-db's `readable.foreignKeyOf`). @since 0.1.72 */
  foreignKeyOf?(relationName: string): RefForeignKey | undefined;
}

/** The target-table surface the check counts on. */
interface RefCountTable {
  count(query: { filter: TScopeFilter; controls: Record<string, never> }): Promise<number>;
}

/**
 * The FK a `checkRefs` entry designates: one of its local fields, or the TO
 * relation it backs (`readable.foreignKeyOf`). A name that is neither is a
 * configuration error.
 */
export function refForeignKeyOf(table: RefTableSource, name: string): RefForeignKey {
  const fk =
    [...(table.foreignKeys?.values() ?? [])].find((f) => f.fields.includes(name)) ??
    table.foreignKeyOf?.(name);
  if (fk) return fk;
  throw new Error(`checkRefs: "${name}" is not a foreign key field or TO relation of this table`);
}

/**
 * The FKs whose target check applies to a write under `scopes` — the union
 * rule: write scopes grant additively (more roles = more access), so a scope
 * WITHOUT the flag for an FK grants unconstrained writes of it; the check is
 * enforced only for the FKs EVERY scope enables (intersection).
 *
 * @example
 * ```ts
 * // role "member":  { filter: { tenant }, checkRefs: ["projectId"] }
 * // role "auditor": { filter: { tenant }, checkRefs: true }
 * // member + auditor → projectId checked (both enable it); assigneeId not
 * // role "importer": { filter: { tenant } }            // no checkRefs
 * // member + importer → nothing checked (importer grants unconstrained FK writes)
 * ```
 */
export function enforcedRefs(
  scopes: readonly ArbacDbScope[],
  table: RefTableSource,
): RefForeignKey[] {
  const all = table.foreignKeys;
  if (!all || all.size === 0 || scopes.length === 0) return [];
  const enforced = intersectEnabled(
    scopes.map((s) =>
      s.checkRefs === true
        ? true
        : new Set((s.checkRefs ?? []).map((name) => refForeignKeyOf(table, name))),
    ),
  );
  return enforced === true ? [...all.values()] : [...enforced];
}

/**
 * Canonical `checkRefs` of a conjunction (credential attenuation): the FKs
 * EITHER side enforces — each side resolved with {@link enforcedRefs} —
 * named by their first local field. `true` when that is every FK of the
 * table; `undefined` when none. Without the table's schema the names are
 * combined as written (per side: the entries every scope lists, `true`
 * matching any).
 */
export function conjoinCheckRefs(
  userScopes: readonly ArbacDbScope[],
  credScopes: readonly ArbacDbScope[],
  table?: RefTableSource,
): true | string[] | undefined {
  if (!table?.foreignKeys) {
    const u = effectiveScope(userScopes).checkRefs;
    const c = effectiveScope(credScopes).checkRefs;
    if (u === true || c === true) return true;
    const names = new Set([...u, ...c]);
    return names.size > 0 ? [...names].toSorted() : undefined;
  }
  const all = new Set([...enforcedRefs(userScopes, table), ...enforcedRefs(credScopes, table)]);
  if (all.size === 0) return undefined;
  if (all.size === table.foreignKeys.size) return true;
  return [...all].map((fk) => fk.fields[0]).toSorted();
}

/** A row value at `path`: a literal dotted key first, else the nested path. */
function readPath(row: Record<string, unknown>, path: string): unknown {
  return path in row ? row[path] : getPath(row, path);
}

function outOfScope(fk: RefForeignKey): HttpError {
  return new HttpError(403, `Referenced row "${fk.fields.join(", ")}" is outside your scope`);
}

/** A patch row touches `fk` in part only — its tuple is completed from the pre-image. */
function needsPreImage(row: Record<string, unknown>, fk: RefForeignKey): boolean {
  const touched = fk.fields.filter((f) => readPath(row, f) !== undefined).length;
  return touched > 0 && touched < fk.fields.length;
}

/**
 * The distinct FK tuples the write SETS: insert / replace rows carry them in
 * full; an update patch only when it touches the FK (a composite FK touched
 * in part is completed from the pre-image). A null / absent part → no
 * reference, skipped. A plain object / array value (an operator shape) →
 * 403 (fail closed); scalars and class instances (a Mongo `ObjectId`, a
 * `Date`) are FK values.
 */
function referencedTuples(
  ctx: TDbWriteGuardContext,
  fk: RefForeignKey,
  pre: ReadonlyArray<Record<string, unknown> | null | undefined>,
): unknown[][] {
  const isPatch = isPatchAction(ctx.action);
  const tuples = new Map<string, unknown[]>();
  for (let i = 0; i < ctx.rows.length; i++) {
    const row = ctx.rows[i];
    if (isPatch && !fk.fields.some((f) => readPath(row, f) !== undefined)) continue;
    const source = pre[i] ? { ...pre[i], ...row } : row;
    const tuple = fk.fields.map((f) => readPath(source, f));
    if (tuple.some((v) => v === null || v === undefined)) continue;
    if (!tuple.every(isScalar)) throw outOfScope(fk);
    tuples.set(stableKey(tuple), tuple);
  }
  return [...tuples.values()];
}

/** The target-row filter of `tuples` over `fk.targetFields`. */
function targetFilter(fk: RefForeignKey, tuples: unknown[][]): TScopeFilter {
  if (fk.targetFields.length === 1)
    return { [fk.targetFields[0]]: { $in: tuples.map((t) => t[0]) } };
  return { $or: tuples.map((t) => Object.fromEntries(fk.targetFields.map((f, j) => [f, t[j]]))) };
}

async function countInScope(
  table: RefCountTable,
  ids: TScopeFilter,
  scope: TScopeFilter | undefined,
): Promise<number> {
  return table.count({ filter: scope ? { $and: [ids, scope] } : ids, controls: {} });
}

interface TargetRefs {
  fk: RefForeignKey;
  tuples: unknown[][];
}

/**
 * One target type's check: every referenced row must be readable by the
 * caller there — ONE count over all of its FKs' references; on a shortfall
 * (or two FKs naming one row through different keys) each FK is re-counted
 * exactly so the error names the offending FK.
 */
async function assertTargetRefs(type: object, refs: TargetRefs[]): Promise<void> {
  const target = await evaluateTypeRead(type);
  const table = target?.table as RefCountTable | undefined;
  if (!target || typeof table?.count !== "function") throw outOfScope(refs[0].fk);
  const scope = effectiveScope(target.scopes).filter;
  if (refs.length > 1) {
    const keys = new Set<string>();
    for (const { fk, tuples } of refs) {
      for (const t of tuples) keys.add(`${fk.targetFields.join(",")}:${stableKey(t)}`);
    }
    const all = { $or: refs.map(({ fk, tuples }) => targetFilter(fk, tuples)) };
    if ((await countInScope(table, all, scope)) === keys.size) return;
  }
  for (const { fk, tuples } of refs) {
    if ((await countInScope(table, targetFilter(fk, tuples), scope)) !== tuples.length) {
      throw outOfScope(fk);
    }
  }
}

/**
 * `checkRefs` enforcement for a write (runs in `guardWrite`, inside the
 * write's transaction): every FK {@link enforcedRefs} returns that the write
 * sets must reference rows the caller can read on the target table (its own
 * `query` grant there) — one count per target table — else 403
 * `Referenced row "<field>" is outside your scope`. No registered ARBAC
 * controller on the target, or no read grant there → 403 as well.
 *
 * @since 0.1.72
 */
export async function assertRefsInScope(
  ctx: TDbWriteGuardContext,
  scopes: readonly ArbacDbScope[],
  table: RefTableSource,
): Promise<void> {
  const fks = enforcedRefs(scopes, table);
  if (fks.length === 0) return;
  // A patch touching a composite FK in part is completed from the pre-images.
  const pre =
    isPatchAction(ctx.action) && ctx.rows.some((row) => fks.some((fk) => needsPreImage(row, fk)))
      ? await ctx.currentAll()
      : [];
  const byType = new Map<object, TargetRefs[]>();
  for (const fk of fks) {
    const tuples = referencedTuples(ctx, fk, pre);
    if (tuples.length === 0) continue;
    const type = fk.targetTypeRef?.() as object | undefined;
    if (!type) throw outOfScope(fk);
    getOrCreate(byType, type, () => []).push({ fk, tuples });
  }
  for (const [type, refs] of byType) await assertTargetRefs(type, refs);
}

/**
 * Start the target-table evaluations {@link assertRefsInScope} will need, so
 * the in-transaction guard finds them memoized (fire-and-forget: a failure
 * resurfaces where the guard awaits it).
 */
export function prefetchRefTargets(scopes: readonly ArbacDbScope[], table: RefTableSource): void {
  const types = new Set<object>();
  for (const fk of enforcedRefs(scopes, table)) {
    const type = fk.targetTypeRef?.() as object | undefined;
    if (type) types.add(type);
  }
  for (const type of types) evaluateTypeRead(type).catch(() => {});
}
