import type { TScopeFilter } from "@aooth/arbac";
import { computeInsights, getPath, isPlainObject } from "@atscript/db";
import { walkFilter } from "@uniqu/core";
import type { FilterExpr, FilterVisitor } from "@uniqu/core";

/** A compiled in-memory WITH CHECK predicate over a (pre- or post-image) row. */
export type RowPredicate = (row: Record<string, unknown>) => boolean;

/** Thrown by {@link compileScopeCheck} for an operator the evaluator does not model. */
export class UnsupportedCheckError extends Error {}

/**
 * Compile a scope `check` filter into an in-memory predicate — used only when
 * the adapter cannot roll back (`!transactional`) and the check must run
 * BEFORE the write. Deliberately a small subset of the filter language
 * (`$eq`/`$ne`/`$in`/`$nin`/ordering/`$exists` + `$and`/`$or`/`$not`) with the
 * database's null model (`$eq: null` matches null or missing, `$exists`
 * means "holds a non-null value"); any other operator (e.g. `$regex`) throws
 * {@link UnsupportedCheckError} — callers fail closed.
 */
export function compileScopeCheck(filter: TScopeFilter): RowPredicate {
  return walkFilter(filter as FilterExpr, checkVisitor) ?? (() => true);
}

/** The field paths a filter references (dotted, as written). */
export function checkFields(filter: TScopeFilter): Set<string> {
  return new Set(computeInsights(filter).keys());
}

function same(a: unknown, b: unknown): boolean {
  if (a instanceof Date && b instanceof Date) return a.getTime() === b.getTime();
  return a === b;
}

function eq(v: unknown, value: unknown): boolean {
  return value === null ? v == null : same(v, value);
}

function ordinal(v: unknown): number {
  return (v instanceof Date ? v.getTime() : v) as number;
}

const checkVisitor: FilterVisitor<RowPredicate> = {
  and: (children) => (row) => children.every((c) => c(row)),
  or: (children) => (row) => children.some((c) => c(row)),
  not: (child) => (row) => !child(row),
  comparison(field, op, value) {
    const read = (row: Record<string, unknown>) => getPath(row, field);
    const compare = (test: (a: number, b: number) => boolean) => (row: Record<string, unknown>) => {
      const v = read(row);
      return v != null && test(ordinal(v), ordinal(value));
    };
    switch (op) {
      case "$eq":
        return (row) => eq(read(row), value);
      case "$ne":
        return (row) => !eq(read(row), value);
      case "$in":
        return (row) => Array.isArray(value) && value.some((x) => same(read(row), x));
      case "$nin":
        return (row) => !(Array.isArray(value) && value.some((x) => same(read(row), x)));
      case "$exists":
        return (row) => (read(row) != null) === Boolean(value);
      case "$gt":
        return compare((a, b) => a > b);
      case "$gte":
        return compare((a, b) => a >= b);
      case "$lt":
        return compare((a, b) => a < b);
      case "$lte":
        return compare((a, b) => a <= b);
      default:
        throw new UnsupportedCheckError(`${field}: ${op}`);
    }
  },
};

/**
 * The post-image of an update patch for the fields a check references, or
 * `undefined` when it cannot be known without the database (fail closed):
 * every referenced path must be untouched by the patch or set by a plain
 * scalar at exactly that path — a nested object / array / operator value
 * (`$inc`, `$insert`, …) over or under a referenced path is not modelled.
 */
export function patchPostImage(
  current: Record<string, unknown>,
  patch: Record<string, unknown>,
  fields: ReadonlySet<string>,
): Record<string, unknown> | undefined {
  const out: Record<string, unknown> = structuredCloneRow(current);
  for (const field of fields) {
    for (const [key, value] of Object.entries(patch)) {
      if (key === field) {
        if (!isComparable(value)) return undefined;
        setPath(out, field, value);
      } else if (field.startsWith(`${key}.`) || key.startsWith(`${field}.`)) {
        return undefined;
      }
    }
  }
  return out;
}

/**
 * A value the in-memory evaluator compares faithfully: a primitive, `null`
 * or a `Date` — other class instances (e.g. a Mongo `ObjectId`) compare by
 * identity here, so a SET of one over a checked field is not modelled.
 */
function isComparable(v: unknown): boolean {
  return v === null || v instanceof Date || (typeof v !== "object" && typeof v !== "function");
}

function structuredCloneRow(row: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(row)) {
    out[k] = isPlainObject(v) ? structuredCloneRow(v) : v;
  }
  return out;
}

function setPath(target: Record<string, unknown>, path: string, value: unknown): void {
  const segs = path.split(".");
  let node = target;
  for (let i = 0; i < segs.length - 1; i++) {
    const next = node[segs[i]];
    if (!next || typeof next !== "object" || Array.isArray(next)) {
      node[segs[i]] = {};
    }
    node = node[segs[i]] as Record<string, unknown>;
  }
  node[segs.at(-1)!] = value;
}
