import { findAncestorInSet, isPlainObject } from "@atscript/db";
import type { TDbWriteAction } from "@atscript/db";

/** `map.get(key)`, created with `create()` and stored on a miss. */
export function getOrCreate<K, V>(
  map: { get(key: K): V | undefined; set(key: K, value: V): unknown },
  key: K,
  create: () => V,
): V {
  let value = map.get(key);
  if (value === undefined) {
    value = create();
    map.set(key, value);
  }
  return value;
}

/** `path` or one of its dotted ancestors is in `set`. */
export function hasSelfOrAncestor(set: ReadonlySet<string>, path: string): boolean {
  return set.has(path) || findAncestorInSet(path, set) !== undefined;
}

/** A patch (`update` / `updateMany`) — only the keys it carries are written. */
export function isPatchAction(action: TDbWriteAction): boolean {
  return action === "update" || action === "updateMany";
}

/** An update / replace — a write whose target row has a pre-image to scope (USING). */
export function hasPreImage(action: TDbWriteAction): boolean {
  return action !== "insert" && action !== "insertMany";
}

/**
 * A value written as-is to one column: a primitive, `null`, or a class
 * instance (`Date`, a Mongo `ObjectId`, a `Buffer`, …) — never a plain object
 * or an array (a nested patch / an operator shape).
 */
export function isScalar(v: unknown): boolean {
  if (v === null) return true;
  if (typeof v === "function") return false;
  return typeof v !== "object" || (!Array.isArray(v) && !isPlainObject(v));
}

interface NavSource {
  navFields?: ReadonlySet<string>;
  relations?: ReadonlyMap<string, unknown>;
}

const navFieldsCache = new WeakMap<object, ReadonlySet<string>>();

/** The table's navigation fields (`navFields`, else its relation names), cached per table. */
export function navFieldsOf(table: NavSource): ReadonlySet<string> {
  return (
    table.navFields ?? getOrCreate(navFieldsCache, table, () => new Set(table.relations?.keys()))
  );
}
