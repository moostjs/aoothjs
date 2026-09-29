import type { TScopeFieldRule } from "@aooth/arbac";

/*
 * Test utility — NOT exported from the package's public entry.
 */

/** A list-valued custom scope field: the scope's value is a string list; absent = unrestricted. */
type ListScope<F extends string> = { [K in F]?: string[] };

/** A side's union of the field (`undefined` when any scope lacks it — unrestricted). */
function unionList<F extends string>(
  side: readonly ListScope<F>[],
  field: F,
): Set<string> | undefined {
  if (side.some((s) => s[field] === undefined)) return undefined;
  return new Set(side.flatMap((s) => s[field] ?? []));
}

/**
 * The rule of a list-valued custom scope field (`teams`, `tenants`, …):
 * `conjoin` intersects the two sides' unions (a side without the field is
 * unrestricted); with `rowFilterColumn`, the field restricts rows to
 * `{ [column]: { $in: value } }`.
 */
export function listFieldRule<S extends object>(
  field: string,
  rowFilterColumn?: string,
): TScopeFieldRule<S> {
  const rule: TScopeFieldRule<S> = {
    conjoin(a, b) {
      const la = unionList(a as unknown as ListScope<string>[], field);
      const lb = unionList(b as unknown as ListScope<string>[], field);
      if (!la) return lb && [...lb].toSorted();
      if (!lb) return [...la].toSorted();
      return [...la].filter((v) => lb.has(v)).toSorted();
    },
  };
  if (rowFilterColumn) {
    rule.rowFilter = (value) => ({ [rowFilterColumn]: { $in: value as string[] } });
  }
  return rule;
}

/** The app's own union of a list field (absent on any scope = unrestricted). */
export function unionListField(scopes: readonly object[], field: string): Set<string> | undefined {
  return unionList(scopes as ListScope<string>[], field);
}
