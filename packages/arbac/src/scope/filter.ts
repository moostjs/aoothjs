import type { TScopeFilter } from "./types";

/**
 * Merge multiple scope filters into a single filter using `$or` semantics.
 *
 * In RBAC, if multiple roles grant access with different filters,
 * the user can see records matching ANY of them — hence `$or`.
 *
 * Behaviour:
 * - Empty input → `undefined` (no filter)
 * - Any empty filter → `undefined` (one role grants unrestricted access)
 * - Single filter → returned as-is
 * - All filters single-keyed on the same primitive field → `{ field: { $in: [...] } }`
 * - Otherwise → `{ $or: [...] }`
 *
 * @returns the merged filter, or `undefined` for unrestricted access
 */
export function mergeScopeFilters(scopes: TScopeFilter[]): TScopeFilter | undefined {
  if (scopes.length === 0) return undefined;

  // Any empty filter means unrestricted
  if (scopes.some((s) => Object.keys(s).length === 0)) return undefined;

  // Single filter — return as-is
  if (scopes.length === 1) return scopes[0];

  // Try $in optimization: all single-key, same field, primitive values
  if (canOptimizeToIn(scopes)) {
    const key = Object.keys(scopes[0])[0];
    const values = scopes.map((s) => s[key]);
    return { [key]: { $in: values } };
  }

  return { $or: scopes };
}

/**
 * Conjoin two ALREADY-UNIONED scope filters (each the output of
 * {@link mergeScopeFilters} for one authority pass) under `$and` semantics — a
 * row survives only if BOTH sides admit it. This is the credential-attenuation
 * combiner: it clips any widening the credential pass might introduce.
 *
 * Polarity is the **opposite** of {@link mergeScopeFilters}: an empty `{}` /
 * `undefined` filter is the universe and acts as the **identity** here
 * (dropped from the `$and`, contributing NO constraint) — never the absorbing
 * "unrestricted wins". Never object-spreads the two filters (credential keys
 * could overwrite user keys and silently widen).
 *
 * @returns the conjoined filter, or `undefined` when BOTH sides are unrestricted.
 */
export function conjoinScopeFilters(
  a: TScopeFilter | undefined,
  b: TScopeFilter | undefined,
): TScopeFilter | undefined {
  const aEmpty = !a || Object.keys(a).length === 0;
  const bEmpty = !b || Object.keys(b).length === 0;
  if (aEmpty && bEmpty) return undefined;
  if (aEmpty) return b;
  if (bEmpty) return a;
  return { $and: [a, b] };
}

function canOptimizeToIn(scopes: TScopeFilter[]): boolean {
  const firstKeys = Object.keys(scopes[0]);
  if (firstKeys.length !== 1) return false;
  const key = firstKeys[0];

  for (const scope of scopes) {
    const keys = Object.keys(scope);
    if (keys.length !== 1 || keys[0] !== key) return false;
    const value = scope[key];
    if (value !== null && typeof value === "object") return false;
  }
  return true;
}
