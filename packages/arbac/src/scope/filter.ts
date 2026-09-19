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
 * Conjoin two filters under `$and` semantics — a row survives only if BOTH
 * sides admit it. The restrict-only combiner, used wherever two independent
 * constraints must both hold:
 *
 * - **credential attenuation** — assigned authority ∧ presented authority, so
 *   a scoped token can only clip what the role grants (see
 *   `conjoinArbacDbScopes`);
 * - **scope ∧ request** — the caller's scope union ∧ the user-supplied query
 *   filter, on both the top-level read and the per-relation `$with` overlay.
 *
 * Either side may be a {@link mergeScopeFilters} output or a raw filter.
 *
 * Polarity is the **opposite** of {@link mergeScopeFilters}: an empty `{}` /
 * `undefined` filter is the universe and acts as the **identity** here
 * (dropped from the `$and`, contributing NO constraint) — never the absorbing
 * "unrestricted wins". Never object-spreads the two filters: a key present on
 * both sides would be overwritten rather than intersected, silently widening
 * access (a caller scoped to `tenantId: 'a'` asking for `'b'` would get `'b'`).
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
