import type { TScopeFilter } from "./types";

/**
 * Merge multiple scope filters into a single filter using $or semantics.
 * In RBAC, if multiple roles grant access with different filters,
 * the user can see records matching ANY of them.
 *
 * Optimizes single-key same-field case to `{ field: { $in: [...] } }`.
 * Returns `undefined` when the result is unrestricted (no filter).
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
