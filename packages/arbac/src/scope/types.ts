/**
 * Mongo-style field projection: `{ field: 0 | 1 }`.
 * - All 1s = inclusion mode (only listed fields allowed)
 * - All 0s = exclusion mode (listed fields denied, rest allowed)
 * - Mixing 0 and 1 in a single projection is invalid.
 *
 * Structurally compatible with @uniqu/core SelectExpr in object form.
 */
export type TProjection = Record<string, 0 | 1>;

/**
 * A filter expression compatible with @uniqu/core FilterExpr.
 * Comparison leaf: `{ field: value }` or `{ field: { $op: value } }`
 * Logical branch: `{ $or: [...] }` | `{ $and: [...] }` | `{ $not: ... }`
 */
export type TScopeFilter = Record<string, unknown>;

/**
 * Per-control policy in a resource scope.
 *
 * Used inside `ArbacDbScope.controls` (in `@aooth/arbac-moost`) to gate
 * Uniquery URL controls (`$with`, `$groupBy`, `$having`, …) on a per-role basis.
 *
 * Semantics:
 * - **silence** (key absent / `undefined`) — no opinion → allow.
 * - `true` — explicit allow (same effect as silence; useful for documentation).
 * - `false` — explicit deny; using the control fails 403.
 * - `readonly string[]` — whitelist mode; only the listed values are allowed.
 *   E.g., `{ $with: ['comments'] }` permits `?$with=comments` but rejects
 *   `?$with=tasks` with 403.
 *
 * Whitelist arrays are supported only for controls whose value is a list of
 * named entities (notably `$with` for relation names and `$groupBy` for
 * column names). For other controls (e.g. `$having`) only boolean gates are
 * supported in v1; supplying a whitelist throws at scope-evaluation time.
 */
export type ControlGate = boolean | readonly string[];
