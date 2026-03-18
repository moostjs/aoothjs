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
