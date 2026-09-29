import type { TScopeFilter } from "@aooth/arbac";

import type { UserAttrs } from "./attrs";

export const tenantFilter = (attrs: UserAttrs): TScopeFilter => ({ tenantId: attrs.tenantId });

/**
 * The caller's username for ownership columns (`creatorUsername`,
 * `assigneeUsername`, `authorUsername`, `ownerUsername`). Scope fns' `userId`
 * is the surrogate `id`, not the username. Unresolved → `""`, matching no row.
 */
export const selfName = (attrs: UserAttrs): string => attrs.username ?? "";

export const tenantSet = (attrs: UserAttrs): Record<string, unknown> => ({
  tenantId: attrs.tenantId,
});

/** Department-only narrowing — conjoined with {@link tenantFilter} by `defineTableAccess` parts. */
export const deptFilter = (attrs: UserAttrs): TScopeFilter => ({
  departmentId: attrs.departmentId,
});

export const tenantDeptFilter = (attrs: UserAttrs): TScopeFilter => ({
  tenantId: attrs.tenantId,
  departmentId: attrs.departmentId,
});
