import type { TScopeFilter } from "@aoothjs/arbac";

import type { UserAttrs } from "./attrs";

export const tenantFilter = (attrs: UserAttrs): TScopeFilter => ({ tenantId: attrs.tenantId });

export const tenantSet = (attrs: UserAttrs): Record<string, unknown> => ({
  tenantId: attrs.tenantId,
});

export const tenantDeptFilter = (attrs: UserAttrs): TScopeFilter => ({
  tenantId: attrs.tenantId,
  departmentId: attrs.departmentId,
});
