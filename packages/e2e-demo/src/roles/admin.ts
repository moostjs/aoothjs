import {
  canAccess,
  defineRole,
  tableActionPrivilege,
  tableActionsPrivilege,
  tableReadPrivilege,
  tableWritePrivilege,
} from "@aoothjs/arbac"

import type { ArbacDbScope, UserAttrs } from "./attrs"
import { PROJ_USER_ADMIN } from "./projections"
import { tenantFilter, tenantSet } from "./scopes"
import { WRITEABLE_USER_FIELDS_ADMIN } from "./writeable-fields"

export const adminRole = defineRole<UserAttrs, ArbacDbScope>()
  .id("admin")
  .name("Tenant Admin")
  .describe("Tenant-scoped god mode; cannot touch other tenants; cannot mutate roles via PATCH")
  .use(
    tableReadPrivilege<UserAttrs, ArbacDbScope>("tenants", {
      scope: (attrs) => ({ filter: { id: attrs.tenantId } }),
    }),
    tableWritePrivilege<UserAttrs, ArbacDbScope>("users", {
      scope: (attrs) => ({
        filter: tenantFilter(attrs),
        projection: PROJ_USER_ADMIN,
        allowedFields: [...WRITEABLE_USER_FIELDS_ADMIN],
      }),
    }),
    tableActionsPrivilege<UserAttrs, ArbacDbScope>("users", ["assignRoles", "lock", "unlock"], {
      scope: (attrs) => ({ filter: tenantFilter(attrs) }),
    }),
    tableWritePrivilege<UserAttrs, ArbacDbScope>("departments", {
      scope: (attrs) => ({ filter: tenantFilter(attrs), set: tenantSet(attrs) }),
    }),
    tableWritePrivilege<UserAttrs, ArbacDbScope>("projects", {
      scope: (attrs) => ({ filter: tenantFilter(attrs), set: tenantSet(attrs) }),
    }),
    tableWritePrivilege<UserAttrs, ArbacDbScope>("tasks", {
      scope: (attrs) => ({ filter: tenantFilter(attrs), set: tenantSet(attrs) }),
    }),
    tableActionPrivilege<UserAttrs, ArbacDbScope>("tasks", "new", {
      scope: (attrs, userId) => ({
        filter: tenantFilter(attrs),
        set: { ...tenantSet(attrs), creatorUsername: userId },
      }),
    }),
    tableActionsPrivilege<UserAttrs, ArbacDbScope>(
      "tasks",
      ["markDone", "markInProgress", "archive", "assign", "delete"],
      { scope: (attrs) => ({ filter: tenantFilter(attrs) }) },
    ),
    tableWritePrivilege<UserAttrs, ArbacDbScope>("comments", {
      scope: (attrs) => ({ filter: tenantFilter(attrs), set: tenantSet(attrs) }),
    }),
    tableWritePrivilege<UserAttrs, ArbacDbScope>("documents", {
      scope: (attrs) => ({ filter: tenantFilter(attrs), set: tenantSet(attrs) }),
    }),
    tableReadPrivilege<UserAttrs, ArbacDbScope>("audit", {
      scope: (attrs) => ({ filter: tenantFilter(attrs) }),
    }),
    canAccess<UserAttrs, ArbacDbScope>("auth", "admin.invite"),
  )
  .build()
