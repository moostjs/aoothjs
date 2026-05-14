import { defineRole, tableActionsPrivilege, tableReadPrivilege } from "@aoothjs/arbac"

import type { ArbacDbScope, UserAttrs } from "./attrs"
import { PROJ_USER_MANAGER } from "./projections"
import { tenantDeptFilter, tenantFilter, tenantSet } from "./scopes"

export const managerRole = defineRole<UserAttrs, ArbacDbScope>()
  .id("manager")
  .name("Department Manager")
  .describe("Read across own tenant; write within own department")
  .use(
    tableReadPrivilege<UserAttrs, ArbacDbScope>("users", {
      scope: (attrs) => ({ filter: tenantFilter(attrs), projection: PROJ_USER_MANAGER }),
    }),
    tableReadPrivilege<UserAttrs, ArbacDbScope>("departments", {
      scope: (attrs) => ({ filter: tenantFilter(attrs) }),
    }),
    tableReadPrivilege<UserAttrs, ArbacDbScope>("projects", {
      scope: (attrs) => ({ filter: tenantFilter(attrs) }),
    }),
    tableActionsPrivilege<UserAttrs, ArbacDbScope>("projects", ["update"], {
      scope: (attrs) => ({ filter: tenantDeptFilter(attrs) }),
    }),
    tableReadPrivilege<UserAttrs, ArbacDbScope>("tasks", {
      scope: (attrs) => ({ filter: tenantFilter(attrs) }),
    }),
    tableActionsPrivilege<UserAttrs, ArbacDbScope>(
      "tasks",
      ["insert", "update", "markDone", "markInProgress", "archive", "assign"],
      {
        scope: (attrs) => ({ filter: tenantDeptFilter(attrs), set: tenantSet(attrs) }),
      },
    ),
    tableActionsPrivilege<UserAttrs, ArbacDbScope>("tasks", ["new"], {
      scope: (attrs, userId) => ({
        filter: tenantDeptFilter(attrs),
        set: { ...tenantSet(attrs), creatorUsername: userId },
      }),
    }),
    tableReadPrivilege<UserAttrs, ArbacDbScope>("comments", {
      scope: (attrs) => ({ filter: tenantFilter(attrs) }),
    }),
    tableActionsPrivilege<UserAttrs, ArbacDbScope>("comments", ["insert", "update"], {
      scope: (attrs, userId) => ({
        filter: { ...tenantFilter(attrs), authorUsername: userId },
        set: { ...tenantSet(attrs), authorUsername: userId },
      }),
    }),
    tableReadPrivilege<UserAttrs, ArbacDbScope>("documents", {
      scope: (attrs) => ({
        filter: { ...tenantFilter(attrs), classification: { $in: ["public", "internal"] } },
      }),
    }),
  )
  .build()
