import {
  defineRole,
  tableActionsPrivilege,
  tableReadPrivilege,
  tableWritePrivilege,
} from "@aoothjs/arbac"

import type { ArbacDbScope, UserAttrs } from "./attrs"

export const superadminRole = defineRole<UserAttrs, ArbacDbScope>()
  .id("superadmin")
  .name("Super Admin")
  .describe("Cross-tenant god mode; for ops & migration")
  .use(
    tableWritePrivilege<UserAttrs, ArbacDbScope>("tenants"),
    tableWritePrivilege<UserAttrs, ArbacDbScope>("users"),
    tableActionsPrivilege<UserAttrs, ArbacDbScope>("users", ["assignRoles", "lock", "unlock"]),
    tableWritePrivilege<UserAttrs, ArbacDbScope>("departments"),
    tableWritePrivilege<UserAttrs, ArbacDbScope>("projects"),
    tableWritePrivilege<UserAttrs, ArbacDbScope>("tasks"),
    tableActionsPrivilege<UserAttrs, ArbacDbScope>("tasks", [
      "new",
      "markDone",
      "markInProgress",
      "archive",
      "assign",
      "delete",
    ]),
    tableWritePrivilege<UserAttrs, ArbacDbScope>("comments"),
    tableWritePrivilege<UserAttrs, ArbacDbScope>("documents"),
    tableReadPrivilege<UserAttrs, ArbacDbScope>("audit"),
  )
  .build()
