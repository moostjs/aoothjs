import { allowTableAction, allowTableRead, allowTableWrite, defineRole } from "@aoothjs/arbac";

import type { ArbacDbScope, UserAttrs } from "./attrs";

export const superadminRole = defineRole<UserAttrs, ArbacDbScope>()
  .id("superadmin")
  .name("Super Admin")
  .describe("Cross-tenant god mode; for ops & migration")
  .use(
    allowTableWrite<UserAttrs, ArbacDbScope>("tenants"),
    allowTableWrite<UserAttrs, ArbacDbScope>("users"),
    allowTableAction<UserAttrs, ArbacDbScope>("users", ["assignRoles", "lock", "unlock"]),
    allowTableWrite<UserAttrs, ArbacDbScope>("departments"),
    allowTableWrite<UserAttrs, ArbacDbScope>("projects"),
    allowTableWrite<UserAttrs, ArbacDbScope>("tasks"),
    allowTableAction<UserAttrs, ArbacDbScope>("tasks", [
      "new",
      "markDone",
      "markInProgress",
      "archive",
      "assign",
      "delete",
    ]),
    allowTableWrite<UserAttrs, ArbacDbScope>("comments"),
    allowTableWrite<UserAttrs, ArbacDbScope>("documents"),
    allowTableRead<UserAttrs, ArbacDbScope>("audit"),
  )
  .allow("auth", "logout")
  .allow("auth", "refresh")
  .allow("auth", "status")
  .build();
