import { allowTableAction, allowTableRead, defineRole } from "@aoothjs/arbac";

import type { ArbacDbScope, UserAttrs } from "./attrs";
import { PROJ_USER_MANAGER } from "./projections";
import { tenantDeptFilter, tenantFilter, tenantSet } from "./scopes";

export const managerRole = defineRole<UserAttrs, ArbacDbScope>()
  .id("manager")
  .name("Department Manager")
  .describe("Read across own tenant; write within own department")
  .use(
    allowTableRead<UserAttrs, ArbacDbScope>("users", {
      scope: (attrs) => ({ filter: tenantFilter(attrs), projection: PROJ_USER_MANAGER }),
    }),
    allowTableRead<UserAttrs, ArbacDbScope>("departments", {
      scope: (attrs) => ({ filter: tenantFilter(attrs) }),
    }),
    allowTableRead<UserAttrs, ArbacDbScope>("projects", {
      scope: (attrs) => ({ filter: tenantFilter(attrs) }),
    }),
    allowTableAction<UserAttrs, ArbacDbScope>("projects", ["update"], {
      scope: (attrs) => ({ filter: tenantDeptFilter(attrs) }),
    }),
    allowTableRead<UserAttrs, ArbacDbScope>("tasks", {
      scope: (attrs) => ({ filter: tenantFilter(attrs) }),
    }),
    allowTableAction<UserAttrs, ArbacDbScope>(
      "tasks",
      ["insert", "update", "markDone", "markInProgress", "archive", "assign"],
      {
        scope: (attrs) => ({ filter: tenantDeptFilter(attrs), set: tenantSet(attrs) }),
      },
    ),
    allowTableAction<UserAttrs, ArbacDbScope>("tasks", ["new"], {
      scope: (attrs, userId) => ({
        filter: tenantDeptFilter(attrs),
        set: { ...tenantSet(attrs), creatorUsername: userId },
      }),
    }),
    allowTableRead<UserAttrs, ArbacDbScope>("comments", {
      scope: (attrs) => ({ filter: tenantFilter(attrs) }),
    }),
    allowTableAction<UserAttrs, ArbacDbScope>("comments", ["insert", "update"], {
      scope: (attrs, userId) => ({
        filter: { ...tenantFilter(attrs), authorUsername: userId },
        set: { ...tenantSet(attrs), authorUsername: userId },
      }),
    }),
    allowTableRead<UserAttrs, ArbacDbScope>("documents", {
      scope: (attrs) => ({
        filter: { ...tenantFilter(attrs), classification: { $in: ["public", "internal"] } },
      }),
    }),
  )
  .allow("auth", "public.*")
  .build();
