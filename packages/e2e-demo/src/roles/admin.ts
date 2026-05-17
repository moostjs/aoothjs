import { allowTableAction, allowTableRead, allowTableWrite, defineRole } from "@aoothjs/arbac";

import type { ArbacDbScope, UserAttrs } from "./attrs";
import { PROJ_USER_ADMIN } from "./projections";
import { tenantFilter, tenantSet } from "./scopes";
import { WRITEABLE_USER_FIELDS_ADMIN } from "./writeable-fields";

export const adminRole = defineRole<UserAttrs, ArbacDbScope>()
  .id("admin")
  .name("Tenant Admin")
  .describe("Tenant-scoped god mode; cannot touch other tenants; cannot mutate roles via PATCH")
  .use(
    allowTableRead<UserAttrs, ArbacDbScope>("tenants", {
      scope: (attrs) => ({ filter: { id: attrs.tenantId } }),
    }),
    allowTableWrite<UserAttrs, ArbacDbScope>("users", {
      scope: (attrs) => ({
        filter: tenantFilter(attrs),
        projection: PROJ_USER_ADMIN,
        allowedFields: [...WRITEABLE_USER_FIELDS_ADMIN],
      }),
    }),
    allowTableAction<UserAttrs, ArbacDbScope>("users", ["assignRoles", "lock", "unlock"], {
      scope: (attrs) => ({ filter: tenantFilter(attrs) }),
    }),
    allowTableWrite<UserAttrs, ArbacDbScope>("departments", {
      scope: (attrs) => ({ filter: tenantFilter(attrs), set: tenantSet(attrs) }),
    }),
    allowTableWrite<UserAttrs, ArbacDbScope>("projects", {
      scope: (attrs) => ({ filter: tenantFilter(attrs), set: tenantSet(attrs) }),
    }),
    allowTableWrite<UserAttrs, ArbacDbScope>("tasks", {
      scope: (attrs) => ({ filter: tenantFilter(attrs), set: tenantSet(attrs) }),
    }),
    allowTableAction<UserAttrs, ArbacDbScope>("tasks", "new", {
      scope: (attrs, userId) => ({
        filter: tenantFilter(attrs),
        set: { ...tenantSet(attrs), creatorUsername: userId },
      }),
    }),
    allowTableAction<UserAttrs, ArbacDbScope>(
      "tasks",
      ["markDone", "markInProgress", "archive", "assign", "delete"],
      { scope: (attrs) => ({ filter: tenantFilter(attrs) }) },
    ),
    allowTableWrite<UserAttrs, ArbacDbScope>("comments", {
      scope: (attrs) => ({ filter: tenantFilter(attrs), set: tenantSet(attrs) }),
    }),
    allowTableWrite<UserAttrs, ArbacDbScope>("documents", {
      scope: (attrs) => ({ filter: tenantFilter(attrs), set: tenantSet(attrs) }),
    }),
    allowTableRead<UserAttrs, ArbacDbScope>("audit", {
      scope: (attrs) => ({ filter: tenantFilter(attrs) }),
    }),
  )
  .allow("auth.invite", "start")
  .allow("auth", "logout")
  .allow("auth", "refresh")
  .allow("auth", "status")
  .build();
