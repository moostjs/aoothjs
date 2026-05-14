import {
  canAccess,
  defineRole,
  tableActionsPrivilege,
  tableReadPrivilege,
} from "@aoothjs/arbac"

import type { ArbacDbScope, UserAttrs } from "./attrs"
import { PROJ_TASK_MEMBER, PROJ_USER_MEMBER } from "./projections"
import { tenantFilter, tenantSet } from "./scopes"

export const memberRole = defineRole<UserAttrs, ArbacDbScope>()
  .id("member")
  .name("Contributor")
  .describe("Tenant-scoped reads via project membership; act on assigned tasks; own comments")
  .use(
    tableReadPrivilege<UserAttrs, ArbacDbScope>("users", {
      scope: (attrs) => ({ filter: tenantFilter(attrs), projection: PROJ_USER_MEMBER }),
    }),
    // Owner-self branch deliberately spans tenants so the UNION test can observe broadening.
    tableReadPrivilege<UserAttrs, ArbacDbScope>("projects", {
      scope: (attrs, userId) => ({
        filter: {
          $or: [
            { ...tenantFilter(attrs), visibility: { $in: ["public", "team"] } },
            { ownerUsername: userId },
          ],
        },
      }),
    }),
    tableReadPrivilege<UserAttrs, ArbacDbScope>("tasks", {
      scope: (attrs, userId) => ({
        filter: {
          ...tenantFilter(attrs),
          $or: [{ creatorUsername: userId }, { assigneeUsername: userId }],
        },
        projection: PROJ_TASK_MEMBER,
      }),
    }),
    tableActionsPrivilege<UserAttrs, ArbacDbScope>("tasks", ["markDone", "markInProgress"], {
      scope: (attrs, userId) => ({
        filter: { ...tenantFilter(attrs), assigneeUsername: userId },
      }),
    }),
    tableActionsPrivilege<UserAttrs, ArbacDbScope>("tasks", ["new"], {
      scope: (attrs, userId) => ({
        filter: { ...tenantFilter(attrs), assigneeUsername: userId },
        set: {
          ...tenantSet(attrs),
          creatorUsername: userId,
          assigneeUsername: userId,
          status: "open",
        },
      }),
    }),
    tableReadPrivilege<UserAttrs, ArbacDbScope>("comments", {
      scope: (attrs) => ({ filter: tenantFilter(attrs) }),
    }),
    tableActionsPrivilege<UserAttrs, ArbacDbScope>("comments", ["insert", "update", "remove"], {
      scope: (attrs, userId) => ({
        filter: { ...tenantFilter(attrs), authorUsername: userId },
        set: { ...tenantSet(attrs), authorUsername: userId },
      }),
    }),
    tableReadPrivilege<UserAttrs, ArbacDbScope>("documents", {
      scope: (attrs) => ({
        filter: { ...tenantFilter(attrs), classification: { $ne: "confidential" } },
      }),
    }),
    canAccess<UserAttrs, ArbacDbScope>("auth", "handover.trigger"),
  )
  .build()
