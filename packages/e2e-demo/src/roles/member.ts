import { allowTableAction, allowTableRead, type ControlGate, defineRole } from "@aoothjs/arbac";

import type { ArbacDbScope, UserAttrs } from "./attrs";
import { PROJ_TASK_MEMBER, PROJ_USER_MEMBER } from "./projections";
import { tenantFilter, tenantSet } from "./scopes";

const memberControls: Record<string, ControlGate> = {
  $groupBy: false,
  $having: false,
};

export const memberRole = defineRole<UserAttrs, ArbacDbScope>()
  .id("member")
  .name("Contributor")
  .describe("Tenant-scoped reads via project membership; act on assigned tasks; own comments")
  .use(
    allowTableRead<UserAttrs, ArbacDbScope>("users", {
      scope: (attrs) => ({
        filter: tenantFilter(attrs),
        projection: PROJ_USER_MEMBER,
        controls: memberControls,
      }),
    }),
    // Owner-self branch deliberately spans tenants so the UNION test can observe broadening.
    allowTableRead<UserAttrs, ArbacDbScope>("projects", {
      scope: (attrs, userId) => ({
        filter: {
          $or: [
            { ...tenantFilter(attrs), visibility: { $in: ["public", "team"] } },
            { ownerUsername: userId },
          ],
        },
        controls: memberControls,
      }),
    }),
    allowTableRead<UserAttrs, ArbacDbScope>("tasks", {
      scope: (attrs, userId) => ({
        filter: {
          ...tenantFilter(attrs),
          $or: [{ creatorUsername: userId }, { assigneeUsername: userId }],
        },
        projection: PROJ_TASK_MEMBER,
        controls: memberControls,
      }),
    }),
    allowTableAction<UserAttrs, ArbacDbScope>("tasks", ["markDone", "markInProgress"], {
      scope: (attrs, userId) => ({
        filter: { ...tenantFilter(attrs), assigneeUsername: userId },
      }),
    }),
    allowTableAction<UserAttrs, ArbacDbScope>("tasks", ["new"], {
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
    allowTableRead<UserAttrs, ArbacDbScope>("comments", {
      scope: (attrs) => ({ filter: tenantFilter(attrs), controls: memberControls }),
    }),
    allowTableAction<UserAttrs, ArbacDbScope>("comments", ["insert", "update", "remove"], {
      scope: (attrs, userId) => ({
        filter: { ...tenantFilter(attrs), authorUsername: userId },
        set: { ...tenantSet(attrs), authorUsername: userId },
      }),
    }),
    allowTableRead<UserAttrs, ArbacDbScope>("documents", {
      scope: (attrs) => ({
        filter: { ...tenantFilter(attrs), classification: { $ne: "confidential" } },
        controls: memberControls,
      }),
    }),
  )
  .allow("auth", "handover.trigger")
  .build();
