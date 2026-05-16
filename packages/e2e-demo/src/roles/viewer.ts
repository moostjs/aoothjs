import { allowTableRead, type ControlGate, defineRole } from "@aoothjs/arbac";

import type { ArbacDbScope, UserAttrs } from "./attrs";
import { PROJ_TASK_VIEWER, PROJ_USER_VIEWER } from "./projections";
import { tenantFilter } from "./scopes";

const viewerControls: Record<string, ControlGate> = {
  $with: false,
  $groupBy: false,
  $having: false,
};

export const viewerRole = defineRole<UserAttrs, ArbacDbScope>()
  .id("viewer")
  .name("Viewer")
  .describe("Read-only on the tenant with the heaviest projection mask")
  .use(
    allowTableRead<UserAttrs, ArbacDbScope>("users", {
      scope: (attrs) => ({
        filter: tenantFilter(attrs),
        projection: PROJ_USER_VIEWER,
        controls: viewerControls,
      }),
    }),
    allowTableRead<UserAttrs, ArbacDbScope>("projects", {
      scope: (attrs) => ({
        filter: { ...tenantFilter(attrs), visibility: { $ne: "private" } },
        controls: viewerControls,
      }),
    }),
    allowTableRead<UserAttrs, ArbacDbScope>("tasks", {
      scope: (attrs) => ({
        filter: tenantFilter(attrs),
        projection: PROJ_TASK_VIEWER,
        controls: viewerControls,
      }),
    }),
    allowTableRead<UserAttrs, ArbacDbScope>("comments", {
      scope: (attrs) => ({ filter: tenantFilter(attrs), controls: viewerControls }),
    }),
    allowTableRead<UserAttrs, ArbacDbScope>("documents", {
      scope: (attrs) => ({
        filter: { ...tenantFilter(attrs), classification: "public" },
        controls: viewerControls,
      }),
    }),
  )
  .allow("auth", "logout")
  .allow("auth", "refresh")
  .allow("auth", "status")
  .build();
