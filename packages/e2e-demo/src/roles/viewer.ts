import { allowTableRead, type ControlGate, defineRole } from "@aooth/arbac";

import { Comment } from "../models/comment.as";
import { Document } from "../models/document.as";
import { Project } from "../models/project.as";
import { Task } from "../models/task.as";
import { DemoUser } from "../models/user.as";
import type { ArbacDbScope, UserAttrs } from "./attrs";
import { PROJ_COMMENT_VIEWER, PROJ_TASK_VIEWER, PROJ_USER_VIEWER } from "./projections";
import { tenantFilter } from "./scopes";

const viewerControls: Record<string, ControlGate> = {
  $with: false,
  $groupBy: false,
  $having: false,
};

// Narrower set for the tasks read scope: viewers can expand the
// `comments` relation (PROJ-04 exercises this) but can't groupBy/having.
// $with is whitelisted to ["comments"] — drill-throughs to other relations
// are still rejected so the surface stays auditable.
const viewerTaskControls: Record<string, ControlGate> = {
  $with: ["comments"],
  $groupBy: false,
  $having: false,
};

export const viewerRole = defineRole<UserAttrs, ArbacDbScope>()
  .id("viewer")
  .name("Viewer")
  .describe("Read-only on the tenant with the heaviest projection mask")
  .use(
    allowTableRead<UserAttrs, ArbacDbScope<DemoUser>>("users", {
      scope: (attrs) => ({
        filter: tenantFilter(attrs),
        projection: PROJ_USER_VIEWER,
        controls: viewerControls,
      }),
    }),
    allowTableRead<UserAttrs, ArbacDbScope<Project>>("projects", {
      scope: (attrs) => ({
        filter: { ...tenantFilter(attrs), visibility: { $ne: "private" } },
        controls: viewerControls,
      }),
    }),
    allowTableRead<UserAttrs, ArbacDbScope<Task>>("tasks", {
      scope: (attrs) => ({
        filter: tenantFilter(attrs),
        projection: PROJ_TASK_VIEWER,
        controls: viewerTaskControls,
        with: {
          comments: { projection: PROJ_COMMENT_VIEWER },
        },
      }),
    }),
    allowTableRead<UserAttrs, ArbacDbScope<Comment>>("comments", {
      scope: (attrs) => ({
        filter: tenantFilter(attrs),
        projection: PROJ_COMMENT_VIEWER,
        controls: viewerControls,
      }),
    }),
    allowTableRead<UserAttrs, ArbacDbScope<Document>>("documents", {
      scope: (attrs) => ({
        filter: { ...tenantFilter(attrs), classification: "public" },
        controls: viewerControls,
      }),
    }),
  )
  .build();
