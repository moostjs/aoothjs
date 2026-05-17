import { allowTableAction, allowTableRead, defineRole } from "@aoothjs/arbac";

import { Comment } from "../models/comment.as";
import { Department } from "../models/department.as";
import { Document } from "../models/document.as";
import { Project } from "../models/project.as";
import { Task } from "../models/task.as";
import { DemoUser } from "../models/user.as";
import type { ArbacDbScope, UserAttrs } from "./attrs";
import { PROJ_USER_MANAGER } from "./projections";
import { tenantDeptFilter, tenantFilter, tenantSet } from "./scopes";

export const managerRole = defineRole<UserAttrs>()
  .id("manager")
  .name("Department Manager")
  .describe("Read across own tenant; write within own department")
  .use(
    allowTableRead<UserAttrs, ArbacDbScope<DemoUser>>("users", {
      scope: (attrs) => ({ filter: tenantFilter(attrs), projection: PROJ_USER_MANAGER }),
    }),
    allowTableRead<UserAttrs, ArbacDbScope<Department>>("departments", {
      scope: (attrs) => ({ filter: tenantFilter(attrs) }),
    }),
    allowTableRead<UserAttrs, ArbacDbScope<Project>>("projects", {
      scope: (attrs) => ({ filter: tenantFilter(attrs) }),
    }),
    allowTableAction<UserAttrs, ArbacDbScope<Project>>("projects", ["update"], {
      scope: (attrs) => ({ filter: tenantDeptFilter(attrs) }),
    }),
    allowTableRead<UserAttrs, ArbacDbScope<Task>>("tasks", {
      scope: (attrs) => ({ filter: tenantFilter(attrs) }),
    }),
    allowTableAction<UserAttrs, ArbacDbScope<Task>>(
      "tasks",
      ["insert", "update", "markDone", "markInProgress", "archive", "assign"],
      {
        scope: (attrs) => ({ filter: tenantDeptFilter(attrs), set: tenantSet(attrs) }),
      },
    ),
    allowTableAction<UserAttrs, ArbacDbScope<Task>>("tasks", ["new"], {
      scope: (attrs, userId) => ({
        filter: tenantDeptFilter(attrs),
        set: { ...tenantSet(attrs), creatorUsername: userId },
      }),
    }),
    allowTableRead<UserAttrs, ArbacDbScope<Comment>>("comments", {
      scope: (attrs) => ({ filter: tenantFilter(attrs) }),
    }),
    allowTableAction<UserAttrs, ArbacDbScope<Comment>>("comments", ["insert", "update"], {
      scope: (attrs, userId) => ({
        filter: { ...tenantFilter(attrs), authorUsername: userId },
        set: { ...tenantSet(attrs), authorUsername: userId },
      }),
    }),
    allowTableRead<UserAttrs, ArbacDbScope<Document>>("documents", {
      scope: (attrs) => ({
        filter: { ...tenantFilter(attrs), classification: { $in: ["public", "internal"] } },
      }),
    }),
  )
  .build();
