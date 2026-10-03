import { allowTableAction, allowTableRead, defineRole, defineTableAccess } from "@aooth/arbac";

import { Comment } from "../models/comment.as";
import { Department } from "../models/department.as";
import { Document } from "../models/document.as";
import { Project } from "../models/project.as";
import { Task } from "../models/task.as";
import { DemoUser } from "../models/user.as";
import type { ArbacDbScope, UserAttrs } from "./attrs";
import { PROJ_USER_MANAGER } from "./projections";
import { deptFilter, selfName, tenantDeptFilter, tenantFilter, tenantSet } from "./scopes";

export const managerRole = defineRole<UserAttrs, ArbacDbScope>()
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
    // Read the whole tenant; update only own-department projects. WITH CHECK
    // (defaults to the filter) keeps an update from moving a project out.
    defineTableAccess<UserAttrs, ArbacDbScope<Project>>("projects", {
      scope: (attrs) => ({ filter: tenantFilter(attrs) }),
      read: true,
      write: { ops: ["update"], scope: (attrs) => ({ filter: deptFilter(attrs) }) },
    }),
    // Read the whole tenant; write (CRUD insert/update + row actions) only
    // own-department tasks. `set` forces the tenant but deliberately NOT the
    // department: the default WITH CHECK (= filter) answers 403 and rolls back
    // an insert or PATCH that would place a task in another department (or in
    // none) instead of silently rewriting it — the move is refused, not undone.
    defineTableAccess<UserAttrs, ArbacDbScope<Task>>("tasks", {
      scope: (attrs) => ({ filter: tenantFilter(attrs) }),
      read: true,
      write: {
        ops: ["insert", "update"],
        // `checkRefs`: the task's project must be readable by the manager.
        scope: (attrs) => ({
          filter: deptFilter(attrs),
          set: tenantSet(attrs),
          checkRefs: ["projectId"],
        }),
      },
      actions: {
        names: ["markDone", "markDoneMany", "markInProgress", "archive", "assign"],
        scope: (attrs) => ({ filter: deptFilter(attrs) }),
      },
    }),
    // The "New task" form carries no department — the manager's tasks land in
    // their own department (forced), so the created row is always in scope.
    allowTableAction<UserAttrs, ArbacDbScope<Task>>("tasks", "new", {
      scope: (attrs) => ({
        filter: tenantDeptFilter(attrs),
        set: {
          ...tenantSet(attrs),
          departmentId: attrs.departmentId,
          creatorUsername: selfName(attrs),
        },
        checkRefs: ["projectId"],
      }),
    }),
    defineTableAccess<UserAttrs, ArbacDbScope<Comment>>("comments", {
      scope: (attrs) => ({ filter: tenantFilter(attrs) }),
      read: true,
      write: {
        ops: ["insert", "update"],
        scope: (attrs) => ({
          filter: { authorUsername: selfName(attrs) },
          set: { ...tenantSet(attrs), authorUsername: selfName(attrs) },
        }),
      },
    }),
    allowTableRead<UserAttrs, ArbacDbScope<Document>>("documents", {
      scope: (attrs) => ({
        filter: { ...tenantFilter(attrs), classification: { $in: ["public", "internal"] } },
      }),
    }),
  )
  .build();
