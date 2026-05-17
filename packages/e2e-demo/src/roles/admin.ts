import { allowTableAction, allowTableRead, allowTableWrite, defineRole } from "@aoothjs/arbac";

import { AuditEntry } from "../models/audit.as";
import { Comment } from "../models/comment.as";
import { Department } from "../models/department.as";
import { Document } from "../models/document.as";
import { Project } from "../models/project.as";
import { Task } from "../models/task.as";
import { Tenant } from "../models/tenant.as";
import { DemoUser } from "../models/user.as";
import type { ArbacDbScope, UserAttrs } from "./attrs";
import { PROJ_USER_ADMIN } from "./projections";
import { tenantFilter, tenantSet } from "./scopes";
import { WRITEABLE_USER_FIELDS_ADMIN } from "./writeable-fields";

export const adminRole = defineRole<UserAttrs, ArbacDbScope>()
  .id("admin")
  .name("Tenant Admin")
  .describe("Tenant-scoped god mode; cannot touch other tenants; cannot mutate roles via PATCH")
  .use(
    allowTableRead<UserAttrs, ArbacDbScope<Tenant>>("tenants", {
      scope: (attrs) => ({ filter: { id: attrs.tenantId } }),
    }),
    allowTableWrite<UserAttrs, ArbacDbScope<DemoUser>>("users", {
      scope: (attrs) => ({
        filter: tenantFilter(attrs),
        projection: PROJ_USER_ADMIN,
        allowedFields: [...WRITEABLE_USER_FIELDS_ADMIN],
      }),
    }),
    allowTableAction<UserAttrs, ArbacDbScope<DemoUser>>(
      "users",
      ["assignRoles", "lock", "unlock"],
      {
        scope: (attrs) => ({ filter: tenantFilter(attrs) }),
      },
    ),
    allowTableWrite<UserAttrs, ArbacDbScope<Department>>("departments", {
      scope: (attrs) => ({ filter: tenantFilter(attrs), set: tenantSet(attrs) }),
    }),
    allowTableWrite<UserAttrs, ArbacDbScope<Project>>("projects", {
      scope: (attrs) => ({ filter: tenantFilter(attrs), set: tenantSet(attrs) }),
    }),
    allowTableWrite<UserAttrs, ArbacDbScope<Task>>("tasks", {
      scope: (attrs) => ({ filter: tenantFilter(attrs), set: tenantSet(attrs) }),
    }),
    allowTableAction<UserAttrs, ArbacDbScope<Task>>("tasks", "new", {
      scope: (attrs, userId) => ({
        filter: tenantFilter(attrs),
        set: { ...tenantSet(attrs), creatorUsername: userId },
      }),
    }),
    allowTableAction<UserAttrs, ArbacDbScope<Task>>(
      "tasks",
      ["markDone", "markInProgress", "archive", "assign", "delete"],
      { scope: (attrs) => ({ filter: tenantFilter(attrs) }) },
    ),
    allowTableWrite<UserAttrs, ArbacDbScope<Comment>>("comments", {
      scope: (attrs) => ({ filter: tenantFilter(attrs), set: tenantSet(attrs) }),
    }),
    allowTableWrite<UserAttrs, ArbacDbScope<Document>>("documents", {
      scope: (attrs) => ({ filter: tenantFilter(attrs), set: tenantSet(attrs) }),
    }),
    allowTableRead<UserAttrs, ArbacDbScope<AuditEntry>>("audit", {
      scope: (attrs) => ({ filter: tenantFilter(attrs) }),
    }),
  )
  .allow("auth.invite", "start")
  .build();
