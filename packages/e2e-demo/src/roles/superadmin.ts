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

export const superadminRole = defineRole<UserAttrs>()
  .id("superadmin")
  .name("Super Admin")
  .describe("Cross-tenant god mode; for ops & migration")
  .use(
    allowTableWrite<UserAttrs, ArbacDbScope<Tenant>>("tenants"),
    allowTableWrite<UserAttrs, ArbacDbScope<DemoUser>>("users"),
    allowTableAction<UserAttrs, ArbacDbScope<DemoUser>>("users", ["assignRoles", "lock", "unlock"]),
    allowTableWrite<UserAttrs, ArbacDbScope<Department>>("departments"),
    allowTableWrite<UserAttrs, ArbacDbScope<Project>>("projects"),
    allowTableWrite<UserAttrs, ArbacDbScope<Task>>("tasks"),
    allowTableAction<UserAttrs, ArbacDbScope<Task>>("tasks", [
      "new",
      "markDone",
      "markInProgress",
      "archive",
      "assign",
      "delete",
    ]),
    allowTableWrite<UserAttrs, ArbacDbScope<Comment>>("comments"),
    allowTableWrite<UserAttrs, ArbacDbScope<Document>>("documents"),
    allowTableRead<UserAttrs, ArbacDbScope<AuditEntry>>("audit"),
  )
  .build();
