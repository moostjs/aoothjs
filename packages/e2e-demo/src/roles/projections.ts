import type { TProjection } from "@aoothjs/arbac";

export const PROJ_USER_ADMIN: TProjection = { "password.history": 0, "mfa.methods": 0 };
export const PROJ_USER_MANAGER: TProjection = {
  password: 0,
  "mfa.value": 0,
  account: 0,
  secretNotes: 0,
};
export const PROJ_USER_MEMBER: TProjection = { id: 1, username: 1, email: 1, departmentId: 1 };
export const PROJ_USER_VIEWER: TProjection = { id: 1, username: 1, departmentId: 1 };
export const PROJ_USER_SELF: TProjection = { id: 1, username: 1, email: 1 };

export const PROJ_TASK_MEMBER: TProjection = { internalNotes: 0 };
export const PROJ_TASK_VIEWER: TProjection = { internalNotes: 0 };

// Direct /comments/query for viewer — exclude-mode is fine because the moost-db
// controller widens it via fieldDescriptors before hitting the field mapper.
export const PROJ_COMMENT_VIEWER: TProjection = { tenantId: 0 };

// Same intent (mask tenantId on expanded comments) for viewer.tasks.with.comments.
// Must be INCLUDE-mode: arbac-moost's `applyArbacRelationScopes` pushes this into
// the relation loader's `$select`, which bypasses moost-db's widenPreferredIdProjection
// and feeds the raw projection straight to the relational field mapper. The mapper's
// allPhysicalFields includes nav-flattened paths (e.g. `task__id`), so an exclude-form
// `{tenantId: 0}` would invert to a SELECT that references columns that don't exist.
// Include-mode side-steps that path (asArray just returns the listed keys).
export const PROJ_COMMENT_VIEWER_EXPANDED: TProjection = {
  id: 1,
  taskId: 1,
  authorUsername: 1,
  body: 1,
  createdAt: 1,
};
