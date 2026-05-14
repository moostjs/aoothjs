import type { TProjection } from "@aoothjs/arbac"

export const PROJ_USER_ADMIN: TProjection = { "password.history": 0, "mfa.methods": 0 }
export const PROJ_USER_MANAGER: TProjection = {
  password: 0,
  "mfa.value": 0,
  account: 0,
  secretNotes: 0,
}
export const PROJ_USER_MEMBER: TProjection = { id: 1, username: 1, email: 1, departmentId: 1 }
export const PROJ_USER_VIEWER: TProjection = { id: 1, username: 1, departmentId: 1 }
export const PROJ_USER_SELF: TProjection = { id: 1, username: 1, email: 1 }

export const PROJ_TASK_MEMBER: TProjection = { internalNotes: 0 }
export const PROJ_TASK_VIEWER: TProjection = { internalNotes: 0 }
