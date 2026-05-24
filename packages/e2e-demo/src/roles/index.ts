import { adminRole } from "./admin";
import { commentsDeniedRole } from "./comments-denied";
import { guestRole } from "./guest";
import { managerRole } from "./manager";
import { memberRole } from "./member";
import { superadminRole } from "./superadmin";
import { tasksWriteDeniedRole } from "./tasks-write-denied";
import { viewerRole } from "./viewer";

export const allRoles = [
  superadminRole,
  adminRole,
  managerRole,
  memberRole,
  viewerRole,
  guestRole,
  commentsDeniedRole,
  tasksWriteDeniedRole,
] as const;

export type { ArbacDbScope, UserAttrs } from "./attrs";
export * from "./projections";
export * from "./writeable-fields";
export {
  adminRole,
  commentsDeniedRole,
  guestRole,
  managerRole,
  memberRole,
  superadminRole,
  tasksWriteDeniedRole,
  viewerRole,
};
