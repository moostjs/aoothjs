/**
 * Roles a tenant admin may grant through `users.assignRoles`. `superadmin`
 * (cross-tenant) is never in it — only a caller holding the privileged
 * `users/assignAnyRole` ARBAC action (the superadmin) may assign any role.
 */
export const TENANT_ASSIGNABLE_ROLES: readonly string[] = [
  "admin",
  "manager",
  "member",
  "viewer",
  "guest",
];

/** ARBAC action (resource `users`) that lifts the {@link TENANT_ASSIGNABLE_ROLES} limit. */
export const ASSIGN_ANY_ROLE_ACTION = "assignAnyRole";
