// `roles` is intentionally absent — role changes only via `users.assignRoles`.
// `password.*` only via `/auth/password`. `mfa.value` only via dedicated MFA endpoints.
export const WRITEABLE_USER_FIELDS_ADMIN = [
  "username",
  "email",
  "tenantId",
  "departmentId",
  "secretNotes",
  "account.active",
  "account.locked",
  "mfa.defaultMethod",
  "mfa.autoSend",
] as const
