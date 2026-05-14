// `roles` is intentionally absent — role changes only via `users.assignRoles`.
// `password.*` only via `/auth/password`. `mfa.value` only via dedicated MFA endpoints.
//
// `id` and `username` are listed because `applyAllowedFieldsAndSet` strips
// every key not in the whitelist — including the PK that PATCH/PUT uses to
// match the row. Without them, every admin write 400s with "Missing primary
// key field". Library-side, the helper should preserve PK fields by default;
// until then, the consumer MUST list them. (Real bug, see WRITE-01 in
// arbac-write.spec.ts.)
export const WRITEABLE_USER_FIELDS_ADMIN = [
  "id",
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
