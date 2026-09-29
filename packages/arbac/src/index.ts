export * from "@aooth/arbac-core";

export { defineRole } from "./define-role";
export type { RoleBuilder, TPrivilegeFunction } from "./define-role";

export { definePrivilege } from "./define-privilege";

export {
  allowTableAction,
  allowTableOps,
  allowTableRead,
  allowTableWrite,
  defineTableAccess,
  TABLE_META_ACTIONS,
  TABLE_OP_ACTIONS,
  TABLE_READ_ACTIONS,
  TABLE_WRITE_ACTIONS,
} from "./db-privileges";
export type { TTableAccessDef, TTableAccessScope, TTableOp, TTableWriteOp } from "./db-privileges";

export {
  expandExcludeToLeaves,
  getProjectionMode,
  intersectProjections,
  isFieldAllowed,
  restrictProjection,
  unionProjections,
} from "./scope/projection";
export { conjoinScopeFilters, DENY_FILTER, mergeScopeFilters } from "./scope/filter";
export { intersectControlsPolicy, unionControlsPolicy } from "./scope/controls";
export {
  applyScopeFieldFilters,
  conjoinRowPolicies,
  conjoinScopes,
  DB_SCOPE_KEYS,
  effectiveScope,
  INHERITED_CONJUNCTION,
  intersectEnabled,
  needsInheritedConjunction,
  normalizeScopes,
  ScopeFieldConfigError,
  stableKey,
  unionOutcomes,
} from "./scope/db-scope";
export type {
  TConjoinScopesOptions,
  TDbScope,
  TEffectiveDbScope,
  TRowPolicy,
  TApplyScopeFieldFiltersOptions,
  TScopeFieldRule,
  TScopeFieldRules,
} from "./scope/db-scope";
export type { ControlGate, TProjection, TScopeFilter } from "./scope/types";
export type { TProjectionChildren, TProjectionMode } from "./scope/projection";

export { extractResourceActions, generateResourceTypes } from "./codegen";
export type { TCodegenOptions, TResourceActionMap } from "./codegen";
