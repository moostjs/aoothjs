export * from "@aooth/arbac-core";

export { defineRole } from "./define-role";
export type { RoleBuilder, TPrivilegeFunction } from "./define-role";

export { definePrivilege } from "./define-privilege";

export { allowTableAction, allowTableRead, allowTableWrite } from "./db-privileges";

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
export type { ControlGate, TProjection, TScopeFilter } from "./scope/types";
export type { TProjectionChildren, TProjectionMode } from "./scope/projection";

export { extractResourceActions, generateResourceTypes } from "./codegen";
export type { TCodegenOptions, TResourceActionMap } from "./codegen";
