export * from "@aoothjs/arbac-core";

export { defineRole } from "./define-role";
export type { RoleBuilder, TPrivilegeFunction } from "./define-role";

export { canAccess, canCrud, definePrivilege } from "./define-privilege";

export {
  getProjectionMode,
  isFieldAllowed,
  restrictProjection,
  unionProjections,
} from "./scope/projection";
export { mergeScopeFilters } from "./scope/filter";
export type { TProjection, TScopeFilter } from "./scope/types";
export type { TProjectionMode } from "./scope/projection";

export { extractResourceActions, generateResourceTypes } from "./codegen";
export type { TCodegenOptions, TResourceActionMap } from "./codegen";
