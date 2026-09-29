export type {
  TArbacCompiledRule,
  TArbacEvalResult,
  TArbacRole,
  TArbacRoleForResource,
  TArbacRule,
} from "@aooth/arbac-core";
export { Arbac, arbacPatternToRegex } from "@aooth/arbac-core";
export type { ControlGate } from "@aooth/arbac";

export * from "./arbac.composables";
export * from "./arbac.decorator";
export * from "./arbac.mate";
export {
  type AoothArbacClaims,
  conjoinArbacDbScopes,
  type ConjoinArbacDbScopesOptions,
} from "./attenuation";
export * from "./db/as-arbac-db-controller";
export * from "./db/as-arbac-db-readable-controller";
export {
  AsArbacJsonValueHelpController,
  AsArbacValueHelpController,
} from "./db/as-arbac-value-help-controller";
export {
  applyArbacMetaOverlay,
  collectMethodNames,
  pruneMetaByVisibility,
} from "./db/meta-projection";
export {
  buildScopeVisibility,
  collectWithGrantNames,
  collectWritableFields,
  isMetaFieldVisible,
  metaAlwaysVisibleFields,
  unionScopeProjection,
} from "./db/visibility";
export type {
  ArbacRelationResolution,
  MetaVisibility,
  ScopeVisibilityOptions,
  VisibilityTableSource,
} from "./db/visibility";
export { registerArbacDbTarget, resolveHandlerArbacIds } from "./db/relation-policy";
export {
  arbacActionRowScope,
  arbacAllowedActions,
  arbacRowFilter,
  authorizeArbacForm,
  cachedRequestScopes,
  isScopedFieldVisible,
  prepareArbacRequest,
  requestFieldVisible,
  requireRequestScopes,
  resolveRequestScopes,
} from "./db/request-scopes";
export {
  applyArbacControls,
  applyArbacProjection,
  applyArbacRelationScopes,
} from "./db/shared-read-helpers";
export { useArbacDbScope } from "./db/use-arbac-db-scope";
export type {
  ArbacDbScopeHelpers,
  ArbacGuardedTable,
  ArbacScopedTable,
} from "./db/use-arbac-db-scope";
export { checkArbacWrite, guardArbacRemove, guardArbacWrite } from "./db/write-policy";
export type { ArbacWriteTable } from "./db/write-policy";
export type { RefForeignKey, RefTableSource } from "./db/write-refs";
export type {
  ControlsOf,
  NavRelationKey,
  NavTarget,
  OwnFieldKey,
  ProjectionOf,
} from "./db/scope-types";
export * from "./moost-arbac";
export * from "./user.provider";
