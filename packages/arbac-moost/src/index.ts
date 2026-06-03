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
export { type AoothArbacClaims, arbacClaims, conjoinArbacDbScopes } from "./attenuation";
export * from "./db/as-arbac-db-controller";
export * from "./db/as-arbac-db-readable-controller";
export type {
  ControlsOf,
  NavRelationKey,
  NavTarget,
  OwnFieldKey,
  ProjectionOf,
} from "./db/scope-types";
export * from "./moost-arbac";
export * from "./user.provider";
