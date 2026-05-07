import type { Mate, TMateParamMeta, TMoostMetadata } from "moost";
import { getMoostMate } from "moost";

/**
 * ARBAC metadata fields attached to classes and methods by ARBAC decorators.
 *
 * Augments the shared `TMoostMetadata` workspace via TypeScript declaration
 * merging so other moost-aware tooling (and `getArbacMate()` readers) sees
 * these fields with full type safety.
 */
export interface TArbacMeta {
  arbacResourceId?: string;
  arbacActionId?: string;
  arbacPublic?: boolean;
}

declare module "moost" {
  interface TMoostMetadata extends TArbacMeta {}
}

export type ArbacMate = Mate<
  TMoostMetadata & { params: TMateParamMeta[] },
  TMoostMetadata & { params: TMateParamMeta[] }
>;

/**
 * Returns the shared `Mate` instance typed with ARBAC metadata fields.
 *
 * All ARBAC decorators write through this typed wrapper so reads and writes
 * stay type-checked against `TArbacMeta`.
 */
export function getArbacMate(): ArbacMate {
  return getMoostMate<TArbacMeta, TArbacMeta>() as ArbacMate;
}
