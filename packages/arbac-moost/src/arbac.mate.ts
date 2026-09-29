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

type ArbacMate = Mate<
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
  return getMoostMate<TArbacMeta, TArbacMeta>();
}

/**
 * Marks a controller whose `prepareRequest` authorizes moost-db's delegated
 * handlers (the ones `getDbEndpoint` tags, e.g. `GET meta/actions/:id`) with
 * ARBAC: a method keyed by this symbol answers whether `method` is such a
 * handler. The authorize interceptor then skips its own evaluation for that
 * handler (the route has no grant of its own). `AsArbacDbController` /
 * `AsArbacDbReadableController` carry it; a controller without it keeps the
 * interceptor's normal (fail-closed) evaluation.
 *
 * @since 0.1.72
 */
export const ARBAC_DELEGATED_AUTH: unique symbol = Symbol.for("aooth.arbac.delegatedAuth");

/** A controller carrying {@link ARBAC_DELEGATED_AUTH}. @since 0.1.72 */
export interface ArbacDelegatedAuth {
  [ARBAC_DELEGATED_AUTH](method: string): boolean;
}
