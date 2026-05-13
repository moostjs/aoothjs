import type { Mate, TMateParamMeta, TMoostMetadata } from "moost";
import { getMoostMate } from "moost";

/**
 * Auth metadata fields written by `@Public()` and read by `authGuardInterceptor`.
 * Merged into `TMoostMetadata` so other moost-aware tooling sees them.
 */
export interface TAuthMeta {
  authPublic?: boolean;
}

declare module "moost" {
  interface TMoostMetadata extends TAuthMeta {}
}

export type AuthMate = Mate<
  TMoostMetadata & { params: TMateParamMeta[] },
  TMoostMetadata & { params: TMateParamMeta[] }
>;

export function getAuthMate(): AuthMate {
  return getMoostMate<TAuthMeta, TAuthMeta>() as AuthMate;
}
