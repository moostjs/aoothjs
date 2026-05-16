import {
  mergeScopeFilters,
  restrictProjection,
  unionControlsPolicy,
  unionProjections,
} from "@aoothjs/arbac";
import type { TProjection } from "@aoothjs/arbac";

import { useArbac } from "../arbac.composables";
import { enforceControlsPolicy } from "./as-arbac-db-controller";
import type { ArbacDbScope } from "./as-arbac-db-controller";

/** Filter that matches no rows; used when ARBAC denies the request. */
const DENY_FILTER: Record<string, unknown> = { $or: [] };

/** Single point of access to the per-event scope cache. */
export function readCachedScopes(): ArbacDbScope[] {
  return useArbac().getScopes<ArbacDbScope>() ?? [];
}

/**
 * Full body of `transformFilter` for both ARBAC DB controllers: evaluate
 * ARBAC once, cache the scopes for the per-event hooks that follow
 * (`transformProjection`, `validateControls`), and merge the user filter
 * with the union of scope filters.
 *
 * Wraps the merge with `$and` (not object spread) so a top-level
 * `$or`/`$and`/`$not` in `filter` cannot drop the scope's sibling field
 * keys when @uniqu/core's `walkFilter` short-circuits on logical
 * operators (see BUG-2). Returns a match-nothing filter on denial so the
 * downstream pipeline returns an empty result set without leaking rows.
 */
export async function transformArbacFilter(
  filter: Record<string, unknown> | undefined,
): Promise<Record<string, unknown>> {
  const arbac = useArbac();
  const { allowed, scopes } = await arbac.evaluate<ArbacDbScope>();
  if (!allowed) return DENY_FILTER;
  arbac.setScopes(scopes);
  const scopeList = scopes ?? [];
  const merged =
    scopeList.length > 0 ? mergeScopeFilters(scopeList.map((s) => s.filter ?? {})) : undefined;
  const userFilter = filter && Object.keys(filter).length > 0 ? filter : undefined;
  if (!merged) return userFilter ?? {};
  if (!userFilter) return merged as Record<string, unknown>;
  return { $and: [merged, userFilter] };
}

/**
 * Union the per-scope `projection` whitelists and restrict the user-supplied
 * projection to that union. Returns the original projection untouched when
 * no scope declares a projection (so caller sees the unrestricted shape).
 */
export function applyArbacProjection(
  projection: TProjection | undefined,
  scopes: ArbacDbScope[],
): TProjection | undefined {
  if (scopes.length === 0) return projection;
  const allowed = unionProjections(...scopes.map((s) => s.projection ?? {}));
  if (Object.keys(allowed).length === 0) return projection;
  return restrictProjection(projection ?? {}, allowed);
}

/**
 * Enforce the union of per-scope `controls` gates against the parsed
 * Uniquery controls. Throws `HttpError(403)` on the first violation.
 */
export function applyArbacControls(
  controls: Record<string, unknown>,
  scopes: ArbacDbScope[],
): void {
  if (scopes.length === 0) return;
  enforceControlsPolicy(unionControlsPolicy(scopes), controls);
}
