import {
  mergeScopeFilters,
  restrictProjection,
  unionControlsPolicy,
  unionProjections,
} from "@aooth/arbac";
import type { TProjection } from "@aooth/arbac";

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

/** A `$with` entry as parsed by uniquery: `{ name, filter?, controls? }`. */
interface WithEntry {
  name: string;
  filter?: Record<string, unknown>;
  controls?: Record<string, unknown>;
}

/**
 * Walk the user-supplied `$with` items in `controls` and inject per-relation
 * filter/projection/controls/nested-$with from the role scopes' `with` field.
 *
 * Mutates `controls` in place (matches the `validateControls` contract).
 * Throws `HttpError(403)` if a per-relation control policy is violated
 * (delegates to `enforceControlsPolicy` like top-level `applyArbacControls`).
 *
 * Silence wins: if no role declares `with.<name>` for a relation, that entry
 * passes through unchanged. The outermost check skips the entire walk when no
 * scope declares `with` at all — this is the common case on every read.
 */
export function applyArbacRelationScopes(
  controls: Record<string, unknown>,
  scopes: ArbacDbScope[],
): void {
  if (scopes.length === 0) return;
  const withArr = controls.$with;
  if (!Array.isArray(withArr) || withArr.length === 0) return;
  // Hot-path bail: most reads have no `with`-declaring scope; skip per-entry work.
  if (!scopes.some((s) => s.with)) return;

  for (const raw of withArr) {
    if (!raw || typeof raw !== "object") continue;
    const entry = raw as WithEntry;
    if (typeof entry.name !== "string") continue;

    const subScopes = collectSubScopes(scopes, entry.name);
    if (subScopes.length === 0) continue; // silence wins

    // Filter overlay — same `$and` wrap as transformArbacFilter (BUG-2).
    const subFilter = mergeScopeFilters(subScopes.map((s) => s.filter ?? {}));
    if (subFilter) {
      const userFilter =
        entry.filter && Object.keys(entry.filter).length > 0 ? entry.filter : undefined;
      entry.filter = userFilter ? { $and: [subFilter, userFilter] } : subFilter;
    }

    const entryControls = entry.controls ?? {};
    const restricted = applyArbacProjection(normalizeSelect(entryControls.$select), subScopes);
    if (restricted !== undefined) {
      entryControls.$select = restricted;
      entry.controls = entryControls;
    }

    // Enforce per-relation control gates (e.g. `with.X.controls.$with: false`)
    // then recurse — sub-scopes' own `with` trees gate the next level.
    enforceControlsPolicy(unionControlsPolicy(subScopes), entryControls);
    applyArbacRelationScopes(entryControls, subScopes);
  }
}

/** Pick `scopes[i].with?.[name]`, dropping undefined. */
function collectSubScopes(scopes: ArbacDbScope[], name: string): ArbacDbScope[] {
  const out: ArbacDbScope[] = [];
  for (const s of scopes) {
    const sub = s.with?.[name];
    if (sub) out.push(sub);
  }
  return out;
}

/**
 * `$select` may be an array of field names (uniquery inclusion list) or a
 * `TProjection` object. `applyArbacProjection` / `restrictProjection` operate
 * on the object form, so normalize the array to `{ field: 1 }` first. Returns
 * undefined if the input is empty (caller treats as "no projection set").
 */
function normalizeSelect(value: unknown): TProjection | undefined {
  if (value === undefined || value === null) return undefined;
  if (Array.isArray(value)) {
    const out: TProjection = {};
    for (const item of value) {
      if (typeof item === "string") out[item] = 1;
    }
    return Object.keys(out).length > 0 ? out : undefined;
  }
  if (typeof value === "object") return value as TProjection;
  return undefined;
}
