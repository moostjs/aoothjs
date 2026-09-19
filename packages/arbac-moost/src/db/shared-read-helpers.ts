import {
  conjoinScopeFilters,
  mergeScopeFilters,
  restrictProjection,
  unionControlsPolicy,
} from "@aooth/arbac";
import type { TProjection } from "@aooth/arbac";

import { useArbac } from "../arbac.composables";
import { enforceControlsPolicy } from "./as-arbac-db-controller";
import type { ArbacDbScope } from "./as-arbac-db-controller";
import { unionScopeProjection } from "./meta-projection";

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
 * Combining is delegated to `conjoinScopeFilters`, which owns the
 * `$and`-never-spread invariant (a user filter constraining the same field as
 * the scope would otherwise replace it and widen access) and treats an empty
 * side as the identity. Returns a match-nothing filter on denial so the
 * downstream pipeline returns an empty result set without leaking rows.
 */
export async function transformArbacFilter(
  filter: Record<string, unknown> | undefined,
): Promise<Record<string, unknown>> {
  const arbac = useArbac();
  const { allowed, scopes } = await arbac.evaluate<ArbacDbScope>();
  if (!allowed) return DENY_FILTER;
  arbac.setScopes(scopes);
  const merged = mergeScopeFilters((scopes ?? []).map((s) => s.filter ?? {}));
  return conjoinScopeFilters(merged, filter) ?? {};
}

/**
 * Union the per-scope `projection` whitelists and restrict the user-supplied
 * projection to that union. Returns the original projection untouched when
 * no scope declares a projection (so caller sees the unrestricted shape).
 * Uses the same `unionScopeProjection` the field-visibility seams (`hasField`
 * / `/meta` pruning) use, so value stripping and name hiding cannot drift.
 */
export function applyArbacProjection(
  projection: TProjection | undefined,
  scopes: ArbacDbScope[],
): TProjection | undefined {
  const allowed = unionScopeProjection(scopes);
  if (!allowed) return projection;
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

    // Filter overlay — same combiner as transformArbacFilter, so the two sites
    // cannot drift on the `$and`-never-spread invariant.
    const subFilter = mergeScopeFilters(subScopes.map((s) => s.filter ?? {}));
    const conjoined = conjoinScopeFilters(subFilter, entry.filter);
    if (conjoined) entry.filter = conjoined;

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
