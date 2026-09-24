import {
  conjoinScopeFilters,
  DENY_FILTER,
  expandExcludeToLeaves,
  mergeScopeFilters,
  restrictProjection,
  unionControlsPolicy,
} from "@aooth/arbac";
import type { TProjection } from "@aooth/arbac";

import { getArbacScopes, useArbac } from "../arbac.composables";
import { enforceControlsPolicy } from "./as-arbac-db-controller";
import type { ArbacDbScope } from "./as-arbac-db-controller";
import { fieldChildrenOf } from "./field-children";
import { scopeVisibility } from "./meta-projection";
import type { MetaVisibility, VisibilityTableSource } from "./meta-projection";

/**
 * Single point of access to the per-event scope cache. Reads the slot
 * directly — `hasField` calls this per referenced path, and `useArbac()`
 * would resolve controller metadata on every call.
 */
export function readCachedScopes(): ArbacDbScope[] {
  return getArbacScopes<ArbacDbScope>() ?? [];
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
 * Restrict the user-supplied `$select` to the scopes' projection union.
 * Returns the original projection untouched when no scope declares a
 * projection (so caller sees the unrestricted shape). Reads the same cached
 * visibility (`vis.allowed`) `hasField` / `/meta` pruning use, so value
 * stripping and name hiding cannot drift.
 *
 * `projection` is the `$select` as moost-db parsed it: an inclusion is an
 * ARRAY of names, an exclusion an object — both are normalized first. A
 * requested parent (`$select=a`) narrows to what the scope shows: to the
 * whitelisted descendants (`a.b: 1`), or — for a hidden descendant
 * (`a.c: 0`) — to its visible children via `childrenOf` (without a schema
 * the parent is dropped). Never the whole object, and never the empty
 * (universe) projection: when nothing survives, the scope's own projection
 * applies (`restrictProjection`'s ceiling fallback).
 *
 * An exclusion result names nested-object parents by their leaves
 * (`{ a: 0 }` → `{ "a.b": 0, "a.c": 0 }`): flattening adapters invert an
 * exclusion against their leaf columns, so a parent key alone would strip
 * nothing (a scope `{ a: 0 }` would otherwise return all of `a`).
 */
export function applyArbacProjection(
  projection: unknown,
  scopes: ArbacDbScope[],
  readable?: VisibilityTableSource,
): TProjection | undefined {
  return restrictSelect(projection, scopeVisibility(scopes, readable));
}

/** {@link applyArbacProjection} over an already-built visibility level. */
function restrictSelect(projection: unknown, vis: MetaVisibility): TProjection | undefined {
  if (Object.keys(vis.allowed).length === 0) return projection as TProjection | undefined;
  const childrenOf = fieldChildrenOf(vis.table);
  const result = restrictProjection(normalizeSelect(projection) ?? {}, vis.allowed, childrenOf);
  return expandExcludeToLeaves(result, childrenOf);
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
  readable?: VisibilityTableSource,
): void {
  if (scopes.length === 0) return;
  // Hot-path bail: most reads have no `with`-declaring scope; skip per-entry work.
  if (!scopes.some((s) => s.with)) return;
  applyRelationLevel(controls, scopeVisibility(scopes, readable));
}

/**
 * One `$with` level of {@link applyArbacRelationScopes}: each granted
 * relation's child visibility already carries its sub-scopes and target table.
 */
function applyRelationLevel(controls: Record<string, unknown>, vis: MetaVisibility): void {
  const withArr = controls.$with;
  if (!Array.isArray(withArr) || withArr.length === 0) return;

  for (const raw of withArr) {
    if (!raw || typeof raw !== "object") continue;
    const entry = raw as WithEntry;
    if (typeof entry.name !== "string") continue;

    const child = vis.relation?.(entry.name);
    const subScopes = child?.scopes ?? [];
    if (!child || subScopes.length === 0) continue; // silence wins

    // Filter overlay — same combiner as transformArbacFilter, so the two sites
    // cannot drift on the `$and`-never-spread invariant.
    const subFilter = mergeScopeFilters(subScopes.map((s) => s.filter ?? {}));
    const conjoined = conjoinScopeFilters(subFilter, entry.filter);
    if (conjoined) entry.filter = conjoined;

    const entryControls = entry.controls ?? {};
    const restricted = restrictSelect(entryControls.$select, child);
    if (restricted !== undefined) {
      entryControls.$select = restricted;
      entry.controls = entryControls;
    }

    // Enforce per-relation control gates (e.g. `with.X.controls.$with: false`)
    // then recurse — sub-scopes' own `with` trees gate the next level.
    enforceControlsPolicy(unionControlsPolicy(subScopes), entryControls);
    if (subScopes.some((s) => s.with)) applyRelationLevel(entryControls, child);
  }
}

/**
 * `$select` may be an array of field names (uniquery inclusion list) or a
 * `TProjection` object. `restrictProjection` operates on the object form
 * (it would read `["a"]` as an exclusion keyed `"0"`), so normalize the array
 * to `{ field: 1 }` first. Returns undefined if the input is empty (caller
 * treats as "no projection set").
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
