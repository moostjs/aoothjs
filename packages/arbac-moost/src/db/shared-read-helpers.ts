import {
  conjoinScopeFilters,
  effectiveScope,
  expandExcludeToLeaves,
  restrictProjection,
} from "@aooth/arbac";
import type { TProjection } from "@aooth/arbac";

import { enforceControlsPolicy } from "./as-arbac-db-controller";
import type { ArbacDbScope } from "./as-arbac-db-controller";
import { fieldChildrenOf } from "./field-children";
import { visibilityFor } from "./request-scopes";
import { isMetaFieldVisible } from "./visibility";
import type { MetaVisibility, VisibilityTableSource } from "./visibility";

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
 *
 * @since 0.1.72
 */
export function applyArbacProjection(
  projection: unknown,
  scopes: ArbacDbScope[],
  readable?: VisibilityTableSource,
): TProjection | undefined {
  return restrictSelect(projection, visibilityFor(scopes, readable));
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
 *
 * @since 0.1.72
 */
export function applyArbacControls(
  controls: Record<string, unknown>,
  scopes: ArbacDbScope[],
): void {
  enforceControlsPolicy(effectiveScope(scopes).controls, controls);
}

/** A `$with` entry as parsed by uniquery: `{ name, filter?, controls? }`. */
interface WithEntry {
  name: string;
  filter?: Record<string, unknown>;
  controls?: Record<string, unknown>;
}

/**
 * Walk the user-supplied `$with` items in `controls` and overlay each joined
 * relation with the policy of its rows (the `$with` inherit-target policy):
 * a relation some scope declares `with.<name>` for gets the union of those
 * sub-scopes (parent authority — silent roles contribute nothing); any other
 * gets the caller's OWN read scopes on the related table, as resolved in
 * `prepareRequest` (for the request's own scopes). Filter conjoined, `$select`
 * restricted, per-relation `controls` gates enforced, recursively.
 *
 * Mutates `controls` in place (matches the `validateControls` contract).
 * Throws `HttpError(403)` if a per-relation control policy is violated. A
 * hidden relation is skipped: moost-db (≥ 0.1.143) rejects it at every
 * level through `hasField`, byte-for-byte like a nonexistent one.
 *
 * @since 0.1.72
 */
export function applyArbacRelationScopes(
  controls: Record<string, unknown>,
  scopes: ArbacDbScope[],
  readable?: VisibilityTableSource,
): void {
  const withArr = controls.$with;
  if (!Array.isArray(withArr) || withArr.length === 0) return;
  applyRelationLevel(controls, visibilityFor(scopes, readable));
}

/** One `$with` level of {@link applyArbacRelationScopes}. */
function applyRelationLevel(controls: Record<string, unknown>, vis: MetaVisibility): void {
  const withArr = controls.$with;
  if (!Array.isArray(withArr) || withArr.length === 0) return;

  for (const raw of withArr) {
    if (!raw || typeof raw !== "object") continue;
    const entry = raw as WithEntry;
    // A dotted name is not loaded by the core — nothing to overlay.
    if (typeof entry.name !== "string" || entry.name.includes(".")) continue;
    // A hidden or nonexistent relation is left to moost-db, which answers
    // `Unknown relation` through `hasField` — identical for both.
    const known =
      (!vis.relationNames || vis.relationNames.has(entry.name)) &&
      isMetaFieldVisible(entry.name, vis);
    const level = known ? vis.relation?.(entry.name) : undefined;
    if (!level) continue;

    const sub = effectiveScope(level.scopes ?? []);
    // Filter overlay — same combiner as the row filter, so the two sites
    // cannot drift on the `$and`-never-spread invariant.
    const conjoined = conjoinScopeFilters(sub.filter, entry.filter);
    if (conjoined) entry.filter = conjoined;

    const entryControls = entry.controls ?? {};
    const restricted = restrictSelect(entryControls.$select, level);
    if (restricted !== undefined) {
      entryControls.$select = restricted;
      entry.controls = entryControls;
    }

    // Per-relation control gates (e.g. `with.X.controls.$with: false`), then
    // the next level.
    enforceControlsPolicy(sub.controls, entryControls);
    applyRelationLevel(entryControls, level);
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
