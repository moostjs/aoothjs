import {
  conjoinScopeFilters,
  intersectControlsPolicy,
  mergeScopeFilters,
  restrictProjection,
  unionControlsPolicy,
  unionProjections,
} from "@aooth/arbac";

import type { ArbacDbScope } from "./db/as-arbac-db-controller";

/**
 * The restrict-only ARBAC attenuation carried by a credential — its assumed
 * role SUBSET and narrowing attribute overrides. Sourced into evaluation via
 * the optional `ArbacUserProvider.getAttenuation()` hook (typically built by
 * walking the credential model's `@arbac.attenuate.*`-annotated typed root
 * fields with {@link extractAttenuation}), it NARROWS (never expands) the
 * principal — see the engine's `evaluate({ attenuate })` for the restrict-only
 * outcome-intersection.
 *
 * - `roles` — assume a SUBSET of the user's roles. `[]` = no roles (deny-all,
 *   fail-closed); an OMITTED key = keep all the user's roles (attrs-only
 *   narrowing); a role the user lacks is dropped by the intersection.
 * - `attrs` — extra/overriding inputs to scope predicates, keyed by the target
 *   user-attribute name, intended to narrow scopes. They are merged LOCALLY
 *   into the credential pass only and clipped by the scope conjunction, so they
 *   can never widen beyond the user.
 */
export interface AoothArbacClaims {
  roles?: string[];
  attrs?: Record<string, unknown>;
}

/**
 * Conjoin the full-authority scopes (`userScopes`, the ceiling) and the
 * credential's narrowed scopes (`credScopes`) into ONE composite
 * `ArbacDbScope`. A row/field/control is admitted only if BOTH passes admit
 * it — the normative restrict-only clip that closes the attr-widen hole.
 *
 * Each side is first UNIONed with the existing additive helpers (today's
 * machinery), then the two RESULTS are CONJOINED with the dedicated combiners
 * ({@link conjoinScopeFilters} `$and`, {@link restrictProjection} field ∩,
 * {@link intersectControlsPolicy} deny-wins, `with` recursion) — never the
 * additive union helpers, which would silently widen.
 *
 * Returned as a single-element list so every downstream scope-application
 * site (which UNIONs the cached scope list per facet) sees the identity of a
 * one-element union — i.e. the conjunction — with no change to those sites.
 */
export function conjoinArbacDbScopes(
  userScopes: ArbacDbScope[],
  credScopes: ArbacDbScope[],
): ArbacDbScope[] {
  const filter = conjoinScopeFilters(
    mergeScopeFilters(userScopes.map((s) => s.filter ?? {})),
    mergeScopeFilters(credScopes.map((s) => s.filter ?? {})),
  );
  const projection = restrictProjection(
    unionProjections(...userScopes.map((s) => s.projection ?? {})),
    unionProjections(...credScopes.map((s) => s.projection ?? {})),
  );
  const controls = intersectControlsPolicy(
    unionControlsPolicy(userScopes),
    unionControlsPolicy(credScopes),
  );
  const allowedFields = intersectAllowedFields(userScopes, credScopes);
  const set = combineSet(userScopes, credScopes);
  const withMap = conjoinWith(userScopes, credScopes);

  const s: ArbacDbScope = {};
  if (filter && Object.keys(filter).length > 0) s.filter = filter;
  if (Object.keys(projection).length > 0) s.projection = projection as ArbacDbScope["projection"];
  if (Object.keys(controls).length > 0) s.controls = controls as ArbacDbScope["controls"];
  if (allowedFields) s.allowedFields = allowedFields as ArbacDbScope["allowedFields"];
  if (set) s.set = set as ArbacDbScope["set"];
  if (withMap) s.with = withMap as ArbacDbScope["with"];
  return [s];
}

/**
 * Intersect the two sides' `allowedFields` write-whitelists (the credential
 * may write FEWER fields). A side with no whitelist is unrestricted (all
 * fields), so the other side wins; both restricting → set intersection.
 */
function intersectAllowedFields(
  userScopes: ArbacDbScope[],
  credScopes: ArbacDbScope[],
): string[] | undefined {
  const u = unionAllowedFields(userScopes);
  const c = unionAllowedFields(credScopes);
  if (u === undefined) return c;
  if (c === undefined) return u;
  const cset = new Set(c);
  return [...new Set(u)].filter((f) => cset.has(f)).toSorted();
}

function unionAllowedFields(scopes: ArbacDbScope[]): string[] | undefined {
  let set: Set<string> | undefined;
  for (const s of scopes) {
    if (Array.isArray(s.allowedFields)) {
      set ??= new Set<string>();
      for (const f of s.allowedFields) set.add(f);
    }
  }
  return set ? [...set] : undefined;
}

/**
 * Combine the two sides' `set` overlays. `set` forces field values on writes;
 * both sides' forced constraints apply, and on a key conflict the USER's value
 * wins so the credential can only ADD constraints, never override the owner's.
 */
function combineSet(
  userScopes: ArbacDbScope[],
  credScopes: ArbacDbScope[],
): Record<string, unknown> | undefined {
  const u = unionSet(userScopes);
  const c = unionSet(credScopes);
  if (!u && !c) return undefined;
  return { ...c, ...u };
}

function unionSet(scopes: ArbacDbScope[]): Record<string, unknown> | undefined {
  let out: Record<string, unknown> | undefined;
  for (const s of scopes) {
    if (s.set) {
      out ??= {};
      Object.assign(out, s.set);
    }
  }
  return out;
}

/**
 * Recurse the conjunction into joined-resource sub-scopes. A relation declared
 * on only one side is conjoined against the other side's silence (unrestricted
 * = identity), so a credential can narrow a relation the user left open but
 * never widen one the user restricted.
 */
function conjoinWith(
  userScopes: ArbacDbScope[],
  credScopes: ArbacDbScope[],
): Record<string, ArbacDbScope> | undefined {
  const relNames = new Set<string>();
  for (const s of userScopes) if (s.with) for (const k of Object.keys(s.with)) relNames.add(k);
  for (const s of credScopes) if (s.with) for (const k of Object.keys(s.with)) relNames.add(k);
  if (relNames.size === 0) return undefined;
  const out: Record<string, ArbacDbScope> = {};
  for (const rel of relNames) {
    const userSub = userScopes
      .map((s) => (s.with as Record<string, ArbacDbScope> | undefined)?.[rel])
      .filter(Boolean) as ArbacDbScope[];
    const credSub = credScopes
      .map((s) => (s.with as Record<string, ArbacDbScope> | undefined)?.[rel])
      .filter(Boolean) as ArbacDbScope[];
    out[rel] = conjoinArbacDbScopes(userSub, credSub)[0];
  }
  return out;
}
