import { conjoinScopes } from "@aooth/arbac";
import type { TProjectionChildren, TScopeFieldRules } from "@aooth/arbac";

import type { ArbacDbScope } from "./db/as-arbac-db-controller";
import { conjoinCheckRefs } from "./db/write-refs";
import type { RefTableSource } from "./db/write-refs";

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
 *   narrowing); a role the user lacks is dropped by the intersection (unless
 *   `allowUnheldRoles`).
 * - `attrs` — extra/overriding inputs to scope predicates, keyed by the target
 *   user-attribute name, intended to narrow scopes. They are merged LOCALLY
 *   into the credential pass only and clipped by the scope conjunction, so they
 *   can never widen beyond the user.
 * - `allowUnheldRoles` — "view as": evaluate the claimed `roles` as given,
 *   including roles the user does not hold (unknown role ids still grant
 *   nothing). The result is still conjoined with the user's full authority,
 *   so it never widens beyond the user — it previews the claimed roles'
 *   surface CLIPPED to the user's own. Opt-in: the app decides who may issue
 *   such a credential (e.g. gate it behind a privilege). Since 0.1.72.
 */
export interface AoothArbacClaims {
  roles?: string[];
  attrs?: Record<string, unknown>;
  allowUnheldRoles?: boolean;
}

/**
 * Conjoin the full-authority scopes (`userScopes`, the ceiling) and the
 * credential's narrowed scopes (`credScopes`) into ONE composite
 * `ArbacDbScope`. A row/field/control is admitted only if BOTH passes admit
 * it — the normative restrict-only clip that closes the attr-widen hole.
 *
 * Each side is first UNIONed, then the two results are CONJOINED facet by
 * facet with `conjoinScopes` from `@aooth/arbac` (`$and` filters and WITH
 * CHECK filters, path-wise projection ∩, deny-wins controls, `allowedFields`
 * / `nestedWrites` intersection, `set` combined with the USER winning a key
 * conflict, recursive `with`) — never the additive union helpers, which
 * would silently widen.
 *
 * Returned as a single-element list so every downstream scope-application
 * site (which UNIONs the cached scope list per facet) sees the identity of a
 * one-element union — i.e. the conjunction — with no change to those sites.
 *
 * The projection conjunction is path-wise and never wider than either side
 * (`{a:1}` ∩ `{"a.b":1}` → `{"a.b":1}`). A nested exclusion under an
 * included parent (`{a:1}` ∩ `{"a.c":0}`) is subtracted exactly via
 * `childrenOf` (the table schema); without it the parent is dropped (fail
 * closed). When NO field survives (`{a:1}` ∩ `{a:0}`, disjoint whitelists),
 * the composite keeps the user's projection and gets a match-nothing filter —
 * an empty field set must never read as the unrestricted `{}`. `with`
 * sub-scopes are conjoined without a schema. `checkRefs` enforces what either
 * side enforces (resolved against `refTable`'s foreign keys when given — the
 * evaluated table). A custom (declaration-merged) scope field is conjoined by
 * its `fields` rule; without one this THROWS — never dropped (fail closed).
 *
 * The third argument is the options object, or (legacy form) `childrenOf`.
 */
export function conjoinArbacDbScopes(
  userScopes: ArbacDbScope[],
  credScopes: ArbacDbScope[],
  opts?: TProjectionChildren | ConjoinArbacDbScopesOptions,
): ArbacDbScope[] {
  const { childrenOf, refTable, fields } =
    typeof opts === "function" ? { childrenOf: opts } : (opts ?? {});
  return [
    conjoinScopes(userScopes, credScopes, {
      childrenOf,
      checkRefs: refTable?.foreignKeys ? (u, c) => conjoinCheckRefs(u, c, refTable) : undefined,
      fields,
    }),
  ];
}

/** Options of {@link conjoinArbacDbScopes}. @since 0.1.72 */
export interface ConjoinArbacDbScopesOptions {
  /** The evaluated table's schema lookup — subtracts a nested exclusion exactly. */
  childrenOf?: TProjectionChildren;
  /** The evaluated table — resolves `checkRefs` names to its foreign keys. */
  refTable?: RefTableSource;
  /**
   * Custom scope field rules (`MoostArbac.registerScopeFields`); a custom
   * field without one throws.
   */
  fields?: TScopeFieldRules<ArbacDbScope>;
}
