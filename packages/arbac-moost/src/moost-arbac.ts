import { applyScopeFieldFilters, DB_SCOPE_KEYS } from "@aooth/arbac";
import type { TDbScope, TScopeFieldRule, TScopeFieldRules } from "@aooth/arbac";
import type { TArbacEvalResult } from "@aooth/arbac-core";
import { Arbac } from "@aooth/arbac-core";
import { Injectable } from "moost";

/**
 * A DI-enabled extension of the `Arbac` class for use within Moost.
 *
 * Allows ARBAC (Advanced Role-Based Access Control) to be injected into
 * Moost services and controllers via the framework's dependency-injection
 * container. Defaults to the SINGLETON scope so all handlers share one
 * registry of roles/resources.
 *
 * @template TUserAttrs - The type representing user attributes relevant to access control.
 * @template TScope - The type representing access control scopes.
 */
@Injectable()
export class MoostArbac<TUserAttrs extends object, TScope extends object> extends Arbac<
  TUserAttrs,
  TScope
> {
  private scopeFieldRules: Record<string, TScopeFieldRule<TScope>> = {};

  /**
   * Register the conjunction rule of custom (declaration-merged) scope
   * fields — used wherever two scope lists are conjoined into one composite
   * scope (credential attenuation, and the `with` sub-scopes it builds). A
   * custom field present in a conjunction without a rule fails the request
   * with a generic 500 (never dropped: a dropped field would read as
   * unrestricted). A rule's optional `rowFilter` turns the field into a ROW
   * restriction every framework row path enforces (folded into each
   * evaluated scope's `filter`). Each field is registered once; a built-in
   * `ArbacDbScope` key is rejected.
   *
   * @example
   * ```ts
   * arbac.registerScopeFields({
   *   teams: {
   *     conjoin: (user, cred) => intersectTeams(user, cred),
   *     rowFilter: (teams) => ({ teamId: { $in: teams } }),
   *   },
   * });
   * ```
   * @since 0.1.72
   */
  registerScopeFields(rules: TScopeFieldRules<TScope>): this {
    // Validate every rule first, then assign once (atomic).
    const entries = Object.entries(rules);
    for (const [name, rule] of entries) {
      if (DB_SCOPE_KEYS.includes(name)) {
        throw new Error(`registerScopeFields: "${name}" is a built-in scope key`);
      }
      if (typeof rule?.conjoin !== "function") {
        throw new TypeError(`registerScopeFields: "${name}" needs a conjoin(a, b) function`);
      }
      if (rule.rowFilter !== undefined && typeof rule.rowFilter !== "function") {
        throw new TypeError(`registerScopeFields: "${name}".rowFilter must be a function`);
      }
      const existing = this.scopeFieldRules[name];
      if (existing && existing !== rule) {
        throw new Error(`registerScopeFields: scope field "${name}" is already registered`);
      }
    }
    // A fresh object per change: the fold / conjunction memos key on it.
    this.scopeFieldRules = { ...this.scopeFieldRules, ...Object.fromEntries(entries) };
    return this;
  }

  /**
   * The engine's evaluation with every custom field's `rowFilter` folded
   * into each evaluated scope's `filter` (both passes of an attenuated
   * evaluation, each with its own scopes) — so every consumer, direct
   * engine calls included, sees the row restriction. A non-built-in scope
   * key without a registered rule is warned about once.
   */
  override async evaluate<T extends string | undefined>(
    res: { resource: string; action: string },
    user: {
      id: T;
      roles: string[];
      attrs: TUserAttrs | ((userId: T) => TUserAttrs | Promise<TUserAttrs>);
      attenuate?: { roles?: string[]; attrs?: Partial<TUserAttrs>; allowUnheldRoles?: boolean };
    },
  ): Promise<TArbacEvalResult<TScope>> {
    const result = await super.evaluate(res, user);
    const fold = (list: TScope[] | undefined): TScope[] | undefined =>
      list &&
      (applyScopeFieldFilters(list as unknown as TDbScope[], this.scopeFieldRules as never, {
        onUnknownField: this.warnUnknownField,
      }) as unknown as TScope[]);
    const scopes = fold(result.scopes);
    const credScopes = fold(result.credScopes);
    if (scopes === result.scopes && credScopes === result.credScopes) return result;
    const out: TArbacEvalResult<TScope> = { ...result, scopes };
    if (credScopes !== undefined) out.credScopes = credScopes;
    return out;
  }

  private readonly warnedFields = new Set<string>();

  private readonly warnUnknownField = (field: string): void => {
    if (this.warnedFields.has(field)) return;
    this.warnedFields.add(field);
    console.warn(
      `[arbac] Scope field "${field}" has no rule registered with registerScopeFields: ` +
        "it reaches only your own code, and an attenuated request carrying it fails with 500.",
    );
  };

  /** The registered custom scope field rules. @since 0.1.72 */
  getScopeFields(): TScopeFieldRules<TScope> {
    return this.scopeFieldRules;
  }
}
