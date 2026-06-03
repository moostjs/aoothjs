import type { TArbacEvalResult, TArbacRole, TArbacRoleForResource, TArbacRule } from "./types";
import { arbacPatternToRegex } from "./utils";

/**
 * Implements Advanced Role-Based Access Control (ARBAC) system.
 * This class allows registering roles and resources, and evaluating access permissions based on user attributes and roles.
 *
 * @template TUserAttrs The type of user attributes.
 * @template TScope The type of scope that access rules can define.
 */
export class Arbac<TUserAttrs extends object, TScope extends object> {
  protected roles: Record<string, TArbacRole<TUserAttrs, TScope> | undefined> = {};

  protected resources: Record<
    string,
    Record<string, TArbacRoleForResource<TUserAttrs, TScope> | undefined> | undefined
  > = {};

  private warnedRoles = new Set<string>();

  /**
   * Registers a new role with the ARBAC system.
   *
   * @param {TArbacRole<TUserAttrs, TScope>} role The role to register.
   */
  registerRole(role: TArbacRole<TUserAttrs, TScope>): Arbac<TUserAttrs, TScope> {
    this.roles[role.id] = role;
    for (const key of Object.keys(this.resources)) {
      this.evalRoleForResource(role.id, key);
    }
    return this;
  }

  /**
   * Registers a new resource in the ARBAC system. If the resource already exists, this method does nothing.
   *
   * @param {string} resource The resource to register.
   */
  registerResource(resource: string): Arbac<TUserAttrs, TScope> {
    if (!this.resources[resource]) {
      this.resources[resource] = {};
      for (const key of Object.keys(this.roles)) {
        this.evalRoleForResource(key, resource);
      }
    }
    return this;
  }

  /**
   * Evaluates the role for a specific resource, updating the internal state with allow/deny rules.
   *
   * @protected
   * @param {string} roleId The ID of the role to evaluate.
   * @param {string} resourceId The ID of the resource to evaluate against.
   */
  protected evalRoleForResource(roleId: string, resourceId: string): Arbac<TUserAttrs, TScope> {
    const resource = this.resources[resourceId]!;
    const role = this.roles[roleId]!;
    resource[roleId] = {
      id: roleId,
      allow: [],
      deny: [],
    };
    const target = resource[roleId];
    for (const rule of role.rules as Array<
      TArbacRule<TUserAttrs, TScope> & { _resourceRegex?: RegExp; _actionRegex?: RegExp }
    >) {
      let rg = rule._resourceRegex;
      if (!rg) {
        rg = arbacPatternToRegex(rule.resource);
        rule._resourceRegex = rg;
      }
      const effect = rule.effect || "allow";
      if (rg.test(resourceId)) {
        let ag = rule._actionRegex;
        if (!ag) {
          ag = arbacPatternToRegex(rule.action);
          rule._actionRegex = ag;
        }
        target[effect].push({
          action: rule.action,
          _actionRegex: ag,
          scope: rule.scope,
        });
      }
    }
    return this;
  }

  /**
   * Evaluates whether a given action on a resource is allowed for a user with
   * the specified roles, returning the allow decision plus any applicable scopes.
   *
   * When `user.attenuate` is supplied (the credential-claims bridge) the policy
   * is evaluated TWICE and the OUTCOMES are intersected — see the `attenuate`
   * field for the restrict-only safety guarantee.
   *
   * @returns {Promise<TArbacEvalResult<TScope>>} The result of the evaluation, including whether the action is allowed and any applicable scopes.
   */
  async evaluate<T extends string | undefined>(
    res: {
      resource: string;
      action: string;
    },
    user: {
      id: T;
      roles: string[];
      attrs: TUserAttrs | ((userId: T) => TUserAttrs | Promise<TUserAttrs>);
      /**
       * Opt-in, restrict-only attenuation sourced from the authenticated
       * credential's claims. When present the policy runs twice — at full
       * authority (the ceiling) and at the credential's narrowed view — and
       * the outcomes are intersected: `allowed` is ANDed (so dropping a role
       * can never drop a matching `deny` and thus can never escalate a denied
       * action), and the two passes' scope lists are surfaced separately as
       * `scopes` (ceiling) and `credScopes` (narrowed) for the scope layer to
       * conjoin. A credential can therefore only ever do/see/affect LESS than
       * its owning user — escalation-proof even against an untrusted minter.
       *
       * `roles: []` → no roles (deny-all, fail-closed). An OMITTED `roles` key
       * → keep all the user's roles (attrs-only narrowing). A claimed role the
       * user lacks is dropped by the intersection (fail-closed). Absent
       * `attenuate` → a single evaluation, byte-for-byte today's behavior.
       */
      attenuate?: { roles?: string[]; attrs?: Partial<TUserAttrs> };
    },
  ): Promise<TArbacEvalResult<TScope>> {
    this.registerResource(res.resource);

    // Resolve attrs at most once, lazily — shared by both passes and every
    // scope predicate, so an attenuated eval never double-fetches.
    let resolvedAttrs: TUserAttrs | undefined;
    const userAttrs = async (): Promise<TUserAttrs> => {
      if (resolvedAttrs === undefined) {
        resolvedAttrs = typeof user.attrs === "function" ? await user.attrs(user.id) : user.attrs;
      }
      return resolvedAttrs;
    };

    const userEval = await this.evaluateForRoles(res, user.roles, userAttrs, user.id);
    if (!user.attenuate) return userEval;

    // Credential (narrowed) pass: a SUBSET of the user's roles (an OMITTED
    // `roles` key keeps them all; a claimed role the user lacks is absent —
    // fail-closed), with the narrowing attrs merged LOCALLY so they cannot
    // leak into the ceiling pass.
    const claimRoles = user.attenuate.roles;
    const claimAttrs = user.attenuate.attrs;
    const credRoles = claimRoles ? user.roles.filter((r) => claimRoles.includes(r)) : user.roles;
    const credAttrs: () => Promise<TUserAttrs> = claimAttrs
      ? async () => ({ ...(await userAttrs()), ...claimAttrs })
      : userAttrs;
    const credEval = await this.evaluateForRoles(res, credRoles, credAttrs, user.id);

    // Outcome intersection. The scope conjunction is the scope layer's job
    // (the engine is scope-agnostic), so surface both passes' scopes.
    if (!userEval.allowed || !credEval.allowed) return { allowed: false };
    return { allowed: true, scopes: userEval.scopes, credScopes: credEval.scopes };
  }

  /**
   * One evaluation pass over a concrete role-id set + attrs resolver. Carries
   * the deny-wins / allow-union / `{}` universe-sentinel semantics; `evaluate`
   * runs it once (no attenuation) or twice (ceiling + narrowed credential view).
   */
  protected async evaluateForRoles(
    res: { resource: string; action: string },
    roleIds: string[],
    getAttrs: () => Promise<TUserAttrs>,
    id: string | undefined,
  ): Promise<TArbacEvalResult<TScope>> {
    const roles = roleIds
      .map((r) => {
        const role = this.resources[res.resource]![r];
        if (!role && !this.roles[r] && !this.warnedRoles.has(r)) {
          this.warnedRoles.add(r);
          console.warn(`Role "${r}" assigned to user "${id}" does not exist.`);
        }
        return role;
      })
      .filter(Boolean) as Array<TArbacRoleForResource<TUserAttrs, TScope>>;
    if (roles.length === 0) {
      return { allowed: false };
    }
    for (const role of roles) {
      for (const rule of role.deny) {
        if (rule._actionRegex.test(res.action)) {
          return { allowed: false };
        }
      }
    }
    const scopes: TScope[] = [];
    let allowed = false;
    for (const role of roles) {
      for (const rule of role.allow) {
        if (rule._actionRegex.test(res.action)) {
          allowed = true;
          if (rule.scope) {
            scopes.push(rule.scope(await getAttrs(), String(id)));
          } else {
            // Universe sentinel — preserves "no restriction" grant under multi-role union.
            scopes.push({} as TScope);
          }
        }
      }
    }
    return allowed ? { allowed, scopes } : { allowed };
  }
}
