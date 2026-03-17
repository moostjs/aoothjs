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
   * Evaluates whether a given action on a resource is allowed for a user with specified roles.
   *
   * @param {{
   *   roleIds: string[];
   *   userId: string;
   *   resource: string;
   *   action: string;
   * }} res The options for the evaluation.
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
    },
  ): Promise<TArbacEvalResult<TScope>> {
    this.registerResource(res.resource);
    const roles = user.roles
      .map((r) => {
        const role = this.resources[res.resource]![r];
        if (!role && !this.roles[r] && !this.warnedRoles.has(r)) {
          this.warnedRoles.add(r);
          console.warn(`Role "${r}" assigned to user "${user.id}" does not exist.`);
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
    let userAttrs: TUserAttrs | undefined;
    const scopes: TScope[] = [];
    let allowed = false;
    for (const role of roles) {
      for (const rule of role.allow) {
        if (rule._actionRegex.test(res.action)) {
          allowed = true;
          if (rule.scope) {
            if (!userAttrs) {
              userAttrs = typeof user.attrs === "function" ? await user.attrs(user.id) : user.attrs;
            }
            scopes.push(rule.scope(userAttrs));
          }
        }
      }
    }
    return allowed ? { allowed, scopes } : { allowed };
  }
}
