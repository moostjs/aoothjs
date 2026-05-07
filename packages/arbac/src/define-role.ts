import type { TArbacRole, TArbacRule } from "@aoothjs/arbac-core";

/**
 * A privilege function produces an array of rules when called.
 * Created by `definePrivilege()`, `canAccess()`, `canCrud()`, or manually.
 */
export type TPrivilegeFunction<TUserAttrs, TScope> = () => TArbacRule<TUserAttrs, TScope>[];

/**
 * Fluent builder produced by {@link defineRole}.
 *
 * All methods return `this` so they can be chained. Rules are emitted in the order
 * the corresponding `.allow()`, `.deny()`, and `.use()` calls were made — this matters
 * for engines that respect rule order (deny-first / first-match-wins variants).
 */
export interface RoleBuilder<TUserAttrs, TScope> {
  /**
   * Set the role id (required). Calling `.id()` more than once overwrites the
   * previous value — the last call wins.
   */
  id(id: string): RoleBuilder<TUserAttrs, TScope>;
  /** Set the human-readable role name. Optional. */
  name(name: string): RoleBuilder<TUserAttrs, TScope>;
  /** Set the role description. Optional. */
  describe(description: string): RoleBuilder<TUserAttrs, TScope>;
  /**
   * Append an allow rule for a (resource, action) pair, with an optional scope
   * function that derives a scope object from user attrs.
   */
  allow(
    resource: string,
    action: string,
    scope?: (attrs: TUserAttrs) => TScope,
  ): RoleBuilder<TUserAttrs, TScope>;
  /** Append a deny rule (`effect: 'deny'`) for a (resource, action) pair. */
  deny(resource: string, action: string): RoleBuilder<TUserAttrs, TScope>;
  /**
   * Splice in rules from one or more privilege functions (see
   * {@link definePrivilege}, {@link canAccess}, {@link canCrud}). Privileges
   * are expanded inline in call order.
   */
  use(...privileges: TPrivilegeFunction<TUserAttrs, TScope>[]): RoleBuilder<TUserAttrs, TScope>;
  /**
   * Finalize and return a plain {@link TArbacRole} object suitable for
   * `Arbac.registerRole`. Throws if `.id()` was never called.
   */
  build(): TArbacRole<TUserAttrs, TScope>;
}

class RoleBuilderImpl<TUserAttrs, TScope> implements RoleBuilder<TUserAttrs, TScope> {
  private _id: string | undefined;
  private _name: string | undefined;
  private _description: string | undefined;
  private _rules: TArbacRule<TUserAttrs, TScope>[] = [];

  id(id: string): this {
    this._id = id;
    return this;
  }

  name(name: string): this {
    this._name = name;
    return this;
  }

  describe(description: string): this {
    this._description = description;
    return this;
  }

  allow(resource: string, action: string, scope?: (attrs: TUserAttrs) => TScope): this {
    if (scope) {
      this._rules.push({ resource, action, scope });
    } else {
      this._rules.push({ resource, action });
    }
    return this;
  }

  deny(resource: string, action: string): this {
    this._rules.push({ resource, action, effect: "deny" });
    return this;
  }

  use(...privileges: TPrivilegeFunction<TUserAttrs, TScope>[]): this {
    for (const priv of privileges) {
      this._rules.push(...priv());
    }
    return this;
  }

  build(): TArbacRole<TUserAttrs, TScope> {
    if (!this._id) {
      throw new Error("Role id is required. Call .id() before .build().");
    }
    return {
      id: this._id,
      ...(this._name !== undefined && { name: this._name }),
      ...(this._description !== undefined && {
        description: this._description,
      }),
      rules: [...this._rules],
    };
  }
}

/**
 * Start building a new role.
 *
 * @example
 * const editor = defineRole<MyAttrs, MyScope>()
 *   .id("editor")
 *   .name("Editor")
 *   .use(canCrud("articles"))
 *   .deny("articles", "publish")
 *   .build();
 */
export function defineRole<
  TUserAttrs extends object = object,
  TScope extends object = object,
>(): RoleBuilder<TUserAttrs, TScope> {
  return new RoleBuilderImpl<TUserAttrs, TScope>();
}
