import type { TArbacRole, TArbacRule } from "@aoothjs/arbac-core";

/**
 * A privilege function produces an array of rules when called.
 * Created by `definePrivilege()`, `canAccess()`, `canCrud()`, or manually.
 */
export type TPrivilegeFunction<TUserAttrs, TScope> = () => TArbacRule<TUserAttrs, TScope>[];

export interface RoleBuilder<TUserAttrs, TScope> {
  id(id: string): RoleBuilder<TUserAttrs, TScope>;
  name(name: string): RoleBuilder<TUserAttrs, TScope>;
  describe(description: string): RoleBuilder<TUserAttrs, TScope>;
  allow(
    resource: string,
    action: string,
    scope?: (attrs: TUserAttrs) => TScope,
  ): RoleBuilder<TUserAttrs, TScope>;
  deny(resource: string, action: string): RoleBuilder<TUserAttrs, TScope>;
  use(...privileges: TPrivilegeFunction<TUserAttrs, TScope>[]): RoleBuilder<TUserAttrs, TScope>;
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

export function defineRole<
  TUserAttrs extends object = object,
  TScope extends object = object,
>(): RoleBuilder<TUserAttrs, TScope> {
  return new RoleBuilderImpl<TUserAttrs, TScope>();
}
