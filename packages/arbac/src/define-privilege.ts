import type { TArbacRule } from "@aoothjs/arbac-core";

import type { TPrivilegeFunction } from "./define-role";

/**
 * Define a reusable privilege factory.
 *
 * Double-call pattern: first call pins TUserAttrs/TScope generics,
 * second call infers TArgs from the factory function.
 *
 * @example
 * const canManageUsers = definePrivilege<MyAttrs, MyScope>()(
 *   (scope: (attrs: MyAttrs) => MyScope) => [
 *     { resource: "users", action: "read", scope },
 *     { resource: "users", action: "update", scope },
 *   ]
 * );
 *
 * defineRole<MyAttrs, MyScope>()
 *   .id("manager")
 *   .use(canManageUsers((attrs) => ({ dept: attrs.dept })))
 *   .build();
 */
export function definePrivilege<
  TUserAttrs extends object = object,
  TScope extends object = object,
>() {
  return <TArgs extends unknown[]>(
    factory: (...args: TArgs) => TArbacRule<TUserAttrs, TScope>[],
  ): ((...args: TArgs) => TPrivilegeFunction<TUserAttrs, TScope>) => {
    return (...args: TArgs) =>
      () =>
        factory(...args);
  };
}

/**
 * Simple access privilege: one resource + one action.
 */
export function canAccess<TUserAttrs extends object = object, TScope extends object = object>(
  resource: string,
  action: string,
  scope?: (attrs: TUserAttrs) => TScope,
): TPrivilegeFunction<TUserAttrs, TScope> {
  return () => (scope ? [{ resource, action, scope }] : [{ resource, action }]);
}

const CRUD_ACTIONS = ["create", "read", "update", "delete"] as const;

/**
 * Full CRUD privilege on a resource.
 * Scope applies to all four actions when provided.
 */
export function canCrud<TUserAttrs extends object = object, TScope extends object = object>(
  resource: string,
  scope?: (attrs: TUserAttrs) => TScope,
): TPrivilegeFunction<TUserAttrs, TScope> {
  return () =>
    CRUD_ACTIONS.map((action) => (scope ? { resource, action, scope } : { resource, action }));
}
