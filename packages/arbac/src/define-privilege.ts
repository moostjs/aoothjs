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
 *   (scope: (attrs: MyAttrs, userId: string) => MyScope) => [
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
 *
 * @param resource - resource string (literal or wildcard)
 * @param action - action string (e.g. `read`, `create`, `*`)
 * @param scope - optional scope function returning a scope object derived from user attrs
 */
export function canAccess<TUserAttrs extends object = object, TScope extends object = object>(
  resource: string,
  action: string,
  scope?: (attrs: TUserAttrs, userId: string) => TScope,
): TPrivilegeFunction<TUserAttrs, TScope> {
  return () => (scope ? [{ resource, action, scope }] : [{ resource, action }]);
}

/**
 * Standard CRUD-plus-list actions emitted by {@link canCrud}.
 *
 * `list` is intentionally separate from `read`: REST APIs typically
 * scope reads-of-one differently from list-of-many.
 */
const CRUD_ACTIONS = ["create", "read", "update", "delete", "list"] as const;

/**
 * Full CRUD privilege on a resource.
 *
 * Emits five rules — `create`, `read`, `update`, `delete`, `list` —
 * because `read` (one item) and `list` (many) are commonly scoped differently.
 * Scope, when provided, applies to all five actions.
 */
export function canCrud<TUserAttrs extends object = object, TScope extends object = object>(
  resource: string,
  scope?: (attrs: TUserAttrs, userId: string) => TScope,
): TPrivilegeFunction<TUserAttrs, TScope> {
  return () =>
    CRUD_ACTIONS.map((action) => (scope ? { resource, action, scope } : { resource, action }));
}
