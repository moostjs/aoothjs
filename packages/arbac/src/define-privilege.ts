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
