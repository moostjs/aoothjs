import type { TArbacRule } from "@aoothjs/arbac-core";

import type { TPrivilegeFunction } from "./define-role";

const TABLE_READ_ACTIONS = ["query", "pages", "one", "meta"] as const;
const TABLE_WRITE_ACTIONS = ["insert", "update", "replace", "remove"] as const;

type ScopeFn<TUserAttrs, TScope> = (attrs: TUserAttrs, userId: string) => TScope;

interface ScopeOpts<TUserAttrs, TScope> {
  scope?: ScopeFn<TUserAttrs, TScope>;
}

function rulesFor<TUserAttrs, TScope>(
  resource: string,
  actions: readonly string[],
  scope?: ScopeFn<TUserAttrs, TScope>,
): TArbacRule<TUserAttrs, TScope>[] {
  return actions.map((action) => (scope ? { resource, action, scope } : { resource, action }));
}

/** Read-side actions on an `AsDbController` table: `query`, `pages`, `one`, `meta`. */
export function tableReadPrivilege<
  TUserAttrs extends object = object,
  TScope extends object = object,
>(resource: string, opts?: ScopeOpts<TUserAttrs, TScope>): TPrivilegeFunction<TUserAttrs, TScope> {
  return () => rulesFor(resource, TABLE_READ_ACTIONS, opts?.scope);
}

/** All actions on an `AsDbController` table: read + `insert`, `update`, `replace`, `remove`. */
export function tableWritePrivilege<
  TUserAttrs extends object = object,
  TScope extends object = object,
>(resource: string, opts?: ScopeOpts<TUserAttrs, TScope>): TPrivilegeFunction<TUserAttrs, TScope> {
  return () => rulesFor(resource, [...TABLE_READ_ACTIONS, ...TABLE_WRITE_ACTIONS], opts?.scope);
}

/** Multiple declarative actions on the same table, sharing a scope. */
export function tableActionsPrivilege<
  TUserAttrs extends object = object,
  TScope extends object = object,
>(
  resource: string,
  actionNames: string[],
  opts?: ScopeOpts<TUserAttrs, TScope>,
): TPrivilegeFunction<TUserAttrs, TScope> {
  return () => rulesFor(resource, actionNames, opts?.scope);
}

/** Single declarative action on a table — typically a row/rows-level `@DbAction*` like `markDone`. */
export function tableActionPrivilege<
  TUserAttrs extends object = object,
  TScope extends object = object,
>(
  resource: string,
  actionName: string,
  opts?: ScopeOpts<TUserAttrs, TScope>,
): TPrivilegeFunction<TUserAttrs, TScope> {
  return tableActionsPrivilege<TUserAttrs, TScope>(resource, [actionName], opts);
}
