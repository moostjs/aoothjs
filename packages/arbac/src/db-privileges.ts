import type { TArbacRule } from "@aoothjs/arbac-core";

import type { TPrivilegeFunction } from "./define-role";

const TABLE_READ_ACTIONS = [
  "query",
  "pages",
  "getOne",
  "getOneComposite",
  "meta",
  "metaForm",
] as const;
const TABLE_WRITE_ACTIONS = ["insert", "update", "replace", "remove", "removeComposite"] as const;

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

/** Read-side actions on an `AsDbController` table: `query`, `pages`, `getOne`, `getOneComposite`, `meta`, `metaForm`. */
export function allowTableRead<TUserAttrs extends object = object, TScope extends object = object>(
  resource: string,
  opts?: ScopeOpts<TUserAttrs, TScope>,
): TPrivilegeFunction<TUserAttrs, TScope> {
  return () => rulesFor(resource, TABLE_READ_ACTIONS, opts?.scope);
}

/** All actions on an `AsDbController` table: read + `insert`, `update`, `replace`, `remove`, `removeComposite`. */
export function allowTableWrite<TUserAttrs extends object = object, TScope extends object = object>(
  resource: string,
  opts?: ScopeOpts<TUserAttrs, TScope>,
): TPrivilegeFunction<TUserAttrs, TScope> {
  return () => rulesFor(resource, [...TABLE_READ_ACTIONS, ...TABLE_WRITE_ACTIONS], opts?.scope);
}

/** One or more declarative actions on the same table, sharing a scope. */
export function allowTableAction<
  TUserAttrs extends object = object,
  TScope extends object = object,
>(
  resource: string,
  name: string | string[],
  opts?: ScopeOpts<TUserAttrs, TScope>,
): TPrivilegeFunction<TUserAttrs, TScope> {
  const actions = typeof name === "string" ? [name] : name;
  return () => rulesFor(resource, actions, opts?.scope);
}
