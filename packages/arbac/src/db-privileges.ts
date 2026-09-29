import type { TArbacRule } from "@aooth/arbac-core";

import type { TPrivilegeFunction } from "./define-role";
import { conjoinRowPolicies } from "./scope/db-scope";
import type { TScopeFilter } from "./scope/types";

/**
 * Read-side handler actions of an `AsDbController` table: `query`, `pages`,
 * `getOne`, `getOneComposite`, `geo`, `meta`, `metaForm`.
 */
export const TABLE_READ_ACTIONS = [
  "query",
  "pages",
  "getOne",
  "getOneComposite",
  "geo",
  "meta",
  "metaForm",
] as const;

/** Write-side handler actions of an `AsDbController` table. */
export const TABLE_WRITE_ACTIONS = [
  "insert",
  "update",
  "replace",
  "remove",
  "removeComposite",
] as const;

/** The `/meta` + `/meta/form/:name` handler actions (a subset of {@link TABLE_READ_ACTIONS}). */
export const TABLE_META_ACTIONS = ["meta", "metaForm"] as const;

/** Table operation names accepted by {@link allowTableOps} / {@link defineTableAccess}. */
export type TTableOp = "read" | "meta" | "insert" | "update" | "replace" | "remove";

/**
 * Operation → handler actions. `meta` is the form-metadata subset of `read`,
 * for write-only principals that still render forms from `/meta`.
 */
export const TABLE_OP_ACTIONS: Readonly<Record<TTableOp, readonly string[]>> = {
  read: TABLE_READ_ACTIONS,
  meta: TABLE_META_ACTIONS,
  insert: ["insert"],
  update: ["update"],
  replace: ["replace"],
  remove: ["remove", "removeComposite"],
};

const ALL_WRITE_OPS: readonly TTableOp[] = ["insert", "update", "replace", "remove"];

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

/** Handler actions of `ops`, in op order, without duplicates. Throws on an unknown op. */
function actionsForOps(ops: readonly string[]): string[] {
  const out = new Set<string>();
  for (const op of ops) {
    const actions = (TABLE_OP_ACTIONS as Record<string, readonly string[] | undefined>)[op];
    if (!actions) throw new Error(`Unknown table operation "${op}"`);
    for (const a of actions) out.add(a);
  }
  return [...out];
}

/** Read-side actions on an `AsDbController` table — see {@link TABLE_READ_ACTIONS}. */
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

/**
 * Selected operations on an `AsDbController` table, sharing a scope — e.g. an
 * insert-only form principal: `allowTableOps("leads", ["insert", "meta"])`.
 *
 * - `read` → `query`, `pages`, `getOne`, `getOneComposite`, `geo`, `meta`, `metaForm`
 * - `meta` → `meta`, `metaForm` (forms for principals without `read`)
 * - `remove` → `remove`, `removeComposite`
 * - `insert` / `update` / `replace` → the same-named action
 *
 * Throws on an unknown op name.
 */
export function allowTableOps<TUserAttrs extends object = object, TScope extends object = object>(
  resource: string,
  ops: readonly TTableOp[],
  opts?: ScopeOpts<TUserAttrs, TScope>,
): TPrivilegeFunction<TUserAttrs, TScope> {
  const actions = actionsForOps(ops);
  return () => rulesFor(resource, actions, opts?.scope);
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

/** The scope keys {@link defineTableAccess} conjoins instead of overriding. */
export interface TTableAccessScope {
  filter?: TScopeFilter;
  check?: TScopeFilter;
}

/** Write ops for {@link TTableAccessDef.write}: any {@link TTableOp} but `read`. */
export type TTableWriteOp = Exclude<TTableOp, "read">;

// Scope fns are not inference sites: `TUserAttrs` / `TScope` come from the
// caller — explicit type arguments or the `defineRole<A, S>().use(...)`
// context — so one part's partial return (`{ allowedFields }`) never narrows
// `TScope` for the others.
type PartScopeFn<TUserAttrs, TScope> = ScopeFn<NoInfer<TUserAttrs>, NoInfer<TScope>>;

/**
 * Table policy for {@link defineTableAccess}. A part's own `scope` merges over
 * the shared one (see there).
 */
export interface TTableAccessDef<TUserAttrs, TScope> {
  /** Shared scope — row filter, projection, controls, `with`, `check`, … — for every part. */
  scope?: PartScopeFn<TUserAttrs, TScope>;
  /** Read side — {@link TABLE_READ_ACTIONS}. */
  read?: boolean | { scope?: PartScopeFn<TUserAttrs, TScope> };
  /**
   * Write side: `true` = insert + update + replace + remove. An op list may
   * add `meta` (forms for a principal without `read`).
   */
  write?:
    | boolean
    | readonly TTableWriteOp[]
    | { ops?: readonly TTableWriteOp[]; scope?: PartScopeFn<TUserAttrs, TScope> };
  /** Declarative `@DbAction` names. */
  actions?:
    | readonly string[]
    | { names: readonly string[]; scope?: PartScopeFn<TUserAttrs, TScope> };
}

/**
 * Merge a part scope over the shared one: the row policy is CONJOINED
 * ({@link conjoinRowPolicies} — a part can only narrow the shared rows, and
 * the effective check is `(shared.check ?? shared.filter) ∧ (part.check ??
 * part.filter)`); every other key (projection, `allowedFields`, `set`,
 * `with`, …) comes from the part when it sets it, else from the shared scope.
 */
function mergePartScope<TScope extends TTableAccessScope>(shared: TScope, part: TScope): TScope {
  const merged: TScope = { ...shared, ...part };
  delete merged.filter;
  delete merged.check;
  return Object.assign(merged, conjoinRowPolicies(shared, part));
}

function composeScope<TUserAttrs, TScope extends TTableAccessScope>(
  shared: ScopeFn<TUserAttrs, TScope> | undefined,
  part: ScopeFn<TUserAttrs, TScope> | undefined,
): ScopeFn<TUserAttrs, TScope> | undefined {
  if (!part) return shared;
  if (!shared) return part;
  return (attrs, userId) => mergePartScope(shared(attrs, userId), part(attrs, userId));
}

type Part<TUserAttrs, TScope> = [
  actions: readonly string[],
  scope: ScopeFn<TUserAttrs, TScope> | undefined,
];

/**
 * One table policy → consistent rules for every endpoint of an
 * `AsDbController` table. The shared `scope` (row filter + projection +
 * controls + `with` + `check` …) applies to every part; a part's own `scope`
 * merges over it — `filter` / `check` conjoined (`$and`), other keys from the
 * part. An action granted by an earlier part (`read` → `write` → `actions`)
 * is not repeated by a later one. Throws on an unknown write op.
 *
 * @example
 * ```ts
 * defineTableAccess<Attrs, ArbacDbScope<typeof Task>>("tasks", {
 *   scope: (a) => ({ filter: { tenantId: a.tenantId }, projection: { secret: 0 } }),
 *   read: true,
 *   write: { ops: ["insert", "update"], scope: () => ({ allowedFields: ["title", "status"] }) },
 *   actions: ["markDone"],
 * });
 * ```
 */
export function defineTableAccess<
  TUserAttrs extends object = object,
  TScope extends TTableAccessScope = TTableAccessScope,
>(
  resource: string,
  def: TTableAccessDef<TUserAttrs, TScope>,
): TPrivilegeFunction<TUserAttrs, TScope> {
  const { read, write, actions } = def;
  const writePart = typeof write === "object" && !isList(write) ? write : undefined;
  const actionsPart = actions && !isList(actions) ? actions : undefined;
  const parts: Part<TUserAttrs, TScope>[] = [];
  if (read) parts.push([TABLE_READ_ACTIONS, typeof read === "object" ? read.scope : undefined]);
  if (write) {
    const ops = isList(write) ? write : (writePart?.ops ?? ALL_WRITE_OPS);
    parts.push([actionsForOps(ops), writePart?.scope]);
  }
  if (actions)
    parts.push([actionsPart?.names ?? (actions as readonly string[]), actionsPart?.scope]);

  const seen = new Set<string>();
  const resolved: Part<TUserAttrs, TScope>[] = parts.map(([names, partScope]) => {
    const fresh = names.filter((n) => !seen.has(n));
    for (const n of fresh) seen.add(n);
    return [fresh, composeScope(def.scope, partScope)];
  });
  return () => resolved.flatMap(([names, scope]) => rulesFor(resource, names, scope));
}

// `Array.isArray` does not narrow `readonly T[]` out of a union.
function isList(v: unknown): v is readonly unknown[] {
  return Array.isArray(v);
}
