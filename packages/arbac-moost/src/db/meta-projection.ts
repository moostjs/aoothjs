import { getProjectionMode, isFieldAllowed, unionProjections } from "@aooth/arbac";
import type { TProjection } from "@aooth/arbac";
import { findAncestorInSet } from "@atscript/db";
import type { TCrudOp, TMetaResponse } from "@atscript/db";
import type {
  TSerializedAnnotatedType,
  TSerializedAnnotatedTypeInner,
} from "@atscript/typescript/utils";
import { getConstructor, useControllerContext } from "moost";

import { useArbac } from "../arbac.composables";
import type { TArbacMeta } from "../arbac.mate";
import type { ArbacDbScope } from "./as-arbac-db-controller";

/**
 * Union the per-scope `projection` whitelists into the single access-control
 * projection used for FIELD-EXISTENCE decisions (`hasField` parity + `/meta`
 * pruning). Returns `undefined` when the union imposes no restriction — no
 * scopes at all, or any scope without a `projection` (a universal grant makes
 * `unionProjections` collapse to the universe `{}`).
 */
export function unionScopeProjection(scopes: ArbacDbScope[]): TProjection | undefined {
  if (scopes.length === 0) return undefined;
  const allowed = unionProjections(...scopes.map((s) => s.projection ?? {}));
  return Object.keys(allowed).length === 0 ? undefined : allowed;
}

/**
 * Relation names any scope explicitly grants via `with.<name>` — an explicit
 * content grant implies the relation EXISTS for this principal even when the
 * projection union does not name it (the sub-scope, not the projection, owns
 * the joined rows' policy — see {@link ArbacDbScope.with}).
 */
export function collectWithGrantNames(scopes: ArbacDbScope[]): ReadonlySet<string> {
  const out = new Set<string>();
  for (const s of scopes) {
    if (s.with) for (const name of Object.keys(s.with)) out.add(name);
  }
  return out;
}

/**
 * The principal's field-visibility verdict set, assembled once per request
 * (or per `/meta` overlay) and threaded through the pruning walk.
 */
export interface MetaVisibility {
  /**
   * Projection union for this level's own fields. `{}` (the universe) means
   * unrestricted — possible when only a `with` sub-scope restricts anything.
   */
  allowed: TProjection;
  /**
   * Identifier fields reads ALWAYS return regardless of projection (the read
   * path widens `preferredId` back in, and PK addressing requires the key) —
   * hiding them would advertise less than reads deliver and break `/one/:id`.
   */
  alwaysVisible: ReadonlySet<string>;
  /** Relation names granted via `with.<name>` (see {@link collectWithGrantNames}). */
  withGrants: ReadonlySet<string>;
  /**
   * Visibility of a `with`-granted relation's JOINED fields, built from the
   * union of its `with.<name>` sub-scopes (with the related table's own
   * identifiers always visible). A path `rel.x.y` is checked as `x.y`
   * against it, recursively for nested relations. The scope-driven builders
   * ({@link buildScopeVisibility}) always supply it; a hand-built visibility
   * without it lets granted paths through unchecked (legacy behavior).
   */
  relation?: (name: string) => MetaVisibility | undefined;
  /**
   * Precompiled `isFieldAllowed(path, allowed)`. Supplied by
   * {@link buildScopeVisibility}; a hand-built visibility falls back to
   * `isFieldAllowed`.
   */
  isAllowed?: (path: string) => boolean;
  /** The scopes this level was built from (set by {@link buildScopeVisibility}). */
  scopes?: ArbacDbScope[];
  /** The table this level describes, when known (set by {@link buildScopeVisibility}). */
  table?: VisibilityTableSource;
  /**
   * Fields the principal's WRITE scopes allow (union of `allowedFields`, or
   * `"all"` for an unrestricted write grant). A field that is writable but not
   * read-visible is NOT pruned from `/meta` — it survives with a `db.writeOnly`
   * stamp (type only; rows/projections never carry it), so generic forms and
   * client preflight validators can still SET sealed fields (e.g. credentials
   * behind a read projection). Absent → nothing extra survives.
   */
  writable?: ReadonlySet<string> | "all";
}

/** Exact-or-ancestor membership: `credit.credentials.user` matches a `credit.credentials` grant. */
function isPathWritable(path: string, writable: MetaVisibility["writable"]): boolean {
  if (!writable) return false;
  return writable === "all" || hasSelfOrAncestor(writable, path);
}

/**
 * Union of write-scope `allowedFields`; `"all"` for field-unrestricted write
 * access. Mirrors `prepareScopeOverlay`: the whitelist exists only when at
 * least one scope carries an `allowedFields` array — scoped-but-unlisted
 * writes are field-unrestricted.
 */
export function collectWritableFields(
  scopes: ArbacDbScope[],
  unrestricted: boolean,
): ReadonlySet<string> | "all" | undefined {
  if (unrestricted) return "all";
  if (scopes.length === 0) return undefined;
  const out = new Set<string>();
  let sawWhitelist = false;
  for (const s of scopes) {
    if (Array.isArray(s.allowedFields)) {
      sawWhitelist = true;
      for (const f of s.allowedFields) out.add(f);
    }
  }
  if (!sawWhitelist) return "all";
  return out.size > 0 ? out : undefined;
}

/**
 * Whether a flattened dot-path field exists for this principal. A
 * `with`-granted relation itself is always visible (the grant implies it);
 * a path UNDER it (`rel.x.y`) is checked as `x.y` against the relation's
 * sub-scope visibility ({@link MetaVisibility.relation}) — so a field the
 * sub-scope hides is as unknown in a `$with` sub-query as a top-level hidden
 * column is in the main query (no filter/sort value oracle).
 */
export function isMetaFieldVisible(path: string, vis: MetaVisibility): boolean {
  if (vis.alwaysVisible.has(path)) return true;
  const dot = path.indexOf(".");
  const head = dot === -1 ? path : path.slice(0, dot);
  if (vis.withGrants.has(head)) {
    if (dot === -1) return true;
    const sub = vis.relation?.(head);
    return sub ? isMetaFieldVisible(path.slice(dot + 1), sub) : true;
  }
  return vis.isAllowed ? vis.isAllowed(path) : isFieldAllowed(path, vis.allowed);
}

/**
 * Prune a `/meta` envelope down to the fields the principal's read scopes can
 * ever surface, so a scoped UI cannot even OFFER an out-of-scope column (the
 * designed contract: the projection removes fields from the META entirely,
 * not just from row payloads). Pruned facets:
 *
 * - `fields` — the flat capability map (sortable/filterable flags).
 * - `type` — the serialized annotated type (what dynamic clients build
 *   tables/forms from); nested object props prune by dot-path. A relation
 *   prop visible through the projection survives whole; a `with`-granted
 *   one is pruned by its sub-scope (recursively), matching `hasField`.
 * - `relations` — entries neither projected nor `with`-granted.
 * - `versionColumn` — dropped when the OCC column itself is hidden.
 *
 * NEVER mutates the input — the base controller caches the static envelope
 * (`applyMetaOverlay` contract); every pruned branch is a fresh object.
 */
export function pruneMetaByVisibility(meta: TMetaResponse, vis: MetaVisibility): TMetaResponse {
  const fields: TMetaResponse["fields"] = {};
  for (const [path, fieldMeta] of Object.entries(meta.fields)) {
    if (isMetaFieldVisible(path, vis)) {
      fields[path] = fieldMeta;
    } else if (isPathWritable(path, vis.writable)) {
      // Writable-but-unreadable: keep the descriptor as write-only. Reads
      // still never surface it (the read projection stands); filter/sort are
      // off so it can't be probed.
      fields[path] = { ...fieldMeta, writeOnly: true, filterable: false, sortable: false };
    }
  }

  // `with`-granted relations survive via isMetaFieldVisible's head check —
  // a top-level relation name IS its own path head.
  const relationNames = new Set(meta.relations.map((r) => r.name));
  const relations = meta.relations.filter((r) => isMetaFieldVisible(r.name, vis));

  const out: TMetaResponse = {
    ...meta,
    fields,
    relations,
    type: pruneSerializedType(meta.type, "", vis, relationNames) as TSerializedAnnotatedType,
  };
  if (out.versionColumn !== undefined && !isMetaFieldVisible(out.versionColumn, vis)) {
    delete out.versionColumn;
  }
  return out;
}

/**
 * Copy-on-prune walk over a serialized type node. `basePath` is the flattened
 * dot-path prefix ("" at the root). Relation props (nav props named in
 * `meta.relations` at the root, or carrying a `db.rel.*` annotation inside a
 * joined type) are dropped when invisible; a `with`-granted one is pruned by
 * its sub-scope visibility (the same one `hasField` checks `rel.x` paths
 * against), any other visible one survives whole. Own-field subtrees prune
 * recursively so an include-mode union like `{ "password.hash": 1 }` keeps
 * `password` with only `hash` inside.
 */
function pruneSerializedType(
  node: TSerializedAnnotatedTypeInner,
  basePath: string,
  vis: MetaVisibility,
  relationNames: ReadonlySet<string>,
): TSerializedAnnotatedTypeInner {
  const def = node.type;
  if (def.kind === "object") {
    const props: Record<string, TSerializedAnnotatedTypeInner> = {};
    for (const [name, prop] of Object.entries(def.props)) {
      const path = basePath ? `${basePath}.${name}` : name;
      if (basePath === "" && (relationNames.has(name) || isNavProp(prop))) {
        if (!isMetaFieldVisible(name, vis)) continue;
        const sub = vis.withGrants.has(name) ? vis.relation?.(name) : undefined;
        props[name] = sub ? pruneSerializedType(prop, "", sub, NO_NAMES) : prop;
        continue;
      }
      if (!isMetaFieldVisible(path, vis)) {
        if (isPathWritable(path, vis.writable)) {
          // Keep the whole subtree (clients need the full shape to WRITE it),
          // stamped write-only so forms render set-only inputs.
          props[name] = {
            ...prop,
            metadata: { ...prop.metadata, "db.writeOnly": true },
          };
        }
        continue;
      }
      props[name] = pruneSerializedType(prop, path, vis, relationNames);
    }
    return { ...node, type: { ...def, props } };
  }
  if (def.kind === "array") {
    return {
      ...node,
      type: { ...def, of: pruneSerializedType(def.of, basePath, vis, relationNames) },
    };
  }
  if (def.kind === "union" || def.kind === "intersection" || def.kind === "tuple") {
    return {
      ...node,
      type: {
        ...def,
        items: def.items.map((item) => pruneSerializedType(item, basePath, vis, relationNames)),
      },
    };
  }
  return node;
}

const NO_NAMES: ReadonlySet<string> = new Set();

/** A nav prop inside a joined type: atscript-db stamps `db.rel.to` / `from` / `via`. */
function isNavProp(prop: TSerializedAnnotatedTypeInner): boolean {
  const meta = prop.metadata as Record<string, unknown> | undefined;
  return !!meta && ("db.rel.to" in meta || "db.rel.from" in meta || "db.rel.via" in meta);
}

/**
 * The slice of an atscript-db readable (table / view) the visibility walk
 * reads — a moost-db controller's `this.readable` satisfies it: identifiers
 * (always visible), nav relations (to reach the joined table) and the
 * flattened schema (to split `$select` parents by scope).
 */
export interface VisibilityTableSource {
  primaryKeys: readonly string[];
  preferredId: readonly string[];
  relations?: ReadonlyMap<string, unknown>;
  /**
   * The target table of nav relation `navField` (atscript-db's
   * `readable.relatedTable`); absent / `undefined` → the joined table's
   * identifiers are not exempted.
   */
  relatedTable?(navField: string): VisibilityTableSource | undefined;
  /** Flattened schema (dot-paths) — used to split `$select` parents by scope. */
  flatMap?: ReadonlyMap<string, unknown>;
  /** Navigation field paths — their joined descendants are not own columns. */
  navFields?: ReadonlySet<string>;
}

// Identifiers per table object (decoration-derived, stable for its lifetime).
const identifierSetCache = new WeakMap<VisibilityTableSource, ReadonlySet<string>>();

/** PK + `preferredId` of a table — the identifiers reads always return. */
function identifierSet(table: VisibilityTableSource | undefined): ReadonlySet<string> {
  if (!table) return NO_NAMES;
  let set = identifierSetCache.get(table);
  if (!set) {
    set = new Set([...table.primaryKeys, ...table.preferredId]);
    identifierSetCache.set(table, set);
  }
  return set;
}

/** Pick `scopes[i].with?.[name]`, dropping undefined (silence wins when empty). */
function collectSubScopes(scopes: ArbacDbScope[], name: string): ArbacDbScope[] {
  const out: ArbacDbScope[] = [];
  for (const s of scopes) {
    const sub = s.with?.[name];
    if (sub) out.push(sub);
  }
  return out;
}

/** `path` or one of its ancestors is in `set`. */
function hasSelfOrAncestor(set: ReadonlySet<string>, path: string): boolean {
  return set.has(path) || findAncestorInSet(path, set) !== undefined;
}

/**
 * Precompiled {@link isFieldAllowed} for one projection: `hasField` asks it
 * for every referenced path, so the mode and key sets are computed once.
 * Inclusion: the path, an ancestor, or a descendant is listed. Exclusion: no
 * listed key is the path or an ancestor.
 */
function compileProjection(projection: TProjection): (path: string) => boolean {
  const keys = Object.keys(projection);
  if (keys.length === 0) return () => true;
  const listed = new Set(keys);
  if (getProjectionMode(projection) === "exclude") {
    return (path) => !hasSelfOrAncestor(listed, path);
  }
  // Every proper prefix of a listed key: a parent of an included child.
  const parents = new Set<string>();
  for (const key of keys) {
    let pos = key.length;
    while ((pos = key.lastIndexOf(".", pos - 1)) !== -1) parents.add(key.slice(0, pos));
  }
  return (path) => parents.has(path) || hasSelfOrAncestor(listed, path);
}

/**
 * Build the {@link MetaVisibility} a set of read scopes implies — the single
 * structure behind `hasField`, `/meta` pruning, `$select` value stripping
 * and the `$with` overlay, so they cannot drift. Own fields: the projection
 * union (`{}` when unrestricted), precompiled into `isAllowed`. A
 * `with`-granted relation: a lazily built (memoized) child visibility over
 * the union of its `with.<name>` sub-scopes — the same sub-scopes joined rows
 * are stripped with — whose `alwaysVisible` is the related table's own PK /
 * `preferredId` (reached through `table.relatedTable`; without it, no
 * related identifier is exempt).
 *
 * @param alwaysVisible - identifiers exempt from the projection; defaults to
 *   the table's PK + `preferredId`
 */
export function buildScopeVisibility(
  scopes: ArbacDbScope[],
  table: VisibilityTableSource | undefined,
  alwaysVisible: ReadonlySet<string> = identifierSet(table),
): MetaVisibility {
  const withGrants = collectWithGrantNames(scopes);
  const allowed = unionScopeProjection(scopes) ?? {};
  const children = new Map<string, MetaVisibility>();
  return {
    allowed,
    alwaysVisible,
    withGrants,
    scopes,
    table,
    isAllowed: compileProjection(allowed),
    relation(name) {
      if (!withGrants.has(name)) return undefined;
      let child = children.get(name);
      if (!child) {
        child = buildScopeVisibility(collectSubScopes(scopes, name), table?.relatedTable?.(name));
        children.set(name, child);
      }
      return child;
    },
  };
}

// `hasField` runs once per field a request references ($select / filter /
// sort keys, `$with` sub-query paths — client-controlled, so potentially many
// per request), and the scopes array is identity-stable for the event once
// the authorize interceptor / transformFilter calls `setScopes(...)` —
// memoize the visibility per (scopes array, readable) instead of rebuilding
// the unions per field. A bare identifier set (the 0.1.67 `hasField`
// argument) keys its own entry; `NO_TABLE` keys the table-less one.
const scopeVisibilityCache = new WeakMap<
  ArbacDbScope[],
  WeakMap<VisibilityTableSource | ReadonlySet<string>, MetaVisibility>
>();
const NO_TABLE: VisibilityTableSource = { primaryKeys: [], preferredId: [] };

/** `source` is an identifier set (the 0.1.67 signatures), not a readable. */
function isIdentifierSet(
  source: VisibilityTableSource | ReadonlySet<string>,
): source is ReadonlySet<string> {
  return !("primaryKeys" in source);
}

/**
 * The event-cached {@link MetaVisibility} for `scopes` over `source` (a
 * readable, or an `alwaysVisible` identifier set).
 */
export function scopeVisibility(
  scopes: ArbacDbScope[],
  source: VisibilityTableSource | ReadonlySet<string> = NO_TABLE,
): MetaVisibility {
  let perSource = scopeVisibilityCache.get(scopes);
  if (!perSource) {
    perSource = new WeakMap();
    scopeVisibilityCache.set(scopes, perSource);
  }
  let vis = perSource.get(source);
  if (!vis) {
    vis = isIdentifierSet(source)
      ? buildScopeVisibility(scopes, undefined, source)
      : buildScopeVisibility(scopes, source === NO_TABLE ? undefined : source);
    perSource.set(source, vis);
  }
  return vis;
}

/**
 * Shared body of both ARBAC controllers' `hasField` overrides (BUG-3 twin of
 * the `/meta` pruning): a field outside the read-scope projection union —
 * or, for a `rel.x` path under a `with`-granted relation, outside that
 * relation's sub-scope union — must be indistinguishable from a field that
 * does not exist. Returns `true` when there are no scopes (unscoped grant).
 *
 * @param source - the controller's `this.readable`; an identifier set (the
 *   0.1.67 signature) still works, without related-table identifiers
 */
export function isScopedFieldVisible(
  scopes: ArbacDbScope[],
  path: string,
  source: VisibilityTableSource | ReadonlySet<string>,
): boolean {
  if (scopes.length === 0) return true;
  return isMetaFieldVisible(path, scopeVisibility(scopes, source));
}

/**
 * PK + `preferredId` for a controller's table/readable — the
 * {@link MetaVisibility.alwaysVisible} set. Kept for compatibility: the
 * controllers now pass `this.readable` and it is derived there.
 */
export function metaAlwaysVisibleFields(
  _controller: object,
  source: { primaryKeys: readonly string[]; preferredId: readonly string[] },
): ReadonlySet<string> {
  return identifierSet(source);
}

/**
 * The write CRUD ops. Everything else in `meta.crud` is row-returning read
 * surface whose scopes govern field VISIBILITY in `/meta` — classified by
 * complement so a read op added upstream defaults to READ and the pruning
 * fails closed (a principal whose only read grant is the new op still gets
 * a pruned envelope rather than the full field map).
 */
const WRITE_CRUD_OPS: ReadonlySet<TCrudOp> = new Set<TCrudOp>([
  "insert",
  "update",
  "replace",
  "remove",
]);

/**
 * The full ARBAC `/meta` overlay, shared by `AsArbacDbController` and
 * `AsArbacDbReadableController`: filter `actions` + `crud` by per-action
 * evaluation, then prune the FIELD surface (`fields`, serialized `type`,
 * `relations`, `versionColumn`) by the read scopes' projection union.
 *
 * Field pruning (BUG-3): a scope projection must remove fields from the META
 * entirely — `transformProjection` already strips their VALUES from every
 * read, but the envelope still advertised the full field map, so a scoped UI
 * offered columns that could never populate, and secret-bearing column NAMES
 * leaked. The pruning union comes from the read-op evaluations already
 * computed for the `crud` overlay (same `unionProjections` the read path
 * applies). An allowed read op WITHOUT scopes is an unscoped grant —
 * universe, no pruning (unchanged behavior for unscoped roles). No read op
 * allowed → the projection union is empty → no pruning: `crud` already
 * advertises no read surface, and write-only principals still need `type`
 * for their insert/update forms. PK + `preferredId` are never pruned —
 * reads always return those fields (projection widening / id addressing).
 *
 * @param source - the controller's `this.readable` (identifiers and related
 *   tables are derived from it); an identifier set (the 0.1.67 signature)
 *   still works, without related-table identifiers
 */
export async function applyArbacMetaOverlay(
  meta: TMetaResponse,
  source: VisibilityTableSource | ReadonlySet<string>,
): Promise<TMetaResponse> {
  const arbac = useArbac();
  const actionToMethodMeta = collectActionMetaByName();

  // Evaluate all gates in parallel: ARBAC evaluate is in-memory + idempotent
  // and reads from the per-event scope cache, so contention is bounded; the
  // win is killing N sequential round-trips through the user provider.
  const crudKeys = Object.keys(meta.crud) as TCrudOp[];
  const [actionResults, crudResults] = await Promise.all([
    Promise.all(
      meta.actions.map((entry) => {
        const methodMeta = actionToMethodMeta.get(entry.name);
        const arbacAction = methodMeta?.arbacActionId ?? methodMeta?.id ?? entry.name;
        return arbac.evaluate({ action: arbacAction });
      }),
    ),
    Promise.all(crudKeys.map((key) => arbac.evaluate({ action: key }))),
  ]);

  const filteredActions: TMetaResponse["actions"] = [];
  for (let i = 0; i < meta.actions.length; i++) {
    if (actionResults[i].allowed) filteredActions.push(meta.actions[i]);
  }

  const filteredCrud: TMetaResponse["crud"] = {};
  for (let i = 0; i < crudKeys.length; i++) {
    if (crudResults[i].allowed) filteredCrud[crudKeys[i]] = meta.crud[crudKeys[i]];
  }

  let overlaid: TMetaResponse = { ...meta, actions: filteredActions, crud: filteredCrud };

  let readUnrestricted = false;
  let writeUnrestricted = false;
  const readScopes: ArbacDbScope[] = [];
  const writeScopes: ArbacDbScope[] = [];
  for (let i = 0; i < crudKeys.length; i++) {
    if (!crudResults[i].allowed) continue;
    const scopes = crudResults[i].scopes;
    if (WRITE_CRUD_OPS.has(crudKeys[i])) {
      if (!scopes || scopes.length === 0) writeUnrestricted = true;
      else writeScopes.push(...scopes);
      continue;
    }
    if (!scopes || scopes.length === 0) readUnrestricted = true;
    else readScopes.push(...scopes);
  }
  if (!readUnrestricted && readScopes.length > 0) {
    const vis = isIdentifierSet(source)
      ? buildScopeVisibility(readScopes, undefined, source)
      : buildScopeVisibility(readScopes, source);
    // Prune when the own-field union restricts OR a `with` grant may
    // restrict a relation's joined fields (the nav type prunes by sub-scope).
    if (Object.keys(vis.allowed).length > 0 || vis.withGrants.size > 0) {
      overlaid = pruneMetaByVisibility(overlaid, {
        ...vis,
        writable: collectWritableFields(writeScopes, writeUnrestricted),
      });
    }
  }

  return overlaid;
}

type ActionResolutionMeta = { arbacActionId?: string; id?: string };

// Per-class memoization: controller and method decorator metadata are bound to
// the class at registration time and never mutate per-request. Caching avoids
// re-walking `getInstanceOwnMethods` + N `getMethodMeta` calls on every meta
// overlay (one per GET `/<resource>/meta` request).
const actionMetaByClassCache = new WeakMap<
  new (...args: never[]) => unknown,
  Map<string, ActionResolutionMeta>
>();

function collectActionMetaByName(): Map<string, ActionResolutionMeta> {
  const cc = useControllerContext();
  const instance = cc.getController();
  const ctor = getConstructor(instance) as new (...args: never[]) => unknown;
  const cached = actionMetaByClassCache.get(ctor);
  if (cached) return cached;

  const map = new Map<string, ActionResolutionMeta>();
  const ctrlMeta = cc.getControllerMeta<TArbacMeta>();

  for (const entry of ctrlMeta?.atscript_db_actions ?? []) {
    map.set(entry.name, {});
  }

  for (const methodName of collectMethodNames(instance)) {
    const m = cc.getMethodMeta<TArbacMeta>(methodName);
    if (!m) continue;
    const actionMeta = m.atscript_db_action;
    if (actionMeta?.name) {
      map.set(actionMeta.name, { arbacActionId: m.arbacActionId, id: m.id });
    }
  }

  actionMetaByClassCache.set(ctor, map);
  return map;
}

/**
 * Test-friendly internal helper — exported for unit tests and helper
 * composition; regular consumers should not call this directly.
 *
 * Method names of an instance, walking the full prototype chain via property
 * DESCRIPTORS. Deliberately NOT moost's `getInstanceOwnMethods`: that helper
 * evaluates `instance[name]` for every property to test "is it a function",
 * which fires accessors — and moost-db's inherited `.table` getter THROWS for
 * view-bound controllers, turning every `/meta` request into a 500. Accessor
 * properties are skipped entirely (a getter-valued property is not a method
 * and can never carry `@DbAction` metadata).
 */
export function collectMethodNames(instance: object): string[] {
  const names = new Set<string>();
  let obj: object | null = instance;
  while (obj && obj !== Object.prototype) {
    for (const name of Object.getOwnPropertyNames(obj)) {
      if (name === "constructor") continue;
      const desc = Object.getOwnPropertyDescriptor(obj, name);
      if (desc && typeof desc.value === "function") names.add(name);
    }
    obj = Object.getPrototypeOf(obj) as object | null;
  }
  return [...names];
}
