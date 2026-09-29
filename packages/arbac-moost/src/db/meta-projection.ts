import { effectiveScope } from "@aooth/arbac";
import type { TCrudOp, TMetaResponse } from "@atscript/db";
import { DB_CRUD_HANDLERS, resolveTerminalRef, VALUE_HELP_CRUD_HANDLERS } from "@atscript/moost-db";
import type { TDbIndexFieldPaths } from "@atscript/moost-db";
import type {
  TAtscriptAnnotatedType,
  TSerializedAnnotatedType,
  TSerializedAnnotatedTypeInner,
} from "@atscript/typescript/utils";
import { getConstructor, getMoostMate, useControllerContext } from "moost";

import { arbacIdsFromMeta } from "../arbac.evaluate";
import type { TArbacMeta } from "../arbac.mate";
import type { ArbacDbScope } from "./as-arbac-db-controller";
import { getOrCreate, hasSelfOrAncestor, navFieldsOf } from "./helpers";
import {
  evaluateHandlers,
  evaluateTypeRead,
  resolveHandlerArbacIds,
  resolveRelationTree,
} from "./relation-policy";
import type { ArbacHandlerIds, RelationNameTree } from "./relation-policy";
import {
  buildScopeVisibility,
  collectWritableFields,
  isIdentifierSet,
  isMetaFieldVisible,
  tablePolicy,
} from "./visibility";
import type { MetaVisibility, VisibilityTableSource } from "./visibility";

/**
 * Exact-or-ancestor membership in the write whitelist: `credit.credentials.user`
 * matches a `credit.credentials` grant. A path through a nav relation is
 * writable only when the relation is opted into nested writes
 * ({@link MetaVisibility.nestedWrites}); a `@db.column.derived` field never is
 * (its payload value is dropped).
 */
function isPathWritable(path: string, vis: MetaVisibility): boolean {
  const writable = vis.writable;
  if (!writable || tablePolicy(vis.table).derived.has(path)) return false;
  const dot = path.indexOf(".");
  const head = dot === -1 ? path : path.slice(0, dot);
  const isRelation = vis.relationNames?.has(head) || vis.table?.navFields?.has(head);
  if (isRelation && !vis.nestedWrites?.has(head)) return false;
  return writable === "all" || hasSelfOrAncestor(writable, path);
}

/**
 * Foreign `ref` targets for `/meta` pruning: annotated type → the caller's
 * visibility on it, or `null` when the caller cannot read it.
 */
export type MetaRefTargets = ReadonlyMap<object, MetaVisibility | null>;

/**
 * Prune a `/meta` envelope down to the fields the principal's read scopes can
 * ever surface, so a scoped UI cannot even OFFER an out-of-scope column (the
 * designed contract: the projection removes fields from the META entirely,
 * not just from row payloads). Pruned facets:
 *
 * - `fields` — the flat capability map (sortable/filterable flags).
 * - `type` — the serialized annotated type (what dynamic clients build
 *   tables/forms from); nested object props prune by dot-path. A visible
 *   relation's nav prop is pruned by that relation's visibility (declared
 *   sub-scope or the caller's own grant on the target), recursively. A
 *   `ref` whose target field is hidden (own table) or whose target table the
 *   caller cannot read (`refTargets`) is stripped.
 * - `relations` — hidden relations dropped.
 * - `versionColumn` — dropped when the OCC column itself is hidden.
 *
 * NEVER mutates the input — the base controller caches the static envelope
 * (`applyMetaOverlay` contract); every pruned branch is a fresh object.
 */
export function pruneMetaByVisibility(
  meta: TMetaResponse,
  vis: MetaVisibility,
  refTargets?: MetaRefTargets,
): TMetaResponse {
  const fields: TMetaResponse["fields"] = {};
  for (const [path, fieldMeta] of Object.entries(meta.fields)) {
    if (isMetaFieldVisible(path, vis)) {
      fields[path] = fieldMeta;
    } else if (isPathWritable(path, vis)) {
      // Writable-but-unreadable: keep the descriptor as write-only. Reads
      // still never surface it (the read projection stands); filter/sort are
      // off so it can't be probed.
      fields[path] = { ...fieldMeta, writeOnly: true, filterable: false, sortable: false };
    }
  }

  // A top-level relation name IS its own path head.
  const relationNames = new Set(meta.relations.map((r) => r.name));
  const relations = meta.relations.filter((r) => isMetaFieldVisible(r.name, vis));

  const out: TMetaResponse = {
    ...meta,
    fields,
    relations,
    type: pruneSerializedType(meta.type, {
      basePath: "",
      vis,
      relationNames,
      refTargets,
    }) as TSerializedAnnotatedType,
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
 * joined type) are dropped when invisible and pruned by the relation's
 * visibility otherwise (a hand-built visibility without one keeps them
 * whole). Own-field subtrees prune recursively so an include-mode union like
 * `{ "password.hash": 1 }` keeps `password` with only `hash` inside.
 */
interface PruneLevel {
  /** The flattened dot-path prefix (`""` at a table root). */
  basePath: string;
  vis: MetaVisibility;
  /** The relation names of the level's table (nav props at its root). */
  relationNames: ReadonlySet<string>;
  refTargets: MetaRefTargets | undefined;
}

function pruneSerializedType(
  node: TSerializedAnnotatedTypeInner,
  level: PruneLevel,
): TSerializedAnnotatedTypeInner {
  const { basePath, vis, relationNames, refTargets } = level;
  const def = node.type;
  if (def.kind === "object") {
    const props: Record<string, TSerializedAnnotatedTypeInner> = {};
    for (const [name, prop] of Object.entries(def.props)) {
      const path = basePath ? `${basePath}.${name}` : name;
      if (basePath === "" && (relationNames.has(name) || isNavProp(prop))) {
        if (!isMetaFieldVisible(name, vis)) {
          // Unreadable but opted into nested writes (`nestedWrites`): keep
          // the shape, stamped write-only. Any other relation is no write
          // affordance — its nested writes answer 403.
          if (vis.nestedWrites?.has(name) && isPathWritable(name, vis)) {
            props[name] = stampWriteOnly(prop);
          }
          continue;
        }
        const sub = vis.relation?.(name);
        props[name] = sub
          ? pruneSerializedType(prop, {
              basePath: "",
              vis: sub,
              relationNames: sub.relationNames ?? NO_NAMES,
              refTargets,
            })
          : prop;
        continue;
      }
      const child = { ...level, basePath: path };
      if (!isMetaFieldVisible(path, vis)) {
        if (isPathWritable(path, vis)) {
          // Keep the whole subtree (clients need the full shape to WRITE it),
          // stamped write-only so forms render set-only inputs.
          props[name] = stampWriteOnly(prop);
        } else if (hasWritableDescendant(path, vis.writable)) {
          // A hidden parent of writable leaves: keep only those (the walk
          // below drops every other hidden child), stamped write-only.
          props[name] = stampWriteOnly(pruneSerializedType(prop, child));
        }
        continue;
      }
      const pruned = pruneSerializedType(prop, child);
      props[name] =
        pruned.ref && !isRefVisible(path, vis, refTargets) ? withoutRef(pruned) : pruned;
    }
    return { ...node, type: { ...def, props } };
  }
  if (def.kind === "array") {
    return { ...node, type: { ...def, of: pruneSerializedType(def.of, level) } };
  }
  if (def.kind === "union" || def.kind === "intersection" || def.kind === "tuple") {
    return {
      ...node,
      type: { ...def, items: def.items.map((item) => pruneSerializedType(item, level)) },
    };
  }
  return node;
}

function stampWriteOnly(node: TSerializedAnnotatedTypeInner): TSerializedAnnotatedTypeInner {
  return { ...node, metadata: { ...node.metadata, "db.writeOnly": true } };
}

/** A strict descendant of `path` is in the write whitelist. */
function hasWritableDescendant(path: string, writable: MetaVisibility["writable"]): boolean {
  if (!writable || writable === "all") return false;
  const prefix = `${path}.`;
  for (const f of writable) if (f.startsWith(prefix)) return true;
  return false;
}

function withoutRef(node: TSerializedAnnotatedTypeInner): TSerializedAnnotatedTypeInner {
  const { ref: _ref, ...rest } = node;
  return rest;
}

/** The field a runtime prop's `ref` finally points at (the same terminal `/meta` serializes). */
function refTargetOf(entry: unknown): { type: object; field: string } | undefined {
  const def = entry as TAtscriptAnnotatedType | undefined;
  if (!def?.ref) return undefined;
  const terminal = resolveTerminalRef(def);
  if (terminal) return terminal;
  try {
    return { type: def.ref.type(), field: def.ref.field };
  } catch {
    return undefined;
  }
}

/**
 * A serialized `ref` at `path` survives when its target field is visible:
 * a self-reference (e.g. a derived column's source) against this level's
 * visibility; a foreign one against the caller's visibility on the target
 * table (`refTargets`, stripped when the caller cannot read it). Without
 * runtime schema info (`vis.table.flatMap`) or `refTargets`, refs are kept.
 */
function isRefVisible(
  path: string,
  vis: MetaVisibility,
  refTargets: MetaRefTargets | undefined,
): boolean {
  const table = vis.table;
  if (!table?.flatMap || !refTargets) return true;
  const target = refTargetOf(table.flatMap.get(path));
  if (!target || !target.field) return true;
  if (target.type === table.type) return isMetaFieldVisible(target.field, vis);
  const targetVis = refTargets.get(target.type);
  return !!targetVis && isMetaFieldVisible(target.field, targetVis);
}

const NO_NAMES: ReadonlySet<string> = new Set();

/** A nav prop inside a joined type: atscript-db stamps `db.rel.to` / `from` / `via`. */
function isNavProp(prop: TSerializedAnnotatedTypeInner): boolean {
  const meta = prop.metadata as Record<string, unknown> | undefined;
  return !!meta && ("db.rel.to" in meta || "db.rel.from" in meta || "db.rel.via" in meta);
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
 * The handler methods serving a `/meta` crud op on this controller (a DB or
 * value-help controller — moost-db's handler maps); an op is allowed when
 * ANY of them is. An op no map lists is its own method name.
 */
function crudHandlers(op: TCrudOp, methods: ReadonlySet<string>): readonly string[] {
  const found = [...(DB_CRUD_HANDLERS[op] ?? []), ...(VALUE_HELP_CRUD_HANDLERS[op] ?? [])].filter(
    (m) => methods.has(m),
  );
  return found.length > 0 ? found : [op];
}

/**
 * The full ARBAC `/meta` overlay, shared by the ARBAC DB and value-help
 * controllers.
 *
 * 1. `actions` and `crud` are filtered by evaluating each one exactly as its
 *    handler is authorized (`useArbac` precedence): a crud op through its
 *    handler method(s) — `one` via `getOne` / `getOneComposite`, `remove`
 *    via `remove` / `removeComposite` (allowed when any is) — and an action
 *    through its method (`@ArbacAction` → `@DbAction` name → …).
 * 2. The FIELD surface (`fields`, serialized `type`, `relations`,
 *    `versionColumn`) is pruned by the read scopes' visibility: the
 *    projection union, derived-column sources, atomic JSON columns, and the
 *    `$with` relation policy (declared `with` sub-scopes, else the caller's
 *    own grant on the related table — no grant → relation and nav type
 *    dropped). `ref`s to hidden targets are stripped. An allowed read op
 *    without scopes is an unscoped grant (no field restriction; relations
 *    still follow the relation policy). No read op allowed → no pruning:
 *    `crud` already advertises no read surface, and write-only principals
 *    still need `type` for their insert/update forms. PK + `preferredId` are
 *    never pruned.
 * 3. The search surface: `searchIndexes` reading a hidden field are dropped,
 *    `searchable` / `vectorSearchable` / `geoSearchable` recomputed, and the
 *    `query` / `pages` control lists lose the controls that became unusable
 *    (`crud.geo` goes when no geo index is left).
 *
 * @param source - the controller's `this.readable` (identifiers, relations
 *   and schema rules are derived from it); an identifier set (the 0.1.67
 *   signature) still works, without them
 * @param indexes - the controller's `indexFieldPaths()`; defaults to calling
 *   it on the current controller when it has one
 */
export async function applyArbacMetaOverlay(
  meta: TMetaResponse,
  source: VisibilityTableSource | ReadonlySet<string>,
  indexes?: readonly TDbIndexFieldPaths[],
): Promise<TMetaResponse> {
  const instance = useControllerContext().getController();
  const { methods } = controllerMethodIndex(instance);

  const crudKeys = Object.keys(meta.crud) as TCrudOp[];
  const [allowedActions, crudScopes] = await Promise.all([
    grantedActions(
      instance,
      meta.actions.map((entry) => entry.name),
    ),
    Promise.all(
      crudKeys.map((op) =>
        evaluateHandlers(crudHandlers(op, methods).map((m) => resolveHandlerArbacIds(instance, m))),
      ),
    ),
  ]);

  const allowed = new Set(allowedActions);
  const actions = meta.actions.filter((entry) => allowed.has(entry.name));
  const crud: TMetaResponse["crud"] = {};
  const readScopes: ArbacDbScope[] = [];
  const writeScopes: ArbacDbScope[] = [];
  for (let i = 0; i < crudKeys.length; i++) {
    const scopes = crudScopes[i];
    if (!scopes) continue;
    crud[crudKeys[i]] = meta.crud[crudKeys[i]];
    (WRITE_CRUD_OPS.has(crudKeys[i]) ? writeScopes : readScopes).push(...scopes);
  }
  const overlaid: TMetaResponse = { ...meta, actions, crud };
  if (readScopes.length === 0) return overlaid;

  const writable = collectWritableFields(writeScopes, false);
  const nestedWrites = effectiveScope(writeScopes).nestedWrites;
  if (isIdentifierSet(source)) {
    const vis = buildScopeVisibility(readScopes, undefined, source);
    return Object.keys(vis.allowed).length > 0 || vis.withGrants.size > 0
      ? pruneMetaByVisibility(overlaid, { ...vis, writable, nestedWrites })
      : overlaid;
  }

  const relations = await resolveRelationTree(readScopes, source, metaRelationNames(meta), {
    listSiblings: false,
  });
  const vis = buildScopeVisibility(readScopes, source, { relations });
  const refTargets = await resolveRefTargets(vis, meta);
  return pruneSearchSurface(
    pruneMetaByVisibility(overlaid, { ...vis, writable, nestedWrites }, refTargets),
    meta,
    vis,
    indexes ?? controllerIndexes(instance),
  );
}

// Per static envelope (the base controller caches it — identity-stable).
const metaNamesCache = new WeakMap<TMetaResponse, RelationNameTree>();

/** The relation names `/meta`'s serialized type reaches: root relations, then nav props of each nav body. */
function metaRelationNames(meta: TMetaResponse): RelationNameTree {
  return getOrCreate(metaNamesCache, meta, () => buildMetaRelationNames(meta));
}

function buildMetaRelationNames(meta: TMetaResponse): RelationNameTree {
  const tree: RelationNameTree = new Map();
  const rootProps = objectProps(meta.type);
  for (const r of meta.relations) {
    const nested = new Map() as RelationNameTree;
    tree.set(r.name, nested);
    const prop = rootProps?.[r.name];
    if (prop) collectNavNames(prop, nested, 0);
  }
  return tree;
}

/** Nested-relation walk bound — serialized nav bodies are finite, this only guards pathological input. */
const MAX_NAV_DEPTH = 8;

function collectNavNames(
  node: TSerializedAnnotatedTypeInner,
  into: RelationNameTree,
  depth: number,
): void {
  if (depth >= MAX_NAV_DEPTH) return;
  const props = objectProps(node);
  if (!props) return;
  for (const [name, prop] of Object.entries(props)) {
    if (!isNavProp(prop)) continue;
    collectNavNames(
      prop,
      getOrCreate(into, name, () => new Map()),
      depth + 1,
    );
  }
}

/** The props of an object node (through arrays). */
function objectProps(
  node: TSerializedAnnotatedTypeInner,
): Record<string, TSerializedAnnotatedTypeInner> | undefined {
  const def = node.type;
  if (def.kind === "object") return def.props;
  if (def.kind === "array") return objectProps(def.of);
  return undefined;
}

/**
 * Foreign `ref` targets of every level the pruned `/meta` shows (the root
 * table and each visible relation's table): the caller's visibility on each
 * target table, or `null` when they cannot read it.
 */
async function resolveRefTargets(
  root: MetaVisibility,
  meta: TMetaResponse,
): Promise<MetaRefTargets> {
  const types = new Set<object>();
  const visit = (vis: MetaVisibility, node: TSerializedAnnotatedTypeInner, depth: number) => {
    if (vis.table) for (const type of foreignRefTypes(vis.table)) types.add(type);
    const props = objectProps(node);
    if (!props || depth >= MAX_NAV_DEPTH) return;
    for (const name of new Set([...(vis.relationNames ?? NO_NAMES), ...vis.withGrants])) {
      const prop = props[name];
      if (!prop || !isMetaFieldVisible(name, vis)) continue;
      const sub = vis.relation?.(name);
      if (sub) visit(sub, prop, depth + 1);
    }
  };
  visit(root, meta.type, 0);
  const out = new Map<object, MetaVisibility | null>();
  await Promise.all(
    [...types].map(async (type) => {
      const read = await evaluateTypeRead(type);
      out.set(type, read ? buildScopeVisibility(read.scopes, read.table) : null);
    }),
  );
  return out;
}

// Per table: the annotated types its own (non-nav) fields `ref` into.
const refTypesCache = new WeakMap<VisibilityTableSource, ReadonlySet<object>>();

function foreignRefTypes(table: VisibilityTableSource): ReadonlySet<object> {
  const flatMap = table.flatMap;
  if (!flatMap) return NO_TYPES;
  return getOrCreate(refTypesCache, table, () => {
    const nav = navFieldsOf(table);
    const out = new Set<object>();
    for (const [path, entry] of flatMap) {
      if (hasSelfOrAncestor(nav, path)) continue;
      const target = refTargetOf(entry);
      if (target && target.type !== table.type) out.add(target.type);
    }
    return out;
  });
}

const NO_TYPES: ReadonlySet<object> = new Set();

/** Controls a text / vector search needs, dropped from `crud.query` / `crud.pages` when unusable. */
const TEXT_SEARCH_CONTROLS = ["search", "fuzzy"];
const VECTOR_CONTROLS = ["vector", "threshold"];

/**
 * Drop `searchIndexes` reading a hidden field, recompute the search /
 * vector / geo flags over what is left (native search, or the visible
 * `@db.column.searchable` fallback), and remove the controls that became
 * unusable from the `query` / `pages` control lists (`crud.geo` goes with
 * the last visible geo index).
 */
function pruneSearchSurface(
  meta: TMetaResponse,
  original: TMetaResponse,
  vis: MetaVisibility,
  indexes: readonly TDbIndexFieldPaths[] | undefined,
): TMetaResponse {
  if (!indexes) return meta;
  const shown = indexes.filter((e) => e.fields.every((f) => isMetaFieldVisible(f, vis)));
  const shownOf = (type: TDbIndexFieldPaths["type"]) => shown.some((e) => e.type === type);
  const hasText = indexes.some((e) => e.type === "text");
  const native = vis.table?.isSearchable?.() ?? hasText;
  const fallback = searchFallbackVisible(meta, vis.table);
  const searchable = original.searchable && ((native && (!hasText || shownOf("text"))) || fallback);
  const vectorSearchable = original.vectorSearchable && shownOf("vector");
  const geoSearchable = original.geoSearchable === true ? shownOf("geo") : original.geoSearchable;

  const out: TMetaResponse = {
    ...meta,
    searchIndexes: original.searchIndexes.filter((info) =>
      shown.some((e) => e.name === info.name && e.type === (info.type ?? "text")),
    ),
    searchable,
    vectorSearchable,
  };
  if (geoSearchable !== undefined) out.geoSearchable = geoSearchable;

  const drop = new Set<string>();
  if (original.searchable && !searchable && !vectorSearchable) {
    for (const c of TEXT_SEARCH_CONTROLS) drop.add(c);
  }
  if (original.vectorSearchable && !vectorSearchable) for (const c of VECTOR_CONTROLS) drop.add(c);
  if (hasText && !shownOf("text")) drop.add("index");
  if (drop.size > 0 || (original.geoSearchable && !geoSearchable)) {
    const crud = { ...meta.crud };
    for (const op of ["query", "pages"] as const) {
      const list = crud[op];
      if (list && drop.size > 0) crud[op] = list.filter((c) => !drop.has(c));
    }
    if (original.geoSearchable && !geoSearchable) delete crud.geo;
    out.crud = crud;
  }
  return out;
}

/** A `@db.column.searchable` field is still listed (visible) in the pruned `fields`. */
function searchFallbackVisible(
  meta: TMetaResponse,
  table: VisibilityTableSource | undefined,
): boolean {
  if (!table?.flatMap) return false;
  for (const path of Object.keys(meta.fields)) {
    const entry = table.flatMap.get(path) as
      | { metadata?: { has?: (key: string) => boolean } }
      | undefined;
    if (entry?.metadata?.has?.("db.column.searchable") && !meta.fields[path].writeOnly) return true;
  }
  return false;
}

/** The current controller's `indexFieldPaths()` (moost-db 0.1.143 DB readables), if it has one. */
function controllerIndexes(instance: object): readonly TDbIndexFieldPaths[] | undefined {
  const c = instance as { indexFieldPaths?: () => readonly TDbIndexFieldPaths[] };
  return typeof c.indexFieldPaths === "function" ? c.indexFieldPaths() : undefined;
}

interface ControllerMethodIndex {
  /** `@DbAction` name → the methods declaring it (absent for class-level action entries). */
  actionMethods: ReadonlyMap<string, readonly string[]>;
  /** Every method name on the instance's prototype chain. */
  methods: ReadonlySet<string>;
}

// Per-class memoization: controller and method decorator metadata are bound to
// the class at registration time and never mutate per-request.
const methodIndexCache = new WeakMap<Function, ControllerMethodIndex>();

/**
 * THE ARBAC ids an action is authorized as — used by the `/meta` overlay,
 * `authorizeForm`, `GET meta/actions` and `actionRowScope` alike: every
 * method declaring the `@DbAction` (allowed when ANY is — a union), each
 * with `useArbac()` precedence; a class-level `@DbActions` entry (no handler
 * method) → `{ resource: defaultResource, action: name }`. `defaultResource`
 * defaults to the controller's class-level resource.
 *
 * @since 0.1.72
 */
export function actionArbacIds(
  instance: object,
  name: string,
  defaultResource: string = controllerArbacResource(instance),
): ArbacHandlerIds[] {
  const methods = controllerMethodIndex(instance).actionMethods.get(name);
  return methods?.length
    ? methods.map((m) => resolveHandlerArbacIds(instance, m))
    : [{ resource: defaultResource, action: name }];
}

/**
 * The action `names` the caller holds a grant on — each evaluated as
 * {@link actionArbacIds} names it (memoized per event). THE action rule of
 * the `/meta` overlay, `allowedActions` (`$actions`, `GET meta/actions`).
 */
export async function grantedActions(
  instance: object,
  names: readonly string[],
): Promise<string[]> {
  const granted = await Promise.all(
    names.map((name) => evaluateHandlers(actionArbacIds(instance, name))),
  );
  return names.filter((_, i) => granted[i] !== undefined);
}

/** The controller's class-level ARBAC resource (`@ArbacResource` → controller id → class name). */
function controllerArbacResource(instance: object): string {
  return arbacIdsFromMeta(getMoostMate().read(instance), undefined, instance, "").resource;
}

/** A controller class's methods and `@DbAction` name → methods map (memoized per class). */
export function controllerMethodIndex(instance: object): ControllerMethodIndex {
  return getOrCreate(methodIndexCache, getConstructor(instance), () => {
    const cc = useControllerContext();
    const methods = new Set(collectMethodNames(instance));
    const actionMethods = new Map<string, string[]>();
    for (const methodName of methods) {
      const name = cc.getMethodMeta<TArbacMeta>(methodName)?.atscript_db_action?.name;
      if (name) getOrCreate(actionMethods, name, () => []).push(methodName);
    }
    return { actionMethods, methods };
  });
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
