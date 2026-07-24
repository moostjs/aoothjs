import { isFieldAllowed, unionProjections } from "@aooth/arbac";
import type { TProjection } from "@aooth/arbac";
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
  /** Constrained projection union (never the empty/universe projection). */
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
  if (writable === "all") return true;
  if (writable.has(path)) return true;
  let pos = path.length;
  while ((pos = path.lastIndexOf(".", pos - 1)) !== -1) {
    if (writable.has(path.slice(0, pos))) return true;
  }
  return false;
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
 * Whether a flattened dot-path field exists for this principal. A path under
 * a `with`-granted relation passes unconditionally — the sub-scope governs
 * the joined content, and rejecting the path here would break the very `$with`
 * expansion the grant permits.
 */
export function isMetaFieldVisible(path: string, vis: MetaVisibility): boolean {
  if (vis.alwaysVisible.has(path)) return true;
  const dot = path.indexOf(".");
  const head = dot === -1 ? path : path.slice(0, dot);
  if (vis.withGrants.has(head)) return true;
  return isFieldAllowed(path, vis.allowed);
}

/**
 * Prune a `/meta` envelope down to the fields the principal's read scopes can
 * ever surface, so a scoped UI cannot even OFFER an out-of-scope column (the
 * designed contract: the projection removes fields from the META entirely,
 * not just from row payloads). Pruned facets:
 *
 * - `fields` — the flat capability map (sortable/filterable flags).
 * - `type` — the serialized annotated type (what dynamic clients build
 *   tables/forms from); nested object props prune by dot-path, relation props
 *   survive whole when the relation itself is visible.
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
 * dot-path prefix ("" at the root). Top-level relation props (nav props named
 * in `meta.relations`) are kept or dropped WHOLE — their internal shape is the
 * joined model's business (content scoping happens per-request through the
 * `with` sub-scopes), while own-field subtrees prune recursively so an
 * include-mode union like `{ "password.hash": 1 }` keeps `password` with only
 * `hash` inside.
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
      if (basePath === "" && relationNames.has(name)) {
        if (isMetaFieldVisible(name, vis)) props[name] = prop;
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

/** The scopes-derived half of {@link MetaVisibility} (no `alwaysVisible`). */
interface ScopeVisibility {
  allowed: TProjection | undefined;
  withGrants: ReadonlySet<string>;
}

const UNRESTRICTED_VISIBILITY: ScopeVisibility = { allowed: undefined, withGrants: new Set() };

// `hasField` runs once per field a request references ($select / filter /
// sort keys — client-controlled, so potentially many per request), and the
// scopes array is identity-stable for the event once the authorize
// interceptor / transformFilter calls `setScopes(...)` — memoize the union +
// with-grant set per array instead of recomputing them per field.
const scopeVisibilityCache = new WeakMap<ArbacDbScope[], ScopeVisibility>();

function scopeVisibility(scopes: ArbacDbScope[]): ScopeVisibility {
  if (scopes.length === 0) return UNRESTRICTED_VISIBILITY;
  let vis = scopeVisibilityCache.get(scopes);
  if (!vis) {
    vis = { allowed: unionScopeProjection(scopes), withGrants: collectWithGrantNames(scopes) };
    scopeVisibilityCache.set(scopes, vis);
  }
  return vis;
}

/**
 * Shared body of both ARBAC controllers' `hasField` overrides (BUG-3 twin of
 * the `/meta` pruning): a field outside the read-scope projection union must
 * be indistinguishable from a field that does not exist. Returns `true` when
 * the scopes impose no projection restriction.
 */
export function isScopedFieldVisible(
  scopes: ArbacDbScope[],
  path: string,
  alwaysVisible: ReadonlySet<string>,
): boolean {
  const { allowed, withGrants } = scopeVisibility(scopes);
  if (!allowed) return true;
  return isMetaFieldVisible(path, { allowed, alwaysVisible, withGrants });
}

// Memoized per controller class (same rationale as the controller module's
// identifierFieldsCache): `primaryKeys` / `preferredId` are decoration-derived
// and stable for the class's lifetime, and the set is needed once per
// `hasField` call.
const alwaysVisibleFieldsCache = new WeakMap<
  new (...args: never[]) => unknown,
  ReadonlySet<string>
>();

/**
 * PK + `preferredId` for a controller's table/readable — the
 * {@link MetaVisibility.alwaysVisible} set both `applyMetaOverlay` and
 * `hasField` pass into the visibility checks.
 */
export function metaAlwaysVisibleFields(
  controller: object,
  source: { primaryKeys: readonly string[]; preferredId: readonly string[] },
): ReadonlySet<string> {
  const ctor = controller.constructor as new (...args: never[]) => unknown;
  let set = alwaysVisibleFieldsCache.get(ctor);
  if (!set) {
    set = new Set([...source.primaryKeys, ...source.preferredId]);
    alwaysVisibleFieldsCache.set(ctor, set);
  }
  return set;
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
 * for their insert/update forms. `alwaysVisible` (PK + preferredId) is never
 * pruned — reads always return those fields (projection widening / id
 * addressing).
 */
export async function applyArbacMetaOverlay(
  meta: TMetaResponse,
  alwaysVisible: ReadonlySet<string>,
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
    const scopes = crudResults[i].scopes as ArbacDbScope[] | undefined;
    if (WRITE_CRUD_OPS.has(crudKeys[i])) {
      if (!scopes || scopes.length === 0) writeUnrestricted = true;
      else writeScopes.push(...scopes);
      continue;
    }
    if (!scopes || scopes.length === 0) readUnrestricted = true;
    else readScopes.push(...scopes);
  }
  if (!readUnrestricted) {
    const allowed = unionScopeProjection(readScopes);
    if (allowed) {
      overlaid = pruneMetaByVisibility(overlaid, {
        allowed,
        alwaysVisible,
        withGrants: collectWithGrantNames(readScopes),
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
