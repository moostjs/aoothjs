import {
  effectiveScope,
  getProjectionMode,
  isFieldAllowed,
  needsInheritedConjunction,
} from "@aooth/arbac";
import type { TProjection } from "@aooth/arbac";
import { findAncestorInSet } from "@atscript/db";

import type { ArbacDbScope } from "./as-arbac-db-controller";
import { getOrCreate, hasSelfOrAncestor } from "./helpers";

/**
 * The slice of an atscript-db readable (table / view) the visibility walk
 * reads — a moost-db controller's `this.readable` satisfies it: identifiers
 * (always visible), nav relations (to reach the joined table), the
 * flattened schema (to split `$select` parents by scope) and the field
 * descriptors (atomic JSON columns, derived-column sources).
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
  /**
   * The readable's annotated type — the `$with` target registry key and the
   * owner a self-`ref` points at.
   *
   * @since 0.1.72
   */
  type?: object;
  /**
   * Field descriptors: `derived` marks a `@db.column.derived` field
   * (visible only while its source is).
   *
   * @since 0.1.72
   */
  fieldDescriptors?: ReadonlyArray<{ path: string; derived?: { sourcePath: string } }>;
  /**
   * Paths stored as ONE JSON column (atscript-db's `readable.jsonParents`,
   * relational adapters): visible whole or not at all.
   *
   * @since 0.1.72
   */
  jsonParents?: ReadonlySet<string>;
  /** Whether the adapter searches natively (`/meta` search-surface pruning). @since 0.1.72 */
  isSearchable?(): boolean;
}

/** Relation name → the visibility its joined rows obey, or `null` when hidden. */
export type ArbacRelationResolution = ReadonlyMap<string, MetaVisibility | null>;

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
  /** Relation names declared via `with.<name>` (see {@link collectWithGrantNames}). */
  withGrants: ReadonlySet<string>;
  /**
   * Visibility of a relation's JOINED fields: for a declared relation, the
   * union of its `with.<name>` sub-scopes; for an undeclared one, the
   * caller's own read scopes on the related table (resolved per request —
   * `undefined` when the relation is hidden). The related table's own
   * identifiers are always visible. A path `rel.x.y` is checked as `x.y`
   * against it, recursively. A hand-built visibility without it lets
   * declared paths through unchecked (legacy behavior).
   */
  relation?: (name: string) => MetaVisibility | undefined;
  /**
   * Relations of this level's table. An undeclared one is visible only when
   * the projection union allows its name AND {@link relation} resolves it
   * (the `$with` inherit-target policy); absent → relation names are
   * ordinary projection paths (legacy).
   */
  relationNames?: ReadonlySet<string>;
  /**
   * Precompiled `isFieldAllowed(path, allowed)` — plus the derived-column
   * rule (a `@db.column.derived` field is visible only while its source is).
   * Supplied by {@link buildScopeVisibility}; a hand-built visibility falls
   * back to `isFieldAllowed`.
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
  /**
   * Nav relations the WRITE scopes opt into nested writes (union of
   * `nestedWrites`). A relation path is writable only when listed here (and
   * covered by {@link writable}) — mirroring the 403 the write endpoints
   * answer for any other nav key. Absent → no relation is writable.
   *
   * @since 0.1.72
   */
  nestedWrites?: ReadonlySet<string>;
}

/**
 * Union the per-scope `projection` whitelists into the single access-control
 * projection used for FIELD-EXISTENCE decisions (`hasField` parity + `/meta`
 * pruning). Returns `undefined` when the union imposes no restriction — no
 * scopes at all, or any scope without a `projection` (a universal grant makes
 * `unionProjections` collapse to the universe `{}`).
 */
export function unionScopeProjection(scopes: ArbacDbScope[]): TProjection | undefined {
  const allowed = effectiveScope(scopes).projection;
  return Object.keys(allowed).length === 0 ? undefined : allowed;
}

/**
 * Relation names any scope explicitly declares via `with.<name>` — those
 * relations are governed by the declared sub-scopes alone (parent authority),
 * and the declaration implies the relation EXISTS for this principal even
 * when the projection union does not name it (see {@link ArbacDbScope.with}).
 */
export function collectWithGrantNames(scopes: ArbacDbScope[]): ReadonlySet<string> {
  return effectiveScope(scopes).withNames;
}

/**
 * Union of write-scope `allowedFields`; `"all"` for field-unrestricted write
 * access. The whitelist exists only when at least one scope carries an
 * `allowedFields` array — scoped-but-unlisted writes are field-unrestricted.
 */
export function collectWritableFields(
  scopes: ArbacDbScope[],
  unrestricted: boolean,
): ReadonlySet<string> | "all" | undefined {
  if (unrestricted) return "all";
  if (scopes.length === 0) return undefined;
  const fields = effectiveScope(scopes).allowedFields;
  if (!fields) return "all";
  return fields.size > 0 ? fields : undefined;
}

/**
 * Whether a flattened dot-path field exists for this principal.
 *
 * - A relation declared via `with.<name>` is visible; a path under it
 *   (`rel.x.y`) is checked as `x.y` against its sub-scope visibility.
 * - An undeclared relation of the table (see {@link MetaVisibility.relationNames})
 *   is visible only when the projection allows its name and the caller's own
 *   grant on the related table resolved ({@link MetaVisibility.relation});
 *   paths under it are checked against that grant.
 * - Anything else follows the projection union (and the derived-column rule).
 *
 * So a field a joined table hides is as unknown in a `$with` sub-query as a
 * top-level hidden column is in the main query (no filter/sort value oracle).
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
  const allowed = (p: string) =>
    vis.isAllowed ? vis.isAllowed(p) : isFieldAllowed(p, vis.allowed);
  if (vis.relationNames?.has(head)) {
    if (!allowed(head)) return false;
    const sub = vis.relation?.(head);
    if (!sub) return false;
    return dot === -1 || isMetaFieldVisible(path.slice(dot + 1), sub);
  }
  return allowed(path);
}

const NO_NAMES: ReadonlySet<string> = new Set();

// Identifiers per table object (decoration-derived, stable for its lifetime).
const identifierSetCache = new WeakMap<VisibilityTableSource, ReadonlySet<string>>();

/** PK + `preferredId` of a table — the identifiers reads always return. */
export function identifierSet(table: VisibilityTableSource | undefined): ReadonlySet<string> {
  if (!table) return NO_NAMES;
  return getOrCreate(
    identifierSetCache,
    table,
    () => new Set([...table.primaryKeys, ...table.preferredId]),
  );
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

/** What the visibility rules read from a table's schema, derived once per table. */
interface TablePolicy {
  /** Atomic JSON columns (`readable.jsonParents`). */
  json: ReadonlySet<string>;
  /** `@db.column.derived` path → its source path. */
  derived: ReadonlyMap<string, string>;
  /** The table's relation names (`undefined` without a table: legacy). */
  relations: ReadonlySet<string> | undefined;
}

const NO_POLICY: TablePolicy = { json: NO_NAMES, derived: new Map(), relations: undefined };
const tablePolicyCache = new WeakMap<VisibilityTableSource, TablePolicy>();

export function tablePolicy(table: VisibilityTableSource | undefined): TablePolicy {
  if (!table) return NO_POLICY;
  return getOrCreate(tablePolicyCache, table, () => {
    const derived = new Map<string, string>();
    for (const fd of table.fieldDescriptors ?? []) {
      if (fd.derived?.sourcePath) derived.set(fd.path, fd.derived.sourcePath);
    }
    return {
      json: table.jsonParents ?? NO_NAMES,
      derived,
      relations: table.relations ? new Set(table.relations.keys()) : undefined,
    };
  });
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
 * The projection union made executable and consistent for the table:
 *
 * - **atomic JSON** — a scope key inside an atomic JSON column (relational
 *   adapters) is folded onto the column: an excluded leaf hides the whole
 *   column (`{ "settings.apiKey": 0 }` → `{ settings: 0 }`), a whitelisted
 *   leaf alone does not reveal it (the key is dropped — fail closed);
 * - **derived columns** — a `@db.column.derived` field whose source the
 *   projection hides is excluded too (or dropped from a whitelist).
 *
 * An include projection the rewrite emptied would read as the universe: it
 * falls back to the table's identifiers (reads return them anyway), else
 * keeps the original (unexecutable → fails closed rather than widening).
 */
function normalizeAllowed(
  allowed: TProjection,
  policy: TablePolicy,
  identifiers: ReadonlySet<string>,
): TProjection {
  const keys = Object.keys(allowed);
  if (keys.length === 0) return allowed;
  const exclude = getProjectionMode(allowed) === "exclude";
  let out: TProjection | undefined;
  if (policy.json.size > 0) {
    for (const key of keys) {
      const column = findAncestorInSet(key, policy.json);
      if (column === undefined) continue;
      out ??= { ...allowed };
      delete out[key];
      if (exclude) out[column] = 0;
    }
  }
  if (policy.derived.size > 0) {
    const visible = compileProjection(out ?? allowed);
    for (const [path, source] of policy.derived) {
      if (identifiers.has(source) || visible(source)) continue;
      if (exclude) {
        if (!visible(path)) continue;
        out ??= { ...allowed };
        out[path] = 0;
      } else if ((out ?? allowed)[path] !== undefined) {
        out ??= { ...allowed };
        delete out[path];
      }
    }
  }
  if (!out || exclude || Object.keys(out).length > 0) return out ?? allowed;
  if (identifiers.size === 0) return allowed;
  return Object.fromEntries([...identifiers].map((id) => [id, 1 as const]));
}

/**
 * The declared relations governed by their `with` sub-scopes alone. A
 * sub-scope a credential conjunction marked `INHERITED_CONJUNCTION` (declared
 * by one side only) is not: such a relation follows the undeclared-relation
 * rule — visible only once resolved (conjoined with the caller's own grant
 * on the related table).
 */
function parentAuthorityGrants(eff: ReturnType<typeof effectiveScope>): ReadonlySet<string> {
  const names = eff.withNames;
  for (const name of names) {
    if (eff.withScopes(name).some(needsInheritedConjunction)) {
      return new Set([...names].filter((n) => !eff.withScopes(n).some(needsInheritedConjunction)));
    }
  }
  return names;
}

/** Options of {@link buildScopeVisibility}. @since 0.1.72 */
export interface ScopeVisibilityOptions {
  /** Identifiers exempt from the projection; default: the table's PK + `preferredId`. */
  alwaysVisible?: ReadonlySet<string>;
  /**
   * The undeclared relations resolved for this level (the caller's own grant
   * on each related table — see `resolveRelationTree`); an undeclared
   * relation missing here is hidden.
   */
  relations?: ArbacRelationResolution;
}

/**
 * Build the {@link MetaVisibility} a set of read scopes implies — the single
 * structure behind `hasField`, `/meta` pruning, `$select` value stripping
 * and the `$with` overlay, so they cannot drift. Own fields: the projection
 * union (`{}` when unrestricted), normalized for atomic JSON columns and
 * derived-column sources, precompiled into `isAllowed`. Relations: an
 * undeclared one → its node in `relations` (none → hidden); a declared
 * `with.<name>` → the union of its sub-scopes (lazily built when `relations`
 * has no node for it). The related table's own PK / `preferredId` stay
 * visible.
 *
 * @param opts - {@link ScopeVisibilityOptions}; a bare identifier set is the
 *   0.1.71 `alwaysVisible` argument
 */
export function buildScopeVisibility(
  scopes: ArbacDbScope[],
  table: VisibilityTableSource | undefined,
  opts: ScopeVisibilityOptions | ReadonlySet<string> = {},
): MetaVisibility {
  const { alwaysVisible = identifierSet(table), relations } =
    opts instanceof Set ? { alwaysVisible: opts } : (opts as ScopeVisibilityOptions);
  const eff = effectiveScope(scopes);
  const withGrants = parentAuthorityGrants(eff);
  const policy = tablePolicy(table);
  const allowed = normalizeAllowed(unionScopeProjection(scopes) ?? {}, policy, alwaysVisible);
  const base = compileProjection(allowed);
  const isAllowed =
    policy.derived.size === 0
      ? base
      : (path: string) => {
          if (!base(path)) return false;
          const source = policy.derived.get(path);
          return source === undefined || alwaysVisible.has(source) || base(source);
        };
  const declared = new Map<string, MetaVisibility>();
  return {
    allowed,
    alwaysVisible,
    withGrants,
    relationNames: policy.relations,
    scopes,
    table,
    isAllowed,
    relation(name) {
      const resolved = relations?.get(name);
      if (resolved || !withGrants.has(name)) return resolved ?? undefined;
      return getOrCreate(declared, name, () =>
        buildScopeVisibility(eff.withScopes(name) as ArbacDbScope[], table?.relatedTable?.(name)),
      );
    },
  };
}

// The scopes array is identity-stable for an event once resolved — memoize
// the visibility per (scopes array, source) instead of rebuilding the unions
// per field. A bare identifier set (the 0.1.67 argument) keys its own entry;
// `NO_TABLE` keys the table-less one.
const scopeVisibilityCache = new WeakMap<
  ArbacDbScope[],
  WeakMap<VisibilityTableSource | ReadonlySet<string>, MetaVisibility>
>();
const NO_TABLE: VisibilityTableSource = { primaryKeys: [], preferredId: [] };

/** `source` is an identifier set (the 0.1.67 signatures), not a readable. */
export function isIdentifierSet(
  source: VisibilityTableSource | ReadonlySet<string>,
): source is ReadonlySet<string> {
  return !("primaryKeys" in source);
}

/**
 * The memoized {@link MetaVisibility} for `scopes` over `source` (a
 * readable, or an `alwaysVisible` identifier set), without relation
 * resolution (undeclared relations hidden).
 */
export function scopeVisibility(
  scopes: ArbacDbScope[],
  source: VisibilityTableSource | ReadonlySet<string> = NO_TABLE,
): MetaVisibility {
  const perSource = getOrCreate(scopeVisibilityCache, scopes, () => new WeakMap());
  return getOrCreate(perSource, source, () =>
    isIdentifierSet(source)
      ? buildScopeVisibility(scopes, undefined, source)
      : buildScopeVisibility(scopes, source === NO_TABLE ? undefined : source),
  );
}
