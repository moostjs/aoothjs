import type { TProjection } from "./types";

export type TProjectionMode = "include" | "exclude" | "empty";

/**
 * Determine whether a projection is in inclusion mode (all 1s),
 * exclusion mode (all 0s), or empty (`{}`, no restriction).
 *
 * @throws when a single projection mixes 0 and 1 values
 */
export function getProjectionMode(proj: TProjection): TProjectionMode {
  const values = Object.values(proj);
  if (values.length === 0) return "empty";
  const hasInclude = values.includes(1);
  const hasExclude = values.includes(0);
  if (hasInclude && hasExclude) {
    throw new Error(
      "Invalid projection: cannot mix include (1) and exclude (0) in a single projection",
    );
  }
  return hasInclude ? "include" : "exclude";
}

/**
 * Check whether a dot-path field is allowed by a projection.
 *
 * Inclusion mode: a field is allowed if it, any of its parents, or any of its children
 *   is explicitly listed.
 * Exclusion mode: a field is allowed unless it or any of its parents is excluded.
 * Empty projection: every field is allowed.
 */
export function isFieldAllowed(field: string, projection: TProjection): boolean {
  const mode = getProjectionMode(projection);
  if (mode === "empty") return true;
  // Exclusion: allowed unless the field or an ancestor is excluded.
  if (mode === "exclude") return !coversPath(projection, field);
  // Inclusion: the field or an ancestor is included — or a child is (field
  // "a" with `{"a.b": 1}` is allowed since it contains included children).
  return coversPath(projection, field) || descendantKeys(Object.keys(projection), field).length > 0;
}

/**
 * Combines projections from multiple RBAC role grants under additive semantics:
 * more roles = broader access. Each projection represents a set of allowed fields:
 * include-mode `{a:1}` allows `{a}`; exclude-mode `{a:0}` allows `universe \ {a}`;
 * empty `{}` allows the universe.
 *
 * A field is effectively allowed if any input grants it. Equivalently, a field
 * stays excluded only if (a) no include-mode role grants it explicitly, AND (b)
 * every exclude-mode role excludes it.
 *
 * Output mode:
 * - All-include input → include-mode result (union of include keys)
 * - At least one exclude-mode → exclude-mode result (or `{}` if no fields excluded)
 * - Empty input or any universal grant `{}` → `{}` (universe)
 *
 * Within a single projection, mixing 1 and 0 keys is an error (call sites should
 * normalize first). Across projections, mixing modes is supported and resolves
 * via the additive rule above.
 *
 * @throws when a single projection mixes 1 and 0 keys, or contains an invalid value
 */
export function unionProjections(...projections: TProjection[]): TProjection {
  // Empty input → universe (no constraint)
  if (projections.length === 0) return {};

  const includeKeys = new Set<string>();
  const excludeKeys: Set<string>[] = []; // one set per exclude-mode projection
  let hasUniverseGrant = false; // any {} input

  for (const p of projections) {
    const entries = Object.entries(p);
    if (entries.length === 0) {
      // Empty projection {} → universe → unioned with anything = universe
      hasUniverseGrant = true;
      continue;
    }
    let mode: "include" | "exclude" | null = null;
    const localExcludes = new Set<string>();
    for (const [k, v] of entries) {
      if (v === 1) {
        if (mode === "exclude") {
          throw new Error(
            `unionProjections: projection mixes 1 and 0 within itself: ${JSON.stringify(p)}`,
          );
        }
        mode = "include";
        includeKeys.add(k);
      } else if (v === 0) {
        if (mode === "include") {
          throw new Error(
            `unionProjections: projection mixes 1 and 0 within itself: ${JSON.stringify(p)}`,
          );
        }
        mode = "exclude";
        localExcludes.add(k);
      } else {
        throw new Error(
          `unionProjections: invalid projection value ${String(v)} for key ${k} (must be 0 or 1)`,
        );
      }
    }
    if (mode === "exclude") excludeKeys.push(localExcludes);
  }

  if (hasUniverseGrant) return {}; // universe wins

  if (excludeKeys.length === 0) {
    // All-include only
    if (includeKeys.size === 0) return {}; // nothing? treat as universe (no constraint)
    return Object.fromEntries([...includeKeys].toSorted().map((k) => [k, 1]));
  }

  // Intersect all exclude-mode key sets by PATH — a field stays denied only if
  // EVERY exclude role denies it or one of its ancestors (`{a:0}` ∪ `{"a.c":0}`
  // still denies `a.c`; exact-key matching would have widened to universe).
  const candidates = new Set<string>();
  for (const set of excludeKeys) for (const k of set) candidates.add(k);
  const denyAcc = [...candidates].filter((k) => excludeKeys.every((set) => coversPath(set, k)));

  // Subtract include keys (a field granted by some include — itself or via an
  // included ancestor — is no longer denied). An include of a DESCENDANT of a
  // denied parent (`{"a.b":1}` ∪ `{a:0}`) cannot be carved out without a
  // schema; the parent stays denied (narrower, never wider).
  const effectivelyExcluded = denyAcc.filter((k) => !coversPath(includeKeys, k)).toSorted();

  if (effectivelyExcluded.length === 0) return {}; // universe — all denials covered by some include
  return Object.fromEntries(effectivelyExcluded.map((k) => [k, 0]));
}

/** `path` itself or one of its ancestors is a key of `keys` (own keys only). */
function coversPath(keys: ReadonlySet<string> | TProjection, path: string): boolean {
  const has =
    keys instanceof Set ? (k: string) => keys.has(k) : (k: string) => Object.hasOwn(keys, k);
  if (has(path)) return true;
  let pos = path.length;
  while ((pos = path.lastIndexOf(".", pos - 1)) !== -1) {
    if (has(path.slice(0, pos))) return true;
  }
  return false;
}

/** The `keys` strictly below `path` (`a` → `a.b`, `a.b.c`). */
function descendantKeys(keys: readonly string[], path: string): string[] {
  const prefix = `${path}.`;
  return keys.filter((k) => k.startsWith(prefix));
}

/**
 * Direct child field paths of a nested-object path (`a` → `["a.b", "a.c"]`),
 * from the model schema; `[]` for a leaf. Lets a projection intersection
 * subtract a nested exclusion from an included parent exactly.
 */
export type TProjectionChildren = (path: string) => readonly string[];

/** Schema recursion bound — a guard against a cyclic `childrenOf`. */
const MAX_SCHEMA_DEPTH = 32;

/**
 * Depth-first walk from `root` through its schema children. `visit` gets each
 * path with its children (`[]` for a leaf, an unknown schema, or past
 * {@link MAX_SCHEMA_DEPTH}) and returns whether to descend into them.
 */
function walkSchema(
  root: string,
  childrenOf: TProjectionChildren | undefined,
  visit: (path: string, children: readonly string[]) => boolean,
): void {
  const go = (path: string, depth: number): void => {
    const children = depth < MAX_SCHEMA_DEPTH ? (childrenOf?.(path) ?? []) : [];
    if (visit(path, children)) for (const child of children) go(child, depth + 1);
  };
  go(root, 0);
}

/** Include-mode `inc` minus exclude-mode `exc`, by path. */
function includeMinusExclude(
  inc: TProjection,
  exc: TProjection,
  childrenOf: TProjectionChildren | undefined,
): TProjection {
  const excKeys = Object.keys(exc);
  const out: TProjection = {};
  for (const key of Object.keys(inc)) {
    walkSchema(key, childrenOf, (path) => {
      if (coversPath(exc, path)) return false; // the path or an ancestor is excluded
      if (descendantKeys(excKeys, path).length === 0) {
        out[path] = 1;
        return false;
      }
      // A descendant is excluded: split the parent into its children. Without
      // a schema the remainder is not representable in one include projection
      // — drop the parent (fail closed; never include the excluded part).
      return true;
    });
  }
  return out;
}

/**
 * Rewrite an exclusion projection so every excluded nested-object parent is
 * named by its LEAF paths (`{ a: 0 }` → `{ "a.b": 0, "a.c": 0 }`), via the
 * schema. Flattening storage adapters invert an exclusion against their leaf
 * columns, so a parent key alone would strip nothing. Without `childrenOf`,
 * or for an inclusion / empty projection, the input is returned unchanged.
 */
export function expandExcludeToLeaves(
  projection: TProjection,
  childrenOf: TProjectionChildren | undefined,
): TProjection {
  if (!childrenOf || getProjectionMode(projection) !== "exclude") return projection;
  const out: TProjection = {};
  for (const key of Object.keys(projection)) {
    walkSchema(key, childrenOf, (path, children) => {
      if (children.length === 0) out[path] = 0;
      return children.length > 0;
    });
  }
  return out;
}

/**
 * The exact field intersection of two projections, by PATH — never wider than
 * either side. Returns `null` when no field survives (a disjoint pair, or
 * `{a:1}` ∩ `{a:0}`); `{}` only when BOTH sides are unrestricted.
 *
 * - include ∩ include: a key survives when the other side includes it or an
 *   ancestor; when the other side only includes DESCENDANTS of it, those
 *   descendants survive instead (`{a:1}` ∩ `{"a.b":1}` → `{"a.b":1}`).
 * - include ∩ exclude: include keys minus excluded paths. An include key with
 *   an excluded DESCENDANT (`{a:1}` ∩ `{"a.c":0}`) is split via `childrenOf`
 *   (→ `{"a.b":1}`); without a schema it is dropped (fail closed).
 * - exclude ∩ exclude: union of the excluded keys.
 *
 * @param childrenOf - optional schema lookup for exact nested subtraction
 */
export function intersectProjections(
  a: TProjection,
  b: TProjection,
  childrenOf?: TProjectionChildren,
): TProjection | null {
  const aMode = getProjectionMode(a);
  const bMode = getProjectionMode(b);
  if (aMode === "empty") return { ...b };
  if (bMode === "empty") return { ...a };

  let out: TProjection;
  if (aMode === "include" && bMode === "include") {
    out = {};
    const bKeys = Object.keys(b);
    for (const key of Object.keys(a)) {
      if (coversPath(b, key)) out[key] = 1;
      else for (const d of descendantKeys(bKeys, key)) out[d] = 1;
    }
  } else if (aMode === "exclude" && bMode === "exclude") {
    out = {};
    for (const key of [...Object.keys(a), ...Object.keys(b)]) out[key] = 0;
  } else if (aMode === "include") {
    out = includeMinusExclude(a, b, childrenOf);
  } else {
    out = includeMinusExclude(b, a, childrenOf);
  }
  return Object.keys(out).length > 0 ? out : null;
}

/**
 * Restrict a desired projection to only fields allowed by an access-control projection.
 *
 * The result is the path-wise intersection ({@link intersectProjections}):
 * only fields that pass both `desired` and `accessControl` survive, and a
 * requested parent narrows to the access-controlled descendants
 * (`{a:1}` against `{"a.b":1}` → `{"a.b":1}`). Either side may be empty
 * (unrestricted), in which case the other side is returned.
 *
 * When NO field survives, the result is `accessControl` itself — never the
 * empty (universe) projection. That fallback is safe only because
 * `accessControl` is the ceiling; to conjoin two ceilings (attenuation), use
 * {@link intersectProjections} and handle its `null`.
 *
 * @param desired - the projection the caller asked for
 * @param accessControl - the projection allowed by RBAC
 * @param childrenOf - optional schema lookup for exact nested subtraction
 */
export function restrictProjection(
  desired: TProjection,
  accessControl: TProjection,
  childrenOf?: TProjectionChildren,
): TProjection {
  return intersectProjections(desired, accessControl, childrenOf) ?? { ...accessControl };
}
