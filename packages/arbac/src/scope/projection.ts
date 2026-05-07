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

  if (mode === "include") {
    // Field is allowed if it or any of its parents is explicitly included
    if (projection[field] === 1) return true;
    // Check if a parent path is included
    const parts = field.split(".");
    for (let i = 1; i < parts.length; i++) {
      const parent = parts.slice(0, i).join(".");
      if (projection[parent] === 1) return true;
    }
    // Check if a child path is included (field "a" with projection {"a.b": 1} — allow "a" since it contains included children)
    for (const key of Object.keys(projection)) {
      if (key.startsWith(`${field}.`)) return true;
    }
    return false;
  }

  // Exclusion mode: field is allowed unless it or any of its parents is excluded
  if (projection[field] === 0) return false;
  const parts = field.split(".");
  for (let i = 1; i < parts.length; i++) {
    const parent = parts.slice(0, i).join(".");
    if (projection[parent] === 0) return false;
  }
  return true;
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

  // Intersect all exclude-mode key sets — only fields denied by EVERY exclude role
  let denyAcc = new Set(excludeKeys[0]);
  for (let i = 1; i < excludeKeys.length; i++) {
    denyAcc = new Set([...denyAcc].filter((k) => excludeKeys[i].has(k)));
  }

  // Subtract include keys (a field explicitly granted by some include is no longer denied)
  const effectivelyExcluded = [...denyAcc].filter((k) => !includeKeys.has(k)).toSorted();

  if (effectivelyExcluded.length === 0) return {}; // universe — all denials covered by some include
  return Object.fromEntries(effectivelyExcluded.map((k) => [k, 0]));
}

/**
 * Restrict a desired projection to only fields allowed by an access-control projection.
 *
 * The result is the intersection of the two projections: only fields that pass both
 * `desired` and `accessControl` survive. Either side may be empty (unrestricted), in
 * which case the other side is returned. Mixed include/exclude modes are normalized
 * to a single result projection.
 *
 * @param desired - the projection the caller asked for
 * @param accessControl - the projection allowed by RBAC
 */
export function restrictProjection(desired: TProjection, accessControl: TProjection): TProjection {
  const desiredMode = getProjectionMode(desired);
  const acMode = getProjectionMode(accessControl);

  // If either is unrestricted, the other is the result
  if (acMode === "empty") return { ...desired };
  if (desiredMode === "empty") return { ...accessControl };

  // Both include: intersection of keys
  if (desiredMode === "include" && acMode === "include") {
    const result: TProjection = {};
    for (const key of Object.keys(desired)) {
      if (isFieldAllowed(key, accessControl)) {
        result[key] = 1;
      }
    }
    return result;
  }

  // Both exclude: union of excluded keys (more restrictive)
  if (desiredMode === "exclude" && acMode === "exclude") {
    const result: TProjection = {};
    for (const key of Object.keys(desired)) {
      result[key] = 0;
    }
    for (const key of Object.keys(accessControl)) {
      result[key] = 0;
    }
    return result;
  }

  // One include, one exclude: filter the include list by the exclude list
  if (desiredMode === "include" && acMode === "exclude") {
    const result: TProjection = {};
    for (const key of Object.keys(desired)) {
      if (isFieldAllowed(key, accessControl)) {
        result[key] = 1;
      }
    }
    return result;
  }

  // desired=exclude, ac=include: return the ac include list minus desired excludes
  const result: TProjection = {};
  for (const key of Object.keys(accessControl)) {
    if (isFieldAllowed(key, desired)) {
      result[key] = 1;
    }
  }
  return result;
}
