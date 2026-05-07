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
 * Union multiple projections — most permissive merge for RBAC.
 * If any scope allows a field, the union allows it.
 *
 * Semantics:
 * - empty ∪ anything = empty (unrestricted)
 * - include ∪ include = union of included keys
 * - exclude ∪ exclude = intersection of excluded keys (only fields excluded by ALL remain excluded)
 * - mixed include + exclude = **throws** — the union is ambiguous
 *
 * Mixed-mode merging silently widening to unrestricted is a security footgun for RBAC,
 * so callers must normalize their projections (e.g. convert all to one mode) before
 * unioning.
 *
 * @throws when projections mix `include` and `exclude` modes
 */
export function unionProjections(...projections: TProjection[]): TProjection {
  if (projections.length === 0) return {};

  const modes = new Set(projections.map((p) => getProjectionMode(p)));

  // If any is empty (unrestricted), the union is unrestricted
  if (modes.has("empty")) return {};

  const hasInclude = modes.has("include");
  const hasExclude = modes.has("exclude");

  // Mixed modes — explicit error to avoid silently widening access
  if (hasInclude && hasExclude) {
    throw new Error(
      "unionProjections: cannot union mixed include and exclude projections — " +
        "the result is ambiguous. Normalize all projections to a single mode before merging.",
    );
  }

  if (hasInclude) {
    // Union of included keys
    const result: TProjection = {};
    for (const proj of projections) {
      for (const key of Object.keys(proj)) {
        result[key] = 1;
      }
    }
    return result;
  }

  // All exclude — intersection of excluded keys (only fields excluded by ALL remain excluded)
  const excludeSets = projections.map((p) => new Set(Object.keys(p)));
  const intersection = [...excludeSets[0]].filter((key) => excludeSets.every((s) => s.has(key)));
  const result: TProjection = {};
  for (const key of intersection) {
    result[key] = 0;
  }
  return result;
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
