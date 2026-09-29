import { effectiveScope } from "@aooth/arbac";
import { isPlainObject } from "@atscript/db";

import type { ArbacDbScope } from "./as-arbac-db-controller";

/**
 * Test-friendly internal helper — exported for unit tests and helper
 * composition; regular consumers should not call this directly.
 *
 * Apply the union of `allowedFields` whitelists (with `preserveFields`
 * always preserved) and overlay each scope's `set` overrides. Returns a
 * copy; the original `data` is not mutated.
 *
 * Path-aware: a top-level entry (`profile`) keeps the whole subtree; a
 * dotted entry (`profile.name`) keeps only that branch of a nested object
 * payload (`profile: { name, tenant }` → `profile: { name }`) — a non-object
 * value under a partially whitelisted key is dropped, never kept whole. A
 * dotted `set` key sets the nested path, merging into the payload's nested
 * object.
 *
 * Patches (`isMergePatch` given): a nested object is written as a whole
 * unless its path is a `@db.patch.strategy 'merge'` block, so a partially
 * whitelisted REPLACE block is dropped (a partial block would clear the
 * non-whitelisted leaves), and a dotted `set` under a replace block the patch
 * does not carry is skipped (adding the block would clear its other leaves).
 */
export function applyAllowedFieldsAndSet(
  data: unknown,
  scopes: ArbacDbScope[],
  preserveFields: readonly string[] = [],
  isMergePatch?: (objectPath: string) => boolean,
): unknown {
  if (scopes.length === 0) return data;
  // Computed once per call, reused across every row of a batch.
  const prepared = prepareScopeOverlay(scopes, preserveFields, isMergePatch);
  return applyPreparedOverlay(data, prepared);
}

/** A whitelist as a path tree: `all` = the whole subtree is writable. */
interface FieldTree {
  all: boolean;
  children: Map<string, FieldTree>;
}

interface PreparedScopeOverlay {
  tree: FieldTree | null;
  setOverrides: Array<[path: string[], value: unknown]> | null;
  isMergePatch?: (objectPath: string) => boolean;
}

function prepareScopeOverlay(
  scopes: ArbacDbScope[],
  preserveFields: readonly string[],
  isMergePatch?: (objectPath: string) => boolean,
): PreparedScopeOverlay {
  const { allowedFields, set } = effectiveScope(scopes);
  let tree: FieldTree | null = null;
  if (allowedFields) {
    tree = newNode();
    for (const f of allowedFields) addPath(tree, f);
    for (const f of preserveFields) addPath(tree, f);
  }
  const setOverrides = set
    ? Object.entries(set).map(([k, v]): [string[], unknown] => [k.split("."), v])
    : null;
  return { tree, setOverrides, isMergePatch };
}

function newNode(): FieldTree {
  return { all: false, children: new Map() };
}

function addPath(tree: FieldTree, path: string): void {
  let node = tree;
  for (const seg of path.split(".")) {
    if (node.all) return;
    let next = node.children.get(seg);
    if (!next) {
      next = newNode();
      node.children.set(seg, next);
    }
    node = next;
  }
  node.all = true;
}

/** `true` when `path` (dotted) is whitelisted by itself or an ancestor. */
function coversPath(tree: FieldTree, path: string): boolean {
  let node: FieldTree | undefined = tree;
  for (const seg of path.split(".")) {
    node = node.children.get(seg);
    if (!node) return false;
    if (node.all) return true;
  }
  return false;
}

function pruneByTree(
  obj: Record<string, unknown>,
  tree: FieldTree,
  prefix: string,
  isMergePatch: PreparedScopeOverlay["isMergePatch"],
): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(obj)) {
    if (k.includes(".")) {
      if (coversPath(tree, k)) out[k] = v;
      continue;
    }
    const node = tree.children.get(k);
    if (!node) continue;
    if (node.all) {
      out[k] = v;
      continue;
    }
    // Only descendants are whitelisted: keep just those branches of a nested
    // object. Any other value — or a partial patch of a block the database
    // replaces whole — would write the non-whitelisted siblings too.
    const path = prefix + k;
    if (!isPlainObject(v) || (isMergePatch && !isMergePatch(path))) continue;
    const pruned = pruneByTree(v, node, `${path}.`, isMergePatch);
    if (Object.keys(pruned).length > 0) out[k] = pruned;
  }
  return out;
}

/**
 * Set `path` in `target` (copy-on-write for nested objects). On a patch, a
 * missing intermediate replace block is not created — returns without
 * setting (the stored block stays as it is).
 */
function setPath(
  target: Record<string, unknown>,
  path: string[],
  value: unknown,
  isMergePatch: PreparedScopeOverlay["isMergePatch"],
  prefix = "",
): void {
  if (path.length === 1) {
    target[path[0]] = value;
    return;
  }
  // A literal dotted payload key naming the same path must not survive next
  // to (or instead of) the nested value.
  delete target[path.join(".")];
  const [head, ...rest] = path;
  const existing = target[head];
  const objectPath = prefix + head;
  if (!isPlainObject(existing) && isMergePatch && !isMergePatch(objectPath)) return;
  const child = isPlainObject(existing) ? { ...existing } : {};
  target[head] = child;
  setPath(child, rest, value, isMergePatch, `${objectPath}.`);
}

function applyPreparedOverlay(data: unknown, prepared: PreparedScopeOverlay): unknown {
  if (Array.isArray(data)) return data.map((row) => applyPreparedOverlay(row, prepared));
  if (!data || typeof data !== "object") return data;
  const source = data as Record<string, unknown>;
  const merged = prepared.tree
    ? pruneByTree(source, prepared.tree, "", prepared.isMergePatch)
    : { ...source };
  if (prepared.setOverrides) {
    for (const [path, value] of prepared.setOverrides) {
      setPath(merged, path, value, prepared.isMergePatch);
    }
  }
  return merged;
}
