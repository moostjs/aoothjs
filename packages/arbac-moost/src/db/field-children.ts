import type { TProjectionChildren } from "@aooth/arbac";

import { getOrCreate, hasSelfOrAncestor, navFieldsOf } from "./helpers";
import type { VisibilityTableSource } from "./visibility";

// Per table: parent path → direct child paths, from its flattened schema.
const fieldChildrenCache = new WeakMap<VisibilityTableSource, TProjectionChildren>();
const NONE: ReadonlySet<string> = new Set();

/**
 * The `TProjectionChildren` schema lookup for a table (its own `flatMap` paths —
 * navigation descendants excluded, they are joined rows, not columns; so are
 * the descendants of an atomic JSON column — `readable.jsonParents`);
 * `undefined` when the table exposes no flattened schema.
 */
export function fieldChildrenOf(
  table: VisibilityTableSource | undefined,
): TProjectionChildren | undefined {
  const flatMap = table?.flatMap;
  if (!flatMap) return undefined;
  return getOrCreate(fieldChildrenCache, table, () => {
    const nav = navFieldsOf(table);
    const json = table.jsonParents ?? NONE;
    const byParent = new Map<string, string[]>();
    for (const path of flatMap.keys()) {
      const dot = path.lastIndexOf(".");
      if (dot === -1) continue;
      const parent = path.slice(0, dot);
      // Navigation descendants are joined rows; an atomic JSON column has no
      // addressable children.
      if (hasSelfOrAncestor(nav, parent) || hasSelfOrAncestor(json, parent)) continue;
      getOrCreate(byParent, parent, () => []).push(path);
    }
    return (path: string) => byParent.get(path) ?? [];
  });
}
