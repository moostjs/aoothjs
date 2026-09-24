import type { TProjectionChildren } from "@aooth/arbac";
import { findAncestorInSet } from "@atscript/db";

import type { VisibilityTableSource } from "./meta-projection";

// Per table: parent path → direct child paths, from its flattened schema.
const fieldChildrenCache = new WeakMap<VisibilityTableSource, TProjectionChildren>();

/**
 * The `TProjectionChildren` schema lookup for a table (its own `flatMap` paths —
 * navigation descendants excluded, they are joined rows, not columns);
 * `undefined` when the table exposes no flattened schema.
 */
export function fieldChildrenOf(
  table: VisibilityTableSource | undefined,
): TProjectionChildren | undefined {
  if (!table?.flatMap) return undefined;
  let lookup = fieldChildrenCache.get(table);
  if (!lookup) {
    const nav = table.navFields ?? new Set(table.relations?.keys());
    const byParent = new Map<string, string[]>();
    for (const path of table.flatMap.keys()) {
      const dot = path.lastIndexOf(".");
      if (dot === -1) continue;
      const parent = path.slice(0, dot);
      // Navigation descendants are joined rows, not own columns.
      if (nav.has(parent) || findAncestorInSet(parent, nav) !== undefined) continue;
      const list = byParent.get(parent);
      if (list) list.push(path);
      else byParent.set(parent, [path]);
    }
    lookup = (path) => byParent.get(path) ?? [];
    fieldChildrenCache.set(table, lookup);
  }
  return lookup;
}
