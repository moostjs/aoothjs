import type { TArbacRole } from "@aoothjs/arbac-core";

export interface TResourceActionMap {
  /** Map of resource string → Set of action strings */
  resources: Map<string, Set<string>>;
  /** All unique resource strings */
  allResources: Set<string>;
  /** All unique action strings */
  allActions: Set<string>;
}

function hasWildcard(s: string): boolean {
  return s.includes("*");
}

/**
 * Extract all resource and action strings from role definitions.
 *
 * @param roles - Array of built role definitions
 * @param options.includeWildcards - If false (default), skip entries containing `*` or `**`
 */
export function extractResourceActions(
  roles: TArbacRole<unknown, unknown>[],
  options?: { includeWildcards?: boolean },
): TResourceActionMap {
  const includeWildcards = options?.includeWildcards ?? false;
  const resources = new Map<string, Set<string>>();
  const allResources = new Set<string>();
  const allActions = new Set<string>();

  for (const role of roles) {
    for (const rule of role.rules) {
      const skipResource = !includeWildcards && hasWildcard(rule.resource);
      const skipAction = !includeWildcards && hasWildcard(rule.action);

      if (!skipResource) {
        allResources.add(rule.resource);
        // Only create an entry in the resource → actions map when there is at
        // least one concrete action to associate with it. A literal resource
        // whose only actions are wildcards would otherwise emit a misleading
        // `"foo": never` entry in the generated ResourceActionMap.
        if (!skipAction) {
          if (!resources.has(rule.resource)) {
            resources.set(rule.resource, new Set());
          }
          resources.get(rule.resource)!.add(rule.action);
        }
      }

      if (!skipAction) {
        allActions.add(rule.action);
      }
    }
  }

  return { resources, allResources, allActions };
}
