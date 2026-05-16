import type { TAtscriptPlugin } from "@atscript/core";
import { AnnotationSpec } from "@atscript/core";

/**
 * Registers the `@arbac.*` annotation namespace for `@aoothjs/arbac-moost`:
 *
 * - `@arbac.role` — field is the source of role identifiers. Exactly one
 *   field per type. Two valid shapes:
 *     - inline `string | string[]` — values are read directly,
 *     - `@db.rel.from` nav prop (1:N to a role table) — provider auto-injects
 *       `controls.$with` and pulls role names off the joined records.
 *   Multiple `@arbac.role` declarations throw at spec computation time.
 * - `@arbac.attribute` — field becomes a user attribute keyed by its prop name.
 *   Multiple `@arbac.attribute` fields are merged into the `UserAttrs` map.
 * - `@arbac.userId` — overrides the user-id source. Resolution order is
 *   (1) `@arbac.userId`, (2) the single field of the `@db.table.preferredId.uniqueIndex`
 *   group, (3) `@meta.id` — first match wins.
 *
 * Install in `atscript.config.ts`:
 *
 * ```ts
 * import arbacPlugin from '@aoothjs/arbac-moost/plugin'
 * export default { plugins: [arbacPlugin()] }
 * ```
 */
export default function arbacPlugin(): TAtscriptPlugin {
  return {
    name: "aoothjs-arbac",
    config() {
      return {
        annotations: {
          arbac: {
            role: new AnnotationSpec({
              description:
                "Marks this field as THE source of role identifiers for ARBAC evaluation. " +
                "Two shapes are supported: inline (string | string[]) or @db.rel.from nav prop. " +
                "Exactly one @arbac.role field per type — multiple declarations throw at boot.",
              nodeType: ["prop"],
              multiple: false,
            }),
            attribute: new AnnotationSpec({
              description:
                "Marks this field as a user attribute used by ARBAC scope evaluation. " +
                "The field name becomes the attribute key. Multiple fields are merged.",
              nodeType: ["prop"],
              multiple: false,
            }),
            userId: new AnnotationSpec({
              description:
                "Overrides which field provides the user identifier for ARBAC. " +
                "Resolution chain: @arbac.userId → @db.table.preferredId.uniqueIndex field → @meta.id.",
              nodeType: ["prop"],
              multiple: false,
            }),
          },
        },
      };
    },
  };
}
