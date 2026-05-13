import type { TAtscriptPlugin } from "@atscript/core";
import { AnnotationSpec } from "@atscript/core";

/**
 * Registers the `@arbac.*` annotation namespace for `@aoothjs/arbac-moost`:
 *
 * - `@arbac.role` — field is a source of role identifiers (`string | string[]`).
 *   Multiple role fields are unioned.
 * - `@arbac.attribute` — field becomes a user attribute keyed by its prop name.
 * - `@arbac.userId` — overrides the user-id source (defaults to `@meta.id`).
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
                "Marks this field as a source of role identifiers for ARBAC evaluation. " +
                "Field type must be string or string[]. Multiple @arbac.role fields are unioned.",
              nodeType: ["prop"],
              multiple: false,
            }),
            attribute: new AnnotationSpec({
              description:
                "Marks this field as a user attribute used by ARBAC scope evaluation. " +
                "The field name becomes the attribute key.",
              nodeType: ["prop"],
              multiple: false,
            }),
            userId: new AnnotationSpec({
              description:
                "Overrides which field provides the user identifier for ARBAC. " +
                "Defaults to the @meta.id field when absent.",
              nodeType: ["prop"],
              multiple: false,
            }),
          },
        },
      };
    },
  };
}
