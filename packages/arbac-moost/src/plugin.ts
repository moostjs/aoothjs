import type { TAtscriptPlugin } from "@atscript/core";
import { AnnotationSpec } from "@atscript/core";

/**
 * Registers the `@arbac.*` annotation namespace for `@aooth/arbac-moost`:
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
 * Credential-side (restrict-only attenuation — a credential authorizes for
 * strictly LESS than its owning user; soundness is the engine's scope
 * conjunction, these only mark WHERE the narrowing inputs live):
 *
 * - `@arbac.attenuate.role` — marks the ONE credential field holding the
 *   assumed-role SUBSET (`string[]`). Intersected with the user's roles
 *   (fail-closed: a claimed role the user lacks is dropped). Exactly one per
 *   type — multiple declarations throw at boot.
 * - `@arbac.attenuate.attr "userAttrName"` — marks a credential field whose
 *   value narrows the named USER attribute. The string argument is the target
 *   key in the user model's `@arbac.attribute` keyspace (validated to exist at
 *   boot). Multiple fields may each carry it, targeting different attrs.
 *
 * This plugin also registers the `@aooth.user.*` identity-handle namespace
 * (read by `getAoothUserHandleSpec`) so `.as` user models can mark their login
 * handles name-agnostically:
 *
 * - `@aooth.user.email` — the field is the EMAIL login/recovery handle. Resolved
 *   by annotation (not by being literally named `email`). MUST carry
 *   `@db.index.unique` (unique-when-present); without it the handle is disabled
 *   with a warning. At most one per type.
 * - `@aooth.user.phone` — the PHONE login/recovery handle, same contract.
 *
 * Install in `atscript.config.ts`:
 *
 * ```ts
 * import arbacPlugin from '@aooth/arbac-moost/plugin'
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
            attenuate: {
              role: new AnnotationSpec({
                description:
                  "Marks the credential field holding the assumed-role SUBSET (string[]) for " +
                  "restrict-only ARBAC attenuation. Intersected with the user's roles (fail-closed). " +
                  "Exactly one @arbac.attenuate.role field per type — multiple declarations throw at boot.",
                nodeType: ["prop"],
                multiple: false,
              }),
              attr: new AnnotationSpec({
                description:
                  "Marks a credential field whose value narrows the named USER attribute for " +
                  "restrict-only ARBAC attenuation. The argument is the target key in the user " +
                  "model's @arbac.attribute keyspace (validated to exist at boot). Multiple fields " +
                  "may each carry it, targeting different attrs.",
                nodeType: ["prop"],
                multiple: false,
                argument: {
                  name: "userAttr",
                  type: "string",
                  description:
                    "Target user-attribute key (a field annotated @arbac.attribute on the user model).",
                },
              }),
            },
          },
          aooth: {
            user: {
              email: new AnnotationSpec({
                description:
                  "Marks this field as the EMAIL login/recovery handle. The framework resolves " +
                  "the field by this annotation (name-agnostic) for findByHandle / recovery / signup. " +
                  "The field MUST carry @db.index.unique (unique-when-present) — a handle must resolve " +
                  "to at most one row; without a unique index the email handle is DISABLED with a warning. " +
                  "At most one @aooth.user.email field per type — multiple declarations throw at boot.",
                nodeType: ["prop"],
                multiple: false,
              }),
              phone: new AnnotationSpec({
                description:
                  "Marks this field as the PHONE login/recovery handle. Same resolution + unique-index " +
                  "contract as @aooth.user.email (disabled with a warning when the field lacks " +
                  "@db.index.unique). At most one @aooth.user.phone field per type — multiple throw at boot.",
                nodeType: ["prop"],
                multiple: false,
              }),
            },
            auth: {
              metadata: new AnnotationSpec({
                description:
                  "Marks the consumer's fully-typed credential-metadata column (@db.json) on their " +
                  "`extends AoothAuthCredential` model — the runtime/validation twin of the " +
                  "`CredentialMetadata` declaration merge. Resolved by `getAoothCredentialMetadataSpec` " +
                  "and threaded to `CredentialStoreAtscriptDb` as `metadataField`. The field MUST carry " +
                  "@db.json (a structured metadata object needs a json column — without it, metadata " +
                  "persistence is DISABLED with a warning). At most one @aooth.auth.metadata field per " +
                  "type — multiple declarations throw at boot. Absent → the atscript-db credential " +
                  "store persists no metadata (non-fatal, warned at boot by the wiring).",
                nodeType: ["prop"],
                multiple: false,
              }),
            },
          },
        },
      };
    },
  };
}
