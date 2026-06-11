import type { TAtscriptAnnotatedType } from "@atscript/typescript/utils";

/**
 * Resolved credential-METADATA column for a credential model, discovered from
 * the `@aooth.auth.metadata` annotation (registered by `arbacPlugin`).
 * Computed once per `TAtscriptAnnotatedType` and cached.
 *
 * - `metadataField` — the field annotated `@aooth.auth.metadata` **and**
 *   carrying `@db.json`. `undefined` when no field is annotated, or when the
 *   annotated field lacks `@db.json` (metadata persistence is then DISABLED —
 *   see `warnings`). Pass it straight to `CredentialStoreAtscriptDb` as its
 *   `metadataField` option — the store stays name-agnostic; this spec owns the
 *   annotation semantics (same split as `getAoothUserHandleSpec` /
 *   `UserStore.handleFields`).
 * - `warnings` — non-fatal misconfig notes (an annotated field without
 *   `@db.json` → metadata persistence disabled, not fatal). The wiring layer
 *   should log these at boot. Ambiguity (more than one annotated field) is
 *   fatal and throws.
 *
 * The `@db.json` gate mirrors the handle spec's unique-index posture: metadata
 * is a structured object, and a non-json column would either reject the write
 * or silently stringify it engine-dependently — so a missing `@db.json`
 * disables rather than silently accepts. A model with no annotated field
 * resolves to `undefined` with NO warning here (graceful degradation — the
 * consumer may simply not persist metadata); the wiring layer decides whether
 * that deserves a boot-time note.
 */
export interface AoothCredentialMetadataSpec {
  metadataField: string | undefined;
  warnings: string[];
}

const specCache = new WeakMap<TAtscriptAnnotatedType, AoothCredentialMetadataSpec>();

/** Minimal structural surface of a prop's atscript metadata map. */
interface FieldMetadata {
  get(key: string): unknown;
}

/**
 * Walk a credential model's `@aooth.auth.metadata` annotation into a cached
 * {@link AoothCredentialMetadataSpec}. Mirrors {@link getAoothUserHandleSpec}:
 * structural, computed once, fail-loud on ambiguity, warn-and-disable on a
 * misconfigured (non-`@db.json`) field.
 */
export function getAoothCredentialMetadataSpec(
  credentialType: TAtscriptAnnotatedType,
): AoothCredentialMetadataSpec {
  const cached = specCache.get(credentialType);
  if (cached !== undefined) return cached;

  const spec: AoothCredentialMetadataSpec = {
    metadataField: undefined,
    warnings: [],
  };
  const def = credentialType.type;
  if (def.kind !== "object") {
    specCache.set(credentialType, spec);
    return spec;
  }

  const candidates: Array<{ field: string; md: FieldMetadata }> = [];
  for (const [fieldName, fieldType] of def.props) {
    const md = fieldType.metadata as FieldMetadata;
    if (md.get("aooth.auth.metadata")) candidates.push({ field: fieldName, md });
  }

  if (candidates.length > 1) {
    throw new Error(
      `getAoothCredentialMetadataSpec: multiple @aooth.auth.metadata fields declared (${candidates
        .map((c) => c.field)
        .join(
          ", ",
        )}). Exactly one credential-metadata column is supported — drop @aooth.auth.metadata from all but the canonical field.`,
    );
  }
  if (candidates.length === 1) {
    const { field, md } = candidates[0];
    if (md.get("db.json")) {
      spec.metadataField = field;
    } else {
      spec.warnings.push(
        `@aooth.auth.metadata on field "${field}" has no @db.json — a structured metadata object needs a json column, so metadata persistence is DISABLED (the atscript-db credential store will not persist/read metadata). Add @db.json to the field to enable it.`,
      );
    }
  }

  specCache.set(credentialType, spec);
  return spec;
}
