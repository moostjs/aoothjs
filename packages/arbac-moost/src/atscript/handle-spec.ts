import type { TAtscriptAnnotatedType } from "@atscript/typescript/utils";

/**
 * Resolved login/recovery HANDLE fields for a user credential model, discovered
 * from the `@aooth.user.*` annotations (registered by `arbacPlugin`). Computed
 * once per `TAtscriptAnnotatedType` and cached.
 *
 * - `emailField` — the field annotated `@aooth.user.email` **and** carrying a
 *   `@db.index.unique` index. `undefined` when no field is annotated, or when
 *   the annotated field lacks a unique index (the handle is then DISABLED — see
 *   `warnings`).
 * - `phoneField` — same, for `@aooth.user.phone`.
 * - `handleFields` — the enabled handle field names in resolution order (email,
 *   then phone; disabled handles omitted). Pass this straight to a `UserStore`
 *   (`UsersStoreAtscriptDb` / `UserStoreMemory`) as its `handleFields` — the
 *   store stays name-agnostic; this spec owns the email/phone semantics.
 * - `warnings` — non-fatal misconfig notes (an annotated field with no unique
 *   index → that handle is disabled, not fatal). The wiring layer should log
 *   these at boot. Ambiguity (more than one field per role) is fatal and throws.
 *
 * A handle MUST be unique-when-present because `findByHandle` resolves a handle
 * to AT MOST one row; a non-unique handle would resolve to an arbitrary one of
 * several rows (an account-takeover footgun). That is why the unique index is
 * the gate, and why a missing index disables rather than silently accepts.
 */
export interface AoothUserHandleSpec {
  emailField: string | undefined;
  phoneField: string | undefined;
  handleFields: string[];
  warnings: string[];
}

const specCache = new WeakMap<TAtscriptAnnotatedType, AoothUserHandleSpec>();

/** Minimal structural surface of a prop's atscript metadata map. */
interface FieldMetadata {
  get(key: string): unknown;
}

/** A `@db.index.unique` annotation is a non-empty `(string | true)[]`. */
function hasUniqueIndex(md: FieldMetadata): boolean {
  const unique = md.get("db.index.unique");
  return Array.isArray(unique) && unique.length > 0;
}

/**
 * Resolve a single handle field for one role: fail loud on ambiguity (more than
 * one annotated field — there is no canonical choice), and warn-and-disable when
 * the sole annotated field lacks a unique index.
 */
function resolveHandleField(
  role: "email" | "phone",
  annotation: string,
  candidates: Array<{ field: string; md: FieldMetadata }>,
  warnings: string[],
): string | undefined {
  if (candidates.length === 0) return undefined;
  if (candidates.length > 1) {
    throw new Error(
      `getAoothUserHandleSpec: multiple ${annotation} fields declared (${candidates
        .map((c) => c.field)
        .join(
          ", ",
        )}). Exactly one ${role} login handle is supported — drop ${annotation} from all but the canonical field.`,
    );
  }
  const { field, md } = candidates[0];
  if (!hasUniqueIndex(md)) {
    warnings.push(
      `${annotation} on field "${field}" has no @db.index.unique — a login handle must resolve to at most one row, so the ${role} handle is DISABLED (login/recovery by ${role} unavailable). Add @db.index.unique to the field to enable it.`,
    );
    return undefined;
  }
  return field;
}

/**
 * Walk a user model's `@aooth.user.*` annotations into a cached
 * {@link AoothUserHandleSpec}. Mirrors {@link getArbacAttenuationSpec}:
 * structural, computed once, fail-loud on ambiguity. A model with no
 * `@aooth.user.*` field resolves to all-`undefined` handles (email/phone login
 * is simply unavailable — graceful degradation, not an error).
 */
export function getAoothUserHandleSpec(userType: TAtscriptAnnotatedType): AoothUserHandleSpec {
  const cached = specCache.get(userType);
  if (cached !== undefined) return cached;

  const spec: AoothUserHandleSpec = {
    emailField: undefined,
    phoneField: undefined,
    handleFields: [],
    warnings: [],
  };
  const def = userType.type;
  if (def.kind !== "object") {
    specCache.set(userType, spec);
    return spec;
  }

  const emailCandidates: Array<{ field: string; md: FieldMetadata }> = [];
  const phoneCandidates: Array<{ field: string; md: FieldMetadata }> = [];
  for (const [fieldName, fieldType] of def.props) {
    const md = fieldType.metadata as FieldMetadata;
    if (md.get("aooth.user.email")) emailCandidates.push({ field: fieldName, md });
    if (md.get("aooth.user.phone")) phoneCandidates.push({ field: fieldName, md });
  }

  spec.emailField = resolveHandleField(
    "email",
    "@aooth.user.email",
    emailCandidates,
    spec.warnings,
  );
  spec.phoneField = resolveHandleField(
    "phone",
    "@aooth.user.phone",
    phoneCandidates,
    spec.warnings,
  );
  // Ordered, enabled-only — the consumable list a store iterates as `handleFields`.
  spec.handleFields = [spec.emailField, spec.phoneField].filter(
    (f): f is string => f !== undefined,
  );

  specCache.set(userType, spec);
  return spec;
}
