import type { TAtscriptAnnotatedType } from "@atscript/typescript/utils";

import type { AoothArbacClaims } from "../attenuation";

/**
 * Spec computed once per credential `TAtscriptAnnotatedType` — which typed root
 * fields carry the restrict-only ARBAC attenuation:
 *
 * - `roleField` — the single `@arbac.attenuate.role`-annotated prop (holds the
 *   assumed-role SUBSET, `string[]`). More than one throws at spec time.
 * - `attrFields` — every `@arbac.attenuate.attr "userAttr"` prop, paired with
 *   the target user-attribute key it narrows (the annotation argument).
 */
export interface ArbacAttenuationSpec {
  roleField: string | undefined;
  attrFields: Array<{ field: string; userAttr: string }>;
}

const specCache = new WeakMap<TAtscriptAnnotatedType, ArbacAttenuationSpec>();

/**
 * Walk a credential model's `@arbac.attenuate.*` annotations into a cached
 * {@link ArbacAttenuationSpec}. Mirrors the user-side `getArbacExtractSpec`:
 * structural, computed once, fail-loud on an ambiguous (multiple) role field.
 */
export function getArbacAttenuationSpec(credType: TAtscriptAnnotatedType): ArbacAttenuationSpec {
  const cached = specCache.get(credType);
  if (cached !== undefined) return cached;

  const spec: ArbacAttenuationSpec = { roleField: undefined, attrFields: [] };
  const def = credType.type;
  if (def.kind !== "object") {
    specCache.set(credType, spec);
    return spec;
  }

  const roleCandidates: string[] = [];
  for (const [fieldName, fieldType] of def.props) {
    const md = fieldType.metadata;
    if (md.get("arbac.attenuate.role")) roleCandidates.push(fieldName);
    const userAttr = md.get("arbac.attenuate.attr");
    if (typeof userAttr === "string" && userAttr !== "") {
      spec.attrFields.push({ field: fieldName, userAttr });
    }
  }

  // Fail loud: exactly one @arbac.attenuate.role source, mirroring @arbac.role.
  if (roleCandidates.length > 1) {
    throw new Error(
      `getArbacAttenuationSpec: multiple @arbac.attenuate.role fields declared (${roleCandidates.join(
        ", ",
      )}). Exactly one assumed-role source is supported — drop @arbac.attenuate.role from all but the canonical field.`,
    );
  }
  if (roleCandidates.length === 1) spec.roleField = roleCandidates[0];

  specCache.set(credType, spec);
  return spec;
}

/**
 * Boot-time cross-model check: every `@arbac.attenuate.attr "userAttr"` target
 * must name a real key in the user model's `@arbac.attribute` keyspace
 * (`validUserAttrs`), else a typo silently no-ops the narrowing. Throws on the
 * first miss. Call once at provider construction; safe and cheap (the spec is
 * cached). Soundness does NOT depend on this — the scope conjunction clips
 * regardless — but it turns a silent misconfig into a loud boot failure.
 */
export function validateAttenuationTargets(
  credType: TAtscriptAnnotatedType,
  validUserAttrs: Iterable<string>,
): void {
  const spec = getArbacAttenuationSpec(credType);
  const valid = new Set(validUserAttrs);
  for (const { field, userAttr } of spec.attrFields) {
    if (!valid.has(userAttr)) {
      throw new Error(
        `validateAttenuationTargets: @arbac.attenuate.attr "${userAttr}" on field "${field}" targets a user attribute that does not exist in the user model's @arbac.attribute keyspace (${
          [...valid].join(", ") || "<none>"
        }). Fix the annotation argument.`,
      );
    }
  }
}

/** Lenient role parse: accept `string | string[]`, drop empty/non-string, dedupe. */
function parseRoles(raw: unknown): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  const push = (v: unknown) => {
    if (typeof v === "string" && v !== "" && !seen.has(v)) {
      seen.add(v);
      out.push(v);
    }
  };
  if (Array.isArray(raw)) for (const item of raw) push(item);
  else push(raw);
  return out;
}

/**
 * Build the restrict-only {@link AoothArbacClaims} for a credential `record`
 * (its typed root fields — e.g. the auth context, which carries the credential
 * payload flat) by reading the fields the credential model annotates. Designed
 * to back a consumer's `ArbacUserProvider.getAttenuation()` override while
 * arbac-moost stays auth-agnostic (the consumer supplies the record).
 *
 * Returns:
 * - `undefined` when the model declares NO attenuation fields, OR a normal
 *   (non-attenuated) token carries none of them set → full user authority.
 * - `{ roles, attrs }` otherwise. The narrowing is then clipped by the engine's
 *   scope conjunction, so it can never widen beyond the user.
 *
 * Fail-closed: when the assumed-role field IS set but holds a malformed value
 * (no usable role strings), {@link parseRoles} yields `[]` — deny-all — never
 * full authority. Absent (`undefined`/`null`) = the field was not set, so roles
 * are omitted (attrs-only narrowing), which is the distinct "no role narrowing"
 * case, not a malformed one.
 */
export function extractAttenuation(
  credType: TAtscriptAnnotatedType,
  record: object | null | undefined,
): AoothArbacClaims | undefined {
  const spec = getArbacAttenuationSpec(credType);
  if (spec.roleField === undefined && spec.attrFields.length === 0) return undefined;
  if (!record) return undefined;
  const rec = record as Record<string, unknown>;

  let roles: string[] | undefined;
  if (spec.roleField !== undefined) {
    const raw = rec[spec.roleField];
    if (raw !== undefined && raw !== null) roles = parseRoles(raw);
  }

  let attrs: Record<string, unknown> | undefined;
  for (const { field, userAttr } of spec.attrFields) {
    const value = rec[field];
    // `null` means the column was never set (stateful stores round-trip an
    // unset optional column as SQL NULL, not absent), so treat it like absent —
    // NOT a narrowing value of `null` (which would clip to zero rows).
    if (value !== undefined && value !== null) {
      attrs ??= {};
      attrs[userAttr] = value;
    }
  }

  if (roles === undefined && attrs === undefined) return undefined;
  const out: AoothArbacClaims = {};
  if (roles !== undefined) out.roles = roles;
  if (attrs !== undefined) out.attrs = attrs;
  return out;
}
