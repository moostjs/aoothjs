import type { TAtscriptAnnotatedType } from "@atscript/typescript/utils";

export interface ArbacExtractSpec {
  /** Resolved id field name: `@arbac.userId` if present, else `@meta.id`. */
  userIdField: string | undefined;
  roleFields: string[];
  attrFields: string[];
}

const specCache = new WeakMap<TAtscriptAnnotatedType, ArbacExtractSpec>();

/**
 * Walk the type's `props` once and record the `@arbac.*` / `@meta.id`
 * field positions. Memoized on the type reference so all downstream
 * helpers (extract, projection, setup) share one traversal per type.
 */
export function getArbacExtractSpec(type: TAtscriptAnnotatedType): ArbacExtractSpec {
  const cached = specCache.get(type);
  if (cached !== undefined) return cached;

  const spec: ArbacExtractSpec = {
    userIdField: undefined,
    roleFields: [],
    attrFields: [],
  };

  const def = type.type;
  if (def.kind !== "object") {
    specCache.set(type, spec);
    return spec;
  }

  let metaIdField: string | undefined;
  let userIdField: string | undefined;

  for (const [fieldName, fieldType] of def.props) {
    const md = fieldType.metadata;
    if (md.get("arbac.userId")) userIdField = fieldName;
    if (md.get("meta.id")) metaIdField = fieldName;
    if (md.get("arbac.role")) spec.roleFields.push(fieldName);
    if (md.get("arbac.attribute")) spec.attrFields.push(fieldName);
  }

  spec.userIdField = userIdField ?? metaIdField;
  specCache.set(type, spec);
  return spec;
}

export function extractArbacUserId<T extends object>(
  record: T,
  type: TAtscriptAnnotatedType,
): string {
  const { userIdField } = getArbacExtractSpec(type);
  if (!userIdField) {
    throw new Error(
      "extractArbacUserId: no @arbac.userId or @meta.id field on type — annotate one to provide the user identifier",
    );
  }
  const raw = (record as Record<string, unknown>)[userIdField];
  if (raw === undefined || raw === null || raw === "") {
    throw new Error(`extractArbacUserId: field "${userIdField}" is empty on the user record`);
  }
  if (typeof raw === "string") return raw;
  if (typeof raw === "number" || typeof raw === "bigint") return raw.toString();
  throw new Error(
    `extractArbacUserId: field "${userIdField}" must be a string, number, or bigint (got ${typeof raw})`,
  );
}

/**
 * Combined list of all `@arbac.role` field values, deduplicated in
 * first-seen order. Each field may be `string` or `string[]`; empty /
 * nullish / non-string entries are skipped.
 */
export function extractArbacRoles<T extends object>(
  record: T,
  type: TAtscriptAnnotatedType,
): string[] {
  const { roleFields } = getArbacExtractSpec(type);
  if (roleFields.length === 0) return [];

  const seen = new Set<string>();
  const out: string[] = [];
  const rec = record as Record<string, unknown>;

  for (const field of roleFields) {
    const value = rec[field];
    if (value === undefined || value === null) continue;
    if (Array.isArray(value)) {
      for (const item of value) {
        if (typeof item === "string" && item !== "" && !seen.has(item)) {
          seen.add(item);
          out.push(item);
        }
      }
    } else if (typeof value === "string" && value !== "" && !seen.has(value)) {
      seen.add(value);
      out.push(value);
    }
  }

  return out;
}

/**
 * `@arbac.attribute` fields keyed by prop name. Undefined entries are
 * retained so consumers can distinguish "declared but empty" from
 * "not declared".
 */
export function extractArbacAttrs<T extends object>(
  record: T,
  type: TAtscriptAnnotatedType,
): Record<string, unknown> {
  const { attrFields } = getArbacExtractSpec(type);
  if (attrFields.length === 0) return {};

  const out: Record<string, unknown> = {};
  const rec = record as Record<string, unknown>;
  for (const field of attrFields) {
    out[field] = rec[field];
  }
  return out;
}
