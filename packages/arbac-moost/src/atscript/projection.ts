import type { TAtscriptAnnotatedType } from "@atscript/typescript/utils";

import { getArbacExtractSpec } from "./extract";

const projectionCache = new WeakMap<TAtscriptAnnotatedType, Record<string, 1>>();

/**
 * Mongo-style projection covering id + every `@arbac.role` /
 * `@arbac.attribute` field. Cached by type reference; pass directly to
 * `table.findOne({ filter, controls: { $select } })`.
 */
export function getArbacProjection(type: TAtscriptAnnotatedType): Record<string, 1> {
  const cached = projectionCache.get(type);
  if (cached !== undefined) return cached;

  const spec = getArbacExtractSpec(type);
  const projection: Record<string, 1> = {};
  if (spec.userIdField) projection[spec.userIdField] = 1;
  for (const f of spec.roleFields) projection[f] = 1;
  for (const f of spec.attrFields) projection[f] = 1;

  projectionCache.set(type, projection);
  return projection;
}
