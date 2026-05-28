import { type ArbacDbScope, type AsArbacDbController, useArbac } from "@aooth/arbac-moost";
import { mergeScopeFilters } from "@aooth/arbac";
import type { TAtscriptAnnotatedType } from "@atscript/typescript/utils";
import { HttpError } from "@moostjs/event-http";

export type DbControllerCtor<M extends TAtscriptAnnotatedType> = new (
  ...args: never[]
) => AsArbacDbController<M>;

export function scopedFilter(extra: Record<string, unknown>): Record<string, unknown> {
  const scopes = useArbac().getScopes<ArbacDbScope>() ?? [];
  const merged = scopes.length
    ? (mergeScopeFilters(scopes.map((s) => s.filter ?? {})) as Record<string, unknown>)
    : {};
  return { ...merged, ...extra };
}

export function scopedSet(): Record<string, unknown> {
  const scopes = useArbac().getScopes<ArbacDbScope>() ?? [];
  const out: Record<string, unknown> = {};
  for (const s of scopes) Object.assign(out, s.set);
  return out;
}

export function assertWritten(
  result: { matchedCount?: number; deletedCount?: number },
  message = "Not found or no permission",
): void {
  if ((result.matchedCount ?? result.deletedCount ?? 0) === 0) {
    throw new HttpError(404, message);
  }
}
