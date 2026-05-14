import { type ArbacDbScope, type AsArbacDbController, useArbac } from "@aoothjs/arbac-moost"
import { mergeScopeFilters } from "@aoothjs/arbac"
import type { TAtscriptAnnotatedType } from "@atscript/typescript/utils"
import { HttpError } from "@moostjs/event-http"

export type DbControllerCtor<M extends TAtscriptAnnotatedType> = new (
  ...args: never[]
) => AsArbacDbController<M>

export function scopedFilter(extra: Record<string, unknown>): Record<string, unknown> {
  const scopes = useArbac().getScopes<ArbacDbScope>() ?? []
  const merged = scopes.length
    ? (mergeScopeFilters(scopes.map((s) => s.filter ?? {})) as Record<string, unknown>)
    : {}
  return { ...merged, ...extra }
}

export function scopedSet(): Record<string, unknown> {
  const scopes = useArbac().getScopes<ArbacDbScope>() ?? []
  return scopes.reduce<Record<string, unknown>>((acc, s) => ({ ...acc, ...(s.set ?? {}) }), {})
}

export function assertWritten(
  result: { matchedCount?: number; deletedCount?: number },
  message = "Not found or no permission",
): void {
  if ((result.matchedCount ?? result.deletedCount ?? 0) === 0) {
    throw new HttpError(404, message)
  }
}
