import {
  mergeScopeFilters,
  restrictProjection,
  unionControlsPolicy,
  unionProjections,
} from "@aoothjs/arbac";
import type { ControlGate, TProjection, TScopeFilter } from "@aoothjs/arbac";
import type { TCrudOp, TMetaResponse } from "@atscript/db";
import { AsDbController } from "@atscript/moost-db";
import type { TAtscriptAnnotatedType } from "@atscript/typescript/utils";
import { HttpError } from "@moostjs/event-http";
import { getInstanceOwnMethods, Inherit, useControllerContext } from "moost";

import { useArbac } from "../arbac.composables";
import type { TArbacMeta } from "../arbac.mate";

export interface ArbacDbScope {
  filter?: TScopeFilter;
  projection?: TProjection;
  set?: Record<string, unknown>;
  allowedFields?: string[];
  /**
   * Per-control gates for Uniquery URL controls (`$with`, `$groupBy`, `$having`, …).
   * Evaluated by {@link AsArbacDbController.validateControls} before query execution;
   * a violation throws `HttpError(403)`.
   *
   * Per-key semantics ({@link ControlGate}):
   *   - absent / `true` — allowed.
   *   - `false` — denied entirely.
   *   - `readonly string[]` — whitelist (e.g. `{ $with: ['comments'] }` allows
   *     `?$with=comments`, rejects `?$with=tasks`). Supported only for `$with`
   *     (relation names) and `$groupBy` (column names) in v1.
   *
   * Across roles, gates union additively (silence wins) via {@link unionControlsPolicy}.
   *
   * @example `{ controls: { $with: false } }` — disable $with for this role.
   * @example `{ controls: { $with: ['comments', 'owner'] } }` — restrict relations.
   */
  controls?: Record<string, ControlGate>;
}

const DENY_FILTER: TScopeFilter = { $or: [] };

const WRITE_ACTION_TO_ARBAC = {
  insert: "insert",
  insertMany: "insert",
  update: "update",
  updateMany: "update",
  replace: "replace",
  replaceMany: "replace",
} as const;

type WriteAction = keyof typeof WRITE_ACTION_TO_ARBAC;

@Inherit()
export class AsArbacDbController<
  T extends TAtscriptAnnotatedType = TAtscriptAnnotatedType,
> extends AsDbController<T> {
  protected async transformFilter(
    filter: Record<string, unknown> | undefined,
  ): Promise<Record<string, unknown>> {
    const arbac = useArbac();
    const { allowed, scopes } = await arbac.evaluate<ArbacDbScope>();
    if (!allowed) {
      return DENY_FILTER as Record<string, unknown>;
    }
    // Cache scopes so transformProjection (called next on the same request)
    // does not re-evaluate, and stays correct without requiring the
    // ArbacAuthorize interceptor to be wired upstream.
    arbac.setScopes(scopes);
    const merged =
      scopes && scopes.length > 0
        ? mergeScopeFilters(scopes.map((s) => s.filter ?? {}))
        : undefined;
    // Wrap with `$and` (not object spread) so a top-level `$or`/`$and`/`$not`
    // in `filter` cannot drop the scope's sibling field keys when @uniqu/core's
    // `walkFilter` short-circuits on logical operators. See BUG-2.
    const userFilter = filter && Object.keys(filter).length > 0 ? filter : undefined;
    if (!merged) return userFilter ?? {};
    if (!userFilter) return merged;
    return { $and: [merged, userFilter] };
  }

  protected transformProjection(
    projection?: TProjection,
  ): TProjection | undefined | Promise<TProjection | undefined> {
    const scopes = useArbac().getScopes<ArbacDbScope>() ?? [];
    if (scopes.length === 0) {
      return projection;
    }
    const allowed = unionProjections(...scopes.map((s) => s.projection ?? {}));
    if (Object.keys(allowed).length === 0) {
      return projection;
    }
    return restrictProjection(projection ?? {}, allowed);
  }

  /**
   * Enforce per-role `ArbacDbScope.controls` gates against the parsed Uniquery
   * controls of a request. Runs after the base validator (which checks the
   * controls DTO shape) and BEFORE the query/aggregation pipeline executes.
   *
   * `transformFilter` runs first on every read endpoint and caches the
   * evaluated scopes via `arbac.setScopes(...)`, so we read those scopes
   * directly here without re-evaluating ARBAC.
   *
   * On a violation we throw `HttpError(403)`. moost-db's `query` / `pages` /
   * `getOne` handlers do NOT wrap `validateParsed` in try/catch, so the
   * thrown error bubbles to moost which translates it to a 403 response.
   */
  protected validateControls(
    controls: Record<string, unknown>,
    type: "query" | "pages" | "getOne",
  ): string | undefined {
    const baseErr = super.validateControls(controls, type);
    if (baseErr) return baseErr;

    const scopes = useArbac().getScopes<ArbacDbScope>() ?? [];
    if (scopes.length === 0) return undefined;

    enforceControlsPolicy(unionControlsPolicy(scopes), controls);
    return undefined;
  }

  protected async applyMetaOverlay(meta: TMetaResponse): Promise<TMetaResponse> {
    const arbac = useArbac();
    const actionToMethodMeta = collectActionMetaByName();

    const filteredActions: TMetaResponse["actions"] = [];
    for (const entry of meta.actions) {
      const methodMeta = actionToMethodMeta.get(entry.name);
      const arbacAction = methodMeta?.arbacActionId ?? methodMeta?.id ?? entry.name;
      if ((await arbac.evaluate({ action: arbacAction })).allowed) {
        filteredActions.push(entry);
      }
    }

    const filteredCrud: TMetaResponse["crud"] = {};
    for (const key of Object.keys(meta.crud) as TCrudOp[]) {
      if ((await arbac.evaluate({ action: key })).allowed) {
        filteredCrud[key] = meta.crud[key];
      }
    }

    return { ...meta, actions: filteredActions, crud: filteredCrud };
  }

  protected async onWrite(action: WriteAction, data: unknown): Promise<unknown> {
    const arbacAction = WRITE_ACTION_TO_ARBAC[action];
    const { allowed, scopes } = await useArbac().evaluate<ArbacDbScope>({ action: arbacAction });
    if (!allowed) {
      throw new HttpError(403, `Forbidden: ${arbacAction}`);
    }
    if (action !== "insert" && action !== "insertMany") {
      await this.assertInScope(data, scopes ?? []);
    }
    return applyAllowedFieldsAndSet(data, scopes ?? [], this.identifierFields());
  }

  protected async onRemove(id: unknown): Promise<unknown> {
    const { allowed, scopes } = await useArbac().evaluate<ArbacDbScope>({ action: "remove" });
    if (!allowed) {
      throw new HttpError(403, "Forbidden: remove");
    }
    await this.assertInScope(id, scopes ?? []);
    return id;
  }

  // BUG-1: base update/remove key purely on payload.id, so without this
  // pre-check a caller could mutate a row outside their scope by knowing its PK.
  private async assertInScope(idOrIds: unknown, scopes: ArbacDbScope[]): Promise<void> {
    const scopeFilter = mergeScopeFilters(scopes.map((s) => s.filter ?? {}));
    if (!scopeFilter) return;
    const ids = Array.isArray(idOrIds) ? idOrIds : [idOrIds];
    const idFilters = ids.map((id) => this.table.resolveIdFilter(id));
    if (idFilters.some((f) => !f)) throw new HttpError(404, "Not found");
    const idFilter = idFilters.length === 1 ? idFilters[0] : { $or: idFilters };
    const count = await this.table.count({
      filter: { $and: [idFilter, scopeFilter] },
      // TScopeFilter is not parameterized over the table type; fixing properly requires a moost-db count overload or a full TScopeFilter refactor — not worth it for one call site.
    } as never);
    if (count < ids.length) throw new HttpError(404, "Not found");
  }

  // Always preserve PK + unique-index fields so callers don't need to whitelist
  // server-derived metadata that update/replace requires to address the row.
  private identifierFields(): string[] {
    const out = new Set<string>();
    for (const ident of this.table.identifications) {
      for (const f of ident.fields) out.add(f);
    }
    return [...out];
  }
}

type ActionResolutionMeta = { arbacActionId?: string; id?: string };

function collectActionMetaByName(): Map<string, ActionResolutionMeta> {
  const cc = useControllerContext();
  const map = new Map<string, ActionResolutionMeta>();
  const ctrlMeta = cc.getControllerMeta<TArbacMeta>();

  for (const entry of ctrlMeta?.atscript_db_actions ?? []) {
    map.set(entry.name, {});
  }

  const instance = cc.getController();
  for (const methodName of getInstanceOwnMethods(instance)) {
    if (typeof methodName !== "string") continue;
    const m = cc.getMethodMeta<TArbacMeta>(methodName);
    if (!m) continue;
    const actionMeta = m.atscript_db_action;
    if (actionMeta?.name) {
      map.set(actionMeta.name, { arbacActionId: m.arbacActionId, id: m.id });
    }
  }

  return map;
}

/**
 * Enforce a per-control policy against a parsed Uniquery `controls` map.
 *
 * Throws `HttpError(403)` on the first violation. Pure (no DI) so it is
 * trivially unit-testable; `validateControls` wires it up to the controller's
 * cached scopes.
 *
 * Semantics per gate (see {@link ControlGate}):
 *   - `true` (or absent — dropped by `unionControlsPolicy`): allow.
 *   - `false`: deny if the control is used at all.
 *   - `readonly string[]`: allow only the listed values; reject any other.
 *
 * "Used" means the control key is present AND non-empty (an empty array is
 * treated as not used, matching how the parser leaves missing controls).
 */
export function enforceControlsPolicy(
  policy: Record<string, ControlGate>,
  controls: Record<string, unknown>,
): void {
  if (Object.keys(policy).length === 0) return;
  for (const [key, gate] of Object.entries(policy)) {
    const used = controls[key];
    if (used === undefined || used === null) continue;
    if (Array.isArray(used) && used.length === 0) continue;

    if (gate === false) {
      throw new HttpError(403, `Control "${key}" is not allowed for your role`);
    }
    if (Array.isArray(gate)) {
      const usedValues = extractUsedControlValues(key, used);
      for (const v of usedValues) {
        if (!gate.includes(v)) {
          throw new HttpError(403, `Control "${key}=${v}" is not allowed for your role`);
        }
      }
    }
    // gate === true: dropped by union helper; defensive no-op here.
  }
}

/**
 * Extract the set of "named values" from a Uniquery control payload, for
 * use against a whitelist gate.
 *
 * Currently supported (matches `WHITELISTABLE_CONTROLS` in `unionControlsPolicy`):
 *   - `$with` — array of `{ name, … }` objects (per `TypedWithRelation`,
 *     see `@uniqu/core` parser at `parseWithSegment`); we extract `name`.
 *     Bare strings are tolerated for forward compatibility.
 *   - `$groupBy` — array of column names (strings). Returned as-is.
 *
 * For unknown controls we return an empty array; the caller then enforces
 * `false`-only semantics (controlled by `unionControlsPolicy`'s whitelist
 * gate, which throws if a non-whitelistable control receives a string[]).
 */
export function extractUsedControlValues(key: string, value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  if (key === "$with") {
    const out: string[] = [];
    for (const entry of value) {
      if (typeof entry === "string") out.push(entry);
      else if (typeof (entry as { name?: unknown } | null)?.name === "string") {
        out.push((entry as { name: string }).name);
      }
    }
    return out;
  }
  if (key === "$groupBy") {
    return value.filter((x): x is string => typeof x === "string");
  }
  return [];
}

export function applyAllowedFieldsAndSet(
  data: unknown,
  scopes: ArbacDbScope[],
  preserveFields: readonly string[] = [],
): unknown {
  if (scopes.length === 0) return data;
  if (Array.isArray(data)) {
    return data.map((row) => applyAllowedFieldsAndSet(row, scopes, preserveFields));
  }
  if (!data || typeof data !== "object") return data;

  const allowedSets = scopes
    .map((s) => s.allowedFields)
    .filter((x): x is string[] => Array.isArray(x));
  const merged: Record<string, unknown> = { ...(data as Record<string, unknown>) };

  if (allowedSets.length > 0) {
    const union = new Set<string>(allowedSets.flat());
    for (const f of preserveFields) union.add(f);
    for (const k of Object.keys(merged)) {
      if (!union.has(k)) delete merged[k];
    }
  }

  for (const s of scopes) {
    if (s.set) Object.assign(merged, s.set);
  }

  return merged;
}
