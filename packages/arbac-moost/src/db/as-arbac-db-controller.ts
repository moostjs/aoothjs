import { mergeScopeFilters } from "@aoothjs/arbac";
import type { ControlGate, TProjection, TScopeFilter } from "@aoothjs/arbac";
import type { TCrudOp, TMetaResponse } from "@atscript/db";
import { AsDbController } from "@atscript/moost-db";
import type { NavPropsOf, TAtscriptAnnotatedType } from "@atscript/typescript/utils";
import { HttpError } from "@moostjs/event-http";
import { getConstructor, getInstanceOwnMethods, Inherit, useControllerContext } from "moost";

import { useArbac } from "../arbac.composables";
import type { TArbacMeta } from "../arbac.mate";
import type {
  ControlsOf,
  NavRelationKey,
  NavTarget,
  OwnFieldKey,
  ProjectionOf,
} from "./scope-types";
import {
  applyArbacControls,
  applyArbacProjection,
  applyArbacRelationScopes,
  readCachedScopes,
  transformArbacFilter,
} from "./shared-read-helpers";

/**
 * Contract returned by an ARBAC role's scope predicate on a DB-backed resource.
 *
 * Apps can extend this interface with their own fields via TypeScript
 * declaration merging — both at role-definition time (returned from
 * `role.allow(...)`) and at consumption time (custom controller overrides
 * reading `scopes[i].myCustomField` get full type safety):
 *
 * @example
 * ```ts
 * declare module '@aoothjs/arbac-moost' {
 *   interface ArbacDbScope {
 *     tenantId?: string
 *   }
 * }
 * ```
 */
export interface ArbacDbScope<T = unknown> {
  filter?: TScopeFilter;
  projection?: ProjectionOf<T>;
  set?: Partial<Record<OwnFieldKey<T>, unknown>>;
  allowedFields?: Array<OwnFieldKey<T>>;
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
  controls?: ControlsOf<T>;
  /**
   * Per-relation sub-scopes applied when the request expands a relation via
   * `?$with=<name>`. Recursive — each sub-scope has the same shape and can
   * declare its own `with` for nested expansions (e.g. tasks → comments → task).
   *
   * **Authority model**: the PARENT scope owns the policy for joined rows.
   * arbac-moost does NOT re-evaluate ARBAC against the joined resource's own
   * scopes — that would be a confusing indirection and a perf hit. Whatever
   * the parent declares here is what surfaces from the expansion.
   *
   * **Union across roles**: when multiple roles allow the same parent table,
   * their `with[name]` sub-scopes are unioned at every nested level using the
   * existing `unionProjections` / `mergeScopeFilters` / `unionControlsPolicy`
   * primitives (additive: broader access wins, same rules as the parent).
   *
   * **Silence wins**: if no role declares `with.<name>`, expansion is
   * unrestricted (matches `controls.$with` whitelist semantics; the gate
   * still applies if declared).
   */
  with?: WithOf<T>;
}

/**
 * Per-relation sub-scope map. For `T = unknown` falls back to the legacy
 * untyped `Record<string, ArbacDbScope>`. With a typed `T`, each known
 * relation key gets its scope typed against the joined model (via
 * `NavTarget` to unwrap arrays), while arbitrary `(string & {})` keys
 * keep the untyped escape hatch. Lives here (not in `scope-types.ts`)
 * because it must reference `ArbacDbScope` recursively.
 */
type WithOf<T> = unknown extends T
  ? Record<string, ArbacDbScope>
  : {
      [K in NavRelationKey<T>]?: K extends keyof NavPropsOf<T>
        ? ArbacDbScope<NavTarget<NavPropsOf<T>[K]>>
        : ArbacDbScope;
    };

@Inherit()
export class AsArbacDbController<
  T extends TAtscriptAnnotatedType = TAtscriptAnnotatedType,
> extends AsDbController<T> {
  protected transformFilter(
    filter: Record<string, unknown> | undefined,
  ): Promise<Record<string, unknown>> {
    return transformArbacFilter(filter);
  }

  protected transformProjection(
    projection?: TProjection,
  ): TProjection | undefined | Promise<TProjection | undefined> {
    return applyArbacProjection(projection, readCachedScopes());
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

    const scopes = readCachedScopes();
    applyArbacControls(controls, scopes);
    applyArbacRelationScopes(controls, scopes);
    return undefined;
  }

  protected async applyMetaOverlay(meta: TMetaResponse): Promise<TMetaResponse> {
    const arbac = useArbac();
    const actionToMethodMeta = collectActionMetaByName();

    // Evaluate all gates in parallel: ARBAC evaluate is in-memory + idempotent
    // and reads from the per-event scope cache, so contention is bounded; the
    // win is killing N sequential round-trips through the user provider.
    const crudKeys = Object.keys(meta.crud) as TCrudOp[];
    const [actionResults, crudResults] = await Promise.all([
      Promise.all(
        meta.actions.map((entry) => {
          const methodMeta = actionToMethodMeta.get(entry.name);
          const arbacAction = methodMeta?.arbacActionId ?? methodMeta?.id ?? entry.name;
          return arbac.evaluate({ action: arbacAction });
        }),
      ),
      Promise.all(crudKeys.map((key) => arbac.evaluate({ action: key }))),
    ]);

    const filteredActions: TMetaResponse["actions"] = [];
    for (let i = 0; i < meta.actions.length; i++) {
      if (actionResults[i].allowed) filteredActions.push(meta.actions[i]);
    }

    const filteredCrud: TMetaResponse["crud"] = {};
    for (let i = 0; i < crudKeys.length; i++) {
      if (crudResults[i].allowed) filteredCrud[crudKeys[i]] = meta.crud[crudKeys[i]];
    }

    return { ...meta, actions: filteredActions, crud: filteredCrud };
  }

  protected async onWrite(
    action: "insert" | "insertMany" | "replace" | "replaceMany" | "update" | "updateMany",
    data: unknown,
  ): Promise<unknown> {
    const scopes = readCachedScopes();
    if (action !== "insert" && action !== "insertMany") {
      await this.assertInScope(data, scopes);
    }
    return applyAllowedFieldsAndSet(data, scopes, this.identifierFields());
  }

  protected async onRemove(id: unknown): Promise<unknown> {
    await this.assertInScope(id, readCachedScopes());
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
  // Memoized per controller class: `table.identifications` is decoration-derived
  // and stable for the class's lifetime.
  private identifierFields(): readonly string[] {
    const ctor = this.constructor as new (...args: never[]) => unknown;
    const cached = identifierFieldsCache.get(ctor);
    if (cached) return cached;
    const out = new Set<string>();
    for (const ident of this.table.identifications) {
      for (const f of ident.fields) out.add(f);
    }
    const arr = [...out];
    identifierFieldsCache.set(ctor, arr);
    return arr;
  }
}

// WeakMap so test harnesses that throw away the controller class also throw
// away the cache entry. Cache key is the controller subclass constructor —
// `table.identifications` is derived from atscript decorations on that class,
// so the resolved field list cannot change without a new class.
const identifierFieldsCache = new WeakMap<new (...args: never[]) => unknown, readonly string[]>();

type ActionResolutionMeta = { arbacActionId?: string; id?: string };

// Per-class memoization: controller and method decorator metadata are bound to
// the class at registration time and never mutate per-request. Caching avoids
// re-walking `getInstanceOwnMethods` + N `getMethodMeta` calls on every meta
// overlay (one per GET `/<resource>/meta` request).
const actionMetaByClassCache = new WeakMap<
  new (...args: never[]) => unknown,
  Map<string, ActionResolutionMeta>
>();

function collectActionMetaByName(): Map<string, ActionResolutionMeta> {
  const cc = useControllerContext();
  const instance = cc.getController();
  const ctor = getConstructor(instance) as new (...args: never[]) => unknown;
  const cached = actionMetaByClassCache.get(ctor);
  if (cached) return cached;

  const map = new Map<string, ActionResolutionMeta>();
  const ctrlMeta = cc.getControllerMeta<TArbacMeta>();

  for (const entry of ctrlMeta?.atscript_db_actions ?? []) {
    map.set(entry.name, {});
  }

  for (const methodName of getInstanceOwnMethods(instance)) {
    if (typeof methodName !== "string") continue;
    const m = cc.getMethodMeta<TArbacMeta>(methodName);
    if (!m) continue;
    const actionMeta = m.atscript_db_action;
    if (actionMeta?.name) {
      map.set(actionMeta.name, { arbacActionId: m.arbacActionId, id: m.id });
    }
  }

  actionMetaByClassCache.set(ctor, map);
  return map;
}

/**
 * Test-friendly internal helper — exported for unit tests and helper
 * composition; regular consumers should not call this directly.
 *
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
 * Test-friendly internal helper — exported for unit tests and helper
 * composition; regular consumers should not call this directly.
 *
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

/**
 * Test-friendly internal helper — exported for unit tests and helper
 * composition; regular consumers should not call this directly.
 *
 * Apply the union of `allowedFields` whitelists (with `preserveFields`
 * always preserved) and overlay each scope's `set` overrides. Returns a
 * shallow copy; original `data` is not mutated.
 */
export function applyAllowedFieldsAndSet(
  data: unknown,
  scopes: ArbacDbScope[],
  preserveFields: readonly string[] = [],
): unknown {
  if (scopes.length === 0) return data;

  // Compute per-scope artefacts once — they're a pure function of `scopes` +
  // `preserveFields`, so reusing them across every row in a batch insert /
  // updateMany avoids O(rows × scopes) Set construction + flat() allocation.
  const prepared = prepareScopeOverlay(scopes, preserveFields);

  if (Array.isArray(data)) {
    return data.map((row) => applyPreparedOverlay(row, prepared));
  }
  return applyPreparedOverlay(data, prepared);
}

interface PreparedScopeOverlay {
  union: ReadonlySet<string> | null;
  setOverrides: Record<string, unknown> | null;
}

function prepareScopeOverlay(
  scopes: ArbacDbScope[],
  preserveFields: readonly string[],
): PreparedScopeOverlay {
  let union: Set<string> | null = null;
  for (const s of scopes) {
    if (Array.isArray(s.allowedFields)) {
      if (!union) union = new Set<string>();
      for (const f of s.allowedFields) union.add(f);
    }
  }
  if (union) {
    for (const f of preserveFields) union.add(f);
  }

  let setOverrides: Record<string, unknown> | null = null;
  for (const s of scopes) {
    if (s.set) {
      if (!setOverrides) setOverrides = {};
      Object.assign(setOverrides, s.set);
    }
  }

  return { union, setOverrides };
}

function applyPreparedOverlay(data: unknown, prepared: PreparedScopeOverlay): unknown {
  if (Array.isArray(data)) return data.map((row) => applyPreparedOverlay(row, prepared));
  if (!data || typeof data !== "object") return data;
  const merged: Record<string, unknown> = { ...(data as Record<string, unknown>) };
  if (prepared.union) {
    for (const k of Object.keys(merged)) {
      if (!prepared.union.has(k)) delete merged[k];
    }
  }
  if (prepared.setOverrides) Object.assign(merged, prepared.setOverrides);
  return merged;
}
