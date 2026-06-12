import { mergeScopeFilters } from "@aooth/arbac";
import type { ControlGate, TProjection, TScopeFilter } from "@aooth/arbac";
import type { TMetaResponse } from "@atscript/db";
import { AsDbController } from "@atscript/moost-db";
import type { NavPropsOf, TAtscriptAnnotatedType } from "@atscript/typescript/utils";
import { HttpError } from "@moostjs/event-http";
import { Inherit } from "moost";

import type {
  ControlsOf,
  NavRelationKey,
  NavTarget,
  OwnFieldKey,
  ProjectionOf,
} from "./scope-types";
import {
  applyArbacMetaOverlay,
  isScopedFieldVisible,
  metaAlwaysVisibleFields,
} from "./meta-projection";
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
 * declare module '@aooth/arbac-moost' {
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
   * Translate `@uniqu/url` parser failures into HTTP 400 instead of letting them
   * bubble as 500. The base `parseQueryString` calls `parseUrl()` directly with
   * no try/catch, so a malformed `?status=...` (e.g. unquoted single quote at a
   * non-string position) surfaces as a server error — misleading, since the
   * server is fine and the client sent bad input.
   *
   * Narrow targeting: only `SyntaxError` raised from inside the parser is
   * remapped. Other errors (e.g. a programmer-introduced TypeError in a future
   * override) still bubble as 500. SQL-injection-shaped payloads remain safely
   * handled either way — see SEC-17 for the parameterisation invariant; this
   * override is an orthogonal robustness pin around the parse step.
   */
  protected parseQueryString(url: string): ReturnType<AsDbController<T>["parseQueryString"]> {
    try {
      return super.parseQueryString(url);
    } catch (err) {
      throw remapUniquUrlSyntaxError(err);
    }
  }

  /**
   * Same parser-error → 400 remap as {@link parseQueryString}, applied to the
   * `/one` and `/one?…` code paths which use `parseControlsOnlyFromUrl`.
   */
  protected parseControlsOnlyFromUrl(
    url: string,
  ): ReturnType<AsDbController<T>["parseControlsOnlyFromUrl"]> {
    try {
      return super.parseControlsOnlyFromUrl(url);
    } catch (err) {
      throw remapUniquUrlSyntaxError(err);
    }
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

  protected applyMetaOverlay(meta: TMetaResponse): Promise<TMetaResponse> {
    return applyArbacMetaOverlay(meta, metaAlwaysVisibleFields(this, this.table));
  }

  /**
   * Field-existence check, scope-aware (BUG-3 twin of the `/meta` pruning
   * above): a field outside the read-scope projection union must be
   * indistinguishable from a field that does not exist. The base controller's
   * ONLY call site is `validateInsights`, which turns a `false` here into the
   * same `Unknown field "x"` HTTP 400 a truly nonexistent field gets — so
   * `$select`, filter, and sort references to a hidden field cannot be used
   * as an existence/value oracle. Identifier fields stay visible (reads
   * always return them — see {@link MetaVisibility.alwaysVisible}), and paths
   * under a `with`-granted relation pass through to the sub-scope's own
   * enforcement. Scopes were cached by the route-level authorize interceptor
   * before validation runs (`useArbac` setScopes), so the union reflects the
   * exact action being executed.
   */
  protected hasField(path: string): boolean {
    return (
      super.hasField(path) &&
      isScopedFieldVisible(readCachedScopes(), path, metaAlwaysVisibleFields(this, this.table))
    );
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

/**
 * Translate a `@uniqu/url` parser `SyntaxError` into `HttpError(400)`. Any
 * other error (including a pre-existing `HttpError`) is returned as-is so the
 * caller's `throw remapUniquUrlSyntaxError(err)` preserves the original
 * status — no double-wrapping.
 *
 * Matching is narrow: only `SyntaxError` whose message carries the parser's
 * "at pos N" / "at N" positional marker (every throw site in @uniqu/url's
 * lexer + parser emits one). This avoids catching unrelated SyntaxErrors that
 * a future override might surface from `JSON.parse` etc.
 */
function remapUniquUrlSyntaxError(err: unknown): unknown {
  if (err instanceof HttpError) return err;
  if (!(err instanceof SyntaxError)) return err;
  const msg = err.message;
  if (!/at (?:pos )?\d+/.test(msg)) return err;
  return new HttpError(400, `Invalid query string: ${msg}`);
}
