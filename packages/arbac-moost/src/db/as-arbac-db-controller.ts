import type { ControlGate, TScopeFilter } from "@aooth/arbac";
import type {
  FilterExpr,
  TDbRemoveGuardContext,
  TDbWriteAction,
  TDbWriteCheckContext,
  TDbWriteGuardContext,
  TMetaResponse,
  UniqueryControls,
} from "@atscript/db";
import { AsDbController, getDbEndpoint } from "@atscript/moost-db";
import type { TDbActionScopeContext, TDbControlsType, TDbRequestContext } from "@atscript/moost-db";
import type {
  NavPropsOf,
  TAtscriptAnnotatedType,
  TAtscriptDataType,
} from "@atscript/typescript/utils";
import { HttpError } from "@moostjs/event-http";
import { groupByFields } from "@uniqu/core";
import { Inherit } from "moost";

import { ARBAC_DELEGATED_AUTH } from "../arbac.mate";
import { isPatchAction } from "./helpers";
import { registerArbacDbTarget } from "./relation-policy";
import {
  arbacActionRowScope,
  arbacAllowedActions,
  arbacRelationFilter,
  arbacRowFilter,
  authorizeArbacForm,
  prepareArbacRequest,
  requestFieldVisible,
  requireRequestScopes,
} from "./request-scopes";
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
} from "./shared-read-helpers";
import { applyArbacMetaOverlay } from "./meta-projection";
import { applyAllowedFieldsAndSet } from "./write-fields";
import {
  assertNestedWritesAllowed,
  checkArbacWrite,
  guardArbacRemove,
  guardArbacWrite,
} from "./write-policy";
import type { ArbacWriteTable } from "./write-policy";
import { prefetchRefTargets } from "./write-refs";

export { applyAllowedFieldsAndSet } from "./write-fields";

type TSelect = UniqueryControls["$select"];

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
 *
 * The framework never reads a custom field — the app unions it with its own
 * rule. Where scope lists are CONJOINED (credential attenuation), each custom
 * field needs a conjunction rule registered once with
 * `MoostArbac.registerScopeFields`; a custom field without one fails the
 * evaluation (it is never silently dropped). Since 0.1.72.
 */
export interface ArbacDbScope<T = unknown> {
  filter?: TScopeFilter;
  /**
   * Post-write WITH CHECK filter: every row an insert / replace / update
   * writes must match it (Postgres RLS semantics). Defaults to `filter`;
   * `{}` disables the check. Conjoined (`$and`) like `filter` by
   * `defineTableAccess` part scopes and credential attenuation; unioned
   * across roles. Enforced by the ARBAC DB controllers from 0.1.72.
   */
  check?: TScopeFilter;
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
   * **Which policy the joined rows obey** (0.1.72+):
   * - Declared in any role → the union of those sub-scopes governs the
   *   joined rows (silent roles contribute nothing).
   * - Not declared → the caller's own `query` grant on the related table's
   *   ARBAC resource (its filter, projection, controls and `with`); no grant
   *   → `Unknown relation` (400), identical to a nonexistent relation.
   *
   * **Union across roles**: when multiple roles declare the same relation,
   * their `with[name]` sub-scopes are unioned at every nested level using the
   * existing `unionProjections` / `mergeScopeFilters` / `unionControlsPolicy`
   * primitives (additive: broader access wins, same rules as the parent).
   * The `controls.$with` gate still applies either way.
   */
  with?: WithOf<T>;
  /**
   * Nav relations (`TO` / `FROM` / `VIA` props) this scope may write THROUGH
   * — nested inserts / updates of related rows in the parent's payload.
   * Default deny: a write payload carrying a nav key not listed by any of
   * the caller's write scopes is rejected with 403. Parent authority — the
   * related rows are written under the PARENT scope, the related table's
   * own ARBAC policy is not consulted. Enforced by the ARBAC DB controllers
   * from 0.1.72.
   */
  nestedWrites?: Array<NavRelationKey<T>>;
  /**
   * FK target checks (opt-in): a write that SETS one of these foreign keys
   * (insert / replace rows; update patches touching it) must reference rows
   * the caller can READ under its own `query` grant on the target table's
   * ARBAC resource — else 403 `Referenced row "<field>" is outside your
   * scope`. `true` = every FK of the table; a list names FK fields or the TO
   * relations they back. A target without a registered ARBAC DB controller or
   * without a read grant → 403. Null / absent FKs are not checked.
   *
   * **Union across roles**: enforced for an FK only when EVERY allowing write
   * scope enables it — write scopes grant additively, so a role without the
   * flag grants unconstrained writes of that FK. Credential attenuation
   * enforces what either side enforces.
   *
   * @since 0.1.72
   */
  checkRefs?: true | Array<OwnFieldKey<T> | NavRelationKey<T>>;
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

/**
 * ARBAC-enforcing CRUD controller over an atscript-db table.
 *
 * Every endpoint — `@DbAction` handlers included — resolves the caller's
 * scopes first in `prepareRequest` (fail closed: no grant → 403, `@Public()`
 * does not bypass it); every other hook reads them. Reads apply
 * the scopes' row filter, projection, controls and `with` sub-scopes. Writes
 * enforce, per request:
 *
 * - **nested writes** — a payload key naming a nav relation → 403 unless a
 *   write scope lists it in `nestedWrites`;
 * - **`allowedFields` / `set`** — path-aware whitelist (identifiers, the
 *   version column and `$cas` always kept) and forced values;
 * - **USING** — update / replace / delete target only rows matching the
 *   scope `filter`, checked on the exact pre-image inside the write's
 *   transaction (missing or out of scope → the same 404);
 * - **`checkRefs`** (opt-in) — an FK the write sets must reference a row
 *   the caller can read on the target table (else 403);
 * - **WITH CHECK** — every written row must match the scope `check`
 *   (default: `filter`; `{}` opts out) after the write, inside the
 *   transaction (→ 403, rolled back). On adapters without real transactions
 *   the check runs in memory before the write and fails closed on anything
 *   it cannot decide.
 */
@Inherit()
export class AsArbacDbController<
  T extends TAtscriptAnnotatedType = TAtscriptAnnotatedType,
> extends AsDbController<T> {
  /** Makes this controller the `$with` policy source for its table's ARBAC resource. */
  protected readonly _arbacRelationTarget = registerArbacDbTarget(this);

  /**
   * Resolve the request's ARBAC scopes before anything else consults them:
   * reuse the ones the authorize interceptor cached, else evaluate the
   * handler's resource/action now — a deny is a 403 (`arbacPublic` never
   * bypasses a DB controller). On read endpoints the `$with` relation policy
   * is resolved for the requested relations.
   */
  protected prepareRequest(ctx: TDbRequestContext): Promise<void> {
    return prepareArbacRequest(ctx, this.readable);
  }

  /**
   * The request filter ∧ the union of the scopes' `filter`s. Computed
   * synchronously, but typed with moost-db's async-capable contract
   * (`FilterExpr | Promise<FilterExpr>`) so a subclass may override it
   * `async` — `await super.transformFilter(filter)` — and moost-db awaits it.
   */
  protected transformFilter(
    filter: Record<string, unknown> | undefined,
  ): FilterExpr | Promise<FilterExpr> {
    return arbacRowFilter(filter);
  }

  /** A client relational predicate's operand ∧ the related rows the caller may see ({@link arbacRelationFilter}). Since 0.1.74. */
  protected transformRelationFilter(
    path: string,
    filter: FilterExpr,
  ): FilterExpr | Promise<FilterExpr> {
    return arbacRelationFilter(path, filter, this.readable);
  }

  /**
   * `$select` restricted to the scopes' projection union. Synchronous, typed
   * async-capable like {@link transformFilter}.
   */
  protected transformProjection(
    projection?: TSelect,
  ): TSelect | undefined | Promise<TSelect | undefined> {
    return applyArbacProjection(projection, requireRequestScopes(), this.readable);
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
   * Reads the scopes `prepareRequest` resolved — unresolved scopes are a 403
   * (never "unrestricted"). A violation throws `HttpError(403)`, which
   * moost-db's read handlers let bubble.
   */
  protected validateControls(
    controls: Record<string, unknown>,
    type: TDbControlsType,
  ): string | undefined {
    const baseErr = super.validateControls(controls, type);
    if (baseErr) return baseErr;

    const scopes = requireRequestScopes();
    applyArbacControls(controls, scopes);
    applyArbacRelationScopes(controls, scopes, this.readable);
    return undefined;
  }

  protected applyMetaOverlay(meta: TMetaResponse): Promise<TMetaResponse> {
    return applyArbacMetaOverlay(meta, this.readable);
  }

  /**
   * `GET /meta/form/:name` serves a form only when the caller may run at
   * least one of the actions taking it as input (else the unknown-form 404).
   */
  protected authorizeForm(_name: string, actionNames: readonly string[]): Promise<boolean> {
    return authorizeArbacForm(actionNames);
  }

  /**
   * The rows each `@DbAction` may run on: the caller's grant on that action
   * ({@link arbacActionRowScope} — several grants union, attenuation
   * intersects). Enforced by the action gate and reflected in `$actions` and
   * `GET /meta/actions/:id`. Since 0.1.72.
   *
   * The grant does not depend on `ctx` (the candidate rows, since 0.1.74).
   * To bound an action further by the candidates, override and AND your
   * filter onto `super`'s — it must never replace it:
   *
   * ```ts
   * protected async actionRowScope(name: string, ctx: TDbActionScopeContext) {
   *   const grant = await super.actionRowScope(name, ctx);
   *   return conjoinScopeFilters(grant, await myCandidateScope(name, ctx));
   * }
   * ```
   */
  protected actionRowScope(
    name: string,
    _ctx?: TDbActionScopeContext,
  ): Promise<Record<string, unknown> | undefined> {
    return arbacActionRowScope(name);
  }

  /**
   * The row-level actions `$actions` and `GET /meta/actions/:id` may list:
   * those the caller holds a grant on (the `/meta` overlay's rule, without
   * building the overlay). Since 0.1.72.
   */
  protected allowedActions(names: readonly string[]): Promise<string[]> {
    return arbacAllowedActions(names);
  }

  /**
   * moost-db handlers that delegate their authorization to `prepareRequest`
   * (`getDbEndpoint` — `GET /meta/actions/:id`): the authorize interceptor
   * skips them; `prepareRequest` serves them iff the caller may run at least
   * one row-level action (else 403). Since 0.1.72.
   */
  [ARBAC_DELEGATED_AUTH](method: string): boolean {
    return getDbEndpoint(this, method) !== undefined;
  }

  /**
   * Scope-aware field visibility (the twin of the `/meta` pruning above): a
   * field outside the read-scope projection union answers `false`, which
   * moost-db's visibility hook turns into the same `Unknown field "x"` 400 a
   * nonexistent field gets at every gated query position — see the docs'
   * "Column-scope security floor". Identifiers stay visible. A `rel.x` path
   * (`$with=rel(x>1)`, `$with=rel($sort=x)`, `$with=rel($select=x)`) is
   * checked as `x` against the relation's policy, recursively; the related
   * table's own PK / `preferredId` stay visible. Unresolved scopes hide every
   * field.
   */
  protected hasField(path: string): boolean {
    return super.hasField(path) && requestFieldVisible(path, this.readable);
  }

  /**
   * Untrusted-body stage: reject nested writes the scopes do not opt in
   * (`nestedWrites`), then apply the `allowedFields` whitelist and `set`.
   */
  protected onWrite(action: TDbWriteAction, data: unknown): unknown {
    const scopes = requireRequestScopes();
    assertNestedWritesAllowed(data, scopes, this.readable.navFields);
    // Warm the `checkRefs` target evaluations outside the write's transaction.
    prefetchRefTargets(scopes, this.readable);
    return applyAllowedFieldsAndSet(
      data,
      scopes,
      this.preservedWriteFields(),
      isPatchAction(action) ? (path) => this.isMergeBlock(path) : undefined,
    );
  }

  /** `true` when a patch merges into the nested object at `path` (`@db.patch.strategy 'merge'`). */
  private isMergeBlock(path: string): boolean {
    return this.readable.flatMap.get(path)?.metadata.get("db.patch.strategy") === "merge";
  }

  /** In-transaction stage — USING, `checkRefs`, and WITH CHECK on non-transactional adapters. */
  protected guardWrite(ctx: TDbWriteGuardContext<TAtscriptDataType<T>>): Promise<void> {
    return guardArbacWrite(
      ctx as unknown as TDbWriteGuardContext,
      requireRequestScopes(),
      this.guardedTable,
      this.readable,
    );
  }

  /** USING for deletes: the exact row the delete targets must match the scope filter (else 404). */
  protected guardRemove(ctx: TDbRemoveGuardContext<TAtscriptDataType<T>>): Promise<void> {
    return guardArbacRemove(
      ctx as TDbRemoveGuardContext,
      requireRequestScopes(),
      this.guardedTable,
    );
  }

  /**
   * WITH CHECK: after the write, inside its transaction, every written row
   * must match the scopes' `check` (default `filter`) — else 403 and the
   * write rolls back. Non-transactional adapters were checked in
   * {@link guardWrite}.
   */
  protected checkWrite(ctx: TDbWriteCheckContext): Promise<void> {
    return checkArbacWrite(ctx, requireRequestScopes());
  }

  /** `this.table` as the write guards see it (the generic `T` defeats structural matching). */
  private get guardedTable(): ArbacWriteTable {
    return this.table as unknown as ArbacWriteTable;
  }

  // Always preserve PK + unique-index fields (update/replace address the row
  // by them), the version column and `$cas` (optimistic concurrency) so a
  // whitelist never has to list server-side metadata. Memoized per controller
  // class: `readable.identifications` / `versionColumn` are decoration-derived
  // and stable for the class's lifetime.
  private preservedWriteFields(): readonly string[] {
    const ctor = this.constructor as new (...args: never[]) => unknown;
    const cached = preservedFieldsCache.get(ctor);
    if (cached) return cached;
    const out = new Set<string>();
    for (const ident of this.readable.identifications) {
      for (const f of ident.fields) out.add(f);
    }
    const version = (this.readable as { versionColumn?: string }).versionColumn;
    if (version) {
      out.add(version);
      out.add("$cas");
    }
    const arr = [...out];
    preservedFieldsCache.set(ctor, arr);
    return arr;
  }
}

// WeakMap so test harnesses that throw away the controller class also throw
// away the cache entry. Cache key is the controller subclass constructor —
// the preserved fields derive from atscript decorations on that class, so
// they cannot change without a new class.
const preservedFieldsCache = new WeakMap<new (...args: never[]) => unknown, readonly string[]>();

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
      const usedValues = extractUsedControlValues(key, used, controls);
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
 *   - `$groupBy` — array of column names (strings). With `controls` given,
 *     a calendar-bucket alias (`$select: [{ $bucket, $field, $as }]`) is
 *     mapped to its source `$field` (`groupByFields` from `@uniqu/core`),
 *     so the whitelist is checked against the column actually grouped on.
 *
 * For unknown controls we return an empty array; the caller then enforces
 * `false`-only semantics (controlled by `unionControlsPolicy`'s whitelist
 * gate, which throws if a non-whitelistable control receives a string[]).
 */
export function extractUsedControlValues(
  key: string,
  value: unknown,
  controls?: Record<string, unknown>,
): string[] {
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
    return controls
      ? groupByFields({ $select: controls.$select, $groupBy: value })
      : value.filter((x): x is string => typeof x === "string");
  }
  return [];
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
