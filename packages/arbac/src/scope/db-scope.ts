import { intersectControlsPolicy, unionControlsPolicy } from "./controls";
import { conjoinScopeFilters, DENY_FILTER, mergeScopeFilters } from "./filter";
import { intersectProjections, unionProjections } from "./projection";
import type { TProjectionChildren } from "./projection";
import type { ControlGate, TProjection, TScopeFilter } from "./types";

/**
 * The DB scope shape the scope algebra reads — structurally what
 * `ArbacDbScope` (`@aooth/arbac-moost`) carries. Every facet is optional.
 *
 * @since 0.1.72
 */
export interface TDbScope {
  filter?: TScopeFilter;
  check?: TScopeFilter;
  projection?: object;
  controls?: object;
  allowedFields?: readonly string[];
  set?: object;
  nestedWrites?: readonly string[];
  checkRefs?: true | readonly string[];
  with?: object;
}

/**
 * The built-in {@link TDbScope} keys — the facets the scope algebra itself
 * combines. Any other key is a custom (declaration-merged) scope field, which
 * {@link conjoinScopes} combines only through a registered
 * {@link TScopeFieldRule}.
 *
 * @since 0.1.72
 */
export const DB_SCOPE_KEYS: readonly string[] = Object.freeze([
  "filter",
  "check",
  "projection",
  "controls",
  "allowedFields",
  "set",
  "nestedWrites",
  "checkRefs",
  "with",
]);

const BUILT_IN_KEYS: ReadonlySet<string> = new Set(DB_SCOPE_KEYS);

/**
 * The conjunction rule of ONE custom scope field (a key an app adds to its
 * scope type by declaration merging). {@link conjoinScopes} calls `conjoin`
 * only when some scope on either side carries the field.
 *
 * @since 0.1.72
 */
export interface TScopeFieldRule<S extends object = TDbScope> {
  /**
   * Optional ROW restriction the field implies: the filter a scope carrying
   * `value` admits (`undefined` / `{}` = no row restriction). Folded into
   * that scope's `filter` by {@link applyScopeFieldFilters} — ANDed within
   * the scope, so the union across scopes stays an `$or`. An explicit
   * `check` is left as written; an absent one follows the folded filter.
   *
   * Must depend ONLY on `(value, scope)` — never on request context: the
   * result is cached process-wide per scope object. Put user-dependent data
   * into the scope value from the role's scope predicate.
   */
  rowFilter?(value: unknown, scope: S): TScopeFilter | undefined;
  /**
   * Combine the field of two restrict-only sides into the ONE value the
   * composite scope carries — never wider than either side. Each side is a
   * scope LIST the app unions with its own rule (a scope without the field is
   * typically unrestricted for it). In a credential attenuation `a` is the
   * user's full authority and `b` the credential's view. Return `undefined`
   * for "unrestricted" (the key is omitted).
   */
  conjoin(a: readonly S[], b: readonly S[]): unknown;
}

/**
 * Thrown by {@link conjoinScopes} for a custom scope field without a
 * conjunction rule — a server CONFIGURATION error (never a client error):
 * the conjunction fails closed instead of dropping the field.
 *
 * @since 0.1.72
 */
export class ScopeFieldConfigError extends Error {
  override readonly name = "ScopeFieldConfigError";
  constructor(
    /** The custom scope field without a rule. */
    readonly field: string,
    message: string,
  ) {
    super(message);
  }
}

/** Custom scope field name → its {@link TScopeFieldRule}. @since 0.1.72 */
export type TScopeFieldRules<S extends object = TDbScope> = Readonly<
  Record<string, TScopeFieldRule<S>>
>;

/**
 * The effective (unioned) policy of a list of DB scopes — one scope per
 * allowing rule, so each facet unions ADDITIVELY (more roles = more access).
 * Every facet's union rule is defined here once; facets compute lazily (a
 * misconfigured facet throws only where it is used). An empty list is the
 * identity (unrestricted) of every union — denial is decided before, by
 * {@link normalizeScopes}.
 *
 * @since 0.1.72
 */
export interface TEffectiveDbScope<S extends TDbScope = TDbScope> {
  /** Row filter union (`$or`, {@link mergeScopeFilters}); `undefined` = unrestricted. */
  readonly filter: TScopeFilter | undefined;
  /**
   * WITH CHECK union — each scope's `check`, defaulting to its `filter`
   * (`{}` = no check); `undefined` = nothing to check.
   */
  readonly check: TScopeFilter | undefined;
  /** Whether any scope sets an explicit `check`. */
  readonly hasExplicitCheck: boolean;
  /** Projection union ({@link unionProjections}); `{}` = every field. */
  readonly projection: TProjection;
  /** Controls union ({@link unionControlsPolicy}); an absent key = allowed. */
  readonly controls: Record<string, ControlGate>;
  /**
   * Union of the `allowedFields` whitelists; `undefined` when no scope
   * carries one (field-unrestricted writes).
   */
  readonly allowedFields: ReadonlySet<string> | undefined;
  /** The `set` overlays, later scopes winning; `undefined` when none sets one. */
  readonly set: Readonly<Record<string, unknown>> | undefined;
  /** Union of the `nestedWrites` opt-ins. */
  readonly nestedWrites: ReadonlySet<string>;
  /**
   * `checkRefs` entries EVERY scope enables (intersection of enforcement —
   * a scope without the flag grants unconstrained writes of that FK);
   * `true` = all. Names as written (a schema-aware caller resolves them).
   */
  readonly checkRefs: true | ReadonlySet<string>;
  /** Relation names some scope declares a `with.<name>` sub-scope for. */
  readonly withNames: ReadonlySet<string>;
  /** The declared `with.<name>` sub-scopes (identity-stable per name). */
  withScopes(name: string): readonly S[];
}

const NONE: ReadonlySet<string> = new Set();

/** Lazily computed facets of one scopes array. */
class EffectiveDbScope<S extends TDbScope> implements TEffectiveDbScope<S> {
  private readonly memo = new Map<string, unknown>();
  private withMemo?: Map<string, readonly S[]>;

  constructor(private readonly scopes: readonly S[]) {}

  private lazy<V>(name: string, compute: () => V): V {
    if (this.memo.has(name)) return this.memo.get(name) as V;
    const value = compute();
    this.memo.set(name, value);
    return value;
  }

  get filter(): TScopeFilter | undefined {
    return this.lazy("filter", () => mergeScopeFilters(this.scopes.map((s) => s.filter ?? {})));
  }

  get check(): TScopeFilter | undefined {
    return this.lazy("check", () =>
      this.hasExplicitCheck
        ? mergeScopeFilters(this.scopes.map((s) => s.check ?? s.filter ?? {}))
        : this.filter,
    );
  }

  get hasExplicitCheck(): boolean {
    return this.lazy("hasCheck", () => this.scopes.some((s) => s.check !== undefined));
  }

  get projection(): TProjection {
    return this.lazy("projection", () =>
      unionProjections(...this.scopes.map((s) => (s.projection ?? {}) as TProjection)),
    );
  }

  get controls(): Record<string, ControlGate> {
    return this.lazy("controls", () =>
      unionControlsPolicy(this.scopes as ReadonlyArray<{ controls?: Record<string, ControlGate> }>),
    );
  }

  get allowedFields(): ReadonlySet<string> | undefined {
    return this.lazy("allowedFields", () => {
      let out: Set<string> | undefined;
      for (const s of this.scopes) {
        if (!Array.isArray(s.allowedFields)) continue;
        out ??= new Set();
        for (const f of s.allowedFields) out.add(f);
      }
      return out;
    });
  }

  get set(): Readonly<Record<string, unknown>> | undefined {
    return this.lazy("set", () => {
      let out: Record<string, unknown> | undefined;
      for (const s of this.scopes) if (s.set) Object.assign((out ??= {}), s.set);
      return out;
    });
  }

  get nestedWrites(): ReadonlySet<string> {
    return this.lazy("nestedWrites", () => {
      const out = new Set(this.scopes.flatMap((s) => s.nestedWrites ?? []));
      return out.size > 0 ? out : NONE;
    });
  }

  get checkRefs(): true | ReadonlySet<string> {
    return this.lazy("checkRefs", () =>
      intersectEnabled(
        this.scopes.map((s) => (s.checkRefs === true ? true : new Set(s.checkRefs ?? []))),
      ),
    );
  }

  get withNames(): ReadonlySet<string> {
    return this.lazy("withNames", () => {
      const out = new Set<string>();
      for (const s of this.scopes)
        if (s.with) for (const name of Object.keys(s.with)) out.add(name);
      return out.size > 0 ? out : NONE;
    });
  }

  withScopes(name: string): readonly S[] {
    this.withMemo ??= new Map();
    let list = this.withMemo.get(name);
    if (!list) {
      list = [];
      for (const s of this.scopes) {
        const sub = (s.with as Record<string, S | undefined> | undefined)?.[name];
        if (sub) (list as S[]).push(sub);
      }
      this.withMemo.set(name, list);
    }
    return list;
  }
}

const effectiveCache = new WeakMap<readonly TDbScope[], EffectiveDbScope<TDbScope>>();

/**
 * The {@link TEffectiveDbScope} of `scopes`, memoized per scopes ARRAY (an
 * identity-stable per-request list reuses every computed facet).
 *
 * @since 0.1.72
 */
export function effectiveScope<S extends TDbScope>(scopes: readonly S[]): TEffectiveDbScope<S> {
  let eff = effectiveCache.get(scopes);
  if (!eff) {
    eff = new EffectiveDbScope<TDbScope>(scopes);
    effectiveCache.set(scopes, eff);
  }
  return eff as unknown as TEffectiveDbScope<S>;
}

/**
 * Intersection of enforcement: an entry is enforced only when EVERY input
 * enables it (`true` enables all). No input → nothing enforced.
 *
 * @since 0.1.72
 */
export function intersectEnabled<K>(inputs: Iterable<true | ReadonlySet<K>>): true | Set<K> {
  let out: true | Set<K> | undefined;
  for (const input of inputs) {
    if (input === true) {
      out ??= true;
      continue;
    }
    out = out === undefined || out === true ? new Set(input) : intersect(out, input);
    if (out.size === 0) return out;
  }
  return out ?? new Set();
}

function intersect<K>(a: ReadonlySet<K>, b: ReadonlySet<K>): Set<K> {
  const out = new Set<K>();
  for (const k of a) if (b.has(k)) out.add(k);
  return out;
}

/**
 * The unified empty-scope rule for an evaluation outcome: denied → `undefined`;
 * allowed with `scopes` absent (a scope-agnostic evaluator) → `[{}]`
 * (unrestricted); a scope predicate that returned nothing contributes nothing
 * (fail closed for that rule); allowed with no scope left → `undefined` (deny).
 *
 * @since 0.1.72
 */
export function normalizeScopes<S extends object>(outcome: {
  allowed: boolean;
  scopes?: ReadonlyArray<S | null | undefined>;
}): S[] | undefined {
  if (!outcome.allowed) return undefined;
  const { scopes } = outcome;
  if (scopes === undefined) return [{} as S];
  const list = scopes.every((s) => s != null)
    ? (scopes as S[])
    : scopes.filter((s): s is S => s != null);
  return list.length > 0 ? list : undefined;
}

/**
 * Several evaluations served as ONE surface (e.g. the handlers of one crud
 * op): each normalized with {@link normalizeScopes}, the allowed ones'
 * scopes concatenated — `undefined` when none allows.
 *
 * @since 0.1.72
 */
export function unionOutcomes<S extends object>(
  outcomes: ReadonlyArray<{ allowed: boolean; scopes?: ReadonlyArray<S | null | undefined> }>,
): S[] | undefined {
  let out: S[] | undefined;
  for (const o of outcomes) {
    const scopes = normalizeScopes(o);
    if (scopes) (out ??= []).push(...scopes);
  }
  return out;
}

/** A row policy: the read / USING `filter` and the WITH CHECK `check` (defaults to `filter`). */
export interface TRowPolicy {
  filter?: TScopeFilter;
  check?: TScopeFilter;
}

/**
 * Conjoin two row policies (`$and`, restrict-only): `filter = a.filter ∧
 * b.filter`; the effective check `(a.check ?? a.filter) ∧ (b.check ??
 * b.filter)`. `check` is set only when it differs from the conjoined
 * `filter` (which an absent `check` defaults to) — `{}` when it is
 * unrestricted while the filter is not.
 *
 * @since 0.1.72
 */
export function conjoinRowPolicies(a: TRowPolicy, b: TRowPolicy): TRowPolicy {
  const out: TRowPolicy = {};
  const filter = conjoinScopeFilters(a.filter, b.filter);
  if (filter && Object.keys(filter).length > 0) out.filter = filter;
  if (a.check === undefined && b.check === undefined) return out;
  const check = conjoinScopeFilters(a.check ?? a.filter, b.check ?? b.filter);
  if (stableKey(check ?? {}) !== stableKey(out.filter ?? {})) out.check = check ?? {};
  return out;
}

/** Options of {@link conjoinScopes}. */
export interface TConjoinScopesOptions<S extends TDbScope> {
  /** Schema lookup to subtract a nested exclusion exactly (without it: fail closed). */
  childrenOf?: TProjectionChildren;
  /**
   * Schema-aware `checkRefs` conjunction; default: the union of each side's
   * {@link TEffectiveDbScope.checkRefs} names.
   */
  checkRefs?: (a: readonly S[], b: readonly S[]) => true | string[] | undefined;
  /**
   * Rules for custom (non-built-in) scope fields, applied at every level
   * (`with` sub-scopes too). A custom field present on either side without a
   * rule throws — it is never dropped (a dropped field reads as absent, i.e.
   * typically unrestricted).
   */
  fields?: TScopeFieldRules<S>;
}

/**
 * Conjoin two scope lists (credential attenuation: the user's ceiling ∧ the
 * credential's narrowed view) into ONE composite scope. Each side is first
 * unioned ({@link effectiveScope}), then the two results are CONJOINED facet
 * by facet — never with the additive union helpers, which would widen:
 *
 * - `filter` / `check` — {@link conjoinRowPolicies};
 * - `projection` — {@link intersectProjections} (no common field → the
 *   first side's projection plus a match-nothing filter, never `{}`);
 * - `controls` — {@link intersectControlsPolicy} (deny wins);
 * - `allowedFields` — intersection (a side without a whitelist is unrestricted);
 * - `nestedWrites` — intersection (a side without the key allows none);
 * - `set` — combined, the FIRST side winning a key conflict;
 * - `checkRefs` — enforced when EITHER side enforces it;
 * - `with` — per relation, recursively; a relation declared by ONE side only
 *   is marked {@link INHERITED_CONJUNCTION} (the silent side's inherited
 *   grant on the related table must be conjoined at resolution time);
 * - a custom field — its `opts.fields` rule; none registered → throws
 *   (fail closed: never silently dropped).
 *
 * @since 0.1.72
 */
export function conjoinScopes<S extends TDbScope>(
  a: readonly S[],
  b: readonly S[],
  opts: TConjoinScopesOptions<S> = {},
): S {
  const custom = customFieldRules(a, b, opts.fields);
  const ea = effectiveScope(a);
  const eb = effectiveScope(b);
  const intersected = intersectProjections(ea.projection, eb.projection, opts.childrenOf);
  const projection = intersected ?? ea.projection;
  const deny = (f: TScopeFilter | undefined) =>
    intersected ? f : conjoinScopeFilters(f, DENY_FILTER);
  const rows = conjoinRowPolicies(
    { filter: ea.filter, check: ea.hasExplicitCheck ? (ea.check ?? {}) : undefined },
    {
      filter: deny(eb.filter),
      check: eb.hasExplicitCheck ? (deny(eb.check) ?? {}) : undefined,
    },
  );
  const controls = intersectControlsPolicy(ea.controls, eb.controls);
  const allowedFields = intersectAllowedFields(ea.allowedFields, eb.allowedFields);
  const nestedWrites = [...ea.nestedWrites].filter((rel) => eb.nestedWrites.has(rel)).toSorted();
  const set = ea.set || eb.set ? { ...eb.set, ...ea.set } : undefined;
  const checkRefs = (opts.checkRefs ?? unionRefNames)(a, b);
  const withMap = conjoinWith(ea, eb, opts.fields);

  const s: TDbScope = { ...rows };
  if (Object.keys(projection).length > 0) s.projection = projection;
  if (Object.keys(controls).length > 0) s.controls = controls;
  if (allowedFields) s.allowedFields = allowedFields;
  if (nestedWrites.length > 0) s.nestedWrites = nestedWrites;
  if (checkRefs) s.checkRefs = checkRefs;
  if (set) s.set = set;
  if (withMap) s.with = withMap;
  for (const [key, rule] of custom) {
    const value = rule.conjoin(a, b);
    if (value !== undefined) (s as Record<string, unknown>)[key] = value;
  }
  return s as S;
}

/**
 * The rules of the custom fields some scope of `a` / `b` carries (a key
 * holding `undefined` does not count). Throws on a custom field without a
 * rule — dropping it would silently widen (fail closed).
 */
function customFieldRules<S extends TDbScope>(
  a: readonly S[],
  b: readonly S[],
  fields: TScopeFieldRules<S> | undefined,
): Map<string, TScopeFieldRule<S>> {
  const out = new Map<string, TScopeFieldRule<S>>();
  for (const scope of [...a, ...b]) {
    for (const key of Object.keys(scope)) {
      if (BUILT_IN_KEYS.has(key) || out.has(key)) continue;
      if ((scope as Record<string, unknown>)[key] === undefined) continue;
      const rule = fields && Object.hasOwn(fields, key) ? fields[key] : undefined;
      if (!rule) {
        throw new ScopeFieldConfigError(
          key,
          `Scope field "${key}" has no conjunction rule: a credential attenuation cannot ` +
            "combine it, and dropping it would widen access. Register one with " +
            `MoostArbac.registerScopeFields({ ${key}: { conjoin: (a, b) => ... } }) ` +
            "(or the `fields` option of conjoinScopes).",
        );
      }
      out.set(key, rule);
    }
  }
  return out;
}

function intersectAllowedFields(
  a: ReadonlySet<string> | undefined,
  b: ReadonlySet<string> | undefined,
): string[] | undefined {
  if (a === undefined) return b && [...b];
  if (b === undefined) return [...a];
  return [...a].filter((f) => b.has(f)).toSorted();
}

/** Schema-less `checkRefs` conjunction: what either side enforces. */
function unionRefNames<S extends TDbScope>(
  a: readonly S[],
  b: readonly S[],
): true | string[] | undefined {
  const ra = effectiveScope(a).checkRefs;
  const rb = effectiveScope(b).checkRefs;
  if (ra === true || rb === true) return true;
  const names = new Set([...ra, ...rb]);
  return names.size > 0 ? [...names].toSorted() : undefined;
}

type RowFilter = NonNullable<TScopeFieldRule<never>["rowFilter"]>;

/** Per rule registry: its row rules and the fold memo (scope → folded scope). */
const foldStates = new WeakMap<
  object,
  { rules: Array<[string, RowFilter]>; memo: WeakMap<object, object> }
>();
const NO_FIELDS: TScopeFieldRules<never> = Object.freeze({});

/** Options of {@link applyScopeFieldFilters}. @since 0.1.72 */
export interface TApplyScopeFieldFiltersOptions {
  /**
   * Called for a non-built-in scope key with no rule in `fields` (once per
   * scope object carrying it) — e.g. to warn about a field that will fail
   * the first attenuated conjunction.
   */
  onUnknownField?: (field: string) => void;
}

/**
 * Fold every custom field's {@link TScopeFieldRule.rowFilter} into its
 * scope's `filter` (`filter ∧ rowFilter(value, scope)`), recursively into
 * `with` sub-scopes. Apply it per evaluated scope list — before any union or
 * conjunction — so every row path sees the restriction. The custom value
 * stays on the scope. Scopes are never mutated: a changed scope is a copy.
 * Memoized per rule registry and scope object (process-wide), and
 * idempotent (a folded scope folds to itself); without row rules (and no
 * `onUnknownField`) the input list is returned as is.
 *
 * @since 0.1.72
 */
export function applyScopeFieldFilters<S extends TDbScope>(
  scopes: readonly S[],
  fields: TScopeFieldRules<S> | undefined,
  opts: TApplyScopeFieldFiltersOptions = {},
): readonly S[] {
  const registry: object = fields ?? NO_FIELDS;
  let state = foldStates.get(registry);
  if (!state) {
    const rules: Array<[string, RowFilter]> = [];
    for (const [key, rule] of Object.entries(registry as TScopeFieldRules<S>)) {
      if (rule.rowFilter) rules.push([key, rule.rowFilter.bind(rule)]);
    }
    state = { rules, memo: new WeakMap() };
    foldStates.set(registry, state);
  }
  const { rules, memo } = state;
  const { onUnknownField } = opts;
  if (rules.length === 0 && !onUnknownField) return scopes;
  const fold = (scope: S): S => {
    if (scope === null || typeof scope !== "object") return scope;
    const hit = memo.get(scope);
    if (hit) return hit as S;
    const record = scope as Record<string, unknown>;
    if (onUnknownField) {
      for (const key of Object.keys(scope)) {
        if (BUILT_IN_KEYS.has(key) || Object.hasOwn(registry, key)) continue;
        if (record[key] !== undefined) onUnknownField(key);
      }
    }
    let filter = scope.filter;
    for (const [key, rowFilter] of rules) {
      const value = record[key];
      if (value !== undefined)
        filter = conjoinScopeFilters(filter, rowFilter(value, scope as never));
    }
    let out = filter === scope.filter ? scope : { ...scope, filter };
    if (scope.with) {
      const subs = scope.with as Record<string, S>;
      let next: Record<string, S> | undefined;
      for (const [rel, sub] of Object.entries(subs)) {
        const folded = fold(sub);
        if (folded !== sub) (next ??= { ...subs })[rel] = folded;
      }
      if (next) out = { ...out, with: next };
    }
    memo.set(scope, out);
    memo.set(out, out);
    return out;
  };
  const out = scopes.map(fold);
  return out.every((s, i) => s === scopes[i]) ? scopes : out;
}

/**
 * Marks a `with.<rel>` sub-scope {@link conjoinScopes} built from ONE side's
 * declaration. The other side is silent on the relation, so ITS policy for
 * the joined rows is its inherited grant on the related table — unknown
 * here. A resolver must conjoin the marked sub-scope with the caller's own
 * grant on the related table (never apply it alone as parent authority);
 * unresolved, the relation is hidden. See {@link needsInheritedConjunction}.
 *
 * @since 0.1.72
 */
export const INHERITED_CONJUNCTION: unique symbol = Symbol.for("aooth.arbac.inheritedConjunction");

/** A `with` sub-scope marked {@link INHERITED_CONJUNCTION}. @since 0.1.72 */
export function needsInheritedConjunction(scope: object): boolean {
  return (scope as { [INHERITED_CONJUNCTION]?: boolean })[INHERITED_CONJUNCTION] === true;
}

function conjoinWith<S extends TDbScope>(
  ea: TEffectiveDbScope<S>,
  eb: TEffectiveDbScope<S>,
  fields: TScopeFieldRules<S> | undefined,
): Record<string, S> | undefined {
  const names = new Set([...ea.withNames, ...eb.withNames]);
  if (names.size === 0) return undefined;
  const out: Record<string, S> = {};
  for (const rel of names) {
    const a = ea.withScopes(rel);
    const b = eb.withScopes(rel);
    const sub = conjoinScopes(a, b, { fields });
    // Declared by one side only (or inheriting on either): the silent side's
    // inherited grant is still owed.
    if (a.length === 0 || b.length === 0 || [...a, ...b].some(needsInheritedConjunction)) {
      (sub as { [INHERITED_CONJUNCTION]?: boolean })[INHERITED_CONJUNCTION] = true;
    }
    out[rel] = sub;
  }
  return out;
}

/**
 * A stable string key for a JSON-like value (bigint-safe) — for
 * de-duplicating filters / tuples and comparing them structurally.
 *
 * @since 0.1.72
 */
export function stableKey(value: unknown): string {
  return JSON.stringify(value, (_k, v: unknown) => (typeof v === "bigint" ? `${v}n` : v));
}
