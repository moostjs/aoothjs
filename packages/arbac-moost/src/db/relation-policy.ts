import { effectiveScope, needsInheritedConjunction, unionOutcomes } from "@aooth/arbac";
import { hasRelationOp, isRelationOp } from "@atscript/db";
import { current, key } from "@wooksjs/event-core";
import { getConstructor, getMoostMate, useControllerContext } from "moost";

import {
  arbacIdsFromMeta,
  conjoinForTable,
  currentScopeFields,
  evaluateArbacCached,
} from "../arbac.evaluate";
import type { ArbacDbScope } from "./as-arbac-db-controller";
import { getOrCreate } from "./helpers";
import { buildScopeVisibility } from "./visibility";
import type { ArbacRelationResolution, MetaVisibility, VisibilityTableSource } from "./visibility";

/*
 * `$with` inherit-target policy (since 0.1.72).
 *
 * A relation some read scope declares `with.<name>` for is governed by the
 * declared sub-scopes only (parent authority; roles silent on it contribute
 * nothing). Any other relation inherits the caller's OWN `query` grant on the
 * related table's ARBAC resource, found through the controllers registered
 * with {@link registerArbacDbTarget}. No registered controller, or no grant →
 * the relation is hidden (`hasField` answers `false`, moost-db 400s
 * `Unknown relation`).
 */

/** Relation names to resolve, per level (`$with=a($with=b),c` → `a → { b }`, `c`). */
export type RelationNameTree = Map<string, RelationNameTree>;

// ── Registry: table → ARBAC DB controllers ──────────────────────────────────

/** Registry bucket for controllers without an `app`. */
const NO_APP = {};
const registry = new WeakMap<object, WeakMap<object, Map<Function, object>>>();

/**
 * Register an ARBAC DB controller as an owner of its readable's ARBAC
 * resource, so a `$with` from another controller can evaluate the caller's
 * own grant on the joined table. Called once per controller instance (a
 * field initializer of the ARBAC DB controllers). Scoped per moost app and
 * keyed by the readable's annotated type; a newer instance of the same class
 * replaces the older one.
 *
 * @returns `true` (so it can initialize a field)
 * @since 0.1.72
 */
export function registerArbacDbTarget(controller: object): true {
  const c = controller as { readable?: { type?: object }; app?: object };
  const target = c.readable?.type ?? c.readable;
  if (!target) return true;
  const perApp = getOrCreate(registry, c.app ?? NO_APP, () => new WeakMap());
  getOrCreate(perApp, target, () => new Map()).set(getConstructor(controller), controller);
  return true;
}

function registeredControllers(target: object): object[] {
  let app: object = NO_APP;
  try {
    app = (useControllerContext().getController() as { app?: object } | undefined)?.app ?? NO_APP;
  } catch {
    // No controller in context — the app-less bucket.
  }
  const perTarget = registry.get(app)?.get(target);
  return perTarget ? [...perTarget.values()] : [];
}

/**
 * The ARBAC resource + action a controller's handler is authorized as — the
 * precedence `useArbac()` applies while that handler serves a request.
 * Resource: method `@ArbacResource` → class `@ArbacResource` → controller id
 * → class name. Action: method `@ArbacAction` → `@DbAction` name → class
 * `@ArbacAction` → method `@Id` → method name.
 *
 * @since 0.1.72
 */
export function resolveHandlerArbacIds(
  instance: object,
  methodName: string,
): { resource: string; action: string } {
  const mate = getMoostMate();
  return arbacIdsFromMeta(
    mate.read(instance),
    mate.read(instance, methodName),
    instance,
    methodName,
  );
}

/** A handler to evaluate: its ARBAC ids, plus the readable it serves when not the current controller's. */
export interface ArbacHandlerIds {
  resource: string;
  action: string;
  table?: VisibilityTableSource;
}

/**
 * Evaluate several handlers as ONE surface (memoized per event): the scopes
 * of every allowing handler concatenated (`unionOutcomes`); `undefined` when
 * none allows.
 */
export async function evaluateHandlers(
  ids: ReadonlyArray<ArbacHandlerIds>,
): Promise<ArbacDbScope[] | undefined> {
  return unionOutcomes(await evaluateHandlerOutcomes(ids));
}

/** The raw per-handler outcomes behind {@link evaluateHandlers} (memoized per event). */
export function evaluateHandlerOutcomes(
  ids: ReadonlyArray<ArbacHandlerIds>,
): Promise<Array<{ allowed: boolean; scopes?: ArbacDbScope[] }>> {
  return Promise.all(
    ids.map(
      (id) =>
        evaluateArbacCached(id.resource, id.action, id.table) as Promise<{
          allowed: boolean;
          scopes?: ArbacDbScope[];
        }>,
    ),
  );
}

/**
 * The caller's read scopes on the readable of annotated type `type` (a
 * `$with` / `ref` target) through its registered ARBAC DB controllers (their
 * `query` handler, each evaluated against ITS table's schema), plus a
 * registered controller's readable — `null` when none is registered or none
 * allows.
 */
export async function evaluateTypeRead(
  type: object,
): Promise<{ scopes: ArbacDbScope[]; table: VisibilityTableSource | undefined } | null> {
  const controllers = registeredControllers(type) as Array<{ readable?: VisibilityTableSource }>;
  if (controllers.length === 0) return null;
  const scopes = await evaluateHandlers(
    controllers.map((c) => ({ ...resolveHandlerArbacIds(c, "query"), table: c.readable })),
  );
  return scopes ? { scopes, table: controllers[0].readable } : null;
}

// ── Resolution ──────────────────────────────────────────────────────────────

/**
 * Deepest `$with` nesting resolved: the request controls the depth, and each
 * level may evaluate grants. A deeper relation stays unresolved (hidden).
 */
const MAX_WITH_DEPTH = 16;

/**
 * Relation names a parsed `$with` control reaches, per level. A dotted
 * name (`a.b`) nests like `a($with=b)`. The relational predicates of each
 * entry's sub-filter (`$with=a(b=$some(…))`) join the entry's level
 * ({@link relationFilterNameTree}).
 */
export function withNameTree(
  withArr: unknown,
  into: RelationNameTree = new Map(),
  depth = 0,
): RelationNameTree {
  if (!Array.isArray(withArr) || depth >= MAX_WITH_DEPTH) return into;
  for (const raw of withArr) {
    const entry = raw as {
      name?: unknown;
      filter?: unknown;
      controls?: { $with?: unknown };
      $with?: unknown;
    } | null;
    const name = typeof raw === "string" ? raw : entry?.name;
    if (typeof name !== "string" || !name) continue;
    const segments = name.split(".");
    if (depth + segments.length > MAX_WITH_DEPTH) continue;
    let level = into;
    for (const segment of segments) level = getOrCreate(level, segment, () => new Map());
    if (entry && typeof entry === "object") {
      withNameTree(entry.controls?.$with ?? entry.$with, level, depth + segments.length);
      relationFilterNameTree(entry.filter, level, depth + segments.length);
    }
  }
  return into;
}

/**
 * Relation names the relational predicates of a filter reach, per level
 * (`ticket=$some(team=$some(…))` → `ticket → { team }`), through
 * `$and` / `$or` / `$not` and nested predicate operands. Only reads
 * `filter` (moost-db hands `prepareRequest` a deep-frozen copy).
 *
 * @since 0.1.74
 */
export function relationFilterNameTree(
  filter: unknown,
  into: RelationNameTree = new Map(),
  depth = 0,
): RelationNameTree {
  if (!filter || typeof filter !== "object" || depth >= MAX_WITH_DEPTH) return into;
  for (const [k, value] of Object.entries(filter as Record<string, unknown>)) {
    if (k === "$and" || k === "$or") {
      if (Array.isArray(value)) for (const c of value) relationFilterNameTree(c, into, depth);
    } else if (k === "$not") {
      relationFilterNameTree(value, into, depth);
    } else if (!k.startsWith("$") && hasRelationOp(value)) {
      const level = getOrCreate(into, k, () => new Map());
      for (const [op, operand] of Object.entries(value)) {
        if (isRelationOp(op)) relationFilterNameTree(operand, level, depth + 1);
      }
    }
  }
  return into;
}

/**
 * Resolve every relation in `names` against `scopes` over `table` into the
 * visibility its joined rows obey: a declared `with.<name>` → its
 * sub-scopes; otherwise the caller's own read grant on the related table
 * (`null` = hidden). Recurses into nested names — the decision is made here
 * once; `MetaVisibility.relation()` only reads it.
 *
 * When a level names a hidden or nonexistent relation, the level's OTHER
 * relations are resolved too (one level deep — `listSiblings: false` skips
 * it), so the `Unknown relation` 400 can list the relations the caller may
 * use — never the hidden ones.
 */
export async function resolveRelationTree(
  scopes: readonly ArbacDbScope[],
  table: VisibilityTableSource | undefined,
  names: RelationNameTree,
  opts: { listSiblings?: boolean } = {},
): Promise<ArbacRelationResolution> {
  const out = new Map<string, MetaVisibility | null>();
  const resolveOne = async (name: string, nested: RelationNameTree): Promise<void> => {
    const target = table?.relatedTable?.(name);
    const declared = effectiveScope(scopes).withScopes(name) as ArbacDbScope[];
    // A declared sub-scope governs alone (parent authority) — unless a
    // credential conjunction marked it one-sided: then it is conjoined with
    // the caller's own grant on the related table (none → hidden).
    const inherits = declared.length === 0 || declared.some(needsInheritedConjunction);
    const read = inherits && target ? await evaluateTypeRead(target.type ?? target) : null;
    let nodeScopes: ArbacDbScope[] | undefined = inherits ? read?.scopes : declared;
    if (nodeScopes && declared.length > 0 && inherits) {
      nodeScopes = [conjoinForTable(declared, nodeScopes, target, await currentScopeFields())];
    }
    if (!nodeScopes) {
      out.set(name, null);
      return;
    }
    const relations =
      nested.size > 0 ? await resolveRelationTree(nodeScopes, target, nested, opts) : undefined;
    out.set(name, buildScopeVisibility(nodeScopes, target, { relations }));
  };
  await Promise.all([...names].map(([name, nested]) => resolveOne(name, nested)));
  if (opts.listSiblings !== false && [...out.values()].includes(null) && table?.relations) {
    const siblings = [...table.relations.keys()].filter((name) => !out.has(name));
    await Promise.all(siblings.map((name) => resolveOne(name, new Map())));
  }
  return out;
}

// The current request's `$with` resolution (set by `prepareRequest`), with
// the readable it was resolved for.
const requestRelationsKey = key<
  { readable: VisibilityTableSource | undefined; relations: ArbacRelationResolution } | undefined
>("arbac.db.relations");

/**
 * Per-request `$with` policy for the ARBAC DB controllers' `prepareRequest`:
 * resolves every relation `controls.$with` names (recursively) and — since
 * 0.1.74 — every relation the client `filter`'s relational predicates name
 * (`ticket=$some(…)`, also inside `$with` sub-filters), and stores the
 * resolution the request's visibility reads.
 *
 * @returns the relation names resolved, per level
 */
export async function resolveRequestRelations(
  scopes: readonly ArbacDbScope[],
  controls: Record<string, unknown> | undefined,
  readable: VisibilityTableSource | undefined,
  filter?: unknown,
): Promise<RelationNameTree> {
  const names = withNameTree(controls?.$with);
  // Siblings are listed only for `$with`'s `Unknown relation` message.
  const listSiblings = names.size > 0;
  relationFilterNameTree(filter, names);
  if (names.size === 0) return names;
  const relations = await resolveRelationTree(scopes, readable, names, { listSiblings });
  current().set(requestRelationsKey, { readable, relations });
  return names;
}

/**
 * The resolution {@link resolveRequestRelations} stored for the current
 * event, if any — only for the readable it was resolved for: another
 * controller evaluated in the same event (a `@DbActionsFrom` source) never
 * sees the delegating request's `$with` resolution.
 */
export function requestRelations(
  readable: VisibilityTableSource | undefined,
): ArbacRelationResolution | undefined {
  const ctx = current();
  const stored = ctx.has(requestRelationsKey) ? ctx.get(requestRelationsKey) : undefined;
  return stored && stored.readable === readable ? stored.relations : undefined;
}
