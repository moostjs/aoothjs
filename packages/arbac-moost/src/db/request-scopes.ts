import {
  conjoinScopeFilters,
  DENY_FILTER,
  effectiveScope,
  normalizeScopes,
  stableKey,
  unionOutcomes,
} from "@aooth/arbac";
import type { FilterExpr } from "@atscript/db";
import { badRequest, discoverRowLevelActions, hasActionDelegations } from "@atscript/moost-db";
import type { TDbRequestContext } from "@atscript/moost-db";
import { cached, current, key, tryGetCurrent } from "@wooksjs/event-core";
import type { EventContext } from "@wooksjs/event-core";
import { getConstructor, useControllerContext } from "moost";
import type { Moost, TConsoleBase } from "moost";

import { useArbac } from "../arbac.composables";
import { evaluateArbacCached, insufficientPrivileges, scopesOwnedBy } from "../arbac.evaluate";
import type { ArbacDbScope } from "./as-arbac-db-controller";
import { getOrCreate } from "./helpers";
import { actionArbacIds, grantedActions, readHandlerIds } from "./meta-projection";
import { enforceRelationGates } from "./shared-read-helpers";
import {
  evaluateHandlerOutcomes,
  evaluateHandlers,
  requestRelations,
  resolveRequestRelations,
} from "./relation-policy";
import type { ArbacHandlerIds } from "./relation-policy";
import {
  buildScopeVisibility,
  isIdentifierSet,
  isMetaFieldVisible,
  scopeVisibility,
  visibleRelation,
} from "./visibility";
import type { MetaVisibility, VisibilityTableSource } from "./visibility";

/*
 * The request-scope resolver of the ARBAC DB layer: the scopes are resolved
 * ONCE per event at the entry point (`prepareRequest` — CRUD endpoints and
 * `@DbAction` handlers alike — or `useArbacDbScope()`); every other hook
 * reads them synchronously and fails closed when they are unresolved.
 */

/** Endpoints whose `prepareRequest` carries parsed Uniquery controls. */
const READ_ENDPOINTS: ReadonlySet<string> = new Set(["query", "pages", "geo", "one"]);

interface ResolvedScopes {
  resource: string;
  action: string;
  /** The authorize interceptor's scopes slot the resolution was made from. */
  source: unknown[] | undefined;
  scopes: ArbacDbScope[];
  /** The request's visibility per readable (with its `$with` resolution). */
  visibility: Map<VisibilityTableSource, MetaVisibility>;
}

const requestScopesKey = key<ResolvedScopes>("arbac.db.scopes");

/** Store the event's resolved scopes (for the handler `ids` resolves to). */
function storeResolved(
  ctx: EventContext,
  ids: { resource: string; action: string },
  source: unknown[] | undefined,
  scopes: ArbacDbScope[],
): void {
  ctx.set(requestScopesKey, {
    resource: ids.resource,
    action: ids.action,
    source,
    scopes,
    visibility: new Map(),
  });
}

function resolved(): ResolvedScopes | undefined {
  const ctx = tryGetCurrent();
  return ctx?.has(requestScopesKey) ? ctx.get(requestScopesKey) : undefined;
}

/**
 * The scopes resolved for the current event, or `undefined` before
 * {@link resolveRequestScopes} ran.
 *
 * @since 0.1.72
 */
export function cachedRequestScopes(): ArbacDbScope[] | undefined {
  return resolved()?.scopes;
}

/**
 * Resolve the current event's scopes once: the ones the authorize
 * interceptor cached, else an ARBAC evaluation of the handler's
 * resource/action. The empty-scope rule (`normalizeScopes` from
 * `@aooth/arbac`): an allowed grant without scopes is unrestricted (`[{}]`),
 * a scope predicate returning nothing contributes nothing, and an allowed
 * evaluation left with NO scope is a deny. A deny throws 403.
 *
 * @since 0.1.72
 */
export async function resolveRequestScopes(): Promise<ArbacDbScope[]> {
  const ctx = current();
  const arbac = useArbac(ctx);
  // Only scopes cached for THIS handler (never ones read through from a
  // delegating parent event — a `@DbActionsFrom` view's request).
  const cachedScopes = arbac.getScopes<ArbacDbScope>();
  const fromInterceptor =
    cachedScopes && scopesOwnedBy(cachedScopes, arbac.resource, arbac.action)
      ? cachedScopes
      : undefined;
  // Reused while the handler (a WF event dispatches several steps) and the
  // interceptor's slot are the ones it was resolved for.
  const prior = resolved();
  if (
    prior &&
    prior.resource === arbac.resource &&
    prior.action === arbac.action &&
    prior.source === fromInterceptor
  ) {
    return prior.scopes;
  }
  const scopes = normalizeScopes(
    fromInterceptor !== undefined
      ? { allowed: true, scopes: fromInterceptor }
      : ((await evaluateArbacCached(arbac.resource, arbac.action)) as {
          allowed: boolean;
          scopes?: ArbacDbScope[];
        }),
  );
  if (!scopes) throw insufficientPrivileges(arbac.resource, arbac.action);
  if (fromInterceptor === undefined) arbac.setScopes(scopes);
  storeResolved(ctx, arbac, fromInterceptor ?? scopes, scopes);
  return scopes;
}

/**
 * The resolved scopes, synchronously — for the hooks that run after the
 * entry point (`validateControls`, `transformFilter`, the write guards …).
 * Unresolved scopes are a 403, never "unrestricted".
 *
 * @since 0.1.72
 */
export function requireRequestScopes(): ArbacDbScope[] {
  const scopes = cachedRequestScopes();
  if (scopes) return scopes;
  const { resource, action } = useArbac();
  throw insufficientPrivileges(resource, action);
}

/**
 * The visibility `scopes` imply over `source`: the current request's scopes
 * over a readable carry the request's `$with` resolution; any other pair is
 * built without one (undeclared relations hidden).
 */
export function visibilityFor(
  scopes: ArbacDbScope[],
  source: VisibilityTableSource | ReadonlySet<string> | undefined,
): MetaVisibility {
  const request = resolved();
  if (source && !isIdentifierSet(source) && request?.scopes === scopes) {
    return getOrCreate(request.visibility, source, () =>
      buildScopeVisibility(scopes, source, { relations: requestRelations(source) }),
    );
  }
  return scopeVisibility(scopes, source);
}

/**
 * Shared body of the ARBAC controllers' `hasField` overrides: a field
 * outside the read-scope visibility — hidden by the projection union, a
 * derived field whose source is hidden, a path inside a hidden atomic JSON
 * column, a hidden relation, or a `rel.x` path the relation's policy hides —
 * is indistinguishable from a field that does not exist. Unresolved scopes
 * hide every field.
 *
 * @since 0.1.72
 */
export function requestFieldVisible(
  path: string,
  source: VisibilityTableSource | ReadonlySet<string>,
): boolean {
  const scopes = cachedRequestScopes();
  return scopes !== undefined && isMetaFieldVisible(path, visibilityFor(scopes, source));
}

/**
 * Whether `path` is visible to `scopes` over `source` (see
 * {@link requestFieldVisible}, which reads the request's scopes).
 *
 * @param source - the controller's `this.readable`; an identifier set (the
 *   0.1.67 signature) still works, without relation / schema rules
 */
export function isScopedFieldVisible(
  scopes: ArbacDbScope[],
  path: string,
  source: VisibilityTableSource | ReadonlySet<string>,
): boolean {
  if (scopes.length === 0 && isIdentifierSet(source)) return true;
  return isMetaFieldVisible(path, visibilityFor(scopes, source));
}

/**
 * Body of the ARBAC DB / value-help controllers' `prepareRequest` — every
 * endpoint, `@DbAction` handlers included (`endpoint: "action"`, before any
 * action id / row is read): resolve the request's scopes
 * ({@link resolveRequestScopes} — 403 on denial, `arbacPublic` does not
 * bypass) and, on read endpoints, the `$with` relation policy for the
 * requested relations — the `$with` entries and, since 0.1.74, the
 * relations the client filter's relational predicates name (`ctx.filter`):
 * a predicate on a relation is allowed exactly when `$with` of it is (same
 * visibility, same `controls.$with` gates).
 *
 * Delegated endpoints (no grant of their own): `"availableActions"`
 * (`GET /meta/actions…`) — some row-level action grant (or, on a
 * `@DbActionsFrom` controller, none: its own part lists nothing);
 * `"delegatedAction"` (`POST /delegated-actions/:name`, since 0.1.74) — the
 * controller's READ grant, since the route only resolves which of the
 * caller's readable rows match the query; the action itself is authorized
 * by its source controller on every batch.
 *
 * @since 0.1.72
 */
export async function prepareArbacRequest(
  ctx: TDbRequestContext,
  readable?: VisibilityTableSource,
): Promise<void> {
  if (ctx.endpoint === "availableActions") {
    await authorizeAvailableActions();
    return;
  }
  if (ctx.endpoint === "delegatedAction") {
    await authorizeDelegatedQueryTarget();
    return;
  }
  const scopes = await resolveRequestScopes();
  if (READ_ENDPOINTS.has(ctx.endpoint)) {
    const names = await resolveRequestRelations(scopes, ctx.controls, readable, ctx.filter);
    enforceRelationGates(names, visibilityFor(scopes, readable));
  }
}

/**
 * `authorizeForm` for the ARBAC DB controllers: a form is served iff the
 * caller may run at least one of the actions that take it as input — each
 * evaluated as the resource/action its handler is authorized as.
 *
 * @since 0.1.72
 */
export async function authorizeArbacForm(actionNames: readonly string[]): Promise<boolean> {
  return (await evaluateHandlers(actionsIds(actionNames))) !== undefined;
}

/** The ARBAC ids of `names` on the current controller ({@link actionArbacIds}). */
function actionsIds(names: readonly string[]): ArbacHandlerIds[] {
  const instance = useControllerContext().getController();
  return names.flatMap((name) => actionArbacIds(instance, name));
}

/**
 * `GET /meta/actions/:id` (endpoint `"availableActions"`): served iff the
 * caller may run at least ONE row-level action of the controller (else 403).
 * The route has no grant of its own and needs no read grant. Its request
 * scopes are the granted row-level actions' scopes WITHOUT their row parts
 * (`filter` / `check`, which carry any custom-field row filter): the row
 * overlay stays unrestricted — each action's rows come from
 * `actionRowScope` ({@link arbacActionRowScope}) — while field visibility
 * is never wider than the widest granted action.
 *
 * A `@DbActionsFrom` controller without an own row-level grant is served
 * too (since 0.1.74): its own part lists nothing (a match-nothing row
 * overlay), and each delegated action is answered by its source controller,
 * under the caller's grants THERE.
 */
async function authorizeAvailableActions(): Promise<void> {
  const ctx = current();
  const instance = useControllerContext(ctx).getController() as {
    app: Moost;
    logger: TConsoleBase;
  };
  const ctor = getConstructor(instance);
  const names = discoverRowLevelActions(ctor, instance.app, instance.logger).map(
    (e) => e.info.name,
  );
  const granted = await evaluateHandlers(actionsIds(names));
  const arbac = useArbac(ctx);
  if (granted) {
    storeResolved(ctx, arbac, undefined, granted.map(withoutRowPolicy));
  } else if (hasActionDelegations(ctor)) {
    storeResolved(ctx, arbac, undefined, NO_OWN_ACTIONS);
  } else {
    throw insufficientPrivileges(arbac.resource, arbac.action);
  }
}

/** The own scopes of a delegating controller's `GET /meta/actions` without an own grant. */
const NO_OWN_ACTIONS: ArbacDbScope[] = [{ filter: DENY_FILTER, check: DENY_FILTER }];

/**
 * `POST /delegated-actions/:name` (endpoint `"delegatedAction"`): the route
 * resolves which rows of THIS controller match the query — a read, so it
 * is served under the caller's read grant (its `query` handler; none →
 * 403), stored as the request's scopes (`transformFilter`, `hasField` and
 * moost-db's default `queryTargetScope` read them). It grants nothing on
 * the action: the source controller's route re-authorizes every batch.
 */
async function authorizeDelegatedQueryTarget(): Promise<void> {
  const ctx = current();
  const arbac = useArbac(ctx);
  const ids = readHandlerIds(useControllerContext(ctx).getController());
  const scopes = ids.length > 0 ? await evaluateHandlers(ids) : undefined;
  if (!scopes)
    throw insufficientPrivileges(ids[0]?.resource ?? arbac.resource, ids[0]?.action ?? "query");
  // Stored for THIS handler, so a later `resolveRequestScopes()` in the event reuses it.
  storeResolved(ctx, arbac, undefined, scopes);
}

/** A scope without its row policy (`filter` / `check`). */
function withoutRowPolicy(scope: ArbacDbScope): ArbacDbScope {
  if (scope.filter === undefined && scope.check === undefined) return scope;
  const { filter: _filter, check: _check, ...rest } = scope;
  return rest;
}

/**
 * Body of the ARBAC DB controllers' `allowedActions`: the action `names` the
 * caller holds a grant on — each evaluated as {@link actionArbacIds} names
 * it, exactly the `/meta` overlay's action rule (memoized per event, so the
 * evaluations `prepareRequest` / the overlay already ran are reused).
 *
 * @since 0.1.72
 */
export function arbacAllowedActions(names: readonly string[]): Promise<string[]> {
  return grantedActions(useControllerContext().getController(), names);
}

// Per event: action row filters by structure — equal grants share ONE
// filter object, so moost-db checks them with one query.
const actionScopes = cached(() => new Map<string, Record<string, unknown>>());

/**
 * Body of the ARBAC DB controllers' `actionRowScope`: the rows the
 * `@DbAction` `name` may run on — the filter of the caller's grant on the
 * action ({@link actionArbacIds}: every handler method of the action, or a
 * class-level entry's fallback ids), including custom-field row filters and
 * credential attenuation. Several grants union (`$or`); attenuation is
 * already intersected into each. No grant → a match-nothing filter (fail
 * closed); an unrestricted grant → `undefined`. When the current request IS
 * that action (its resolved scopes are the same evaluation), the row overlay
 * already applies it → `undefined`. Equal filters are returned as ONE
 * object per request.
 *
 * Candidate-free on purpose (evaluated once per action per event) — see
 * `AsArbacDbController.actionRowScope` to bound an action by its candidate
 * rows.
 *
 * @since 0.1.72
 */
export async function arbacActionRowScope(
  name: string,
): Promise<Record<string, unknown> | undefined> {
  const ctx = current();
  const ids = actionsIds([name]);
  const outcomes = await evaluateHandlerOutcomes(ids);
  // One handler: its own (normalized) list — the same array, so the
  // effective-scope memo is shared with every other consumer.
  const scopes = ids.length === 1 ? normalizeScopes(outcomes[0]) : unionOutcomes(outcomes);
  if (!scopes) return DENY_FILTER;
  const prior = resolved();
  if (
    prior &&
    ids.length === 1 &&
    ids[0].resource === prior.resource &&
    ids[0].action === prior.action &&
    outcomes[0].scopes !== undefined &&
    (outcomes[0].scopes === prior.source || outcomes[0].scopes === prior.scopes)
  ) {
    return undefined;
  }
  const filter = effectiveScope(scopes).filter;
  if (!filter || Object.keys(filter).length === 0) return undefined;
  return getOrCreate(ctx.get(actionScopes), stableKey(filter), () => filter);
}

/**
 * Body of the ARBAC controllers' `transformFilter` (and so of the row
 * overlay `/one`, `DELETE` and `@DbAction` ids use): the user filter
 * CONJOINED with the union of the request's scope filters.
 *
 * @since 0.1.72
 */
export function arbacRowFilter(
  filter: Record<string, unknown> | undefined,
): Record<string, unknown> {
  return conjoinScopeFilters(effectiveScope(requireRequestScopes()).filter, filter) ?? {};
}

/**
 * Body of the ARBAC DB controllers' `transformRelationFilter` (since 0.1.74):
 * the operand of a CLIENT relational predicate at `path` (`ticket`,
 * `ticket.team`, `tickets.issues` inside `$with=tickets(…)`) CONJOINED
 * with the row filter of the related rows the caller may see there — the
 * same policy `$with` of that relation applies: a declared `with.<rel>`
 * sub-scope, else the caller's own read grant on the related table. So
 * `$some` matches, and `$none` excludes, only on rows the caller could
 * load. A relation the request did not resolve answers like an unknown
 * field (400 — the request gate rejects it first).
 *
 * @since 0.1.74
 */
export function arbacRelationFilter(
  path: string,
  filter: FilterExpr,
  readable: VisibilityTableSource,
): FilterExpr {
  let level: MetaVisibility | undefined = visibilityFor(requireRequestScopes(), readable);
  for (const name of path.split(".")) level = level && visibleRelation(name, level);
  if (!level?.scopes) throw badRequest(path, `Unknown field "${path}"`);
  return conjoinScopeFilters(effectiveScope(level.scopes).filter, filter) ?? filter;
}
