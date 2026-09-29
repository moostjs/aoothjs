import {
  conjoinScopeFilters,
  DENY_FILTER,
  effectiveScope,
  normalizeScopes,
  stableKey,
  unionOutcomes,
} from "@aooth/arbac";
import { discoverRowLevelActions } from "@atscript/moost-db";
import type { TDbRequestContext } from "@atscript/moost-db";
import { cached, current, key, tryGetCurrent } from "@wooksjs/event-core";
import type { EventContext } from "@wooksjs/event-core";
import { getConstructor, useControllerContext } from "moost";
import type { Moost, TConsoleBase } from "moost";

import { useArbac } from "../arbac.composables";
import { evaluateArbacCached, insufficientPrivileges } from "../arbac.evaluate";
import type { ArbacDbScope } from "./as-arbac-db-controller";
import { getOrCreate } from "./helpers";
import { actionArbacIds, grantedActions } from "./meta-projection";
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
  const fromInterceptor = arbac.getScopes<ArbacDbScope>();
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
      buildScopeVisibility(scopes, source, { relations: requestRelations() }),
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
 * requested relations.
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
  const scopes = await resolveRequestScopes();
  if (ctx.controls && READ_ENDPOINTS.has(ctx.endpoint)) {
    await resolveRequestRelations(scopes, ctx.controls, readable);
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
 */
async function authorizeAvailableActions(): Promise<void> {
  const ctx = current();
  const instance = useControllerContext(ctx).getController() as {
    app: Moost;
    logger: TConsoleBase;
  };
  const names = discoverRowLevelActions(
    getConstructor(instance),
    instance.app,
    instance.logger,
  ).map((e) => e.info.name);
  const granted = await evaluateHandlers(actionsIds(names));
  const arbac = useArbac(ctx);
  if (!granted) throw insufficientPrivileges(arbac.resource, arbac.action);
  storeResolved(ctx, arbac, undefined, granted.map(withoutRowPolicy));
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
 * credential attenuation. No grant → a match-nothing filter (fail closed);
 * an unrestricted grant → `undefined`. When the current request IS that
 * action (its resolved scopes are the same evaluation), the row overlay
 * already applies it → `undefined`. Equal filters are returned as ONE
 * object per request.
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
