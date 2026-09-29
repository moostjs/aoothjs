import { ScopeFieldConfigError } from "@aooth/arbac";
import type { TScopeFieldRules } from "@aooth/arbac";
import { HttpError } from "@moostjs/event-http";
import type { EventContext } from "@wooksjs/event-core";
import { cached, cachedBy, current, eventTypeKey, key } from "@wooksjs/event-core";
import { getConstructor, useControllerContext, useLogger } from "moost";

import type { TArbacMeta } from "./arbac.mate";
import { conjoinArbacDbScopes } from "./attenuation";
import type { ArbacDbScope } from "./db/as-arbac-db-controller";
import { fieldChildrenOf } from "./db/field-children";
import type { VisibilityTableSource } from "./db/visibility";
import type { RefTableSource } from "./db/write-refs";
import { MoostArbac } from "./moost-arbac";
import { ArbacUserProvider, ArbacUserProviderToken } from "./user.provider";

/*
 * Internal evaluation core shared by `useArbac().evaluate()` and the DB
 * layer's per-event evaluation memo. Not part of the public entry.
 */

type HandlerMeta = TArbacMeta & { id?: string; atscript_db_action?: { name?: string } };

/**
 * The ARBAC resource + action a handler is authorized as. Resource: method
 * `@ArbacResource` → class `@ArbacResource` → controller id → class name.
 * Action: method `@ArbacAction` → `@DbAction` name → class `@ArbacAction` →
 * method `@Id` → method name.
 */
export function arbacIdsFromMeta(
  cMeta: HandlerMeta | undefined,
  mMeta: HandlerMeta | undefined,
  controller: object,
  methodName: string,
): { resource: string; action: string } {
  return {
    resource:
      mMeta?.arbacResourceId ||
      cMeta?.arbacResourceId ||
      cMeta?.id ||
      getConstructor(controller).name,
    action:
      mMeta?.arbacActionId ||
      // atscript_db_action is set by @atscript/moost-db on method metadata —
      // a side-channel read (arbac-moost does not depend on moost-db at runtime).
      mMeta?.atscript_db_action?.name ||
      cMeta?.arbacActionId ||
      mMeta?.id ||
      methodName,
  };
}

/** The 403 every ARBAC deny answers. */
export function insufficientPrivileges(resource: string, action: string): HttpError {
  return new HttpError(
    403,
    `Insufficient privileges for action "${action}" on resource "${resource}"`,
  );
}

/** An evaluation outcome as `useArbac().evaluate()` returns it. */
export interface ArbacOutcome<TScope = object> {
  allowed: boolean;
  scopes?: TScope[];
  userId: string;
}

/** The evaluation target: resource / action, plus the readable the grant is evaluated on. */
export interface ArbacTarget {
  resource: string;
  action: string;
  table?: VisibilityTableSource;
}

interface Principal {
  userId: string;
  roles: string[];
  attenuate?: { roles?: string[]; attrs?: Record<string, unknown>; allowUnheldRoles?: boolean };
  attrs: (id: string) => Promise<object>;
}

async function loadPrincipal(user: ArbacUserProvider): Promise<Principal> {
  const userId = await user.getUserId();
  // Restrict-only credential attenuation (the credential's typed
  // `@arbac.attenuate.*` root fields), sourced through the optional provider
  // hook so arbac-moost stays auth-agnostic. Only triggers the engine's
  // dual-pass when the claim actually narrows (a present-but-empty `{}` is a
  // no-op).
  const [roles, att] = await Promise.all([user.getRoles(userId), user.getAttenuation?.()]);
  let attrs: Promise<object> | undefined;
  return {
    userId,
    roles,
    attenuate:
      att && (att.roles !== undefined || att.attrs !== undefined)
        ? {
            roles: att.roles,
            attrs: att.attrs,
            ...(att.allowUnheldRoles === true && { allowUnheldRoles: true }),
          }
        : undefined,
    attrs: (id) => (attrs ??= Promise.resolve(user.getAttrs(id))),
  };
}

// Per-event principal memo — only the DB layer opts in, and only on HTTP
// events: a WF event spans steps whose principal may change, so neither the
// general `evaluate()` nor a non-HTTP event ever reads it.
const principalKey = key<Promise<Principal>>("arbac.principal");

function isHttpEvent(ctx: EventContext): boolean {
  return ctx.has(eventTypeKey) && ctx.get(eventTypeKey) === "http";
}

// Per-event evaluation memo: normalized table → `resource\0action` → outcome.
// Filled by every evaluation, read only by {@link evaluateArbacCached}.
const evalMemo = cachedBy(
  (_table: VisibilityTableSource | undefined) => new Map<string, Promise<ArbacOutcome>>(),
);

/**
 * Evaluate `target` for the current principal. Attenuated + allowed: the
 * ceiling pass and the narrowed pass are conjoined into ONE composite scope
 * (every downstream site unions the list per facet — a one-element union is
 * the identity). `table` defaults to the current controller's `readable`.
 */
export function evaluateArbac<TScope extends object>(
  ctx: EventContext,
  target: ArbacTarget,
  memoPrincipal = false,
): Promise<ArbacOutcome<TScope>> {
  const cc = useControllerContext(ctx);
  // The evaluated table's schema (default: the DB controller's) lets a nested
  // exclusion be subtracted exactly (without one the conjunction fails
  // closed) and resolves `checkRefs` names to its foreign keys.
  const table =
    target.table ??
    (cc.getController() as { readable?: VisibilityTableSource } | undefined)?.readable;
  const pending = (async (): Promise<ArbacOutcome<TScope>> => {
    const [user, arbac] = (await Promise.all([
      cc.instantiate(ArbacUserProviderToken),
      cc.instantiate(MoostArbac),
    ])) as [ArbacUserProvider, MoostArbac<object, TScope>];
    let principal: Promise<Principal>;
    if (!memoPrincipal || !isHttpEvent(ctx)) principal = loadPrincipal(user);
    else if (ctx.has(principalKey)) principal = ctx.get(principalKey);
    else ctx.set(principalKey, (principal = loadPrincipal(user)));
    const p = await principal;
    const result = await arbac.evaluate(
      { resource: target.resource, action: target.action },
      { id: p.userId, roles: p.roles, attrs: p.attrs, attenuate: p.attenuate },
    );
    // `MoostArbac.evaluate` already folded custom-field row filters into
    // each pass's scopes.
    if (result.allowed && result.credScopes !== undefined) {
      const conjoined = conjoinForTable(
        result.scopes ?? [],
        result.credScopes,
        table,
        arbac.getScopeFields(),
      );
      return { allowed: true, scopes: [conjoined] as unknown as TScope[], userId: p.userId };
    }
    return { allowed: result.allowed, scopes: result.scopes, userId: p.userId };
  })();
  evalMemo(table, ctx).set(`${target.resource}\u0000${target.action}`, pending);
  return pending;
}

const loggedConfigErrors = new Set<string>();

/**
 * Run `fn`; a {@link ScopeFieldConfigError} (a server misconfiguration)
 * becomes a generic 500 — the details are logged server-side once per
 * distinct error, never sent to the client. Fail closed either way.
 */
export function asServerError<T>(fn: () => T): T {
  try {
    return fn();
  } catch (error) {
    if (!(error instanceof ScopeFieldConfigError)) throw error;
    if (!loggedConfigErrors.has(error.message)) {
      loggedConfigErrors.add(error.message);
      useLogger("arbac").error(error.message);
    }
    throw new HttpError(500, "Internal Server Error");
  }
}

/**
 * THE conjunction of two scope lists over `table` (credential attenuation,
 * and a `$with` sub-scope ∧ the caller's grant on the related table): the
 * table's schema subtracts nested exclusions exactly, its foreign keys
 * resolve `checkRefs`, `fields` conjoin custom scope fields — and an
 * unregistered custom field is a generic 500 ({@link asServerError}).
 */
export function conjoinForTable(
  a: ArbacDbScope[],
  b: ArbacDbScope[],
  table: VisibilityTableSource | undefined,
  fields: TScopeFieldRules<ArbacDbScope> | undefined,
): ArbacDbScope {
  return asServerError(
    () =>
      conjoinArbacDbScopes(a, b, {
        childrenOf: fieldChildrenOf(table),
        refTable: table as RefTableSource | undefined, // a moost-db readable carries its foreign keys
        fields,
      })[0],
  );
}

const scopeFieldsSlot = cached(
  async (ctx): Promise<TScopeFieldRules<ArbacDbScope>> =>
    (
      (await useControllerContext(ctx).instantiate(MoostArbac)) as MoostArbac<object, ArbacDbScope>
    ).getScopeFields(),
);

/** The current app's custom scope field rules — resolved once per event. */
export function currentScopeFields(): Promise<TScopeFieldRules<ArbacDbScope>> {
  return current().get(scopeFieldsSlot);
}

/**
 * {@link evaluateArbac} memoized for the current HTTP event (with the
 * per-event principal memo) — `/meta`, `$with` resolution and `checkRefs`
 * evaluate the same pairs repeatedly, and an evaluation the authorize
 * interceptor already ran is reused. Other events (a WF event spans steps)
 * evaluate afresh. `table` omitted → the current controller's readable.
 */
export function evaluateArbacCached(
  resource: string,
  action: string,
  table?: VisibilityTableSource,
): Promise<ArbacOutcome> {
  const ctx = current();
  const normalized =
    table ??
    (useControllerContext(ctx).getController() as { readable?: VisibilityTableSource } | undefined)
      ?.readable;
  const pending = isHttpEvent(ctx)
    ? evalMemo(normalized, ctx).get(`${resource}\u0000${action}`)
    : undefined;
  return pending ?? evaluateArbac(ctx, { resource, action, table: normalized }, true);
}
