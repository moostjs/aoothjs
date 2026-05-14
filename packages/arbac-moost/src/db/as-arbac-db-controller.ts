import { mergeScopeFilters, restrictProjection, unionProjections } from "@aoothjs/arbac";
import type { TProjection, TScopeFilter } from "@aoothjs/arbac";
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
    return merged ? { ...merged, ...filter } : (filter ?? {});
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
    return applyAllowedFieldsAndSet(data, scopes ?? []);
  }

  protected async onRemove(id: unknown): Promise<unknown> {
    const { allowed } = await useArbac().evaluate<ArbacDbScope>({ action: "remove" });
    if (!allowed) {
      throw new HttpError(403, "Forbidden: remove");
    }
    return id;
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

export function applyAllowedFieldsAndSet(data: unknown, scopes: ArbacDbScope[]): unknown {
  if (scopes.length === 0) return data;
  if (Array.isArray(data)) {
    return data.map((row) => applyAllowedFieldsAndSet(row, scopes));
  }
  if (!data || typeof data !== "object") return data;

  const allowedSets = scopes
    .map((s) => s.allowedFields)
    .filter((x): x is string[] => Array.isArray(x));
  const merged: Record<string, unknown> = { ...(data as Record<string, unknown>) };

  if (allowedSets.length > 0) {
    const union = new Set<string>(allowedSets.flat());
    for (const k of Object.keys(merged)) {
      if (!union.has(k)) delete merged[k];
    }
  }

  for (const s of scopes) {
    if (s.set) Object.assign(merged, s.set);
  }

  return merged;
}
