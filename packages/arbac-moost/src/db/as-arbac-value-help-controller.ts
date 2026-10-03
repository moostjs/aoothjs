import { getProjectionMode } from "@aooth/arbac";
import type { TProjection } from "@aooth/arbac";
import type { FilterExpr, TMetaResponse } from "@atscript/db";
import {
  AsJsonValueHelpController,
  AsValueHelpController,
  type TDbControlsType,
  type TDbRequestContext,
  type ValueHelpSelect,
} from "@atscript/moost-db";
import type { TAtscriptAnnotatedType, TAtscriptDataType } from "@atscript/typescript/utils";
import { Inherit } from "moost";

import { ArbacAction } from "../arbac.decorator";
import { applyArbacMetaOverlay } from "./meta-projection";
import {
  arbacRowFilter,
  requestFieldVisible,
  requireRequestScopes,
  resolveRequestScopes,
} from "./request-scopes";
import type { VisibilityTableSource } from "./visibility";
import { applyArbacControls, applyArbacProjection } from "./shared-read-helpers";

/**
 * What the shared ARBAC hooks below read from a value-help controller —
 * built once per controller instance so both ARBAC value-help classes (which
 * extend DIFFERENT moost-db bases; legacy decorators cannot sit on a mixin)
 * share one implementation, and the visibility caches keyed by `source`
 * stay warm.
 */
interface ValueHelpHost {
  readonly primaryKey: string | undefined;
  readonly searchableFields: readonly string[];
  /**
   * The visibility source: the PK is the value-help identifier — always
   * visible, like a table's PK / `preferredId` — and `flatMap` is the bound
   * interface's own props (value-help fields are top-level names).
   */
  readonly source: VisibilityTableSource;
}

function valueHelpHost(
  fields: ReadonlyMap<string, unknown>,
  primaryKey: string | undefined,
  searchableFields: readonly string[],
): ValueHelpHost {
  const ids = primaryKey ? [primaryKey] : [];
  return {
    primaryKey,
    searchableFields,
    source: { primaryKeys: ids, preferredId: ids, flatMap: fields },
  };
}

function transformValueHelpProjection<D>(
  host: ValueHelpHost,
  select: ValueHelpSelect<D> | undefined,
): ValueHelpSelect<D> | undefined {
  const restricted = applyArbacProjection(select, requireRequestScopes(), host.source);
  return widenPrimaryKey(restricted, select, host.primaryKey);
}

/**
 * The PK is always visible (`hasField`, `/meta`), so a scope projection
 * never strips it — mirroring the DB controllers' `preferredId` widening.
 * An explicit `$select` that leaves the PK out (or excludes it) still wins.
 */
function widenPrimaryKey(
  projection: TProjection | undefined,
  requested: unknown,
  pk: string | undefined,
): TProjection | undefined {
  if (!pk || !projection || Array.isArray(projection)) return projection;
  const mode = getProjectionMode(projection);
  if (mode === "empty") return projection;
  if (!requestsField(requested, pk)) return projection;
  if (mode === "include" && !projection[pk]) return { ...projection, [pk]: 1 };
  if (mode === "exclude" && projection[pk] === 0) {
    const { [pk]: _dropped, ...rest } = projection;
    return Object.keys(rest).length > 0 ? rest : undefined;
  }
  return projection;
}

/** Whether a raw value-help `$select` (absent, list, or `{ f: 0 | 1 }` map) asks for `field`. */
function requestsField(requested: unknown, field: string): boolean {
  if (requested === undefined || requested === null) return true;
  if (Array.isArray(requested)) return requested.length === 0 || requested.includes(field);
  if (typeof requested !== "object") return true;
  const map = requested as Record<string, unknown>;
  const values = Object.values(map);
  if (values.length === 0) return true;
  const exclusion = values.every((v) => v === 0 || v === false);
  return exclusion ? map[field] === undefined : !!map[field];
}

async function applyValueHelpMetaOverlay(
  host: ValueHelpHost,
  meta: TMetaResponse,
): Promise<TMetaResponse> {
  const overlaid = await applyArbacMetaOverlay(meta, host.source);
  if (!overlaid.searchable || overlaid.fields === meta.fields) return overlaid;
  // `$search` only matches visible fields — advertise it only if one survived.
  const searchable = host.searchableFields.some((f) => f in overlaid.fields);
  return searchable ? overlaid : { ...overlaid, searchable: false };
}

/**
 * ARBAC-scoped mirror of `@atscript/moost-db`'s {@link AsValueHelpController}
 * (bring your own backing source): the same scope contract as
 * {@link AsArbacDbController} applied through the value-help seams.
 *
 * - `prepareRequest` — every route (`/query`, `/pages`, `/one`, `/meta`)
 *   resolves the scopes first: the authorize interceptor's cached ones, else
 *   a fresh evaluation. Denied → 403. `@Public()` / `arbacPublic` does NOT
 *   bypass it, and a missing interceptor fails closed rather than open.
 * - `transformFilter` — the request filter ∧ the union of scope `filter`s
 *   (denied → match-nothing). `/one` outside the scope answers 404.
 * - `transformProjection` — `$select` restricted to the scopes' projection
 *   union; the PK is always kept.
 * - `hasField` — a scope-hidden field is `Unknown field "x"` (400) in
 *   filter / `$sort` / `$select`, and never matches `$search`.
 * - `validateControls` — per-scope `controls` gates (e.g. `$search: false`).
 * - `/meta` — `crud` filtered per action, `fields` / `type` pruned by the
 *   read scopes' projection union, `searchable` dropped when no searchable
 *   field survives.
 *
 * **Action names**: the data routes are re-tagged with the standard table
 * READ action ids — `runQuery` → `query`, `runPages` → `pages`, `runGetOne`
 * → `getOne`, `runGetOneComposite` → `getOneComposite` (`meta` / `metaForm`
 * already match) — so `allowTableRead(resource, { scope })` grants a
 * value-help source exactly like a table. The resource is the controller's
 * `@ArbacResource(...)` (else the ARBAC fallback: controller id, then class
 * name).
 *
 * Implementations of `query` must honor {@link hasField} for `$search` (skip
 * hidden fields) — the ARBAC layer cannot see inside a custom search.
 *
 * @since 0.1.72
 */
@Inherit()
export abstract class AsArbacValueHelpController<
  T extends TAtscriptAnnotatedType = TAtscriptAnnotatedType,
  DataType = TAtscriptDataType<T>,
> extends AsValueHelpController<T, DataType> {
  private _arbacHost?: ValueHelpHost;

  private get arbacHost(): ValueHelpHost {
    return (this._arbacHost ??= valueHelpHost(
      this.fieldMeta,
      this.primaryKey,
      this.searchableFields,
    ));
  }

  protected async prepareRequest(_ctx: TDbRequestContext): Promise<void> {
    await resolveRequestScopes();
  }

  /** Same contract as {@link AsArbacDbController.transformFilter}. */
  protected transformFilter(filter: FilterExpr): FilterExpr | Promise<FilterExpr> {
    return arbacRowFilter(filter);
  }

  protected transformProjection(
    select: ValueHelpSelect<DataType> | undefined,
  ): ValueHelpSelect<DataType> | undefined | Promise<ValueHelpSelect<DataType> | undefined> {
    return transformValueHelpProjection(this.arbacHost, select);
  }

  protected hasField(path: string): boolean {
    return super.hasField(path) && requestFieldVisible(path, this.arbacHost.source);
  }

  protected validateControls(
    controls: Record<string, unknown>,
    type: TDbControlsType,
  ): string | undefined {
    const baseErr = super.validateControls(controls, type);
    if (baseErr) return baseErr;
    applyArbacControls(controls, requireRequestScopes());
    return undefined;
  }

  protected applyMetaOverlay(meta: TMetaResponse): Promise<TMetaResponse> {
    return applyValueHelpMetaOverlay(this.arbacHost, meta);
  }

  @ArbacAction("query")
  override runQuery(url: string): ReturnType<AsValueHelpController<T, DataType>["runQuery"]> {
    return super.runQuery(url);
  }

  @ArbacAction("pages")
  override runPages(url: string): ReturnType<AsValueHelpController<T, DataType>["runPages"]> {
    return super.runPages(url);
  }

  @ArbacAction("getOne")
  override runGetOne(id: string): ReturnType<AsValueHelpController<T, DataType>["runGetOne"]> {
    return super.runGetOne(id);
  }

  @ArbacAction("getOneComposite")
  override runGetOneComposite(
    query: Record<string, string>,
  ): ReturnType<AsValueHelpController<T, DataType>["runGetOneComposite"]> {
    return super.runGetOneComposite(query);
  }
}

/**
 * ARBAC-scoped mirror of `@atscript/moost-db`'s
 * {@link AsJsonValueHelpController} (a static in-memory row set) — the same
 * contract, action names and resource naming as
 * {@link AsArbacValueHelpController}; `$search` already skips scope-hidden
 * fields.
 *
 * ```ts
 * @Controller('dicts/status')
 * @ArbacResource('dict-status')
 * class StatusDictController extends AsArbacJsonValueHelpController<typeof StatusDict> {
 *   constructor(app: Moost) { super(StatusDict, STATUS_ROWS, app) }
 * }
 * // grant: allowTableRead('dict-status', { scope: () => ({ filter: { active: true } }) })
 * ```
 *
 * @since 0.1.72
 */
@Inherit()
export class AsArbacJsonValueHelpController<
  T extends TAtscriptAnnotatedType = TAtscriptAnnotatedType,
  DataType = TAtscriptDataType<T>,
> extends AsJsonValueHelpController<T, DataType> {
  private _arbacHost?: ValueHelpHost;

  private get arbacHost(): ValueHelpHost {
    return (this._arbacHost ??= valueHelpHost(
      this.fieldMeta,
      this.primaryKey,
      this.searchableFields,
    ));
  }

  protected async prepareRequest(_ctx: TDbRequestContext): Promise<void> {
    await resolveRequestScopes();
  }

  /** Same contract as {@link AsArbacDbController.transformFilter}. */
  protected transformFilter(filter: FilterExpr): FilterExpr | Promise<FilterExpr> {
    return arbacRowFilter(filter);
  }

  protected transformProjection(
    select: ValueHelpSelect<DataType> | undefined,
  ): ValueHelpSelect<DataType> | undefined | Promise<ValueHelpSelect<DataType> | undefined> {
    return transformValueHelpProjection(this.arbacHost, select);
  }

  protected hasField(path: string): boolean {
    return super.hasField(path) && requestFieldVisible(path, this.arbacHost.source);
  }

  protected validateControls(
    controls: Record<string, unknown>,
    type: TDbControlsType,
  ): string | undefined {
    const baseErr = super.validateControls(controls, type);
    if (baseErr) return baseErr;
    applyArbacControls(controls, requireRequestScopes());
    return undefined;
  }

  protected applyMetaOverlay(meta: TMetaResponse): Promise<TMetaResponse> {
    return applyValueHelpMetaOverlay(this.arbacHost, meta);
  }

  @ArbacAction("query")
  override runQuery(url: string): ReturnType<AsJsonValueHelpController<T, DataType>["runQuery"]> {
    return super.runQuery(url);
  }

  @ArbacAction("pages")
  override runPages(url: string): ReturnType<AsJsonValueHelpController<T, DataType>["runPages"]> {
    return super.runPages(url);
  }

  @ArbacAction("getOne")
  override runGetOne(id: string): ReturnType<AsJsonValueHelpController<T, DataType>["runGetOne"]> {
    return super.runGetOne(id);
  }

  @ArbacAction("getOneComposite")
  override runGetOneComposite(
    query: Record<string, string>,
  ): ReturnType<AsJsonValueHelpController<T, DataType>["runGetOneComposite"]> {
    return super.runGetOneComposite(query);
  }
}
