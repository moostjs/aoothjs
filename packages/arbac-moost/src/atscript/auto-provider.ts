import type { TAtscriptAnnotatedType } from "@atscript/typescript/utils";
import type { EventContext } from "@wooksjs/event-core";
import { defineWook, key } from "@wooksjs/event-core";
import { Injectable } from "moost";

import { ArbacUserProvider } from "../user.provider";

/**
 * Minimal atscript-db readable surface used to fetch the user record. Matches
 * `AtscriptDbTable.findOne` exactly so consumers pass the table directly.
 * Kept loose to avoid pulling `@atscript/db` types into the public surface.
 */
export interface ArbacUserTable<T extends object> {
  findOne(query: {
    filter: Record<string, unknown>;
    controls?: { $select?: Record<string, 1> };
  }): Promise<T | null>;
}

interface ArbacExtractSpec {
  /** Resolved id field name: `@arbac.userId` if present, else `@meta.id`. */
  userIdField: string | undefined;
  roleFields: string[];
  attrFields: string[];
}

/**
 * Walk the type's `props` once and record the `@arbac.*` / `@meta.id`
 * field positions. Memoized on the type reference (module-level WeakMap)
 * so multiple provider instances share one traversal per type.
 */
const specCache = new WeakMap<TAtscriptAnnotatedType, ArbacExtractSpec>();

function getArbacExtractSpec(type: TAtscriptAnnotatedType): ArbacExtractSpec {
  const cached = specCache.get(type);
  if (cached !== undefined) return cached;

  const spec: ArbacExtractSpec = {
    userIdField: undefined,
    roleFields: [],
    attrFields: [],
  };

  const def = type.type;
  if (def.kind !== "object") {
    specCache.set(type, spec);
    return spec;
  }

  let metaIdField: string | undefined;
  let userIdField: string | undefined;

  for (const [fieldName, fieldType] of def.props) {
    const md = fieldType.metadata;
    if (md.get("arbac.userId")) userIdField = fieldName;
    if (md.get("meta.id")) metaIdField = fieldName;
    if (md.get("arbac.role")) spec.roleFields.push(fieldName);
    if (md.get("arbac.attribute")) spec.attrFields.push(fieldName);
  }

  spec.userIdField = userIdField ?? metaIdField;
  specCache.set(type, spec);
  return spec;
}

/** Mongo-style projection covering id + every `@arbac.role` / `@arbac.attribute` field. */
const projectionCache = new WeakMap<TAtscriptAnnotatedType, Record<string, 1>>();

function getArbacProjection(type: TAtscriptAnnotatedType): Record<string, 1> {
  const cached = projectionCache.get(type);
  if (cached !== undefined) return cached;
  const spec = getArbacExtractSpec(type);
  const projection: Record<string, 1> = {};
  if (spec.userIdField) projection[spec.userIdField] = 1;
  for (const f of spec.roleFields) projection[f] = 1;
  for (const f of spec.attrFields) projection[f] = 1;
  projectionCache.set(type, projection);
  return projection;
}

// Per-event slot keyed by the provider instance. Multiple providers (e.g.
// admin handlers that probe multiple user types in one event) get isolated
// caches, while repeated `getRoles + getAttrs` for the same id share one
// fetch. The provider class itself stays SINGLETON so it inherits the base
// `ArbacUserProvider`'s scope metadata — making it FOR_EVENT would force a
// scope-id lookup that fails when the interceptor resolves the provider in a
// context where a different adapter's scope was the most recently registered
// (multi-adapter apps observed this in e2e tests).
// Cache holds heterogeneous provider types — erase to `unknown` at the slot
// level and re-narrow per-instance inside `fetchRecord`.
type FetchCache = WeakMap<object, Map<string, Promise<unknown>>>;
const fetchCacheKey = key<FetchCache | undefined>("aooth.arbacFetchCache");
const useFetchCache = defineWook((ctx: EventContext): FetchCache => {
  let cache = ctx.has(fetchCacheKey) ? ctx.get(fetchCacheKey) : undefined;
  if (!cache) {
    cache = new WeakMap();
    ctx.set(fetchCacheKey, cache);
  }
  return cache;
});

/**
 * `@Injectable()` (SINGLETON) — moost@0.6.x's `Injectable` metadata is NOT
 * inherited from the base `ArbacUserProvider` by infact, so the decorator
 * must be re-applied here. SINGLETON is the right scope: there is no
 * per-instance state worth scoping per event, and FOR_EVENT trips a
 * scope-id mismatch when the interceptor resolves the provider in a
 * multi-adapter app (HTTP + WF). Per-event memoization is provided via
 * a wooks-slot cache keyed by `this` — see `useFetchCache` above.
 *
 * Consumers extend this class, implement `getUserId()` (typically reading
 * the JWT subject from the auth composable), inject their atscript-db
 * table, and register the subclass via `setReplaceRegistry`.
 *
 * `extractRoles` and `extractAttrs` are protected seams — override to
 * reshape roles/attrs without re-implementing the fetch path.
 */
@Injectable()
export abstract class AtscriptArbacUserProvider<
  T extends object = object,
> extends ArbacUserProvider {
  private readonly spec: ArbacExtractSpec;
  private readonly projection: Record<string, 1>;

  constructor(
    protected readonly userType: TAtscriptAnnotatedType,
    protected readonly table: ArbacUserTable<T>,
  ) {
    super();
    this.spec = getArbacExtractSpec(userType);
    if (!this.spec.userIdField) {
      throw new Error(
        "AtscriptArbacUserProvider: userType has no @arbac.userId or @meta.id field — annotate one to identify users",
      );
    }
    this.projection = getArbacProjection(userType);
  }

  abstract override getUserId(): string | Promise<string>;

  override async getRoles(id: string): Promise<string[]> {
    const record = await this.fetchRecord(id);
    if (record === null) return [];
    return this.extractRoles(record);
  }

  override async getAttrs(id: string): Promise<object> {
    const record = await this.fetchRecord(id);
    if (record === null) return {};
    return this.extractAttrs(record);
  }

  /**
   * Override seam: combined list of all `@arbac.role` field values,
   * deduplicated in first-seen order. Each declared role field may hold
   * `string` or `string[]`; empty / nullish / non-string entries are skipped.
   */
  protected extractRoles(record: T): string[] {
    const roleFields = this.spec.roleFields;
    if (roleFields.length === 0) return [];
    const seen = new Set<string>();
    const out: string[] = [];
    const rec = record as Record<string, unknown>;
    for (const field of roleFields) {
      const value = rec[field];
      if (value === undefined || value === null) continue;
      if (Array.isArray(value)) {
        for (const item of value) {
          if (typeof item === "string" && item !== "" && !seen.has(item)) {
            seen.add(item);
            out.push(item);
          }
        }
      } else if (typeof value === "string" && value !== "" && !seen.has(value)) {
        seen.add(value);
        out.push(value);
      }
    }
    return out;
  }

  /**
   * Override seam: `@arbac.attribute` fields keyed by prop name. Undefined
   * entries are retained so consumers can distinguish "declared but empty"
   * from "not declared".
   */
  protected extractAttrs(record: T): object {
    const attrFields = this.spec.attrFields;
    if (attrFields.length === 0) return {};
    const out: Record<string, unknown> = {};
    const rec = record as Record<string, unknown>;
    for (const field of attrFields) {
      out[field] = rec[field];
    }
    return out;
  }

  /**
   * Per-event, per-instance, per-userId memoized fetch. The cache lives on
   * the wooks event context so two distinct events never share state, and
   * is keyed by `this` so multiple replacement subclasses in the same
   * process do not collide.
   */
  private fetchRecord(userId: string): Promise<T | null> {
    const ctxCache = useFetchCache();
    let perProvider = ctxCache.get(this) as Map<string, Promise<T | null>> | undefined;
    if (!perProvider) {
      perProvider = new Map<string, Promise<T | null>>();
      ctxCache.set(this, perProvider);
    }
    const cached = perProvider.get(userId);
    if (cached !== undefined) return cached;
    // userIdField is guaranteed non-empty by the constructor check.
    const userIdField = this.spec.userIdField as string;
    const promise = this.table.findOne({
      filter: { [userIdField]: userId },
      controls: { $select: this.projection },
    });
    // Drop a rejected entry so a retry within the same event can re-fetch
    // (otherwise concurrent getRoles/getAttrs would all see the same failure).
    promise.catch(() => perProvider?.delete(userId));
    perProvider.set(userId, promise);
    return promise;
  }
}
