import type { TAtscriptAnnotatedType } from "@atscript/typescript/utils";
import type { EventContext } from "@wooksjs/event-core";
import { defineWook, key } from "@wooksjs/event-core";
import { Injectable } from "moost";

import { ArbacUserProvider } from "../user.provider";
import { uniqueStrings } from "./role-list";

/**
 * Minimal atscript-db readable surface used to fetch the user record.
 * Structurally compatible with `AtscriptDbTable<T>.findOne` so the runtime
 * call site Just Works™ — but the public typings differ (atscript-db's
 * `findOne` takes a wider `controls` shape with engine-specific keys we
 * deliberately omit here to keep this surface narrow and engine-agnostic).
 *
 * Consequence: passing `db.getTable(UserModel)` directly will not satisfy
 * this interface in TypeScript. Cast at the call site:
 *
 * ```ts
 * super(UserModel, db.getTable(UserModel) as unknown as ArbacUserTable<UserModel>)
 * ```
 *
 * Kept loose to avoid pulling `@atscript/db` types into the public surface.
 *
 * `controls.$with` is optional — included so providers can request nav-prop
 * expansion when `@arbac.role` is declared on a `@db.rel.from` field.
 */
export interface ArbacUserTable<T extends object> {
  findOne(query: {
    filter: Record<string, unknown>;
    controls?: {
      $select?: Record<string, 1>;
      $with?: Array<{ name: string }>;
    };
  }): Promise<T | null>;
}

/**
 * Spec computed once per `TAtscriptAnnotatedType`.
 *
 * `userIdField` resolution order (first match wins):
 *   1. explicit `@arbac.userId`
 *   2. field declared by `@db.table.preferredId.uniqueIndex` (a `@db.index.unique`
 *      group declared on exactly one field; named index variant or first declared)
 *   3. `@meta.id` (PK)
 *
 * `roleField` is the single `@arbac.role`-annotated prop (more than one throws):
 *   - shape `'inline'` → field holds `string | string[]`; values are read directly
 *     and projected via `$select`.
 *   - shape `'rel.from'` → field is a `@db.rel.from` nav prop (1:N to a role
 *     table); provider auto-injects `controls.$with = [{ name: roleField }]`
 *     and extracts role names from joined records using `roleTargetIdField`
 *     (resolved on the target type with the same chain as `userIdField`).
 */
interface ArbacExtractSpec {
  userIdField: string | undefined;
  roleField:
    | { name: string; shape: "inline" }
    | { name: string; shape: "rel.from"; roleTargetIdField: string }
    | undefined;
  attrFields: string[];
}

const specCache = new WeakMap<TAtscriptAnnotatedType, ArbacExtractSpec>();

/**
 * Resolve the identifier field on an object type using the three-step chain
 * documented on `ArbacExtractSpec.userIdField`. Used for the user type AND
 * for the role target type referenced by `@db.rel.from`-shaped role fields.
 */
function resolveIdentifierField(type: TAtscriptAnnotatedType): string | undefined {
  const def = type.type;
  if (def.kind !== "object") return undefined;

  let explicit: string | undefined;
  let metaId: string | undefined;
  const uniqueIndexFields = new Map<string, string[]>(); // index-name → fields
  const anyUniqueField: string[] = [];

  for (const [fieldName, fieldType] of def.props) {
    const md = fieldType.metadata;
    if (md.get("arbac.userId")) explicit = fieldName;
    if (md.get("meta.id")) metaId = fieldName;
    // `@db.index.unique` is a `(string | true)[]` — each entry is one group
    // membership. `true` is an anonymous unique index on this field alone.
    const unique = md.get("db.index.unique");
    if (Array.isArray(unique)) {
      for (const entry of unique) {
        if (entry === true) {
          anyUniqueField.push(fieldName);
        } else if (typeof entry === "string") {
          const bucket = uniqueIndexFields.get(entry);
          if (bucket) bucket.push(fieldName);
          else uniqueIndexFields.set(entry, [fieldName]);
        }
      }
    }
  }
  if (explicit) return explicit;

  // `@db.table.preferredId.uniqueIndex` lives on the type-level metadata. Value
  // is `string` (target an index by name) or `true` (use the first declared
  // unique index). Either way it must resolve to a single-field group — a
  // composite unique index makes a poor identifier, so we skip those silently
  // and fall through to `@meta.id`. The whole point of preferredId is "address
  // rows by a single human-readable field".
  const preferred = type.metadata.get("db.table.preferredId.uniqueIndex");
  if (preferred !== undefined) {
    if (typeof preferred === "string") {
      const fields = uniqueIndexFields.get(preferred);
      if (fields && fields.length === 1) return fields[0];
    } else {
      // `true`: pick the first unique-index group with exactly one member.
      for (const fields of uniqueIndexFields.values()) {
        if (fields.length === 1) return fields[0];
      }
      if (anyUniqueField.length > 0) return anyUniqueField[0];
    }
  }

  return metaId;
}

function getArbacExtractSpec(type: TAtscriptAnnotatedType): ArbacExtractSpec {
  const cached = specCache.get(type);
  if (cached !== undefined) return cached;

  const spec: ArbacExtractSpec = {
    userIdField: undefined,
    roleField: undefined,
    attrFields: [],
  };

  const def = type.type;
  if (def.kind !== "object") {
    specCache.set(type, spec);
    return spec;
  }

  const roleCandidates: Array<{ name: string; fieldType: TAtscriptAnnotatedType }> = [];

  for (const [fieldName, fieldType] of def.props) {
    const md = fieldType.metadata;
    if (md.get("arbac.role")) {
      roleCandidates.push({ name: fieldName, fieldType });
    }
    if (md.get("arbac.attribute")) spec.attrFields.push(fieldName);
  }

  // Fail loud: more than one `@arbac.role` is rejected outright. Silent union
  // was the previous behavior; surfacing the conflict at spec time stops apps
  // from booting with an ambiguous role source.
  if (roleCandidates.length > 1) {
    throw new Error(
      `AtscriptArbacUserProvider: multiple @arbac.role fields declared (${roleCandidates
        .map((c) => c.name)
        .join(
          ", ",
        )}). Exactly one role source is supported — drop the @arbac.role from all but the canonical field.`,
    );
  }

  if (roleCandidates.length === 1) {
    const { name, fieldType } = roleCandidates[0];
    const isRelFrom = fieldType.metadata.get("db.rel.from") !== undefined;
    if (isRelFrom) {
      // Resolve the role table's identifier field — the value we pull off each
      // joined record. The target sits in `fieldType.type.of` for an array
      // nav-prop. We tolerate weirder shapes (e.g. someone annotates a non-
      // array `@db.rel.from`) by walking through to the first annotated type
      // we can resolve.
      const target = resolveRelTargetType(fieldType);
      if (!target) {
        throw new Error(
          `AtscriptArbacUserProvider: @arbac.role on @db.rel.from field "${name}" — could not resolve the target role type. Declare the nav prop as \`<RoleType>[]\`.`,
        );
      }
      const roleTargetIdField = resolveIdentifierField(target);
      if (!roleTargetIdField) {
        throw new Error(
          `AtscriptArbacUserProvider: @arbac.role on @db.rel.from field "${name}" — target role type has no @arbac.userId / preferred unique index / @meta.id to identify role names by.`,
        );
      }
      spec.roleField = { name, shape: "rel.from", roleTargetIdField };
    } else {
      spec.roleField = { name, shape: "inline" };
    }
  }

  spec.userIdField = resolveIdentifierField(type);
  specCache.set(type, spec);
  return spec;
}

/**
 * Walk an annotated type to the target type of a navigation prop. Most cases
 * are `Role[]` (array of annotated types), so we descend through `array.of`
 * once. If the descent doesn't land on an `object`, the caller treats it as
 * unresolvable.
 */
function resolveRelTargetType(
  fieldType: TAtscriptAnnotatedType,
): TAtscriptAnnotatedType | undefined {
  const def = fieldType.type;
  if (def.kind === "array") {
    const of = (def as { of?: TAtscriptAnnotatedType }).of;
    if (of && of.type.kind === "object") return of;
  }
  if (def.kind === "object") return fieldType;
  return undefined;
}

/** Mongo-style projection covering id + `@arbac.role` (when inline) + `@arbac.attribute` fields. */
const projectionCache = new WeakMap<TAtscriptAnnotatedType, Record<string, 1>>();

function getArbacProjection(type: TAtscriptAnnotatedType): Record<string, 1> {
  const cached = projectionCache.get(type);
  if (cached !== undefined) return cached;
  const spec = getArbacExtractSpec(type);
  const projection: Record<string, 1> = {};
  if (spec.userIdField) projection[spec.userIdField] = 1;
  // Inline role fields project as a regular column. `rel.from` role fields are
  // requested via `$with` (not `$select`) and the adapter materializes them
  // onto the record as joined arrays — so they do NOT belong in the projection.
  if (spec.roleField && spec.roleField.shape === "inline") {
    projection[spec.roleField.name] = 1;
  }
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
  private readonly withClause: Array<{ name: string }> | undefined;

  constructor(
    protected readonly userType: TAtscriptAnnotatedType,
    protected readonly table: ArbacUserTable<T>,
  ) {
    super();
    this.spec = getArbacExtractSpec(userType);
    if (!this.spec.userIdField) {
      throw new Error(
        "AtscriptArbacUserProvider: userType has no @arbac.userId, @db.table.preferredId.uniqueIndex field, or @meta.id — annotate one to identify users",
      );
    }
    this.projection = getArbacProjection(userType);
    this.withClause =
      this.spec.roleField?.shape === "rel.from" ? [{ name: this.spec.roleField.name }] : undefined;
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
   * Override seam: role identifiers pulled off the record.
   *
   * - inline (`string | string[]`): the field value, with empty / nullish /
   *   non-string entries dropped and duplicates collapsed in first-seen order.
   * - `@db.rel.from` (joined array of role records): each entry's
   *   `roleTargetIdField` value (resolved at spec time on the target type
   *   using the same `@arbac.userId` → preferred unique index → `@meta.id`
   *   chain). Same dedup / drop-empty rules.
   *
   * Returns `[]` when the role field is undeclared or its value is null /
   * undefined / empty.
   */
  protected extractRoles(record: T): string[] {
    const roleField = this.spec.roleField;
    if (!roleField) return [];
    const rec = record as Record<string, unknown>;
    const raw = rec[roleField.name];
    if (raw === undefined || raw === null) return [];

    if (roleField.shape === "inline") {
      return uniqueStrings(Array.isArray(raw) ? raw : [raw]);
    }
    // rel.from: raw is an array of joined role records; pull each role id.
    if (!Array.isArray(raw)) return [];
    const idField = roleField.roleTargetIdField;
    return uniqueStrings(
      raw.map((item) =>
        item && typeof item === "object" ? (item as Record<string, unknown>)[idField] : undefined,
      ),
    );
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
    const controls: { $select: Record<string, 1>; $with?: Array<{ name: string }> } = {
      $select: this.projection,
    };
    if (this.withClause) controls.$with = this.withClause;
    const promise = this.table.findOne({
      filter: { [userIdField]: userId },
      controls,
    });
    // Drop a rejected entry so a retry within the same event can re-fetch
    // (otherwise concurrent getRoles/getAttrs would all see the same failure).
    promise.catch(() => perProvider?.delete(userId));
    perProvider.set(userId, promise);
    return promise;
  }
}
