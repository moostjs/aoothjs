# `@aooth/arbac-moost` API Reference

Complete export reference for `@aooth/arbac-moost`. See the [Moost Integration Guide](/moost/) and [ARBAC Authorize](/moost/arbac-authorize) for narrative documentation. Subpaths: `./atscript`, `./plugin`.

## Classes

### `MoostArbac<TUserAttrs, TScope>`

```ts
@Injectable()
class MoostArbac<TUserAttrs extends object, TScope extends object> extends Arbac<
  TUserAttrs,
  TScope
> {}
```

DI-injectable `Arbac` subclass. Register a singleton in the provide registry so `registerRole(...)` is reachable at boot. See [ARBAC Authorize](/moost/arbac-authorize).

### `ArbacUserProvider<TUserAttrs>` (abstract)

```ts
abstract class ArbacUserProvider<TUserAttrs extends object = object> {
  abstract getUserId(): string | Promise<string>;
  abstract getRoles(id: string): string[] | Promise<string[]>;
  abstract getAttrs(id: string): TUserAttrs | Promise<TUserAttrs>;
}
```

Abstract base. Every concrete subclass MUST re-apply `@Injectable()` — moost@0.6.x does not inherit injectable metadata across `extends`. Bind your concrete class via `setReplaceRegistry([ArbacUserProviderToken, MyProvider])`. See [ARBAC Authorize](/moost/arbac-authorize).

### `ArbacUserProviderToken`

```ts
const ArbacUserProviderToken: TClassConstructor<ArbacUserProvider>;
```

DI key used to look up the user provider. The abstract class itself does not satisfy moost's `TClassConstructor` shape, so this cast is the registration handle. See [ARBAC Authorize](/moost/arbac-authorize).

### `AsArbacDbController<T>`

```ts
class AsArbacDbController<T> extends AsDbController<T> {}
```

`@atscript/moost-db` controller subclass that wires ARBAC into every CRUD seam: `transformFilter`, `transformProjection`, `validateControls`, `applyMetaOverlay`, `hasField`, `onWrite`, `onRemove`, `assertInScope`. Scopes auto-applied — no explicit `getScopes()` call needed in handlers. See [DB Controllers](/moost/).

Two seams enforce that a scope `projection` removes fields from existence, not just from row payloads:

- **`applyMetaOverlay`** prunes the `/meta` envelope — `fields`, the serialized `type`, `relations`, `versionColumn` — down to the union of the allowed read ops' scope projections (PK + `preferredId` always survive; reads always return them). A scoped UI can no longer offer columns that would never populate, and secret-bearing column names stop leaking. Unscoped read grants keep the full envelope; write-only principals keep `type` for their insert/update forms.
- **`hasField`** answers `false` for paths outside that union, so any query reference to a hidden field gets the **identical** `Unknown field "x"` 400 a nonexistent field gets — no existence or value oracle. A path under a `with`-granted relation (`$with=rel(x>1)`, `$with=rel($sort=x)`, `$with=rel($select=x)`) is checked as `x` against the union of the `with.rel` sub-scopes, recursively; the related table's PK / `preferredId` stay visible, and `/meta` prunes the relation's nav type the same way. Requirements (moost-db version, authorize interceptor, search indexes): [Column-scope security floor](/moost/db-controllers#column-scope-security-floor).

### `AsArbacDbReadableController<T>`

```ts
class AsArbacDbReadableController<T> extends AsDbReadableController<T> {}
```

Read-only mirror of `AsArbacDbController` for view controllers — including the same `/meta` pruning + `hasField` parity. Both classes are view-safe on every read path (all read-side enforcement goes through the bound readable, never the view-guarded `.table` getter); bind `@db.view` models with `@ReadableController(ViewModel)`. See [DB Controllers](/moost/).

## Functions

### `arbacAuthorizeInterceptor`

```ts
const arbacAuthorizeInterceptor: TInterceptorFn & {
  __authTransports: TAuthTransportDeclaration;
};
```

`defineBeforeInterceptor` at `TInterceptorPriority.GUARD`. No-ops on public/no-metadata events. On deny throws `HttpError(403)`; non-`HttpError` from the evaluator is rethrown as `HttpError(401)`. The `__authTransports: {}` marker makes `@moostjs/swagger` treat it as an auth-guard with no transport requirement. See [ARBAC Authorize](/moost/arbac-authorize).

### `useArbac`

```ts
function useArbac(ctx?: EventContext): ArbacBindings;

interface ArbacBindings {
  readonly resource: string;
  readonly action: string;
  readonly isPublic: boolean;
  getScopes<TScope>(): TScope[] | undefined;
  setScopes<TScope>(scopes: TScope[]): void;
  evaluate<TScope>(over?: {
    resource?: string;
    action?: string;
  }): Promise<{ allowed: boolean; scopes?: TScope[]; userId: string }>;
  evaluateOrThrow<TScope>(over?: {
    resource?: string;
    action?: string;
  }): Promise<{ allowed: true; scopes?: TScope[]; userId: string }>;
}
```

### `getArbacScopes`

```ts
function getArbacScopes<TScope extends object>(ctx?: EventContext): TScope[] | undefined;
```

Reads the scopes cached for the current event, the same slot `useArbac().getScopes()` reads, without resolving controller metadata. Use it in per-field hot paths such as a custom `hasField`. `undefined` before the authorize interceptor or `setScopes` ran.

**`useArbac` is intentionally not a `defineWook`** — wook cache would replay parent HTTP resolution into WF child events. Resource/action resolution chain: `mMeta.arbacResourceId → cMeta.arbacResourceId → cMeta.id → constructor.name` and `mMeta.arbacActionId → mMeta.atscript_db_action.name → cMeta.arbacActionId → mMeta.id → cc.getMethod()`. See [ARBAC Authorize](/moost/arbac-authorize).

### `getArbacMate`

```ts
function getArbacMate(): Mate<TArbacMeta>;
interface TArbacMeta {
  arbacResourceId?: string;
  arbacActionId?: string;
  arbacPublic?: boolean;
}
```

Shared moost `Mate` typed with `TArbacMeta`. `TArbacMeta` is **declaration-merged into `moost`'s `TMoostMetadata`** so framework consumers see fields on their handler metadata. See [Decorators](/moost/decorators).

::: warning Internal — exposed for custom subclassers
The three helpers below (`enforceControlsPolicy`, `extractUsedControlValues`, `applyAllowedFieldsAndSet`) are wired into `AsArbacDbController`'s hooks for you. They're exported so subclassers writing custom hook overrides can compose them; app code that stays on the documented `AsArbacDbController` subclassing patterns never calls them directly. See [DB Controllers](/moost/).
:::

### `enforceControlsPolicy`

```ts
function enforceControlsPolicy(
  policy: Record<string, ControlGate>,
  controls: Record<string, unknown>,
): void;
```

Throws `HttpError(403, 'Control "$with" is not allowed for your role')` on violations. Applied by `AsArbacDbController.validateControls` against the union of scope `controls` maps.

### `extractUsedControlValues`

```ts
function extractUsedControlValues(key: string, value: unknown): string[];
```

Normalizes a control value into the list of names it references — used to feed `enforceControlsPolicy` for `$with` / `$groupBy` whitelist checks. Pass the query's `controls` as the third argument to map `$groupBy` calendar-bucket aliases to their source fields (`groupByFields` from `@uniqu/core`); `enforceControlsPolicy` does this.

### `applyAllowedFieldsAndSet`

```ts
function applyAllowedFieldsAndSet(
  data: unknown,
  scopes: ArbacDbScope[],
  identifierFields?: readonly string[],
): unknown;
```

Strips fields outside the union of `allowedFields` and overlays `set` defaults. Auto-preserves keys in `identifierFields` (PK + unique-index columns). Used by `AsArbacDbController.onWrite`.

### `applyArbacMetaOverlay` / `pruneMetaByVisibility` / `unionScopeProjection` / `collectWithGrantNames` / `isMetaFieldVisible` / `buildScopeVisibility`

```ts
function applyArbacMetaOverlay(
  meta: TMetaResponse,
  source: VisibilityTableSource | ReadonlySet<string>,
): Promise<TMetaResponse>;
function pruneMetaByVisibility(meta: TMetaResponse, vis: MetaVisibility): TMetaResponse;
function unionScopeProjection(scopes: ArbacDbScope[]): TProjection | undefined;
function collectWithGrantNames(scopes: ArbacDbScope[]): ReadonlySet<string>;
function isMetaFieldVisible(path: string, vis: MetaVisibility): boolean;
function isScopedFieldVisible(
  scopes: ArbacDbScope[],
  path: string,
  source: VisibilityTableSource | ReadonlySet<string>,
): boolean;
function buildScopeVisibility(
  scopes: ArbacDbScope[],
  table: VisibilityTableSource | undefined,
  alwaysVisible?: ReadonlySet<string>,
): MetaVisibility;
function metaAlwaysVisibleFields(
  controller: object,
  source: { primaryKeys: readonly string[]; preferredId: readonly string[] },
): ReadonlySet<string>;
```

The `/meta` field-visibility machinery behind both ARBAC controllers (see [`AsArbacDbController`](#asarbacdbcontroller-t)). `applyArbacMetaOverlay` is the full per-request overlay (actions/crud filtering + field pruning; needs the moost event context); the rest are pure and composable from custom `applyMetaOverlay` / `hasField` overrides. Pass the controller's `this.readable` as `source` (a `VisibilityTableSource`): identifiers (PK + `preferredId`) are derived from it, and its `relatedTable(navField)` reaches each joined table so that table's identifiers stay visible too.

- `isScopedFieldVisible` is the shared `hasField` body. It memoizes the visibility per event-stable scopes array and readable.
- `buildScopeVisibility` is the single builder behind `hasField`, `/meta` pruning, `$select` value stripping and the `$with` overlay.
- `metaAlwaysVisibleFields` returns the PK + `preferredId` set; it is kept for compatibility.

`MetaVisibility` is `{ allowed: TProjection; alwaysVisible: ReadonlySet<string>; withGrants: ReadonlySet<string>; relation?: (name) => MetaVisibility | undefined; isAllowed?: (path) => boolean; scopes?; table?; writable?: … }`:

- `allowed` is `{}` when own fields are unrestricted.
- `isAllowed` is `isFieldAllowed(path, allowed)` precompiled.
- `relation(name)` is the `with.<name>` sub-scope visibility a `name.x` path is checked against.

A hand-built `MetaVisibility` without `relation` lets granted paths through unchecked, so build it with `buildScopeVisibility`. Passing a bare identifier set as `source` (the 0.1.67 signatures) still enforces sub-scopes, but does not exempt related identifiers. `pruneMetaByVisibility` never mutates its input (the base controller caches the static envelope).

### `conjoinArbacDbScopes`

```ts
function conjoinArbacDbScopes(
  userScopes: ArbacDbScope[],
  credScopes: ArbacDbScope[],
  childrenOf?: TProjectionChildren,
): ArbacDbScope[];
```

Credential-attenuation combiner: UNIONs each side with the additive helpers, then CONJOINS the two results facet-by-facet (`conjoinScopeFilters` `$and`, `intersectProjections` path-wise field ∩ — a parent narrows to the other side's nested whitelist; the optional `childrenOf` schema lookup (supplied by `useArbac().evaluate` for DB controllers) splits an included parent with a hidden child exactly, otherwise it is dropped; no common field → the user's projection plus a match-nothing filter, never `{}` — `intersectControlsPolicy` deny-wins, `allowedFields` intersection, recursive `with`) — never the additive union helpers, which would silently widen. Returns a single-element list so downstream scope-application sites (which union the scope list per facet) see the conjunction unchanged. Consumes `credScopes` from an attenuated [`Arbac.evaluate`](/api/arbac-core#arbac-tuserattrs-tscope). See [Scope Merging](/arbac/scopes).

## Decorators

### `@ArbacResource`

```ts
function ArbacResource(name: string): ClassDecorator & MethodDecorator;
```

Writes `arbacResourceId` onto class or method mate. Method-level wins over class-level. See [Decorators](/moost/decorators).

### `@ArbacAction`

```ts
function ArbacAction(name: string): ClassDecorator & MethodDecorator;
```

Writes `arbacActionId`. Typically applied per-method. See [Decorators](/moost/decorators).

### `@ArbacAuthorize`

```ts
function ArbacAuthorize(): ClassDecorator & MethodDecorator;
```

Sugar for `Authenticate(arbacAuthorizeInterceptor)`. Use when you don't apply the interceptor globally and want to authorize a single route. See [Decorators](/moost/decorators).

::: info Not exported
`@ArbacPublic` and `@ArbacScopes` are intentionally NOT exported. Use [`@Public()`](./auth-moost#public) from `@aooth/auth-moost` (writes both `authPublic` and `arbacPublic`), and read scopes via `useArbac().getScopes<TScope>()`.
:::

## Types

### `ArbacDbScope<T>`

```ts
interface ArbacDbScope<T = unknown> {
  filter?: TScopeFilter;
  projection?: ProjectionOf<T>;
  set?: Partial<Record<OwnFieldKey<T>, unknown>>;
  allowedFields?: Array<OwnFieldKey<T>>;
  controls?: ControlsOf<T>;
  /** Per-relation sub-scopes applied when the request expands a relation via
   *  `?$with=<name>`. Recursive — each sub-scope has the same shape and can
   *  declare its own `with` for nested expansions: keys are the model's nav
   *  relations, values are `ArbacDbScope<NavTarget>` (untyped `T` falls back to
   *  `Record<string, ArbacDbScope>`; the mapped type is internal, not an
   *  exported symbol). Parent-authority model: arbac-moost does NOT
   *  re-evaluate ARBAC against the joined resource. */
  with?: Record<string, ArbacDbScope>;
}
```

The scope shape `AsArbacDbController` understands. Pass an `.as` model as `T` (e.g. `ArbacDbScope<Task>`) to get autocomplete on `projection` / `with` / `controls` / `set` / `allowedFields` against the model's own and navigation fields. `T = unknown` (the default) keeps the legacy untyped shape for back-compat. **Open to declaration merging** — augment with custom fields if you extend the controller. See [DB Controllers](/moost/).

::: warning Known gap — joined-resource projection in exclude mode
arbac-moost does not apply the joined-resource projection mask to `$with` expansions when the request uses exclude-mode `$select` for the relation loader. Include-mode `$select` works end-to-end. Track via the e2e-demo's `PROJ_COMMENT_VIEWER_EXPANDED` notes.
:::

### `AoothArbacClaims`

```ts
interface AoothArbacClaims {
  roles?: string[];
  attrs?: Record<string, unknown>;
}
```

Restrict-only attenuation claims carried by a credential (extracted via `extractAttenuation`). `roles` = assume a SUBSET of the user's roles — `[]` means no roles (deny-all, fail-closed), an omitted key keeps all the user's roles; a role the user lacks is dropped by the intersection. `attrs` are merged into the credential pass only and clipped by the scope conjunction, so they can never widen beyond the user's own authority. Feeds `Arbac.evaluate`'s `attenuate` option.

## Subpath: `@aooth/arbac-moost/atscript`

```ts
import {
  AtscriptArbacUserProvider,
  ArbacUserTable,
  AoothArbacUserCredentials,
  extractAttenuation,
  getArbacAttenuationSpec,
  validateAttenuationTargets,
  getAoothUserHandleSpec,
  getAoothCredentialMetadataSpec,
} from "@aooth/arbac-moost/atscript";
```

### `AtscriptArbacUserProvider<T>`

```ts
abstract class AtscriptArbacUserProvider<T extends object> extends ArbacUserProvider<T> {
  constructor(userType: TAtscriptAnnotatedType, table: ArbacUserTable<T>);
  abstract getUserId(): string | Promise<string>;
}
```

Drop-in subclass driven by a `.as` user model. Only `getUserId()` remains abstract — typically reads from `useAuth()`. Caches `(EventContext, this, userId)` so `getRoles + getAttrs` collapse to one round-trip per request. Missing record → `getRoles: []`, `getAttrs: {}` (fail-closed). See [Atscript Models](/moost/).

### `ArbacUserTable<T>`

```ts
interface ArbacUserTable<T extends object> {
  findOne(opts: {
    filter: Record<string, unknown>;
    controls?: { $select?: TProjection; $with?: Array<{ name: string }> };
  }): Promise<T | null>;
}
```

Structural interface — the subset of `AtscriptDbTable` `AtscriptArbacUserProvider` calls. Structurally compatible at runtime with `AtscriptDbTable<T>.findOne` but the public typings differ (atscript-db's signature has wider engine-specific `controls.*` keys), so you cast at the call site:

```ts
super(MyUser, db.getTable(MyUser) as unknown as ArbacUserTable<MyUser>);
```

See [Atscript Models](/moost/).

### `extractAttenuation`

```ts
function extractAttenuation(
  credType: TAtscriptAnnotatedType,
  record: object | null | undefined,
): AoothArbacClaims | undefined;
```

Reads a validated credential record's `@arbac.attenuate.role` / `@arbac.attenuate.attr` fields into the `AoothArbacClaims` shape consumed by `Arbac.evaluate`'s `attenuate` option. Returns `undefined` when the model declares no attenuation fields or the record is absent (→ plain non-attenuated evaluation). See [Atscript Models](/moost/).

### `getArbacAttenuationSpec` / `validateAttenuationTargets`

```ts
function getArbacAttenuationSpec(credType: TAtscriptAnnotatedType): ArbacAttenuationSpec;
function validateAttenuationTargets(
  credType: TAtscriptAnnotatedType,
  validUserAttrs: Iterable<string>,
): void;
```

`getArbacAttenuationSpec` walks (and caches per type) the credential model's `@arbac.attenuate.*` annotations into `ArbacAttenuationSpec` (`{ roleField, attrFields: [{ field, userAttr }] }`). `validateAttenuationTargets` throws at boot when an `@arbac.attenuate.attr` target names a user attribute that doesn't exist in the user model's `@arbac.attribute` keyspace — call it once at startup, fail fast.

### `getAoothUserHandleSpec`

```ts
function getAoothUserHandleSpec(userType: TAtscriptAnnotatedType): AoothUserHandleSpec;
```

Resolves (and caches per type) the user model's `@aooth.user.email` / `@aooth.user.phone` identity-handle fields into `AoothUserHandleSpec` (`{ emailField, phoneField, handleFields, warnings }`). A handle field missing `@db.index.unique` is dropped with a warning (warn-and-disable contract) — surface `warnings` in your boot log. See [Recovery & Handles](/moost/recovery-and-handles).

### `getAoothCredentialMetadataSpec`

```ts
function getAoothCredentialMetadataSpec(
  credentialType: TAtscriptAnnotatedType,
): AoothCredentialMetadataSpec;
```

Resolves (and caches per type) the credential model's `@aooth.auth.metadata` column into `AoothCredentialMetadataSpec` (`{ metadataField, warnings }`). Thread `metadataField` into `CredentialStoreAtscriptDb` (`@aooth/auth/atscript-db`) so the store maps the envelope's `metadata` through your fully-typed `@db.json` column (shape it as `AoothCredentialMetadataBase & { ...your keys }` — the type exported from `@aooth/auth/atscript-db/model` single-sources the framework envelope keys). At most one annotated field per type (throws on ambiguity); a field without `@db.json` is dropped with a warning (warn-and-disable contract) — surface `warnings` in your boot log. No annotated field → `metadataField: undefined`, and the atscript-db credential store persists no metadata.

### `AoothArbacUserCredentials`

Re-exported from `@aooth/arbac-moost/atscript/models[.as]`. Extends `AoothUserCredentials` with `@arbac.role roles: string[]`. See [Atscript Models](/moost/).

## Subpath: `@aooth/arbac-moost/plugin`

```ts
import arbacPlugin from "@aooth/arbac-moost/plugin";
```

### `arbacPlugin()` (default export)

```ts
export default function arbacPlugin(): TAtscriptPlugin;
```

Atscript compile-time plugin registering eight prop-level `AnnotationSpec`s across two namespaces: `@arbac.role`, `@arbac.attribute`, `@arbac.userId`, `@arbac.attenuate.role`, `@arbac.attenuate.attr "userAttrName"` (credential-attenuation field markers — see `extractAttenuation`), the identity-handle pair `@aooth.user.email` / `@aooth.user.phone` (login/recovery handle discovery — each requires `@db.index.unique`, warn-and-disable otherwise; at most one field per type), plus `@aooth.auth.metadata` (the consumer's fully-typed credential-metadata column — requires `@db.json`, warn-and-disable otherwise; at most one field per type; resolved by `getAoothCredentialMetadataSpec`). Pull into `atscript.config.ts`. **No runtime DI surface**. See [Atscript Models](/moost/) and [Recovery & Handles](/moost/recovery-and-handles).
