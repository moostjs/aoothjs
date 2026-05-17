# `@aoothjs/arbac-moost` API Reference

Complete export reference for `@aoothjs/arbac-moost`. See the [Moost Integration Guide](/moost/) and [ARBAC Authorize](/moost/arbac-authorize) for narrative documentation. Subpaths: `./atscript`, `./plugin`.

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

`@atscript/moost-db` controller subclass that wires ARBAC into every CRUD seam: `transformFilter`, `transformProjection`, `validateControls`, `applyMetaOverlay`, `onWrite`, `onRemove`, `assertInScope`. Scopes auto-applied — no explicit `getScopes()` call needed in handlers. See [DB Controllers](/moost/).

### `AsArbacDbReadableController<T>`

```ts
class AsArbacDbReadableController<T> extends AsDbReadableController<T> {}
```

Read-only mirror of `AsArbacDbController` for view controllers. See [DB Controllers](/moost/).

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

**Intentionally not a `defineWook`** — wook cache would replay parent HTTP resolution into WF child events. Resource/action resolution chain: `mMeta.arbacResourceId → cMeta.arbacResourceId → cMeta.id → constructor.name` and `mMeta.arbacActionId → mMeta.atscript_db_action.name → cMeta.arbacActionId → mMeta.id → cc.getMethod()`. See [ARBAC Authorize](/moost/arbac-authorize).

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

Normalizes a control value into the list of names it references — used to feed `enforceControlsPolicy` for `$with` / `$groupBy` whitelist checks.

### `applyAllowedFieldsAndSet`

```ts
function applyAllowedFieldsAndSet(
  data: unknown,
  scopes: ArbacDbScope[],
  identifierFields?: readonly string[],
): unknown;
```

Strips fields outside the union of `allowedFields` and overlays `set` defaults. Auto-preserves keys in `identifierFields` (PK + unique-index columns). Used by `AsArbacDbController.onWrite`.

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
`@ArbacPublic` and `@ArbacScopes` are intentionally NOT exported. Use [`@Public()`](./auth-moost#public) from `@aoothjs/auth-moost` (writes both `authPublic` and `arbacPublic`), and read scopes via `useArbac().getScopes<TScope>()`.
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
   *  declare its own `with` for nested expansions. Parent-authority model:
   *  arbac-moost does NOT re-evaluate ARBAC against the joined resource. */
  with?: WithOf<T>;
}
```

The scope shape `AsArbacDbController` understands. Pass an `.as` model as `T` (e.g. `ArbacDbScope<Task>`) to get autocomplete on `projection` / `with` / `controls` / `set` / `allowedFields` against the model's own and navigation fields. `T = unknown` (the default) keeps the legacy untyped shape for back-compat. **Open to declaration merging** — augment with custom fields if you extend the controller. See [DB Controllers](/moost/).

::: warning Known gap — joined-resource projection in exclude mode
arbac-moost does not apply the joined-resource projection mask to `$with` expansions when the request uses exclude-mode `$select` for the relation loader. Include-mode `$select` works end-to-end. Track via the e2e-demo's `PROJ_COMMENT_VIEWER_EXPANDED` notes.
:::

## Subpath: `@aoothjs/arbac-moost/atscript`

```ts
import {
  AtscriptArbacUserProvider,
  ArbacUserTable,
  AoothArbacUserCredentials,
} from "@aoothjs/arbac-moost/atscript";
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

Structural interface — the subset of `AtscriptDbTable` `AtscriptArbacUserProvider` calls. See [Atscript Models](/moost/).

### `AoothArbacUserCredentials`

Re-exported from `@aoothjs/arbac-moost/atscript/models[.as]`. Extends `AoothUserCredentials` with `@arbac.role roles: string[]`. See [Atscript Models](/moost/).

## Subpath: `@aoothjs/arbac-moost/plugin`

```ts
import arbacPlugin from "@aoothjs/arbac-moost/plugin";
```

### `arbacPlugin()` (default export)

```ts
export default function arbacPlugin(): TAtscriptPlugin;
```

Atscript compile-time plugin registering three `AnnotationSpec`s under the `arbac` namespace: `role`, `attribute`, `userId` — all `nodeType: ['prop']`, `multiple: false`. Pull into `atscript.config.ts`. **No runtime DI surface**. See [Atscript Models](/moost/).
