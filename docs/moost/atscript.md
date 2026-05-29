# Atscript Models

This page covers the atscript integration — the compile-time `arbacPlugin()`, the `@arbac.*` annotations it registers, the bundled `AoothArbacUserCredentials` model, the `AtscriptArbacUserProvider` runtime that auto-derives roles + attrs from a `.as` annotated user type, and the bundled forms model from `@aooth/auth-moost`.

## The two atscript surfaces

| Surface               | Subpath                                   | Purpose                                                                                                                          |
| --------------------- | ----------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------- |
| Compile-time plugin   | `@aooth/arbac-moost/plugin`               | Registers `@arbac.role` / `@arbac.attribute` / `@arbac.userId` so `.as` files type-check.                                        |
| Runtime user provider | `@aooth/arbac-moost/atscript`             | `AtscriptArbacUserProvider` builds `getRoles` / `getAttrs` automatically from the model's annotations.                           |
| Bundled user model    | `@aooth/arbac-moost/atscript/models[.as]` | `AoothArbacUserCredentials` — extends `@aooth/user`'s base credential record and pre-applies `@arbac.role` to `roles: string[]`. |
| Bundled forms model   | `@aooth/auth-moost/atscript/models.as`    | 18 form types consumed by `AuthWorkflow`. Replaceable per-workflow via `opts.forms.*`.                                           |

::: warning Compile-time vs runtime imports
`@aooth/arbac-moost/plugin` is **compile-time only** — atscript pulls it inside `atscript.config.ts`. No runtime DI surface. `@aooth/arbac-moost` (main) is the runtime — interceptor, composable, decorators, DB controllers, `MoostArbac`, hand-rolled provider base. `@aooth/arbac-moost/atscript` is the atscript-aware runtime: `AtscriptArbacUserProvider`, `ArbacUserTable`, and the re-exported `AoothArbacUserCredentials` model class.
:::

## `arbacPlugin()` in `atscript.config.ts`

```ts
// atscript.config.ts
import { defineConfig } from "@atscript/typescript/config";
import arbacPlugin from "@aooth/arbac-moost/plugin";

export default defineConfig({
  plugins: [arbacPlugin()],
  // ... your other atscript config
});
```

The plugin is a single default function exporting a `TAtscriptPlugin` that registers three `AnnotationSpec`s under the `arbac` namespace:

| Annotation         | Target | Multiple?                                                        |
| ------------------ | ------ | ---------------------------------------------------------------- |
| `@arbac.role`      | `prop` | No — exactly one                                                 |
| `@arbac.attribute` | `prop` | No — but the _user model_ can have many `@arbac.attribute` props |
| `@arbac.userId`    | `prop` | No                                                               |

## The `@arbac.*` annotations

### `@arbac.role`

Marks the field that carries the user's roles. Two valid shapes:

```as
// inline — string or string[]
interface User {
  @arbac.role
  roles: string[]
}

// rel.from — 1:N nav prop to a roles table
interface User {
  @db.rel.from { table: 'user_roles', field: 'userId' }
  @arbac.role
  roleAssignments: UserRole[]
}
```

::: warning `@arbac.role` is single-source, fail-loud
Exactly one `@arbac.role` field per user model. The provider's `extractRoles` resolution walks one field; finding zero or more than one is a fatal `Error` at construction time, not a runtime guess. Multi-role inheritance from base interfaces is fine — only the resolved set on the final type is counted.
:::

### `@arbac.attribute`

Marks each field that should appear in the `UserAttrs` map. Zero or more:

```as
interface User {
  @arbac.role
  roles: string[]

  @arbac.attribute
  tenantId: string

  @arbac.attribute
  department?: string
}
```

At runtime, `getAttrs(userId)` returns `{ tenantId, department }` (omitting undefined fields).

### `@arbac.userId`

Marks the field carrying the canonical user id. Optional — if omitted, the resolution chain falls through.

### User-id resolution chain

| Step | Lookup                                             | Notes                                        |
| ---- | -------------------------------------------------- | -------------------------------------------- |
| 1    | Field with `@arbac.userId`                         | Explicit. Highest priority.                  |
| 2    | Field of `@db.table.preferredId.uniqueIndex` group | Pulled from `@atscript/db`'s table metadata. |
| 3    | Field with `@meta.id`                              | The atscript primary-id annotation.          |

If none resolve, `AtscriptArbacUserProvider`'s constructor throws. Fail-loud, not fail-silent.

::: tip Annotate `username` as `@arbac.userId` for the standard wiring
`useAuth().getUserId()` returns the **username string** — the value `UserService.login(username, password)` set, not the user's `@meta.id` UUID. For the provider's lookup to match, declare `@arbac.userId` on the inherited `username` field via a mutating `annotate` block (`extends` can't redeclare inherited props):

```atscript
import { AoothUserCredentials } from '@aooth/user/atscript-db/model'

annotate AoothUserCredentials {
    @arbac.userId
    username
}
```

Without this, the chain falls through to `@meta.id` and `findOne({ filter: { id: 'alice' } })` returns null because `alice` is not a UUID.
:::

## The bundled `AoothArbacUserCredentials` model

[`packages/arbac-moost/src/atscript/models/user.as`](https://github.com/moostjs/aoothjs/blob/main/packages/arbac-moost/src/atscript/models/user.as):

```as
import { AoothUserCredentials } from '@aooth/user/atscript-db/model'

/**
 * Base credential record for ARBAC-enabled atscript users.
 * Pre-applies `@arbac.role` to `roles: string[]` so subclasses inherit it.
 */
export interface AoothArbacUserCredentials extends AoothUserCredentials {
    @arbac.role
    roles: string[]
}
```

Intentionally minimal. Extend it in your app model:

```as
// my-app/models/user.as
import { AoothArbacUserCredentials } from '@aooth/arbac-moost/atscript/models'

export interface MyUser extends AoothArbacUserCredentials {
  @arbac.attribute
  tenantId: string

  @arbac.attribute
  department?: string

  // ... your domain fields
}
```

Now `roles` is already typed `string[]` and pre-annotated with `@arbac.role`; you only add the `@arbac.attribute` fields.

## `AtscriptArbacUserProvider`

```ts
import { AtscriptArbacUserProvider, type ArbacUserTable } from "@aooth/arbac-moost/atscript";
import { Injectable } from "moost";
import { MyUser } from "./models/user.as";

@Injectable()
class MyArbacUserProvider extends AtscriptArbacUserProvider<MyUser> {
  constructor() {
    super(MyUser, myUserTable);
  }
  override getUserId(): string {
    return useAuth().getUserId();
  }
}
```

### Constructor — `(userType, table)`

| Param      | Type                     | Purpose                                                                                                   |
| ---------- | ------------------------ | --------------------------------------------------------------------------------------------------------- |
| `userType` | `TAtscriptAnnotatedType` | The runtime-metadata class generated by `unplugin-atscript` or `asc -f dts`.                              |
| `table`    | `ArbacUserTable<T>`      | A minimal `{ findOne({ filter, controls? }): Promise<T \| null> }` shim. Often an `AtscriptDbTable` cast. |

### What's left abstract

Only `getUserId()`. Everything else is auto-derived:

- `getRoles(id)` — resolves through the `@arbac.role` field (inline array or `rel.from`).
- `getAttrs(id)` — collects every `@arbac.attribute` field into a `UserAttrs` map.

### `getUserId()` — the consumer's seam

Typically reads from `useAuth()`:

```ts
override getUserId(): string {
  return useAuth().getUserId();
}
```

For event kinds where the auth context isn't HTTP (e.g. a CLI script with a hard-coded admin id), override to return that id directly.

### `extractRoles` / `extractAttrs` — protected seams

If your model encodes roles in a non-standard shape (e.g. a comma-separated string field), override one of the protected `extractRoles(record)` / `extractAttrs(record)` methods:

```ts
@Injectable()
class MyArbacUserProvider extends AtscriptArbacUserProvider<MyUser> {
  constructor() {
    super(MyUser, myUserTable);
  }
  override getUserId() {
    return useAuth().getUserId();
  }

  protected override extractRoles(record: MyUser): string[] {
    return record.rolesCsv
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean);
  }
}
```

## Per-event memoization

`getRoles(id)` and `getAttrs(id)` both dispatch through a private `fetchRecord(userId)` that runs `table.findOne({ filter: { [userIdField]: userId }, controls: { $select, $with? } })`. The result is **memoized per `(EventContext, this, userId)`** via a wooks slot — so `getRoles + getAttrs` collapse to **one round-trip per request**.

::: warning Two distinct events do NOT share the cache
Cross-request caching is not provided. If a role is revoked, the next request reflects it on its next `fetchRecord` call. There is no TTL knob — caching is per-event only.
:::

## Injectable inheritance gotcha

::: warning `@Injectable()` does NOT inherit across `extends` in moost@0.6.x
Every concrete subclass of `AtscriptArbacUserProvider` MUST re-apply `@Injectable()`. Without it, Moost's DI fails to instantiate the provider with an opaque "could not instantiate" error.
:::

```ts
// CORRECT
@Injectable()
class MyProvider extends AtscriptArbacUserProvider<MyUser> {
  /* ... */
}

// WRONG — Moost won't instantiate
class MyProvider extends AtscriptArbacUserProvider<MyUser> {
  /* ... */
}
```

The same gotcha applies to workflow subclasses, where the recipe is `@Inherit() @Injectable("FOR_EVENT") @Controller()`.

## Codegen — `unplugin-atscript` or `asc -f dts`

The runtime provider reads `@atscript/typescript`'s generated metadata at construction time. **`unplugin-atscript` (or `asc -f dts`) must run before app build.**

```bash
# one-shot codegen
pnpm exec asc -f dts

# or via Vite plugin
# vite.config.ts
import unpluginAtscript from "unplugin-atscript/vite";
export default defineConfig({
  plugins: [unpluginAtscript({ /* ... */ })],
});
```

Without a built `.as.d.ts` / `.as.js` pair, importing `MyUser` from `./models/user.as` will fail at runtime with `Cannot read properties of undefined (reading 'metadata')`.

## The forms model from `@aooth/auth-moost`

`AuthWorkflow` consumes **18** `.as` form types from [`packages/auth-moost/src/atscript/models/forms.as`](https://github.com/moostjs/aoothjs/blob/main/packages/auth-moost/src/atscript/models/forms.as):

| Form                              | Used by                                                                 |
| --------------------------------- | ----------------------------------------------------------------------- |
| `WithInlineConsentForm`           | Base — carries the inline `consents` field (extended by the four below) |
| `LoginCredentialsForm`            | Login — username + password                                             |
| `Select2faForm`                   | Login / invite — MFA method picker                                      |
| `MfaCodeForm`                     | Login / invite — TOTP code entry                                        |
| `PincodeForm`                     | Login / recovery — SMS/email OTP entry                                  |
| `EmailIdentifierForm`             | Recovery — identifier (email/username)                                  |
| `SetPasswordForm` ⁺               | Login forced change / invite set / recovery reset                       |
| `EnrollPickMethodForm`            | MFA enrollment — pick method                                            |
| `EnrollAddressForm`               | MFA enrollment — email/phone address                                    |
| `EnrollConfirmForm` ⁺             | MFA enrollment — confirm (TOTP shows a QR)                              |
| `AskEmailForm` / `AskPhoneForm` ⁺ | Login — channel enrollment carrier forms                                |
| `TermsBumpForm` ⁺                 | Login — terms re-acceptance                                             |
| `ConcurrencyLimitForm`            | Login — session-limit kick prompt                                       |
| `InviteForm`                      | Invite admin form — email / name / roles                                |
| `MagicLinkRequestForm`            | Login — `magicLink` alt-action                                          |
| `RecoveryModeSelectForm`          | Recovery — magic-link vs OTP                                            |
| `RecoveryFactorForm`              | Recovery — known-factor verification                                    |

⁺ extends `WithInlineConsentForm` (renders the inline pending-consents field).

Three fields carry a `@ui.form.component '<Name>'` annotation pointing at SPA components from `@atscript/vue-aooth` — register the matching component name in `<AsWfForm :components>` (see [SPA Components](./spa-components)):

| Field                            | `@ui.form.component` | Renders                                 |
| -------------------------------- | -------------------- | --------------------------------------- |
| `WithInlineConsentForm.consents` | `AsConsentArray`     | one checkbox per pending consent        |
| `SetPasswordForm.passwordRules`  | `AsPasswordRules`    | live password-policy fulfillment dots   |
| `EnrollConfirmForm.qrCode`       | `AsQrCode`           | scannable TOTP `otpauth://` QR + secret |

Every form is replaceable per-workflow through `opts.forms.<slot>`:

```ts
import { LoginCredentialsForm as MyLoginForm } from "./my-forms.as";

new AuthWorkflow({ forms: { loginCredentials: MyLoginForm } }, users, auth, consentStore);
```

Annotations used in `forms.as`: `@meta.label` / `@meta.required` / `@meta.sensitive` / `@meta.default` / `@meta.description`, `@ui.form.type` / `@ui.form.autocomplete` / `@ui.form.component` / `@ui.form.options` / `@ui.form.order` / `@ui.form.grid.colSpan` / `@ui.form.action` / `@ui.form.submit.text` / `@ui.form.validate`, the `@ui.form.fn.*` reactive family (`value` / `hidden` / `options` / `attr` / `title` / `description`), `@expect.minLength` / `@expect.maxLength` / `@expect.pattern`, and `@wf.context.pass` / `@wf.action.withData`.

Clients consume the forms via `@atscript/vue-wf` (`<AsWfForm>` mounts the form at the paused step automatically). See [SPA Components](./spa-components).

## See also

- [Setup](./setup) — wiring the provider via `setReplaceRegistry([ArbacUserProviderToken, ...])`.
- [ARBAC Authorize](./arbac-authorize) — how the provider feeds into the interceptor.
- [Workflows](./workflows) — how the forms are consumed at each paused step.
