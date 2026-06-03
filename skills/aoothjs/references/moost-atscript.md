# atscript

`@aooth/arbac-moost/atscript` + `/plugin` — the atscript-driven path that auto-builds an `ArbacUserProvider` from a `.as`-annotated user model. Covers plugin registration, the three `@arbac.*` annotations, the user-id resolution chain, `AtscriptArbacUserProvider` seams, per-event memoization, and the bundled `AoothArbacUserCredentials` model. The bundled forms `.as` model lives in [workflows.md](workflows.md#forms-catalogue).

## Contents

- [Import boundary](#import-boundary)
- [`arbacPlugin()` registration](#arbacplugin-registration)
- [`@arbac.*` annotations](#arbac-annotations)
- [User-id resolution chain](#user-id-resolution-chain)
- [`AtscriptArbacUserProvider`](#atscriptarbacuserprovider)
- [Per-event memoization and cross-event isolation](#per-event-memoization-and-cross-event-isolation)
- [`AoothArbacUserCredentials` bundled model](#ootharbacusercredentials-bundled-model)
- [Replacing a bundled form](#replacing-a-bundled-form)
- [Codegen step](#codegen-step)

## Import boundary

Three subpath exports, three different audiences:

| Subpath                                   | Compile/runtime       | Audience                                                                                                              |
| ----------------------------------------- | --------------------- | --------------------------------------------------------------------------------------------------------------------- |
| `@aooth/arbac-moost`                      | runtime               | `arbacAuthorizeInterceptor`, `useArbac`, `MoostArbac`, `ArbacUserProvider` (hand-rolled base), `AsArbacDbController`. |
| `@aooth/arbac-moost/atscript`             | runtime               | `AtscriptArbacUserProvider`, `ArbacUserTable`, re-exported `AoothArbacUserCredentials`.                               |
| `@aooth/arbac-moost/plugin`               | **compile-time only** | atscript build-time plugin. Pull from `atscript.config.ts`. No runtime DI surface.                                    |
| `@aooth/arbac-moost/atscript/models/user` | raw `.as`             | The `.as` source of `AoothArbacUserCredentials` for `extends` in your own models.                                     |

## `arbacPlugin()` registration

Single default export. Registers three `AnnotationSpec`s under the `arbac` namespace.

```ts
// atscript.config.ts
import { defineConfig } from "@atscript/core/config";
import dbPlugin from "@atscript/db/plugin";
import arbacPlugin from "@aooth/arbac-moost/plugin";

export default defineConfig({
  plugins: [dbPlugin(), arbacPlugin()],
  // ... rest of config
});
```

Without this, the `.as` compiler treats `@arbac.role` etc. as unknown annotations and either errors or strips them.

## `@arbac.*` annotations

All three annotations target `nodeType: ['prop']`, `multiple: false`.

| Annotation         | Cardinality on type              | Value shape                                                                    | Notes                                                                                     |
| ------------------ | -------------------------------- | ------------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------- |
| `@arbac.role`      | **exactly one** prop (fail-loud) | Inline (`string` or `string[]`) OR a `@db.rel.from` nav prop (1:N role table). | Multi-role declared inline + via rel → fail at provider construction.                     |
| `@arbac.attribute` | zero or more                     | Any primitive. Each becomes a key in the `UserAttrs` map.                      | Inline only — no rel-from attribute model supported today.                                |
| `@arbac.userId`    | zero or one                      | The prop that holds the canonical user id used for ARBAC lookups.              | Optional — if absent, resolved via [user-id resolution chain](#user-id-resolution-chain). |

Example:

```atscript
import { AoothUserCredentials } from '@aooth/user/atscript-db/model'

@db.table 'users'
export interface AppUser extends AoothUserCredentials {
    // id (PK / @meta.id — the token subject), username + email — all inherited.
    // No @arbac.userId: the default chain already resolves to @meta.id = id = subject.
    @arbac.role
    roles: string[]

    @arbac.attribute
    tenantId: string

    @arbac.attribute
    department?: string
}
```

Inline-role example uses `roles: string[]`. A rel-based shape would replace `roles` with a `@db.rel.from` nav prop pointing at a `UserRole` join table; the provider resolves the `roleTargetIdField` on that target type.

## User-id resolution chain

`AtscriptArbacUserProvider` computes an `ArbacExtractSpec` once per user type (cached in a module-level `WeakMap`). The `userIdField` is resolved in this order:

1. `@arbac.userId` on a prop.
2. The single field carrying `@db.table.preferredId.uniqueIndex` group.
3. `@meta.id`.

If none of these resolves, the constructor throws. This is a hard fail — the provider cannot work without a stable user-id seam.

**Since the id-subject re-key, the auth subject (`useAuth().getUserId()`) IS the base `@meta.id`** — so the chain falls through to step 3 and matches with **no `@arbac.userId`**. Do NOT annotate `@arbac.userId username` (the old pattern when the subject was the username): it would point the lookup at `username` while the subject is the `id`, and every request 401s "user not found".

## `AtscriptArbacUserProvider`

```ts
class AtscriptArbacUserProvider<T> extends ArbacUserProvider<Record<string, unknown>> {
  constructor(userType: TAtscriptAnnotatedType, table: ArbacUserTable<T>);

  abstract getUserId(): string; // app-supplied — typically useAuth().getUserId()

  // Inherited from ArbacUserProvider — implemented by this class
  async getRoles(id: string): Promise<string[]>;
  async getAttrs(id: string): Promise<Record<string, unknown>>;

  // Protected seams — override to reshape extracted data
  protected extractRoles(record: T): string[];
  protected extractAttrs(record: T): Record<string, unknown>;
}
```

At construction:

- Computes `ArbacExtractSpec`: `userIdField`, `roleField` (`'inline'` or `'rel.from'` with resolved `roleTargetIdField`), `attrFields[]`.
- Computes a Mongo-style `$select` projection covering id + inline role + all attrs.
- Pre-builds `withClause = [{ name: roleField }]` only when `roleField.shape === 'rel.from'`.

`ArbacUserTable<T>` is a minimal structural type — just `findOne({ filter, controls })`. Apps wrap any backing store (atscript-db `AtscriptDbTable`, custom shim, or a thin proxy over `userStore`) into this shape.

### Hand-rolled vs atscript-driven

Pick one — they're mutually exclusive providers for `ArbacUserProviderToken`.

| Path            | Subclass                        | Override                                      | Use when                                                                                                 |
| --------------- | ------------------------------- | --------------------------------------------- | -------------------------------------------------------------------------------------------------------- |
| Hand-rolled     | `ArbacUserProvider<TUserAttrs>` | `getUserId()`, `getRoles(id)`, `getAttrs(id)` | No `.as` user model; roles + attrs come from arbitrary store.                                            |
| Atscript-driven | `AtscriptArbacUserProvider<T>`  | Only `getUserId()` is abstract                | `.as` user model present; want auto-extraction via `@arbac.role` / `@arbac.attribute` / `@arbac.userId`. |

## Per-event memoization and cross-event isolation

Inside `AtscriptArbacUserProvider`, `getRoles(id)` and `getAttrs(id)` both call a private `fetchRecord(userId)` that dispatches `table.findOne({ filter: { [userIdField]: userId }, controls: { $select, $with? } })`.

**Memoized per `(EventContext, this, userId)`** via a wooks slot — so `getRoles + getAttrs` for the same user inside one event collapse to **one** round-trip.

- Two distinct events do **NOT** share the cache.
- Cross-request caching is not provided. Role / attribute revocation takes effect on the **next** request.
- Provider class stays SINGLETON (`@Injectable()` re-applied — moost@0.6.x does not inherit injectable metadata across `extends`).
- Missing record → `getRoles` returns `[]`, `getAttrs` returns `{}`. **Fail-closed**, not fail-throw.

The `extractRoles` / `extractAttrs` protected seams let you override the extraction shape — e.g. transform inline `roles: 'admin' | 'editor'` (string discriminator) into `['admin']`, or post-process attributes.

## `AoothArbacUserCredentials` bundled model

`src/atscript/models/user.as`:

```atscript
import { AoothUserCredentials } from '@aooth/user/atscript-db/model'

export interface AoothArbacUserCredentials extends AoothUserCredentials {
    @arbac.role
    roles: string[]
}
```

Intentionally minimal: extends the base credential record (from `@aooth/user`) and pre-applies `@arbac.role` to a `roles: string[]` field. Apps that want this default extend it; apps with custom role shapes extend `AoothUserCredentials` directly and apply `@arbac.role` themselves.

The companion class is re-exported at `@aooth/arbac-moost/atscript/models/user` for `extends` use in your `.as` files.

## Replacing a bundled form

Every form in [workflows.md § Forms catalogue](workflows.md#forms-catalogue) is replaceable via `opts.forms.<formName>` on the workflow opts. Define a new `.as` interface, then pass it through:

```atscript
// src/forms/my-login-credentials.as
export interface MyLoginCredentialsForm {
    @ui.form.type 'text'
    @meta.label 'Account ID'
    @meta.required
    accountId: string

    @ui.form.type 'password'
    @meta.label 'Passphrase'
    @meta.sensitive
    @meta.required
    @expect.minLength 12
    password: string
}
```

```ts
import { MyLoginCredentialsForm } from "./forms/my-login-credentials.as";

@Inherit()
@Controller()
class AppAuth extends AuthWorkflow {
  constructor(users: UserService, auth: AuthCredential, consents: ConsentStore) {
    super(
      {
        forms: { loginCredentials: MyLoginCredentialsForm },
      },
      users,
      auth,
      consents,
    );
  }
}
```

The handler reads `input.accountId` / `input.password` — field names match your replacement, not the base form. Workflow logic that consumes a specific field (e.g. password equality, MFA codes) is not field-name-rewriting; replace the form only when the underlying step accepts your field shape.

## Codegen step

`@aooth/arbac-moost/atscript` depends on `@atscript/typescript` runtime metadata. The build chain must run **before** app build:

- **Vite / bundler builds**: `unplugin-atscript` runs automatically. No manual step.
- **Plain `tsc` / Node builds**: invoke `asc -f dts` (or `npx asc`) before `tsc`. Generated `*.as.d.ts` + `*.as.js` + `atscript.d.ts` must exist when TS compiles.

Generated files are produced by `asc`. Never hand-edit. Regenerate via `npx asc` or let `unplugin-atscript` do it at bundle time.
