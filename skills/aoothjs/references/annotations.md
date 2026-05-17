# annotations

Every annotation aoothjs writes (`@arbac.*`) or reads (`@db.*`, `@meta.*`, `@ui.form.*`,
`@expect.*`, `@wf.*` — all owned by sibling skills). One row per annotation, with target
nodeType, multiplicity, and which aoothjs package consumes it.

## Contents

- [`@arbac.*` annotations (owned)](#arbac-annotations-owned)
- [User-id resolution chain](#user-id-resolution-chain)
- [`@db.*` annotations read by aoothjs](#db-annotations-read-by-aoothjs)
- [`@meta.*` annotations read by aoothjs](#meta-annotations-read-by-aoothjs)
- [Form-only annotations](#form-only-annotations)

## `@arbac.*` annotations (owned)

Registered by `arbacPlugin()` from `@aoothjs/arbac-moost/plugin`. All three target
`nodeType: ['prop']` with `multiple: false`. Read at runtime by
`AtscriptArbacUserProvider` (from `@aoothjs/arbac-moost/atscript`) via the
`ArbacExtractSpec` it builds once per user type and caches in a module-level WeakMap.

| Annotation         | Target | Multiplicity | Argument | What aoothjs does with it                                                                                                                                                             |
| ------------------ | ------ | ------------ | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `@arbac.role`      | `prop` | exactly one  | none     | Marks the field whose value(s) become `user.roles[]` at evaluate time. Inline (`string \| string[]`) or a `@db.rel.from` nav prop (1:N role table). Multi-role on one type fail-loud. |
| `@arbac.attribute` | `prop` | 0..N         | none     | Each annotated field becomes a key in `UserAttrs`. The `$select` projection used by `AtscriptArbacUserProvider` covers id + role + every `@arbac.attribute` field.                    |
| `@arbac.userId`    | `prop` | 0..1         | none     | Pin the user-id resolution to a specific field. Highest precedence in the chain.                                                                                                      |

## User-id resolution chain

`AtscriptArbacUserProvider` resolves the user-id field in this order (first wins):

1. `@arbac.userId` — explicit pin.
2. A field of the `@db.table.preferredId.uniqueIndex` group (when set on the table). Used so the provider matches the same identifier moost-db uses for `/one/:id` routes.
3. `@meta.id` — the canonical PK marker (composite keys not supported by the provider).

Constructor throws `"AtscriptArbacUserProvider: no user-id field"` if none resolve.
Hand-rolled `ArbacUserProvider` subclasses don't read these annotations — they implement
`getUserId()` themselves (typically by reading `useAuth().getUserId()`).

## `@db.*` annotations read by aoothjs

`@aoothjs/user` and `@aoothjs/auth` read a small subset of `@db.*` from the shipped `.as`
models. See the `atscript-db` skill for the full annotation reference.

| Annotation                          | Where it appears                                                                   | Why aoothjs depends on it                                                                                                                                                                                                                                                                   |
| ----------------------------------- | ---------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `@db.patch.strategy 'merge'`        | `AoothUserCredentials` sub-objects: `password`, `account`, `mfa`, `trustedDevices` | `UserService.update.set` emits partial sub-object patches (`set: { account: { lastLogin, failedLoginAttempts: 0 } }`). Without merge strategy, those become wholesale replaces and clobber the other fields. Re-declaring sub-objects in an extending interface MUST repeat the annotation. |
| `@db.depth.limit 0`                 | `AoothAuthCredential` table                                                        | `@aoothjs/auth/atscript-db` never writes nested credentials. Locking depth at 0 makes the moost-db boundary reject nested writes with HTTP 400.                                                                                                                                             |
| `@db.index.unique 'username_idx'`   | `AoothUserCredentials.username`                                                    | `UsersStoreAtscriptDb.create` relies on the unique-index conflict to surface as `DbError.code === 'CONFLICT'`, which the structural `isConflict` check translates to `UserAuthError('ALREADY_EXISTS')`.                                                                                     |
| `@db.index.plain`                   | `AoothAuthCredential.userId`                                                       | `revokeAllForUser` issues `deleteMany({ userId })` — needs the index for any reasonable size.                                                                                                                                                                                               |
| `@db.json`                          | `AoothAuthCredential.claims`, `AoothAuthCredential.metadata`                       | `CredentialState`'s open structural fields. SQL adapters store as JSON column; mongo nests natively.                                                                                                                                                                                        |
| `@db.default.uuid`                  | (consumer-supplied — typical on `AppUser.id`)                                      | `UserService.createUser` deliberately omits `id` from the create payload so this default fires. If a consumer wants a specific id, pass it via `extras`.                                                                                                                                    |
| `@db.table.preferredId.uniqueIndex` | (consumer-supplied)                                                                | Read by `AtscriptArbacUserProvider` as the middle step in the user-id resolution chain. Also lets `moost-db` route `/one/:id` to a non-PK identifier (e.g. `email`).                                                                                                                        |
| `@db.rel.from` (with `@arbac.role`) | (consumer-supplied — only when storing roles in a side table)                      | `AtscriptArbacUserProvider` detects `shape === 'rel.from'` and pre-builds `withClause = [{ name: roleField }]` so `fetchRecord` expands the join in the same round-trip as the attrs fetch.                                                                                                 |

## `@meta.*` annotations read by aoothjs

| Annotation        | Where read                                                                       | Effect                                                                                                                                          |
| ----------------- | -------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------- |
| `@meta.id`        | `AtscriptArbacUserProvider` (user-id chain, step 3)                              | Fallback user-id field. Composite `@meta.id` keys NOT supported by the provider — pick a single-column user id.                                 |
| `@meta.label`     | Workflow forms (`LoginCredentialsForm`, etc.) read by `<AsWfForm>` on the client | Rendered as the field label. Workflows are agnostic; the client side is `@atscript/vue-wf`.                                                     |
| `@meta.required`  | Workflow forms                                                                   | Validated server-side by `@atscript/moost-validator` (via `formInputInterceptor`) and client-side by `<AsForm>`'s default validator chain.      |
| `@meta.sensitive` | Workflow forms (e.g. `SetPasswordForm.password`)                                 | Pipes through to `<AsForm>` which renders `type="password"` and never logs the field. Workflow ctx serialization MUST NOT round-trip the value. |

## Form-only annotations

The atscript workflow forms in `@aoothjs/auth-moost/atscript/models/forms.as` use a
fixed annotation alphabet. Each is owned by a sibling skill — load the relevant skill
for the full reference.

| Annotation              | Owned by skill      | Used on                                                                                                                                      |
| ----------------------- | ------------------- | -------------------------------------------------------------------------------------------------------------------------------------------- |
| `@ui.form.type`         | `atscript-ui-forms` | `password`, `textarea`, etc. — picks the renderer.                                                                                           |
| `@ui.form.autocomplete` | `atscript-ui-forms` | HTML autocomplete hint (`username`, `current-password`, `new-password`, `one-time-code`, etc.).                                              |
| `@ui.form.fn.options`   | `atscript-ui-forms` | Dynamic options (e.g. `Select2faForm.method` derives options from `ctx.availableMfaMethods`).                                                |
| `@expect.minLength`     | `atscript`          | Validator constraint — used in pincode/backup-code forms.                                                                                    |
| `@expect.maxLength`     | `atscript`          | Validator constraint.                                                                                                                        |
| `@expect.pattern`       | `atscript`          | Regex pattern — `BackupCodeForm` uses `^[A-Z0-9-]+$`.                                                                                        |
| `@wf.context.pass`      | `atscript-ui-wf`    | Carries non-form-field context values across the round-trip (`EmailIdentifierForm` uses `'defaults'`, `InviteForm` uses `'availableRoles'`). |

The full list of workflow form interfaces (`LoginCredentialsForm`, `MfaCodeForm`,
`BackupCodeForm`, `EmailIdentifierForm`, `SetPasswordForm`, `InviteForm`,
`InviteEmailForm`, `InviteSendModeForm`, `Select2faForm`, `PincodeForm`,
`AskEmailForm`, `AskPhoneForm`, `TermsAcceptForm`, `ProfileCompleteForm`,
`ConsentMarketingForm`, `TenantSelectForm`, `PersonaSelectForm`,
`ConcurrencyLimitForm`, `MagicLinkRequestForm`, `RecoveryModeSelectForm`,
`RecoveryFactorForm`) lives in `packages/auth-moost/src/atscript/models/forms.as`.
Every form is replaceable per-workflow via `opts.forms.<formName>`.
