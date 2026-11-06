# Upgrading

What to check when you move to a newer aooth release. Each entry lists the changes that can break an app or change what users see, and links to the page that documents the current behaviour. All `@aooth/*` packages share one version number — upgrade them together.

## To 0.2.5

The moost-facing packages need `moost` / `@moostjs/*` `^0.7.3` (its translator API), `@wooksjs/*` `^0.8.1`, `@atscript/typescript` `^0.2.7`, `@atscript/moost-wf` `^0.1.166` and `@atscript/db` / `@atscript/moost-db` `^0.1.170`. The SPA that renders the bundled workflow forms needs the atscript-ui client packages (`@atscript/ui-fns`, `@atscript/vue-form`, `@atscript/vue-wf`) at `^0.1.166`: the forms' expressions call `t`, the argument those versions pass. **Clients below 0.1.165 fail to render the sign-in and other workflow forms** — upgrade the client packages together with the server. An app that compiles the forms itself (an `extends` of a bundled form, or the `.as` source) needs `@atscript/ui-fns` ≥ 0.1.166 in its atscript config; with 0.1.165 the paragraph texts (`fn.value`) are not served translated and stay English.

### Localization through the moost translator

aooth's texts now go through moost's translator. Nothing changes until you register one with `setTranslator`; then:

- The auth workflow resolves each text through `AuthWorkflowOpts.messages`, then the translator in the request's locale, then the English template. An existing `messages` override keeps winning.
- Every 4xx `HttpError` aooth raises carries a `code` and `params` (new catalogues `AOOTH_HTTP_MESSAGES` and `ARBAC_MESSAGES`), and `MoostHttp` translates error bodies by code. With a translator registered, `message` can be in the user's language — branch on `code` in clients and tests, never on `message`.
- The built-in password policies carry `PP_*` codes and `params` (`PASSWORD_POLICY_MESSAGES`); the set-password forms list their rules and failures in the request's language. `PolicyCheckResult.policies` entries and `POLICY_VIOLATION`'s `params.policies` gain `errorMessage`, `code` and `params` (all optional in the type).
- Workflow texts that were hard-coded are catalogue codes now — the password screens' headings and intros (`CHANGE_PASSWORD_*`, `SET_PASSWORD_*`), the invite confirmation (`ACCOUNT_CREATED`), pincode and address checks, the OTP disclosure and the manage-MFA results. The English wording is unchanged.
- Texts are resolved per response: the workflow state keeps codes (or your own text), never a translation, so a flow resumed in another language answers in that language. `WfTriggerProvider` strips the rendered `ctx.public` projection before a paused state is persisted; your own `beforePersist` hook still runs, after the strip. **Changed hooks:** `resolveSetPasswordCopy()` returns `SetPasswordCopy` — by default the codes (`headingCode` / `introCode`) instead of English text; `heading` / `intro` you return are shown as is and win over the codes. `resolveAccept()` no longer returns a default `confirmationMessage` (the confirmation renders `ACCOUNT_CREATED`); a `confirmationMessage` you return is shown as is. An override that read the default text from `super` now gets codes.
- The rate limiter's default 429 text is `RATE_LIMIT_MESSAGES.RATE_LIMITED` (`@aooth/auth`), now `"Too many requests. Retry after {retryAfter} s."` — plural-safe, with the 429's own `retryAfter` (seconds); it read "Too many requests. Please try again in 4 minutes 32 seconds." before. Rule messages may use `{limit}`, `{window}`, `{retryAfter}` (seconds) besides the `{{…}}` placeholders. Under a translator a rule's own English `message` is replaced by the `RATE_LIMITED` translation.
- `AuthEmailEvent`, `AuthSmsEvent` and `AuthDeliveryPayload` carry `locale` — copy `payload.locale` across when your `deliver()` builds your own events.
- The workflow forms are served in the request's language: labels, action and option labels and validator messages are translated, and the texts the forms' expressions build go through `t(text, params)`, keyed by the English text, and are served with the form. The English wording is unchanged. To show them translated in the browser, provide the locale with atscript-ui's `provideAsLocale` — see [Forms in the user's language](/moost/messages#forms-in-the-user-s-language).
- `UserAuthError`'s default messages are exported as `USER_AUTH_ERROR_MESSAGES` (`@aooth/user`), keyed by type, and registered by `@aooth/auth-moost`.

The catalogues are registered with moost's `registerMessages` on import. See [Messages & Localization](/moost/messages).

### ARBAC and two-level aggregates

For atscript-db's two-level aggregates (`$from`) and conditional aggregates:

- A scope may gate `$from` like any boolean control: `controls: { $from: false }` answers 403 `CONTROL_NOT_ALLOWED`.
- Under a `$groupBy` whitelist the outer level of a two-level aggregate may group by the inner level's columns (its keys and aliases); before 0.2.5 an outer `$groupBy` on an inner alias answered 403. The inner keys still meet the whitelist.
- `/meta` drops `nestedAggregates` (and `from`) when `$from`, `$groupBy` or `$select` is denied, and `conditionalAggregates` / `distinctFieldLists` when `$groupBy` or `$select` is.

See [DB Controllers — control gates](/moost/db-controllers#control-gates).

## To 0.2.4

### Reads inside write handlers answer 403

On an ARBAC DB controller, a read (`this.getOne()`, `this.getOneComposite()`, `this.query()`, `this.pages()`, `this.geo()`) inside an override of `insert`, `update`, `replace`, `remove` or `removeComposite` now answers **403**. Before 0.2.4 that read ran with the write grant, so a caller could see rows and fields their read grant hides. The 403 comes after the write has committed.

If an override answers the written row, read it with `readBackUnderReadGrant`. It uses the caller's read grant on the `/one` handler and returns `undefined` when that grant does not allow the read:

```ts
await super.update(payload);
const row = await readBackUnderReadGrant(payload.id, () => this.getOne(String(payload.id), ""));
```

See [Reading inside a write handler override](/moost/db-controllers#reading-inside-a-write-handler-override).

### Additive

- **Inserted row on an ARBAC DB controller.** A controller that overrides `returnRepresentation()` to return `true` answers `POST /` with `Prefer: return=representation` with the stored row as `row`, exactly as `GET /one/:id` would answer the caller. Off by default. See [Returning the inserted row](/moost/db-controllers#returning-the-inserted-row-prefer-return-representation).

## To 0.2.3

The moost-facing packages peer on `moost` / `@moostjs/*` `^0.7.2`, `@atscript/typescript` `^0.2.4`, `@atscript/moost-wf` `^0.1.164` and `@atscript/db` / `@atscript/moost-db` `^0.1.168` ([Installation — peer dependencies](./installation#per-package-peer-dependencies)). moost 0.7.2 accumulates class-level interceptors, pipes and auth transports along `extends` under `@Inherit()`, so a subclass of an aooth controller keeps the base class's guards and error mapping.

Additive, no action needed:

- **Workflow trigger hooks.** `WfTriggerProvider.triggerHooks()` and `@WfTrigger({ around, beforePersist, renderEnvelope, restoreOnError, maxRestores })` — transactions around a step, pre-persist checks, custom rendering and retryable links. `restoreOnError` is opt-in and also works on allow-listed routes. See [Trigger hooks](/moost/workflows#trigger-hooks).
- **Coded 429.** A rate-limited request answers `code: "RATE_LIMITED"` with `params` (`limit`, `window` and `retryAfter` in seconds), so clients translate by code instead of parsing `message`. See [Rate Limiting](/moost/rate-limit).
- **`userAuthErrorToHttp()` / `userAuthErrorInterceptor`** map a `UserAuthError` to a coded 4xx `HttpError`. See [Errors — HTTP mapping](/user/errors#http-mapping).
- **`UserService.revokeInvitation(id)`** cancels a pending invite, safely against a racing acceptance; the invite link then answers `410`. See [Revoking an invite](/moost/invites#revoking-an-invite).
- **`useArbac().principal()`** returns the user id, effective roles and attributes. See [`principal()`](/moost/arbac-authorize#principal).

## To 0.2.2

Dependency update only. The moost-facing packages peer on `moost` / `@moostjs/*` `^0.7.1`, `@atscript/typescript` `^0.2.3`, `@atscript/moost-wf` `^0.1.163` and `@atscript/db` / `@atscript/moost-db` `^0.1.167` ([Installation — peer dependencies](./installation#per-package-peer-dependencies)). Use `@atscript/typescript` 0.2.3: 0.2.2 is not installable from npm. If you added an `@atscript/core>glob` override for the glob advisories, remove it — `@atscript/core` 0.2.3 depends on glob 14.

## To 0.2.1

### Ecosystem line: moost 0.7, wooks 0.8, atscript 0.2

The moost-facing packages now peer on `moost` / `@moostjs/*` `^0.7.0`, `@wooksjs/*` `^0.8.0`, `@atscript/typescript` `^0.2.1` and `@atscript/db` / `@atscript/moost-db` `^0.1.166` (full list: [Installation — peer dependencies](./installation#per-package-peer-dependencies)). Upgrade the whole stack in one step, and read the moost 0.7 and wooks 0.8 release notes for changes to your own handlers — among them, numeric cookie and cache durations are seconds, and a `PUT` / `PATCH` / `DELETE` that returns a body answers `200`.

What this changes in aooth:

- **`OAuthController.unlink`** (`DELETE /auth/oauth/:provider/:subject`) answers `200` instead of `202`. Accept any `2xx` in clients.
- **Rate-limit `trustProxy: true`** trusts exactly one proxy hop and reads the right-most `x-forwarded-for` entry (it read the left-most, which a client can forge). Behind more than one proxy, or with the app also reachable directly, leave it off and configure `trustProxy` on the wooks HTTP app instead — see [Rate Limiting](/moost/rate-limit#ratelimitinterceptors-options-—-the-interceptor-pair).
- Cookies aooth sets (session, refresh, trusted device, OAuth CSRF, authorize binding) keep their lifetimes — no action needed.

### `RedisLike` must support `SET … XX`

`CredentialStoreRedis` now rewrites existing credentials with a conditional `SET key value PX ms XX`, so a write racing a logout can't bring a revoked credential back. An `ioredis` client already fits. A hand-written adapter (for example over `node-redis`) must pass `XX` through and resolve `null` when the key is missing — see [Stores — `RedisLike`](/auth/stores#redislike-—-structural-typing). A custom `CredentialStore` must likewise never upsert in `update` / `touch` ([method semantics](/auth/stores#method-semantics)).

### Session revocation and password changes

No code changes; behaviour you may notice:

- A refresh in flight can no longer outlive a logout or session revocation on a stateful store — it fails with `INVALID_TOKEN`. A revocation that keeps finding fresh rows after 8 passes throws; retry it. Point the store at a primary, not a lagging replica. See [Sessions — revoking sessions](/auth/sessions#revoking-sessions).
- Changing the password ends the session it was changed from, as well as the others the flow revokes ([Change password](/moost/workflows#change-password-auth-change-password-flow)).
- A forced password change at sign-in (initial or expired password) revokes the user's existing sessions, and a sign-in paused across a password change made elsewhere ends with `PASSWORD_CHANGED_SIGN_IN_AGAIN` — translate that new code if you localize the [message catalogue](/moost/messages) (untranslated codes fall back to English).
- A refused refresh **cookie** clears both auth cookies ([`POST /auth/refresh`](/moost/controllers#post-auth-refresh)).

## To 0.2.0

### Changed defaults

| Change                                                                                                                                                                           | Where it is documented                                                                    |
| -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------- |
| Tokens appear in JSON bodies only under `exposeTokensInBody` (default `!enableCookie`), no longer whenever `enableBearer` is on                                                  | [Config Reference](/moost/config#authoptions)                                             |
| `@WfTrigger({ allow })` also checks resumes, and `allow: []` refuses every workflow                                                                                              | [Workflows — trigger allow lists](/moost/workflows#trigger-allow-lists-start-and-resume)  |
| `createAuthedFetch` logs out only on a 400/401/403 from refresh (`logoutOn: 'any-failure'` restores the old behaviour)                                                           | [Client](/auth/client#options)                                                            |
| Stacked `@RateLimit` decorators are independent policies (the last one used to replace the others)                                                                               | [Rate Limiting — stacking](/moost/rate-limit#stacking-decorators-—-independent-policies)  |
| `lockoutDisclosure` defaults to `'uniform'` — unknown handles lock like real accounts, so the lock message no longer tells which handles exist (`'reveal'` is the old behaviour) | [Workflows — lockout disclosure](/moost/workflows#lockout-disclosure)                     |
| A re-invite voids the earlier links of that account (`410 INVITE_REPLACED`)                                                                                                      | [Invites — re-invites](/moost/invites#re-invites)                                         |
| `CredentialStoreAtscriptDb` refuses credentials with restricting metadata when the table has no metadata column                                                                  | [Stores — metadata column](/auth/stores#metadata-column-options-and-the-fail-closed-rule) |
| An ARBAC allow rule whose scope returns `null` / `undefined` denies (it used to allow with no scope)                                                                             | [Builder API](/arbac/builder#a-scope-that-returns-null-undefined-admits-nothing)          |
| A `$with` control whitelist checks nested relations as dotted paths (`"author.org"`)                                                                                             | [DB Controllers — control gates](/moost/db-controllers#control-gates)                     |
| `/meta` no longer offers fields pinned by a write scope's `set` as inputs                                                                                                        | [DB Controllers — `allowedFields` and `set`](/moost/db-controllers#allowedfields-and-set) |
| A failing ARBAC user provider answers a generic `401`; its error message is logged, not sent                                                                                     | [ARBAC Authorize](/moost/arbac-authorize#arbacauthorizeinterceptor)                       |

### Moved export

`getAoothCredentialMetadataSpec` moved from `@aooth/arbac-moost/atscript` to `@aooth/auth/atscript-db` — update the import ([API](/api/auth#getaoothcredentialmetadataspec-authority-metadata-keys)).

### Schema

`@aooth/user` adds two optional account fields, `account.invitedBy` and `account.inviteNonce`. Run your schema sync after upgrading ([Credentials Model](/user/credentials)).

### New opt-ins

Nothing changes until you turn these on: hashed tokens at rest ([`tokens.hashAtRest`](/auth/credentials#tokens-at-rest-tokens-hashatrest)), persistent "stay signed in" cookies ([Config](/moost/config#persistent-cookies-stay-signed-in)), the message catalogue ([Messages & Localization](/moost/messages)) and the invite options ([Invites](/moost/invites)).

## See also

- [Installation](./installation) — packages and peer dependencies of the current release.
- [Ecosystem & Packages](./ecosystem) — which package owns what.
