# Upgrading

What to check when you move to a newer aooth release. Each entry lists the changes that can break an app or change what users see, and links to the page that documents the current behaviour. All `@aooth/*` packages share one version number — upgrade them together.

## To 0.2.6

### Message codes no longer collide with other libraries

Message codes share one process-wide registry with every library on the server (moost's `registerMessages`): when two catalogues register one code with different texts, the last one wins and one translation applies to both. aooth's generically named codes now carry a prefix ([One id space](/moost/messages#one-id-space-shared-with-other-libraries)). Rename them in your translator catalogue, in `AuthWorkflowOpts.messages` overrides, and wherever a client or test branches on an error body's `code`:

| Before                                                                                                                                                                                                                                                                                                                                                                                                                                                                   | Now                              |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | -------------------------------- |
| Workflow (`AOOTH_MESSAGES`): `ACCOUNT_LOCKED`, `INVALID_CODE`, `CODE_EXPIRED`, `TOO_MANY_CODE_ATTEMPTS`, `RESEND_WAIT`, `RESEND_WAIT_ANOTHER`, `RESEND_WAIT_CHANNEL`, `ADDRESS_REQUIRED`, `INVALID_EMAIL_ADDRESS`, `INVALID_PHONE_NUMBER`, `UNKNOWN_METHOD`, `METHOD_UNAVAILABLE`, `METHOD_NOT_CHANGEABLE`, `CHOOSE_OPTION`, `ACCOUNT_LINKED`, `ACCOUNT_CREATED`, `ALREADY_HAVE_ACCOUNT`, `INVALID_ROLE`, `USER_ALREADY_EXISTS` (also a 409 body code), `BACK`, `GO_NOW` | the same with an `AOOTH_` prefix |
| HTTP (`AOOTH_HTTP_MESSAGES`): `AUTH_REQUIRED`, `CREDENTIAL_INVALID`, `NOT_AUTHENTICATED`, `MISSING_UID`, `UNKNOWN_PROVIDER`, `WORKFLOW_NOT_ALLOWED`                                                                                                                                                                                                                                                                                                                      | the same with an `AOOTH_` prefix |
| ARBAC (`ARBAC_MESSAGES`): `INSUFFICIENT_PRIVILEGES`, `CONTROL_NOT_ALLOWED`, `CONTROL_VALUE_NOT_ALLOWED`, `NESTED_WRITE_NOT_ALLOWED`, `ROW_OUT_OF_SCOPE`, `REFERENCE_OUT_OF_SCOPE`, `INVALID_QUERY_STRING`                                                                                                                                                                                                                                                                | the same with an `ARBAC_` prefix |
| `UserAuthError` (`USER_AUTH_ERROR_MESSAGES`): `ALREADY_EXISTS`, `LOCKED`, `INACTIVE`, `POLICY_VIOLATION`, `CAS_EXHAUSTED`                                                                                                                                                                                                                                                                                                                                                | `AOOTH_USER_<type>`              |

- A `UserAuthError`'s `type` is unchanged — keep branching on it in code. Its message code is the new `err.code` (`USER_AUTH_ERROR_CODES` maps type → code); `USER_AUTH_ERROR_MESSAGES` is keyed by code, and `userAuthErrorToHttp()` bodies carry it as `code` ([Errors — HTTP mapping](/user/errors#http-mapping)).
- `NOT_FOUND`, `INVALID_CREDENTIALS` and `RATE_LIMITED` keep their ids: they are shared with other libraries on purpose. `NOT_FOUND`'s English text is now the neutral `"Not found"` (was `"User not found"`), also as `UserAuthError("NOT_FOUND")`'s default message.
- English texts are unchanged otherwise.

### `POST /auth/refresh` is rate limited

`AuthController.refresh` now declares two rate-limit policies, enforced when `rateLimitInterceptors` are installed: `aooth.refresh` — `150/5m` per client IP — and `aooth.refresh-token` — `10/1m` per presented refresh token, from any IP. A rejected call answers the usual coded `429` (`RATE_LIMITED`, `Retry-After`). Re-tune or switch them off with the new `rateLimitInterceptors({ policies })` option ([Rate Limiting — bundled limits](/moost/rate-limit#bundled-limits)). A client that refreshes in a loop, or behind a NAT shared by many users, may need a higher `aooth.refresh` budget.

### Magic links for recovery and sign-in

Recovery can send a single-use link instead of a code (`resolveRecoveryDeliveryMode` → `'magicLink'` or `'choice'`), and the login form's `magicLink` action now signs in by link (first factor only) instead of answering `501` — see [Workflows — Magic links](/moost/workflows#magic-links). Nothing changes until you enable one. If you do:

- Both send through the `email` outlet (`createAuthEmailOutlet`) with the new kinds `recovery.magicLink` / `login.magicLink` — an `EmailSender` that switches over `AuthEmailKind` needs a `login.magicLink` case.
- `WfTriggerProvider` registers a third outlet (`magic-link`) and a third state strategy (`magic-link`). If you replace `this.outlets` or override `stateRegistry()`, keep them (`createMagicLinkOutlet`, `MAGIC_LINK_STRATEGY`). With several instances, override `magicLinkStore()` with a shared store and pass a shared `lockoutShadowStore`.
- The unused `magicLinkSkipsMfa` and `embedRecovery` fields are gone from the alternate-credentials policy (`ctx.alternateCredentials`): a sign-in link is always the first factor only, and recovery always runs as its own flow.
- Opening a link shows `MagicLinkConfirmForm` ("Continue as a•••@example.com"); the link is used up only when that step is submitted, so a mail scanner that opens links does not spend it. Your SPA renders it like any other workflow form. Serve the landing page with `Referrer-Policy: no-referrer`.
- `resolveAlternateCredentials` may return `magicLinkSameBrowser: true` to bind sign-in links to the browser that asked for them (a cookie); off by default.

### `/auth/token` and `/auth/register` are rate limited

The authorization server's token and registration endpoints declare bundled limits, enforced when `rateLimitInterceptors` are installed: `aooth.token` (`150/5m` per IP), `aooth.token-refresh` (`10/1m` per presented `refresh_token`) and `aooth.register` (`20/1h` per IP) — see [Authorization server — Rate limits](/moost/authorization-server#rate-limits). Tune them with `rateLimitInterceptors({ policies })`.

### ARBAC: un-aliased inner aggregates of `$from`

Under a `$groupBy` whitelist, the outer level of a two-level aggregate may now group by an inner aggregate that has no `$as` — by its default name (`count(*)` → `count_star`), like an aliased one. It answered `403` before.

### ARBAC 404s carry `code: "NOT_FOUND"`

Needs `@atscript/db` / `@atscript/moost-db` `^0.1.173`, `@atscript/typescript` `^0.2.9` and `@atscript/moost-wf` `^0.1.168` (the atscript-ui client packages at `^0.1.168` too). The 404s of ARBAC-scoped tables (a write or delete outside the scope, `assertRowsInScope`) now use moost-db's `notFoundError()`, so they are byte-identical with a missing row: `{ statusCode: 404, message: "Not found", code: "NOT_FOUND", error: "Not Found" }`. An action identifier that matches no row answers the same body (it said "Row not found for action identifier"). Branch on `code`.

### Recovery no longer tells whether an account exists

Before, an unknown identifier finished the one-time-code recovery at once ("If an account exists, …"), while a known one paused on the code form — a different response and token. Now every identifier gets the code form ([No enumeration](/auth/password-reset#no-enumeration)):

- Unknown identifiers, **inactive accounts** (pending invitations, deactivated users) and, under M2, accounts without a deliverable channel run a ghost code step: nothing is sent and no code is accepted. Inactive accounts no longer receive a recovery code.
- Under M2 (`resolveRecoveryDeliverySource` → `'registered'`) the code form no longer shows the masked destination (`ctx.public.pincode.sentTo` is absent).
- Recovery stages pending consents only after the code is verified (`ctx.consents` is unset on the code form).
- The `RECOVERY_INSTRUCTIONS_SENT` message code is gone (nothing renders it any more). Drop it from your translations.
- Recovery keeps nothing about the account in its state before the code is verified: `ctx.subject` is unset for **every** run until then, so a resolver override that reads it in recovery (`resolvePostReset`, `resolveLockout`, …) sees it unset. The account is looked up from the typed identifier when a code is sent and when one is checked.

### One-time codes: server-side limits, bound and single-use

Applies to every emailed or texted code — recovery, the email/SMS second factor, signup, enrolment, the federated link proof ([One-time codes](/moost/workflows#one-time-codes)).

- The attempt limit (`mfa.pincodeMaxAttempts`) is counted on the server, in `lockoutShadowStore`, and holds against replayed older tokens. **With several instances, pass a shared `lockoutShadowStore`** (e.g. `RateLimitStoreRedis`) — the in-memory default counts per instance.
- Past the limit every submit for that code answers `AOOTH_TOO_MANY_CODE_ATTEMPTS` (it answered `AOOTH_CODE_EXPIRED` after the first). A code that verified is spent: replaying the earlier state with it answers `AOOTH_CODE_EXPIRED`.
- The state holds a keyed digest of the code instead of the code: `ctx.pin` and `ctx.pinAttempts` are gone (the code in flight is `ctx.pinNonce` + `ctx.pinDigest`). A code sent before the upgrade answers `AOOTH_CODE_EXPIRED`; the user requests a new one.
- The digests are keyed with the new `WfTriggerProvider.pincodeSecret()` — the wf-state secret by default, so nothing to configure. A workflow run outside `WfTriggerProvider` derives the same key as a default provider; with a credential store that has no derivable secret, or a provider whose `wfStateSecret()` / `pincodeSecret()` is overridden, it overrides `AuthWorkflow.pincodeKey()`.
- A recovery code works only for the account the identifier resolved to when it was sent; if the identifier resolves to another account by the time it is entered, the code reads as wrong.
- To keep recovery reads equal for every identifier, `resolvePincodeTarget` now also runs for an unknown or inactive identifier, with the placeholder subject `00000000-0000-4000-8000-000000000000`; its result, or any error it throws, is discarded there.
- A recovery code is bound to the account **and the address** it went to: with registered-channel delivery, a code sent to a channel that changed before the check answers `AOOTH_INVALID_CODE`.
- The resend wait is enforced on the server, per destination (the typed identifier for recovery and signup, the account and address otherwise) and client IP: a resend inside it answers `AOOTH_RESEND_WAIT` from any state, and a new run inside it pauses on the code form without sending. Two recovery requests for the same identifier from one IP within `mfa.pincodeResendTimeoutMs` send one code. New option `mfa.pincodeMaxSendsGlobal` (10) caps the codes per destination from all IPs per `mfa.pincodeFailureWindowMs`; past it a request sends nothing.
- New failure budgets per destination, across its codes, per `mfa.pincodeFailureWindowMs` (1 h): `mfa.pincodeMaxFailures` (10) per client IP and `mfa.pincodeMaxFailuresGlobal` (100) from all IPs. Past one, every send and check answers `429 AOOTH_CODE_LIMIT_REACHED` (new code in `AOOTH_HTTP_MESSAGES` — add it to your translations). Behind a proxy, install `rateLimitInterceptors({ trustProxy: true })` so the client IP is the forwarded one.
- New bundled limit `aooth.send-user` (`10/1h` per account) on codes sent after a first factor (second factor, enrolment, link proof), enforced with `rateLimitInterceptors`. Re-tune or switch it off with `policies`.
- Subclass overrides: `mintPin(ctx, binding, length?, ttlMs?)` takes the binding, and `verifyPin(ctx, code, binding, target)` takes the binding and the destination key and is async; a custom send calls `await claimCodeSend(target, account?)` first and sends only when it returns `true`.

### Auto-login stops before the login stamp for an inactive account

A new `auto-login-check` step runs ahead of `record-login` on the invite, recovery and signup auto-login paths. An account deactivated meanwhile is no longer stamped with `lastLogin` and no longer fires `afterLogin`: invite and recovery finish with the fresh-login redirect, signup answers `403`. `finalize-auto-login` still refuses an inactive account itself (403), for custom schemas.

The login flow does the same: a new `check-can-sign-in` step before `record-login` finishes a run whose account was deactivated or locked while it was paused (second factor, enrolment, consent) with an error — `AOOTH_ACCOUNT_LOCKED` for a lock (unless `lockoutDisclosure: 'generic'`), else `INVALID_CREDENTIALS` — without a `lastLogin` stamp, `afterLogin` or session. `issue` and `mint-authz-code` re-check it too.

### Recommended: hash the `store` strategy's handles

aooth stores the [magic-link](/moost/workflows#magic-links) handles hashed; the `store` strategy is yours. Pass `hashHandles: true` to the `HandleStateStrategy` you return from `storeStrategy()`, so a read of the wf-state table yields no resumable invite link or paused recovery run ([state strategy](/moost/workflows#workflow-state-strategy)). Runs paused before the switch keep working: their plain (UUID) handles are still found until they are used. In production, also return a durable `magicLinkStore()`: the bounded in-memory default can be flooded.

### Rate limits: declared ids, a send limit

- `rateLimitInterceptors({ policies })` accepts only declared policy ids — the bundled ones and every `@RateLimit({ id })` — and throws on an unknown one. Import your controllers before you configure the interceptors.
- The `GET /auth/invite/post-redemption` policy is now named `aooth.invite-post-redemption` (its 429's `params.policy`; before, `AuthController.invitePostRedemption`).
- A new bundled limit, `aooth.send` (`20/15m` per IP), counts every anonymous send request of the auth workflow — recovery codes, magic links, signup codes. Over it the request answers the coded `429` and the run ends. Re-tune or switch it off with `policies`.

### Workflow state

- Every strategy `WfTriggerProvider` registers now records itself in the states it stores and refuses to resume another strategy's state (`410`). Tokens issued before the upgrade keep working. If you override `stateRegistry()`, you lose this.
- Encapsulated workflow tokens are padded to 256-byte buckets, so they are longer than before.
- `CredentialStoreEncapsulated` (`@aooth/auth`) accepts only the canonical base64url spelling of a token; a token with added `=` padding, whitespace or `+/` characters no longer validates.

### `RecoveryFactorForm` removed

The `RecoveryFactorForm` model is gone from `@aooth/auth-moost/atscript`. No workflow step ever rendered it: the recovery flow verifies the OTP and goes straight to the new password. Drop any `extends RecoveryFactorForm` and imports of it.

## To 0.2.5

The moost-facing packages need `moost` / `@moostjs/*` `^0.7.3` (its translator API), `@wooksjs/*` `^0.8.1`, `@atscript/typescript` `^0.2.8`, `@atscript/moost-wf` `^0.1.167` and `@atscript/db` / `@atscript/moost-db` `^0.1.171`. The SPA that renders the bundled workflow forms needs the atscript-ui client packages (`@atscript/ui-fns`, `@atscript/vue-form`, `@atscript/vue-wf`) at `^0.1.167`: the forms' expressions call `t`, the argument those versions pass. **Clients below 0.1.165 fail to render the sign-in and other workflow forms** — upgrade the client packages together with the server. An app that compiles the forms itself (an `extends` of a bundled form, or the `.as` source) needs `@atscript/ui-fns` ≥ 0.1.166 in its atscript config; with 0.1.165 the paragraph texts (`fn.value`) are not served translated and stay English.

### Localization through the moost translator

aooth's texts now go through moost's translator. Nothing changes until you register one with `setTranslator`; then:

- The auth workflow resolves each text through `AuthWorkflowOpts.messages`, then the translator in the request's locale, then the English template. An existing `messages` override keeps winning.
- Every 4xx `HttpError` aooth raises carries a `code` and `params` (new catalogues `AOOTH_HTTP_MESSAGES` and `ARBAC_MESSAGES`), and `MoostHttp` translates error bodies by code. With a translator registered, `message` can be in the user's language — branch on `code` in clients and tests, never on `message`.
- The built-in password policies carry `PP_*` codes and `params` (`PASSWORD_POLICY_MESSAGES`); the set-password forms list their rules and failures in the request's language. `PolicyCheckResult.policies` entries and `POLICY_VIOLATION`'s `params.policies` gain `errorMessage`, `code` and `params` (all optional in the type).
- Workflow texts that were hard-coded are catalogue codes now — the password screens' headings and intros (`CHANGE_PASSWORD_*`, `SET_PASSWORD_*`), the invite confirmation (`ACCOUNT_CREATED`), pincode and address checks, the OTP disclosure and the manage-MFA results. The English wording is unchanged.
- Texts are resolved per response: the workflow state keeps codes (or your own text), never a translation, so a flow resumed in another language answers in that language. `WfTriggerProvider` strips the rendered `ctx.public` projection before a paused state is persisted; your own `beforePersist` hook still runs, after the strip. **Changed hooks:** `resolveSetPasswordCopy()` returns `SetPasswordCopy` — by default the codes (`headingCode` / `introCode`) instead of English text; `heading` / `intro` you return are shown as is and win over the codes. `resolveAccept()` no longer returns a default `confirmationMessage` (the confirmation renders `ACCOUNT_CREATED`); a `confirmationMessage` you return is shown as is. An override that read the default text from `super` now gets codes.
- The rate limiter's default 429 text is `RATE_LIMIT_MESSAGES.RATE_LIMITED` (`@aooth/auth`), now `"Too many requests. Retry after {retryAfter} s."` — plural-safe, with the 429's own `retryAfter` (seconds); it read "Too many requests. Please try again in 4 minutes 32 seconds." before. Rule messages may use `{limit}`, `{window}`, `{retryAfter}` (seconds) besides the <code v-pre>{{…}}</code> placeholders. Under a translator a rule's own English `message` is replaced by the `RATE_LIMITED` translation.
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
