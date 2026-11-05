# upgrading

Load when bumping `@aooth/*`, when an app "worked before" an upgrade, or when writing code against an older aooth. All `@aooth/*` packages share one version — bump them together, with the matching ecosystem line ([ecosystem.md](./ecosystem.md) § Peer dependencies).

## 0.2.5 — localization through the moost translator; `$from` gates

Peers: `moost` / `@moostjs/*` `^0.7.3` (translator API), `@wooksjs/*` `^0.8.1`, `@atscript/typescript` `^0.2.6`. No action needed until the app calls moost `setTranslator`; then:

- Workflow texts: `messages` → translator (request locale) → English. Every 4xx `HttpError` has `code` + `params` (new `AOOTH_HTTP_MESSAGES`, `ARBAC_MESSAGES`); `MoostHttp` translates error bodies by code → `message` may be localized: branch on `code`.
- Password policies carry `PP_*` codes; `PolicyCheckResult.policies[]` / `POLICY_VIOLATION` `params.policies[]` gain `errorMessage?`, `code?`, `params?`.
- New workflow codes (English unchanged): `SET_PASSWORD_*_{HEADING,INTRO}`, `CHANGE_PASSWORD_{HEADING,INTRO}`, `ACCOUNT_CREATED`, `UNKNOWN_SSO_PROVIDER`, `TOTP_NOT_CONFIGURED`, `CODE_EXPIRED`, `TOO_MANY_CODE_ATTEMPTS`, `ADDRESS_REQUIRED`, `INVALID_EMAIL_ADDRESS`, `INVALID_PHONE_NUMBER`, `OTP_DISCLOSURE_{EMAIL,PHONE}`, `LAST_MFA_METHOD_NOT_REMOVABLE`, `MFA_METHOD_*`.
- **Hook change:** `resolveSetPasswordCopy()` default returns codes (`{ headingCode, introCode }`, type `SetPasswordCopy`), not text; returned `heading`/`intro` text wins and is shown as is. `resolveAccept()` default has no `confirmationMessage` (rendered from `ACCOUNT_CREATED`). State never holds translations: `WfTriggerProvider` strips the rendered `ctx.public` projection in `beforePersist` (an app's own `beforePersist` still runs, after the strip).
- Rate limiter: default 429 text `RATE_LIMIT_MESSAGES.RATE_LIMITED` = `"Too many requests. Retry after {retryAfter} s."` (was "Please try again in {{delta}}", humanized); rule messages accept `{limit}`/`{window}`/`{retryAfter}`; under a translator a rule's English `message` is replaced by the `RATE_LIMITED` translation.
- `AuthEmailEvent` / `AuthSmsEvent` / `AuthDeliveryPayload` gain `locale?` — copy it when mapping `deliver()` payloads.
- ARBAC: `controls.$from` boolean gate (403 `CONTROL_NOT_ALLOWED`); outer `$groupBy` on inner columns passes a `$groupBy` whitelist (was 403); `/meta` prunes `nestedAggregates` / `from` / `conditionalAggregates` / `distinctFieldLists` with the gates.

See [messages.md](./messages.md), [db-controllers.md](./db-controllers.md).

## 0.2.4 — insert read-back; reads under write handlers 403

**Breaking:** on an ARBAC DB controller, a read (`this.getOne/getOneComposite/query/pages/geo`) inside an `insert` / `update` / `replace` / `remove` / `removeComposite` override → **403** (it used to run under the WRITE grant; the 403 comes after the committed write). Migration: `await super.update(payload); return readBackUnderReadGrant(id, () => this.getOne(String(id), ""))` — the read grant on the `/one` handler; `undefined` when not allowed.

Additive: `returnRepresentation()` → `true` on an `AsArbacDbController` subclass: `POST /` + `Prefer: return=representation` answers `row` = what `GET /one/:id` answers the caller (READ grant, not the insert grant). Default off. See [db-controllers.md](./db-controllers.md) § Protected hook table.

## 0.2.3 — moost 0.7.2 line; additive features

Peers: `moost` / `@moostjs/*` `^0.7.2`, `@atscript/typescript` `^0.2.4`, `@atscript/moost-wf` `^0.1.164`, `@atscript/db` + `moost-db` `^0.1.168`. moost 0.7.2 accumulates class-level interceptors, pipes and auth transports along `extends` under `@Inherit()` — a subclass of an aooth controller keeps the base's guards and error mapping.

Additive: `WfTriggerProvider.triggerHooks()` / `@WfTrigger({ around, beforePersist, renderEnvelope, restoreOnError, maxRestores })` (see [workflows.md](./workflows.md)); coded 429 `code: "RATE_LIMITED"` with `params` `limit` / `window` / `retryAfter` (seconds) (see [rate-limit.md](./rate-limit.md)); `userAuthErrorToHttp()` / `userAuthErrorInterceptor` map `UserAuthError` → coded 4xx `HttpError`; `UserService.revokeInvitation(id)` (invite link then 410, see [invites.md](./invites.md)); `useArbac().principal()` → user id, effective roles, attrs.

## 0.2.2 — dependency update

Peers: `moost` / `@moostjs/*` `^0.7.1`, `@atscript/typescript` `^0.2.3` (0.2.2 is not installable), `@atscript/moost-wf` `^0.1.163`, `@atscript/db` + `moost-db` `^0.1.167`. No API change. Remove any `@atscript/core>glob` override (core 0.2.3 depends on glob 14).

## 0.2.1 — moost 0.7 / wooks 0.8 / atscript 0.2 line

| #   | Change                                                                                                                                                                                                                                                                                                     | Action                                                                                                                 |
| --- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------- |
| 1   | Peers: `moost` / `@moostjs/*` `^0.7.0`, `@wooksjs/*` `^0.8.0`, `@atscript/typescript` `^0.2.1`, `@atscript/db` + `moost-db` `^0.1.166`. wooks 0.8: bare-number durations (cookie `maxAge`, …) are SECONDS; a body-returning `PUT`/`PATCH`/`DELETE` answers 200.                                            | Upgrade the whole stack at once; check own handlers against the moost 0.7 / wooks 0.8 notes.                           |
| 2   | `OAuthController.unlink` (`DELETE /auth/oauth/:provider/:subject`) → 200 (was 202).                                                                                                                                                                                                                        | Clients accept any 2xx.                                                                                                |
| 3   | Rate-limit `trustProxy: true` = exactly one proxy hop, RIGHT-most `x-forwarded-for` (was left-most, forgeable). See [rate-limit.md](./rate-limit.md) #6.                                                                                                                                                   | Multi-hop / CIDR trust → configure `trustProxy` on the wooks HTTP app, leave the limiter option off.                   |
| 4   | **BREAKING for custom Redis adapters:** `RedisLike.set` must support `(k, v, 'PX', ms, 'XX')` and resolve `null` when the key is gone. See [auth-stores.md](./auth-stores.md).                                                                                                                             | ioredis fits; node-redis wrapper: `{ PX: ms, ...(xx && { XX: true }) }`. Custom stores: no upsert in `update`/`touch`. |
| 5   | Revocation beats in-flight refreshes (stateful stores); a revocation still finding rows after 8 passes THROWS. See [sessions.md](./sessions.md) #13.                                                                                                                                                       | Retry a thrown revocation; never point the credential store at a lagging replica.                                      |
| 6   | Password change ends the pre-change session; forced change at sign-in revokes all sessions; a sign-in paused across a password change ends with `PASSWORD_CHANGED_SIGN_IN_AGAIN`; a refused refresh COOKIE clears both auth cookies. See [sessions.md](./sessions.md), [controllers.md](./controllers.md). | Translate the new message code if localizing ([messages.md](./messages.md)).                                           |
| 7   | Cookies aooth sets keep their lifetimes (unit-explicit `"<n>s"` internally).                                                                                                                                                                                                                               | None.                                                                                                                  |

## 0.2.0 — security defaults

| #   | Change                                                                                                                                                       | Details                                              |
| --- | ------------------------------------------------------------------------------------------------------------------------------------------------------------ | ---------------------------------------------------- |
| 1   | Body tokens follow `exposeTokensInBody` (default `!enableCookie`), not `enableBearer`.                                                                       | [moost.md](./moost.md) #13                           |
| 2   | `@WfTrigger({ allow })` also gates RESUME; `allow: []` denies all.                                                                                           | [moost.md](./moost.md) #23                           |
| 3   | `createAuthedFetch` logs out only on 400/401/403 (`logoutOn: 'any-failure'` = old behaviour).                                                                | [client.md](./client.md) #5                          |
| 4   | Stacked `@RateLimit` = independent policies (last one used to win).                                                                                          | [rate-limit.md](./rate-limit.md) #2                  |
| 5   | `CredentialStoreAtscriptDb` without a metadata column refuses restricted credentials (`INVALID_CONFIG`).                                                     | [auth.md](./auth.md) #20                             |
| 6   | A re-invite voids earlier links (`410 INVITE_REPLACED`); new optional `account.invitedBy` / `account.inviteNonce` → run schema sync.                         | [invites.md](./invites.md) #8                        |
| 7   | `lockoutDisclosure` defaults to `'uniform'` (`'reveal'` = old behaviour).                                                                                    | [workflows.md](./workflows.md) #26                   |
| 8   | ARBAC allow rule whose scope fn returns `null`/`undefined` → DENY (was allowed with empty scope); nullish `defineTableAccess` part denies (was `TypeError`). | [builder.md](./builder.md), [scopes.md](./scopes.md) |
| 9   | `$with` control whitelists see nested relations as dotted paths (`"author.org"`); `/meta` no longer offers `set`-pinned fields as inputs.                    | [db-controllers.md](./db-controllers.md)             |
| 10  | ARBAC user-provider failure → generic 401, message logged not echoed.                                                                                        | [moost.md](./moost.md)                               |
| 11  | `getAoothCredentialMetadataSpec` moved: `@aooth/arbac-moost/atscript` → `@aooth/auth/atscript-db`.                                                           | [auth.md](./auth.md)                                 |

Opt-ins added in 0.2.0 (nothing changes until enabled): `tokens.hashAtRest` ([auth.md](./auth.md)), persistent cookies ([controllers.md](./controllers.md)), `messages` ([messages.md](./messages.md)), invite options ([invites.md](./invites.md)).

## See also

Docs: https://aooth.moost.org/guide/upgrading · [ecosystem.md](./ecosystem.md) · [invariants.md](./invariants.md)
