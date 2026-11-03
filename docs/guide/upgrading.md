# Upgrading

What to check when you move to a newer aooth release. Each entry lists the changes that can break an app or change what users see, and links to the page that documents the current behaviour. All `@aooth/*` packages share one version number — upgrade them together.

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
