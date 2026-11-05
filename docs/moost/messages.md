# Messages & Localization

Every text aooth shows a user has a **message code**:

- the auth workflow's form errors, banners, finish messages, button labels and set-password copy — `AOOTH_MESSAGES` (`@aooth/auth-moost`);
- the `HttpError`s auth-moost raises outside the workflow (guard, controllers, workflow trigger) — `AOOTH_HTTP_MESSAGES` (`@aooth/auth-moost`);
- the rate limiter's 429 — `RATE_LIMIT_MESSAGES` (`@aooth/auth`), the `RATE_LIMITED` code;
- the `HttpError`s of the ARBAC layer (authorize interceptor, DB controller gates) — `ARBAC_MESSAGES` (`@aooth/arbac-moost`);
- the built-in password policies — `PASSWORD_POLICY_MESSAGES` (`@aooth/user`), the `PP_*` codes.

Each catalogue holds the English templates, with `{name}` placeholders filled from the message params. Localize them all with one moost translator, or reword workflow texts per app with `AuthWorkflowOpts.messages`.

## Localizing with the moost translator

Register a translator once at startup, before the server listens (moost ≥ 0.7.3):

```ts
import { setTranslator } from "moost";

setTranslator({
  en: {}, // the default locale: the English templates as they are
  de: {
    INVALID_CREDENTIALS: "Ungültige Anmeldedaten",
    RESEND_WAIT: "Bitte {seconds}s warten.",
    NOT_AUTHENTICATED: "Nicht angemeldet",
    PP_MIN_LENGTH: "Das Passwort muss mindestens {min} Zeichen lang sein",
  },
});
```

A function translator (i18next, FormatJS, …) works the same way — see the moost docs on `setTranslator`. Then:

- `MoostHttp` picks each request's locale from `Accept-Language` against the translator's locales; without the header the first locale is used.
- The workflow translates its texts in the request's locale ([resolution order](#how-a-workflow-text-is-resolved)).
- `MoostHttp` translates every error body by its `code`, filling `params` — the English `message` is the fallback. Untranslated codes stay English.

The catalogues are registered with moost's `registerMessages` on import — `@aooth/auth-moost` also registers `RATE_LIMIT_MESSAGES` and `PASSWORD_POLICY_MESSAGES`. Every registered template is available to moost's translation helpers, and atscript-db's `/meta` serves them, translated, in `$i18n` (atscript-db versions that serve `$i18n`).

::: tip Your own `WooksHttp`
`MoostHttp` sets up the locale and the error-body translation only when it creates the HTTP app itself (`new MoostHttp()` or `new MoostHttp(options)`). If you pass a `WooksHttp` you built, add both yourself:

```ts
import { createHttpApp, useAcceptLanguage } from "@wooksjs/event-http";
import { translateErrorBody } from "moost";

new MoostHttp(
  createHttpApp({
    resolveLocale: () => useAcceptLanguage().negotiate(["en", "de"], "en"),
    transformErrorBody: (body, _error, ctx) => translateErrorBody(body, ctx),
  }),
);
```

:::

## How a workflow text is resolved

For each code the workflow produces, in this order:

1. **`AuthWorkflowOpts.messages`** — the app's override: a partial map (`{ CODE: "template" }`, same `{name}` placeholders), or a resolver `(code, params) => string | undefined`. `undefined` (or a code the map does not list) falls through.
2. **The moost translator**, in the request's locale.
3. **The English template** from `AOOTH_MESSAGES`, params filled in.

```ts
import { AuthWorkflow } from "@aooth/auth-moost";

// Fixed wording for this app — wins over the translator
new AuthWorkflow(
  {
    messages: {
      INVALID_CREDENTIALS: "Wrong username or password",
      RESEND_WAIT: "Wait {seconds} s before asking for a new code.",
    },
  },
  users,
  auth,
  consentStore,
);
```

Texts are resolved when a response is rendered, never stored translated in the workflow state: a flow opened in one language and resumed in another answers in the language of the request at hand. The form-facing `ctx.public` projection is rebuilt in the request's language before every pause, and `WfTriggerProvider` strips it before the paused state is persisted (store-backed and token-backed alike); your own `beforePersist` hook still runs, after the strip. A flow you persist outside the trigger (e.g. `mintWfToken`) keeps `ctx.public` as a render cache — it is rebuilt on every response, so it is never shown stale. The one exception is the channel-OTP disclosure (`OTP_DISCLOSURE_*`), which is kept as shown because it is recorded with the user's consent.

Copy hooks return your own text, shown as is in every language: `resolveSetPasswordCopy()` (`heading` / `intro`, or other codes as `headingCode` / `introCode`; the default is the `SET_PASSWORD_*` codes), `resolveAccept()`'s `confirmationMessage` (default: `ACCOUNT_CREATED`) and `resolveOtpDisclosure()`. For per-language wording, override the codes through `messages` or the translator instead.

An unknown placeholder is left as-is. For full control — e.g. a per-tenant catalogue — override the protected `msg(code, params)` method on your `AuthWorkflow` subclass; every workflow text goes through it.

The helpers are exported for your own UI: `renderAoothMessage(template, params)` fills placeholders, `resolveAoothMessage(code, params, messages?)` applies the same order as the workflow (the translator only inside a request). Types: `AoothMessageCode`, `AoothMessageParams`, `AoothMessages`.

## Error bodies

Every 4xx `HttpError` aooth raises carries a `code` and, where the text names a value, `params`. Branch on `code` in clients and tests, never on `message`:

```json
{
  "statusCode": 403,
  "code": "WORKFLOW_NOT_ALLOWED",
  "params": { "workflow": "auth/x" },
  "message": "Workflow 'auth/x' is not allowed"
}
```

| Catalogue             | Code                             | Status | Params                                                 |
| --------------------- | -------------------------------- | ------ | ------------------------------------------------------ |
| `AOOTH_HTTP_MESSAGES` | `AUTH_REQUIRED`                  | 401    | — (guarded route, no credential)                       |
|                       | `CREDENTIAL_INVALID`             | 401    | — (guarded route, invalid credential)                  |
|                       | `NOT_AUTHENTICATED`              | 401    | — (`useAuth().getUserId()`, `AuthController`)          |
|                       | `NO_CURRENT_SESSION`             | 401    |                                                        |
|                       | `MISSING_REFRESH_TOKEN`          | 401    |                                                        |
|                       | `INVALID_REFRESH_TOKEN`          | 401    |                                                        |
|                       | `LOGOUT_OTHERS_REQUIRED`         | 400    |                                                        |
|                       | `INVITE_NOT_FOUND`               | 404    |                                                        |
|                       | `MISSING_UID`                    | 400    |                                                        |
|                       | `LINKED_IDENTITY_NOT_FOUND`      | 404    |                                                        |
|                       | `LAST_SIGN_IN_METHOD`            | 409    |                                                        |
|                       | `UNKNOWN_PROVIDER`               | 404    | `provider`                                             |
|                       | `WORKFLOW_NOT_ALLOWED`           | 403    | `workflow`                                             |
| `RATE_LIMIT_MESSAGES` | `RATE_LIMITED`                   | 429    | `policy`, `limit`, `window`, `retryAfter` (seconds)    |
| `AOOTH_MESSAGES`      | `USER_ALREADY_EXISTS`            | 409    |                                                        |
|                       | `INVITE_CANCELLED`               | 410    |                                                        |
|                       | `INVITE_REPLACED`                | 410    |                                                        |
|                       | `INVITE_ALREADY_ACCEPTED`        | 410    |                                                        |
|                       | `PASSWORD_CHANGED_SIGN_IN_AGAIN` | 410    |                                                        |
|                       | `UNKNOWN_SSO_PROVIDER`           | 400    |                                                        |
|                       | `TOTP_NOT_CONFIGURED`            | 400    |                                                        |
| `ARBAC_MESSAGES`      | `INSUFFICIENT_PRIVILEGES`        | 403    | `resource`, `action`                                   |
|                       | `ARBAC_FORBIDDEN`                | 403    | `resource`, `action` (`evaluateOrThrow()`)             |
|                       | `ARBAC_NOT_AUTHORIZED`           | 401    |                                                        |
|                       | `CONTROL_NOT_ALLOWED`            | 403    | `control`                                              |
|                       | `CONTROL_VALUE_NOT_ALLOWED`      | 403    | `control`, `value`                                     |
|                       | `NESTED_WRITE_NOT_ALLOWED`       | 403    | `relation`                                             |
|                       | `ROW_OUT_OF_SCOPE`               | 403    |                                                        |
|                       | `REFERENCE_OUT_OF_SCOPE`         | 403    | `fields`                                               |
|                       | `INVALID_QUERY_STRING`           | 400    | `error` (the parser's text)                            |
| `UserAuthError` types | `POLICY_VIOLATION`, …            | 4xx    | see [Errors — HTTP mapping](/user/errors#http-mapping) |

Under a translator, a rate-limit rule's own English `message` is replaced by the `RATE_LIMITED` translation — the 429 is translated by its code. Use `{limit}`, `{window}` and `{retryAfter}` (seconds) in your translations.

Not coded: server errors (`5xx`), the `404` a row outside the caller's scope answers — it is the same answer as a missing row on purpose — and the authorization server's token endpoint, which answers OAuth's `{ error, error_description }`.

The workflow's coded `HttpError`s are resolved like any workflow text, then `MoostHttp` translates the error body by its code once more: for those codes a translator entry wins over `AuthWorkflowOpts.messages` in the error body. Override such a code in one place.

## Password policies

The built-in policies (`ppHasMinLength`, `ppHasUpperCase`, …) carry a `code` and `params`. A policy's failure (`errorMessage`) is translated by its code, its rule text (`description`) by `<code>_DESCRIPTION`:

| Policy                  | Failure code      | Rule code                     | Params  |
| ----------------------- | ----------------- | ----------------------------- | ------- |
| `ppHasMinLength(min)`   | `PP_MIN_LENGTH`   | `PP_MIN_LENGTH_DESCRIPTION`   | `min`   |
| `ppHasUpperCase(n)`     | `PP_UPPERCASE`    | `PP_UPPERCASE_DESCRIPTION`    | `count` |
| `ppHasLowerCase(n)`     | `PP_LOWERCASE`    | `PP_LOWERCASE_DESCRIPTION`    | `count` |
| `ppHasNumber(n)`        | `PP_NUMBER`       | `PP_NUMBER_DESCRIPTION`       | `count` |
| `ppHasSpecialChar(n)`   | `PP_SPECIAL_CHAR` | `PP_SPECIAL_CHAR_DESCRIPTION` | `count` |
| `ppMaxRepeatedChars(m)` | `PP_MAX_REPEATED` | `PP_MAX_REPEATED_DESCRIPTION` | `max`   |

The templates in `PASSWORD_POLICY_MESSAGES` are the plural forms ("at least {count} numbers"). Without a translation a user sees the policy's own English text, which is singular for a count of 1 — a translator that handles plurals (i18next's `count`) can do the same per language.

Where they are translated, in the request's locale:

- the password rules the set-password and change-password forms list (`ctx.public.password.policies`), and their failure on submit;
- `userAuthErrorToHttp()`: a `POLICY_VIOLATION` message lists the translated failures, and each entry of `params.policies` carries `description`, `passed`, `errorMessage`, `code` and `params`, so a client can render them itself.

Give your own policies a code with `definePasswordPolicy({ rule, args, description, errorMessage, code, params })` and register their English templates with moost's `registerMessages`. A policy without a code is translated by its text. Using `@aooth/user` on a moost server without `@aooth/auth-moost`? Call `registerMessages(PASSWORD_POLICY_MESSAGES)` yourself.

## Localized emails and SMS

Deliveries carry the locale of the request that sent them, so your sender can pick a template language:

| Event                                                   | Field     |
| ------------------------------------------------------- | --------- |
| `AuthEmailEvent` (`EmailSender.send`, the email outlet) | `locale?` |
| `AuthSmsEvent` (`SmsSender.send`, built by your app)    | `locale?` |
| `AuthDeliveryPayload` (`AuthWorkflow.deliver()`)        | `locale?` |

`locale` is absent when the request has no locale (no translator and no `resolveLocale`) or the event is emitted outside a request. When you map a `deliver()` payload to your own email or SMS event, copy `payload.locale` across.

```ts
class MyAuthWorkflow extends AuthWorkflow {
  protected override async deliver(payload: AuthDeliveryPayload): Promise<void> {
    await mailer.send(templateFor(payload.kind, payload.locale ?? "en"), payload);
  }
}
```

## The workflow catalogue

| Group                | Codes                                                                                                                                                                                                                                                                                                                                                                |
| -------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Sign-in              | `INVALID_CREDENTIALS`, `ACCOUNT_LOCKED`, `INVALID_PASSWORD`, `INCORRECT_PASSWORD`, `SESSION_LIMIT_REACHED`, `PASSWORD_CHANGED_SIGN_IN_AGAIN`                                                                                                                                                                                                                         |
| Codes (MFA / OTP)    | `INVALID_CODE`, `CODE_EXPIRED`, `TOO_MANY_CODE_ATTEMPTS`, `RESEND_WAIT` `{seconds}`, `RESEND_WAIT_ANOTHER` `{seconds}`, `RESEND_WAIT_CHANNEL` `{seconds, channel}`, `TOTP_RESEND_NOT_APPLICABLE`, `TOTP_NOT_CONFIGURED`                                                                                                                                              |
| Contact addresses    | `ADDRESS_REQUIRED`, `INVALID_EMAIL_ADDRESS`, `INVALID_PHONE_NUMBER`, `OTP_DISCLOSURE_EMAIL`, `OTP_DISCLOSURE_PHONE`                                                                                                                                                                                                                                                  |
| MFA management       | `UNKNOWN_MFA_METHOD`, `UNKNOWN_METHOD`, `METHOD_UNAVAILABLE`, `METHOD_NOT_CHANGEABLE`, `KEEP_ONE_MFA_METHOD`, `LAST_MFA_METHOD_NOT_REMOVABLE`, `CHOOSE_OPTION`, `ALL_MFA_METHODS_SET_UP`, `NO_MFA_CHANGES`, `MFA_METHOD_TOTP`, `MFA_METHOD_EMAIL`, `MFA_METHOD_SMS`, `MFA_METHOD_ADDED` `{method}`, `MFA_METHOD_UPDATED` `{method}`, `MFA_METHOD_REMOVED` `{method}` |
| Passwords            | `PASSWORDS_DO_NOT_MATCH`, `PASSWORD_CHANGE_TOO_RECENT`, `PASSWORD_CHANGED`, `PASSWORD_UPDATED_REDIRECTING`, `PASSWORD_UPDATED_STILL_LOCKED`                                                                                                                                                                                                                          |
| Password screens     | `CHANGE_PASSWORD_HEADING`, `CHANGE_PASSWORD_INTRO`, `SET_PASSWORD_EXPIRED_HEADING`, `SET_PASSWORD_EXPIRED_INTRO`, `SET_PASSWORD_RESET_HEADING`, `SET_PASSWORD_RESET_INTRO`, `SET_PASSWORD_INVITE_HEADING`, `SET_PASSWORD_INVITE_INTRO`, `SET_PASSWORD_INITIAL_HEADING`, `SET_PASSWORD_INITIAL_INTRO`                                                                 |
| Recovery / signup    | `RECOVERY_INSTRUCTIONS_SENT`, `SIGNUP_DISABLED`, `ALREADY_HAVE_ACCOUNT`, `ACCOUNT_LINKED`, `UNKNOWN_SSO_PROVIDER`                                                                                                                                                                                                                                                    |
| Invites              | `ACCOUNT_CREATED`, `INVALID_ROLE`, `INVITE_ALREADY_PENDING`, `USER_ALREADY_EXISTS`, `DUPLICATE_INVITE_REJECTED`, `INVITE_CANCELLED`, `INVITE_REPLACED`, `INVITE_ALREADY_ACCEPTED`, `CHOOSE_USERNAME_TAKEN`, `USERNAME_NOT_ALLOWED`                                                                                                                                   |
| Authorization server | `AUTHZ_EXPIRED`, `AUTHZ_BROWSER_MISMATCH`, `AUTHZ_FAILED`                                                                                                                                                                                                                                                                                                            |
| Button labels        | `GO_TO_SIGN_IN`, `BACK_TO_SIGN_IN`, `REQUEST_NEW_INVITE`, `BACK`, `GO_NOW`                                                                                                                                                                                                                                                                                           |

Read the English wording from the catalogues themselves (or the [source](https://github.com/moostjs/aoothjs/blob/main/packages/auth-moost/src/workflow/auth-messages.ts)) rather than copying it.

## Where the codes surface

- **Form errors and banners** — the resolved text is what the SPA renders; nothing changes on the client.
- **`HttpError` bodies** — `code` and `params` next to the message ([Error bodies](#error-bodies)).
- **Client-side confirm-password check** — `SetPasswordForm` / `ChangePasswordForm` validate "passwords match" in the browser too. When `PASSWORDS_DO_NOT_MATCH` resolves to anything but the English default (an override or a translation), the workflow ships the text to the form (`ctx.public.messages.PASSWORDS_DO_NOT_MATCH`) and the validator uses it.
- **`GET /auth/invite/post-redemption`** — that route renders the "already accepted" envelope outside the workflow, in the request's locale. With `messages` overrides, return the same `messages` value from `AuthController.resolveInvitePostRedemption()` so it matches. The underlying helper is `buildInviteAlreadyAcceptedEnvelope({ loginUrl, alreadyAcceptedRedirectUrl, messages })`.

## DOs and DON'Ts

- **DO** localize with one moost translator; keep `messages` for app-specific wording.
- **DO** pass one `messages` value to both `AuthWorkflowOpts` and `resolveInvitePostRedemption()`.
- **DON'T** match on English strings in the SPA or in tests that may run with a translator — use the `code` on error bodies.
- **DON'T** expect field labels and form titles here — those live on the `.as` form models; replace a form via `forms.<slot>` to relabel it (see [Atscript Models](./atscript)).

## See also

- [Invites](./invites) — the invite error codes in context.
- [Workflows](./workflows) — the flows that produce these texts.
- [Password Policies](/user/policy) — defining policies.
- [API reference](/api/auth-moost#messages) — `AOOTH_MESSAGES` and the helper signatures.
