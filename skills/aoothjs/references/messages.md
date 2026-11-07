# Messages & localization

Every user-facing aooth text has a message code. Catalogues (English templates, `{name}` placeholders):

| Catalogue                  | Package              | Covers                                                                                               |
| -------------------------- | -------------------- | ---------------------------------------------------------------------------------------------------- |
| `AOOTH_MESSAGES`           | `@aooth/auth-moost`  | `AuthWorkflow` form errors, banners, finish messages, buttons, set-password copy, the workflow's 4xx |
| `AOOTH_HTTP_MESSAGES`      | `@aooth/auth-moost`  | 4xx outside the workflow: guard, `AuthController`, `useAuth()`, workflow trigger (since 0.2.5)       |
| `RATE_LIMIT_MESSAGES`      | `@aooth/auth`        | the 429 `RATE_LIMITED {policy, limit, window, retryAfter}` (seconds); registered by auth-moost       |
| `ARBAC_MESSAGES`           | `@aooth/arbac-moost` | ARBAC 4xx: authorize interceptor, `evaluateOrThrow`, DB controller gates (since 0.2.5)               |
| `PASSWORD_POLICY_MESSAGES` | `@aooth/user`        | built-in policies: failure `PP_*`, rule text `PP_*_DESCRIPTION` (since 0.2.5)                        |
| `USER_AUTH_ERROR_MESSAGES` | `@aooth/user`        | `UserAuthError` default messages, code = the error `type`; registered by auth-moost (since 0.2.5)    |

## Quick start

```ts
import { setTranslator } from "moost"; // moost ≥ 0.7.3

// once, before listen — `en` first = default locale
setTranslator({
  en: {},
  de: {
    INVALID_CREDENTIALS: "Ungültige Anmeldedaten",
    AOOTH_NOT_AUTHENTICATED: "Nicht angemeldet",
    PP_MIN_LENGTH: "Das Passwort muss mindestens {min} Zeichen lang sein",
    Username: "Benutzername", // form label — the English text is the id
    MIN_LENGTH: "Mindestens {min} Zeichen", // .as validator message — by code
    "Code sent to {recipient}.": "Code an {recipient} gesendet.", // form expression text — by text
  },
});

// SPA root: the client sends the locale (Accept-Language) and merges served $i18n
provideAsLocale(() => locale.value); // @atscript/vue-form ≥ 0.1.166

// app-specific wording (wins over the translator)
new AuthWorkflow(
  { messages: { INVALID_CREDENTIALS: "Wrong username or password" } },
  users,
  auth,
  consents,
);
```

## Invariants

| #   | Rule                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| --- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1   | Workflow text chain (`this.msg(code, params)` / `resolveAoothMessage`): `AuthWorkflowOpts.messages` (partial map or `(code, params) => string \| undefined`; `undefined` falls through) → moost translator in the request's locale → English template. Translator only inside a request.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| 2   | Catalogues are registered with moost `registerMessages` on import (auth-moost: `AOOTH_MESSAGES`, `AOOTH_HTTP_MESSAGES`, `RATE_LIMIT_MESSAGES`, `PASSWORD_POLICY_MESSAGES`, `USER_AUTH_ERROR_MESSAGES`; arbac-moost: `ARBAC_MESSAGES`) → served translated (only entries differing from English) in the flat `$i18n` of workflow form schemas and atscript-db `/meta` (moost-db ≥ 0.1.170). Registered = public.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| 3   | `MoostHttp` (when it creates the HTTP app) negotiates `Accept-Language` against the translator's locales and translates every error body by `code` + `params`. A hand-built `WooksHttp` needs `resolveLocale` + `transformErrorBody: (b, _e, ctx) => translateErrorBody(b, ctx)`.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| 4   | Every 4xx aooth `HttpError` carries `code` (+ `params` when the text names a value). Clients / tests branch on `code`, never on `message` (localized under a translator). Not coded: 5xx, the ARBAC out-of-scope `404` (= missing row on purpose), OAuth token-endpoint `{ error }`.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| 5   | Workflow `HttpError` bodies are translated again by code → for those codes a translator entry beats `messages` in the error body. Override a code in one place.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| 6   | Full control: override `protected msg(code, params)`. In own steps use `this.msg(...)`, never hard-coded English.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| 7   | `PASSWORDS_DO_NOT_MATCH` is checked client-side too: a non-default resolution (override or translation) ships as `ctx.public.messages.PASSWORDS_DO_NOT_MATCH`.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| 8   | `GET /auth/invite/post-redemption` renders outside the workflow (in the request's locale) → return the SAME `messages` from `AuthController.resolveInvitePostRedemption()`. Helper: `buildInviteAlreadyAcceptedEnvelope({ loginUrl, alreadyAcceptedRedirectUrl, messages })`.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| 9   | Password policies: `errorMessage` by `code`, `description` by `${code}_DESCRIPTION`, filled with `params`; policy's own English (plural-correct) = fallback; templates are plural forms. No code → translated by text. Translated in `ctx.public.password.policies`, set/change-password failures, `userAuthErrorToHttp` (`POLICY_VIOLATION` message; `params.policies[]` = `{ description, passed, errorMessage, code?, params? }`). Own policies: `definePasswordPolicy({ …, code, params })` + `registerMessages(yourTemplates)`.                                                                                                                                                                                                                                                                                                                                                                     |
| 10  | Deliveries carry `locale?` (request's `useLocale()`): `AuthEmailEvent` (email outlet), `AuthDeliveryPayload` (`deliver()`). Absent outside a request / without a locale. `AuthSmsEvent.locale?` is set by the APP — aooth never builds that event: copy `payload.locale` when mapping `deliver()` payloads to own events.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| 11  | **Persisted workflow state never holds translated text**: texts render per response (`ctx.public` = projection rebuilt in the request's language before every pause; `WfTriggerProvider`'s `beforePersist` strips it before persist — store AND token strategies — then runs the app's own `beforePersist`; persisted outside the trigger, e.g. `mintWfToken`, it is a harmless render cache); state keeps codes (`ctx.password.headingCode` / `introCode`) or the app's own text. Copy hooks (`resolveSetPasswordCopy` → `{ heading?, intro?, headingCode?, introCode? }`, default = `SET_PASSWORD_*` codes; `resolveAccept().confirmationMessage`, default unset → `AOOTH_ACCOUNT_CREATED` at render) return app text shown as is. Exception: the OTP disclosure (`OTP_DISCLOSURE_*`) is kept as shown — it is the consent record. A flow opened in `de` and resumed without a header answers English. |
| 12  | Bundled forms are served in the request's language: `@meta.label` / `description`, submit text, action + static option labels by their English TEXT; `@expect.*` / `@meta.required` messages by validator CODE (`MIN_LENGTH`, `REQUIRED`), server-side and in the browser; option VALUES never change. English wording changes only by replacing the form (`forms.<slot>`).                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| 13  | Form expressions call `t(text, params)` — trailing arg: `(v, data, ctx, entry, t)` on fields, `(data, ctx, t)` on the form (`fn.title`). Whole sentences with `{name}`, never `"Code sent to " + x`. Server extracts the literals of text fns (`fn.label/description/hint/placeholder/title/options/attr/value`, `@ui.form.validate`) into the form's `$i18n` — nothing to register. `fn.value` / `fn.attr` results are shown as returned → wrap texts in `t`. Static `@ui.form.attr` values are not translated — use `@ui.form.fn.attr` with `t`. Own forms: compile with `@atscript/ui-fns` ≥ 0.1.166; client versions: [upgrading.md](./upgrading.md).                                                                                                                                                                                                                                                |

## Codes

Workflow (`AOOTH_MESSAGES`):
Sign-in: `INVALID_CREDENTIALS`, `AOOTH_ACCOUNT_LOCKED`, `INVALID_PASSWORD`, `INCORRECT_PASSWORD`, `SESSION_LIMIT_REACHED`, `PASSWORD_CHANGED_SIGN_IN_AGAIN` (410).
Codes: `AOOTH_INVALID_CODE`, `AOOTH_CODE_EXPIRED`, `AOOTH_TOO_MANY_CODE_ATTEMPTS`, `AOOTH_RESEND_WAIT {seconds}`, `AOOTH_RESEND_WAIT_ANOTHER {seconds}`, `AOOTH_RESEND_WAIT_CHANNEL {seconds, channel}`, `TOTP_RESEND_NOT_APPLICABLE`, `TOTP_NOT_CONFIGURED` (400).
Contact addresses: `AOOTH_ADDRESS_REQUIRED`, `AOOTH_INVALID_EMAIL_ADDRESS`, `AOOTH_INVALID_PHONE_NUMBER`, `OTP_DISCLOSURE_EMAIL`, `OTP_DISCLOSURE_PHONE`.
MFA management: `UNKNOWN_MFA_METHOD`, `AOOTH_UNKNOWN_METHOD`, `AOOTH_METHOD_UNAVAILABLE`, `AOOTH_METHOD_NOT_CHANGEABLE`, `KEEP_ONE_MFA_METHOD`, `LAST_MFA_METHOD_NOT_REMOVABLE`, `AOOTH_CHOOSE_OPTION`, `ALL_MFA_METHODS_SET_UP`, `NO_MFA_CHANGES`, `MFA_METHOD_{TOTP,EMAIL,SMS}` (labels), `MFA_METHOD_{ADDED,UPDATED,REMOVED} {method}`.
Passwords: `PASSWORDS_DO_NOT_MATCH`, `PASSWORD_CHANGE_TOO_RECENT`, `PASSWORD_CHANGED`, `PASSWORD_UPDATED_REDIRECTING`, `PASSWORD_UPDATED_STILL_LOCKED`.
Password screens: `CHANGE_PASSWORD_{HEADING,INTRO}`, `SET_PASSWORD_{EXPIRED,RESET,INVITE,INITIAL}_{HEADING,INTRO}`.
Recovery / signup: `AOOTH_MAGIC_LINK_INVALID` (an expired, used-up or refused magic link), `SIGNUP_DISABLED`, `AOOTH_ALREADY_HAVE_ACCOUNT`, `AOOTH_ACCOUNT_LINKED`, `UNKNOWN_SSO_PROVIDER` (400).
Invites: `AOOTH_ACCOUNT_CREATED`, `AOOTH_INVALID_ROLE`, `INVITE_ALREADY_PENDING`, `AOOTH_USER_ALREADY_EXISTS` (409), `DUPLICATE_INVITE_REJECTED`, `INVITE_CANCELLED` (410), `INVITE_REPLACED` (410), `INVITE_ALREADY_ACCEPTED` (410), `CHOOSE_USERNAME_TAKEN`, `USERNAME_NOT_ALLOWED`.
Authorization server: `AUTHZ_EXPIRED`, `AUTHZ_BROWSER_MISMATCH`, `AUTHZ_FAILED`.
Buttons: `GO_TO_SIGN_IN`, `BACK_TO_SIGN_IN`, `REQUEST_NEW_INVITE`, `AOOTH_BACK`, `AOOTH_GO_NOW`.

HTTP (`AOOTH_HTTP_MESSAGES`): `AOOTH_AUTH_REQUIRED` 401, `AOOTH_CREDENTIAL_INVALID` 401, `AOOTH_NOT_AUTHENTICATED` 401, `NO_CURRENT_SESSION` 401, `MISSING_REFRESH_TOKEN` 401, `INVALID_REFRESH_TOKEN` 401, `LOGOUT_OTHERS_REQUIRED` 400, `INVITE_NOT_FOUND` 404, `AOOTH_MISSING_UID` 400, `LINKED_IDENTITY_NOT_FOUND` 404, `LAST_SIGN_IN_METHOD` 409, `AOOTH_UNKNOWN_PROVIDER {provider}` 404, `AOOTH_WORKFLOW_NOT_ALLOWED {workflow}` 403 (a refused start), `AOOTH_WORKFLOW_RESUME_NOT_ALLOWED` 403 (a refused resume, no params), `AOOTH_CODE_LIMIT_REACHED` 429 (code budget spent). Rate limiter (`RATE_LIMIT_MESSAGES`): `RATE_LIMITED {policy, limit, window, retryAfter}` 429 — under a translator a rule's own English `message` is replaced by the code's translation.

ARBAC (`ARBAC_MESSAGES`): `ARBAC_INSUFFICIENT_PRIVILEGES {resource, action}` 403, `ARBAC_FORBIDDEN {resource, action}` 403, `ARBAC_NOT_AUTHORIZED` 401, `ARBAC_CONTROL_NOT_ALLOWED {control}` 403, `ARBAC_CONTROL_VALUE_NOT_ALLOWED {control, value}` 403, `ARBAC_NESTED_WRITE_NOT_ALLOWED {relation}` 403, `ARBAC_ROW_OUT_OF_SCOPE` 403, `ARBAC_REFERENCE_OUT_OF_SCOPE {fields}` 403, `ARBAC_INVALID_QUERY_STRING {error}` 400.

Policies (`PASSWORD_POLICY_MESSAGES`): `PP_MIN_LENGTH {min}`, `PP_UPPERCASE {count}`, `PP_LOWERCASE {count}`, `PP_NUMBER {count}`, `PP_SPECIAL_CHAR {count}`, `PP_MAX_REPEATED {max}`, each + `_DESCRIPTION`.

`UserAuthError` (`USER_AUTH_ERROR_MESSAGES`, keyed by `err.code`; `USER_AUTH_ERROR_CODES` maps type → code; branch on `err.type`, translate by `err.code`): `NOT_FOUND`, `AOOTH_USER_ALREADY_EXISTS`, `AOOTH_USER_LOCKED`, `AOOTH_USER_INACTIVE`, `INVALID_CREDENTIALS`, `AOOTH_USER_POLICY_VIOLATION`, `PASSWORDS_MISMATCH`, `PASSWORD_IN_HISTORY`, `MFA_REQUIRED`, `MFA_INVALID`, `MFA_NOT_CONFIGURED`, `AOOTH_USER_CAS_EXHAUSTED` — also the `code` of `userAuthErrorToHttp()` bodies.

**One id space** (moost's `registerMessages`: last catalogue registering a code wins its English template, and one translation applies to every library using the id). Naming rule for aooth codes: generic names carry a prefix (`AOOTH_`, `ARBAC_`, `PP_`); unprefixed codes name an aooth concept (MFA, TOTP, OTP, password, invite, sign-in, session, refresh token, SSO, authz); three are **shared on purpose** with neutral templates any library must match: `NOT_FOUND` "Not found", `INVALID_CREDENTIALS` "Invalid credentials", `RATE_LIMITED` "Too many requests. Retry after {retryAfter} s." → translate those neutrally (`NOT_FOUND: "Nicht gefunden"`, never "Benutzer nicht gefunden"). Prefix the app's own codes too. Renames: [upgrading.md](./upgrading.md) § 0.2.6.

Form expression texts (id = English text, served per form in `$i18n`): e.g. `"Code sent to {recipient}."`, `"Continue with {provider}"`, `"TOTP (Authenticator app)"`, `"{method} ({recipient})"`, `"Add {method}"` / `"Change {method}"` / `"Remove {method}"`, `"Signed in as {account}."` — the full list is the `t("…")` literals of `@aooth/auth-moost/atscript/models` (`forms.as`).

English templates: read the catalogues (sources `packages/auth-moost/src/workflow/auth-messages.ts`, `packages/auth-moost/src/http-messages.ts`, `packages/auth/src/rate-limit/rules.ts`, `packages/arbac-moost/src/messages.ts`, `packages/user/src/password/policies.ts`, `packages/user/src/errors.ts`).

## Key imports

```ts
import {
  AOOTH_MESSAGES,
  AOOTH_HTTP_MESSAGES,
  renderAoothMessage,
  resolveAoothMessage,
} from "@aooth/auth-moost";
import type {
  AoothMessageCode,
  AoothHttpMessageCode,
  AoothMessageParams,
  AoothMessages,
  AuthDeliveryPayload,
} from "@aooth/auth-moost";
import { ARBAC_MESSAGES, type ArbacMessageCode } from "@aooth/arbac-moost";
import {
  PASSWORD_POLICY_MESSAGES,
  type PasswordPolicyMessageCode,
  USER_AUTH_ERROR_MESSAGES,
} from "@aooth/user";
import { RATE_LIMIT_MESSAGES } from "@aooth/auth";
import { setTranslator, registerMessages, translateErrorBody } from "moost";
```

## References

| Domain         | File                                   | When                                          |
| -------------- | -------------------------------------- | --------------------------------------------- |
| Workflows      | [workflows.md](workflows.md)           | where the texts are produced; subclass recipe |
| Invites        | [invites.md](invites.md)               | invite error codes in context                 |
| Password       | [password.md](password.md)             | policies, `definePasswordPolicy`              |
| DB controllers | [db-controllers.md](db-controllers.md) | control gates and their codes                 |

## See also

Docs: https://aooth.moost.org/moost/messages
