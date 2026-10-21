# Messages & Localization

Every text `AuthWorkflow` shows a user — form errors, banners, finish messages and button labels — is looked up by a **message code** in the exported `AOOTH_MESSAGES` catalogue (English templates). Override any of them with `AuthWorkflowOpts.messages`: a partial map for a fixed wording, or a resolver function for localization.

```ts
import { AuthWorkflow } from "@aooth/auth-moost";

// Fixed wording
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

// Localized — the resolver runs inside the request, so it can read the locale
new AuthWorkflow(
  {
    messages: (code, params) => i18n.t(`auth.${code}`, params, { locale: currentLocale() }),
  },
  users,
  auth,
  consentStore,
);
```

## How resolution works

| `messages` value                                 | Result                                                                                    |
| ------------------------------------------------ | ----------------------------------------------------------------------------------------- |
| omitted                                          | the English template from `AOOTH_MESSAGES`                                                |
| partial map `{ CODE: "template" }`               | your template for listed codes (same `{name}` placeholders), the English one for the rest |
| resolver `(code, params) => string \| undefined` | your text; return `undefined` to keep the English default for that code                   |

Placeholders are `{name}` and are filled from the message params (`RESEND_WAIT` gets `{ seconds }`); an unknown placeholder is left as-is. For full control — e.g. a per-tenant catalogue — override the protected `msg(code, params)` method on your `AuthWorkflow` subclass; every text goes through it.

The helpers are exported for your own UI: `renderAoothMessage(template, params)` fills placeholders, `resolveAoothMessage(code, params, messages?)` applies the same lookup as the workflow. Types: `AoothMessageCode`, `AoothMessageParams`, `AoothMessages`.

## The catalogue

| Group                | Codes                                                                                                                                                                                   |
| -------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Sign-in              | `INVALID_CREDENTIALS`, `ACCOUNT_LOCKED`, `INVALID_PASSWORD`, `INCORRECT_PASSWORD`, `SESSION_LIMIT_REACHED`                                                                              |
| Codes (MFA / OTP)    | `INVALID_CODE`, `RESEND_WAIT` `{seconds}`, `RESEND_WAIT_ANOTHER` `{seconds}`, `RESEND_WAIT_CHANNEL` `{seconds, channel}`, `TOTP_RESEND_NOT_APPLICABLE`                                  |
| MFA management       | `UNKNOWN_MFA_METHOD`, `UNKNOWN_METHOD`, `METHOD_UNAVAILABLE`, `METHOD_NOT_CHANGEABLE`, `KEEP_ONE_MFA_METHOD`, `CHOOSE_OPTION`, `ALL_MFA_METHODS_SET_UP`, `NO_MFA_CHANGES`               |
| Passwords            | `PASSWORDS_DO_NOT_MATCH`, `PASSWORD_CHANGE_TOO_RECENT`, `PASSWORD_CHANGED`, `PASSWORD_UPDATED_REDIRECTING`, `PASSWORD_UPDATED_STILL_LOCKED`                                             |
| Recovery / signup    | `RECOVERY_INSTRUCTIONS_SENT`, `SIGNUP_DISABLED`, `ALREADY_HAVE_ACCOUNT`, `ACCOUNT_LINKED`                                                                                               |
| Invites              | `INVALID_ROLE`, `INVITE_ALREADY_PENDING`, `USER_ALREADY_EXISTS`, `DUPLICATE_INVITE_REJECTED`, `INVITE_CANCELLED`, `INVITE_REPLACED`, `INVITE_ALREADY_ACCEPTED`, `CHOOSE_USERNAME_TAKEN` |
| Authorization server | `AUTHZ_EXPIRED`, `AUTHZ_BROWSER_MISMATCH`, `AUTHZ_FAILED`                                                                                                                               |
| Button labels        | `GO_TO_SIGN_IN`, `BACK_TO_SIGN_IN`, `REQUEST_NEW_INVITE`, `BACK`, `GO_NOW`                                                                                                              |

Read the English wording from `AOOTH_MESSAGES` itself (or the [source](https://github.com/moostjs/aoothjs/blob/main/packages/auth-moost/src/workflow/auth-messages.ts)) rather than copying it.

## Where the codes surface

- **Form errors and banners** — the resolved text is what the SPA renders; nothing changes on the client.
- **Invite `HttpError`s** — the body carries the `code` next to the resolved message: `409 USER_ALREADY_EXISTS`, `410 INVITE_CANCELLED`, `410 INVITE_REPLACED`. Branch on `code`, not on the text. See [Invites](./invites).
- **Client-side confirm-password check** — `SetPasswordForm` / `ChangePasswordForm` validate "passwords match" in the browser too. When you override `PASSWORDS_DO_NOT_MATCH`, the workflow ships your text to the form (`ctx.public.messages.PASSWORDS_DO_NOT_MATCH`) and the validator uses it; otherwise the form's built-in English applies.
- **`GET /auth/invite/post-redemption`** — that route renders the "already accepted" envelope outside the workflow. Return the same `messages` value from `AuthController.resolveInvitePostRedemption()` so it matches. The underlying helper is `buildInviteAlreadyAcceptedEnvelope({ loginUrl, alreadyAcceptedRedirectUrl, messages })`.

## DOs and DON'Ts

- **DO** pass one `messages` value to both `AuthWorkflowOpts` and `resolveInvitePostRedemption()`.
- **DO** return `undefined` from a resolver for codes you have not translated — the English default is used.
- **DON'T** match on English strings in the SPA or in tests that may run with overrides — use the `code` on `HttpError` bodies.
- **DON'T** expect field labels and form titles here — those live on the `.as` form models; replace a form via `forms.<slot>` to relabel it (see [Atscript Models](./atscript)).

## See also

- [Invites](./invites) — the invite error codes in context.
- [Workflows](./workflows) — the flows that produce these texts.
- [API reference](/api/auth-moost#messages) — `AOOTH_MESSAGES` and the helper signatures.
