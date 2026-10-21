# Messages (AuthWorkflow texts)

Every form error, banner, finish message and button label `AuthWorkflow` produces is resolved by code: `this.msg(code, params)` → `AuthWorkflowOpts.messages` → `AOOTH_MESSAGES` (English, `{name}` placeholders). Since 0.2.

## Quick start

```ts
// fixed wording
new AuthWorkflow(
  { messages: { INVALID_CREDENTIALS: "Wrong username or password" } },
  users,
  auth,
  consents,
);

// localized — resolver runs inside the request (read the locale there)
new AuthWorkflow(
  { messages: (code, params) => i18n.t(`auth.${code}`, params, { locale: currentLocale() }) },
  users,
  auth,
  consents,
);
```

## Invariants

| #   | Rule                                                                                                                                                                                                                                                |
| --- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1   | `messages` = partial map `{ CODE: template }` (same `{name}` placeholders) OR resolver `(code, params) => string \| undefined`; `undefined` → English default. Unknown placeholders are left as-is.                                                 |
| 2   | Full control: override `protected msg(code, params)` on the subclass. In your own steps use `this.msg(...)`, never hard-coded English.                                                                                                              |
| 3   | Invite `HttpError` bodies carry `code`: `409 USER_ALREADY_EXISTS`, `410 INVITE_CANCELLED`, `410 INVITE_REPLACED`. Clients / tests branch on `code`, not text.                                                                                       |
| 4   | `PASSWORDS_DO_NOT_MATCH` is also checked client-side (`SetPasswordForm` / `ChangePasswordForm`): an override is shipped to the form as `ctx.public.messages.PASSWORDS_DO_NOT_MATCH`; without one the form's built-in English applies.               |
| 5   | `GET /auth/invite/post-redemption` renders outside the workflow → return the SAME `messages` from `AuthController.resolveInvitePostRedemption()`. Helper: `buildInviteAlreadyAcceptedEnvelope({ loginUrl, alreadyAcceptedRedirectUrl, messages })`. |
| 6   | Not covered: field labels / form titles (they live on the `.as` forms — replace via `forms.<slot>`), and server-error texts of terminal `HttpError(500)`s.                                                                                          |

## Codes

Sign-in: `INVALID_CREDENTIALS`, `ACCOUNT_LOCKED`, `INVALID_PASSWORD`, `INCORRECT_PASSWORD`, `SESSION_LIMIT_REACHED`.
Codes: `INVALID_CODE`, `RESEND_WAIT {seconds}`, `RESEND_WAIT_ANOTHER {seconds}`, `RESEND_WAIT_CHANNEL {seconds, channel}`, `TOTP_RESEND_NOT_APPLICABLE`.
MFA management: `UNKNOWN_MFA_METHOD`, `UNKNOWN_METHOD`, `METHOD_UNAVAILABLE`, `METHOD_NOT_CHANGEABLE`, `KEEP_ONE_MFA_METHOD`, `CHOOSE_OPTION`, `ALL_MFA_METHODS_SET_UP`, `NO_MFA_CHANGES`.
Passwords: `PASSWORDS_DO_NOT_MATCH`, `PASSWORD_CHANGE_TOO_RECENT`, `PASSWORD_CHANGED`, `PASSWORD_UPDATED_REDIRECTING`, `PASSWORD_UPDATED_STILL_LOCKED`.
Recovery / signup: `RECOVERY_INSTRUCTIONS_SENT`, `SIGNUP_DISABLED`, `ALREADY_HAVE_ACCOUNT`, `ACCOUNT_LINKED`.
Invites: `INVALID_ROLE`, `INVITE_ALREADY_PENDING`, `USER_ALREADY_EXISTS`, `DUPLICATE_INVITE_REJECTED`, `INVITE_CANCELLED`, `INVITE_REPLACED`, `INVITE_ALREADY_ACCEPTED`, `CHOOSE_USERNAME_TAKEN`.
Authorization server: `AUTHZ_EXPIRED`, `AUTHZ_BROWSER_MISMATCH`, `AUTHZ_FAILED`.
Buttons: `GO_TO_SIGN_IN`, `BACK_TO_SIGN_IN`, `REQUEST_NEW_INVITE`, `BACK`, `GO_NOW`.

English templates: read `AOOTH_MESSAGES` (source `packages/auth-moost/src/workflow/auth-messages.ts`).

## Key imports

```ts
import { AOOTH_MESSAGES, renderAoothMessage, resolveAoothMessage } from "@aooth/auth-moost";
import type { AoothMessageCode, AoothMessageParams, AoothMessages } from "@aooth/auth-moost";
```

## References

| Domain    | File                         | When                                          |
| --------- | ---------------------------- | --------------------------------------------- |
| Workflows | [workflows.md](workflows.md) | where the texts are produced; subclass recipe |
| Invites   | [invites.md](invites.md)     | invite error codes in context                 |

## See also

Docs: https://aoothjs.dev/moost/messages
