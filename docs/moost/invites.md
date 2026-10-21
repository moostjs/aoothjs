# Invites

The `auth/invite/start` workflow lets a signed-in user with the `auth.invite` privilege create a pending account and hand the invitee a single-use link; the invitee opens the link, sets a password (and, optionally, picks a username or enrols MFA) and the account becomes active. This page covers the issue phase, the delivery modes, re-invites and the accept phase. The step list is in [Workflows — Invite](./workflows#invite-auth-invite-start); signatures are in the [API reference](/api/auth-moost#authworkflow).

```ts
import { AuthWorkflow, type AuthWfCtx } from "@aooth/auth-moost";
import { HttpError } from "@moostjs/event-http";
import { Controller, Inherit } from "moost";

@Inherit()
@Controller()
class AppAuth extends AuthWorkflow {
  // Server-side context of THIS invite, from the start request (see below).
  protected override async resolveInviteContext(_ctx: AuthWfCtx, start?: Record<string, unknown>) {
    const tenantId = String(start?.tenantId ?? "");
    if (!(await issuerMayInviteInto(tenantId))) throw new HttpError(403, "Not your tenant");
    return { tenantId };
  }

  // Every column your users table requires must come from here.
  protected override prepareUser(input: { app?: Record<string, unknown> }) {
    return { tenantId: input.app?.tenantId, roles: [] };
  }
}
```

```bash
# 1. start — the start input carries the app context
POST /auth/trigger  { "wfid": "auth/invite/start", "input": { "formData": { "tenantId": "t-1" } } }
# 2. submit the admin form
POST /auth/trigger  { "wfs": "<wfs>", "input": { "formData": { "email": "ann@example.com", "roles": ["member"] } } }
```

## Issue phase

The admin phase runs only for a caller whose role grants the `auth.invite` resource (action `start`). It pauses on `InviteForm` (email + roles; roles are validated against `getAvailableRoles()`), creates the pending user, then delivers the link.

| Seam                                       | Receives                                                     | Use it to                                                                                                                            |
| ------------------------------------------ | ------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------ |
| `resolveInviteContext(ctx, startFormData)` | the start request's `input.formData`, plus the session       | resolve app context once (e.g. `{ tenantId }`). Kept server-side as `ctx.admin.app`. Throw an `HttpError` to refuse the invite.      |
| `forms.invite`                             | —                                                            | a form that `extends InviteForm` with extra fields (e.g. a display name). The extra fields are kept server-side as `ctx.admin.form`. |
| `inferAdminRoles(input)`                   | `{ email, invitedBy?, app?, form? }`                         | derive roles server-side; unioned with the admin-picked roles.                                                                       |
| `duplicateInviteCheck(input)`              | `{ email, existingUser, invitedBy?, app?, form?, pending? }` | decide `'allow' \| 'reject' \| 'reuse'` — see [Re-invites](#re-invites).                                                             |
| `prepareUser(input)`                       | `{ email, roles, invitedBy?, app?, form? }`                  | return the extra columns of the new user row.                                                                                        |

An extended admin form, wired with `forms: { invite: AppInviteForm }`:

```as
import { InviteForm } from '@aooth/auth-moost/atscript/models'

@wf.context.pass 'public' // keep the role-picker context, as on InviteForm
export interface AppInviteForm extends InviteForm {
    displayName?: string
}
```

`invitedBy` is the issuer's user id. Treat `resolveInviteContext`'s input as untrusted client data — check that the issuer may act on the requested tenant before returning it.

::: warning Required columns come from `prepareUser`
aooth writes only the credential fields it owns (username, account state, the roles the admin picked). Any other column your users table requires — a tenant id, a non-null `roles` array when no role was picked — must be returned by `prepareUser`. A falsy return means "no extra columns" (the user is still created and the link still sent). An issue phase that ends without a created user is a `500`, never a silent `{ finished: true }`.
:::

## Delivery modes {#delivery-modes}

`AuthWorkflowOpts.inviteDelivery` decides how the link reaches the invitee:

| Mode                       | What happens                                                                                                                              | Needs                                                                |
| -------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------- |
| `'outlet-email'` (default) | The workflow pauses on the `email` outlet, which sends `invite.magicLink` through your `EmailSender`.                                     | `createAuthEmailOutlet(...)` appended to `WfTriggerProvider.outlets` |
| `'deliver'`                | The link goes to `deliver({ kind: 'invite-link', channel: 'email', recipient, url, expiresInMs })` — the same seam as every other notice. | `inviteLinkUrl`, a `deliver()` override                              |
| `'return-link'`            | Nothing is sent. The issuer's trigger response carries `data: { inviteLink, userId }` so the issuer can share the link by hand.           | `inviteLinkUrl`                                                      |

```ts
new AppAuth(
  {
    inviteDelivery: "return-link",
    inviteLinkUrl: (token, { userId }) =>
      `${env.FRONTEND_URL}/invite?wfs=${token}${userId ? `&uid=${userId}` : ""}`,
  },
  users,
  auth,
  consentStore,
);
```

- `inviteLinkUrl(token, { userId })` builds the URL for `'deliver'` and `'return-link'`: put the token in the `wfs` query parameter of the page that renders the invite workflow, and the `userId` in `uid` so a re-click after acceptance can be answered by [`GET /auth/invite/post-redemption`](./controllers#get-auth-invite-post-redemption). Missing `inviteLinkUrl` in those modes is a `500`.
- Both modes pause on the `invite` outlet, which `WfTriggerProvider` registers by default. A provider subclass that **appends** outlets (`this.outlets = [...this.outlets, emailOutlet]`) keeps it; one that **replaces** the array must include `createInviteOutlet()` (exported, name `INVITE_OUTLET`).
- With `'return-link'` a click proves nothing about the invitee's inbox, so accepting such a link does **not** record `account.verifiedEmail`.

## The invitee picks a username

By default the invited email is the login handle. With `inviteUsername: 'choose'` the accept phase first pauses on `InviteChooseUsernameForm` (replace it via `forms.inviteChooseUsername`), before the password step. The pick is normalised (Unicode NFKC, trimmed) and checked by the overridable `validateChosenUsername(ctx, username)` — by default at most 256 characters, no whitespace or control characters, and no `@` unless it is the invited address itself (a chosen name must not look like another user's email handle); a refusal re-pauses with `USERNAME_NOT_ALLOWED`. A taken username re-pauses with `CHOOSE_USERNAME_TAKEN` ("This username is taken"). The pick replaces the login handle; the invited email stays the correspondence address (`account.verifiedEmail`).

## Re-invites {#re-invites}

Inviting an email that is still pending is the "resend" — there is no separate resend flow. The default `duplicateInviteCheck` verdict for a pending row is `'reuse'`; an accepted account is `'reject'` (`USER_ALREADY_EXISTS`).

::: warning Since 0.2: a re-invite supersedes every earlier link
Each issued link carries a fresh marker, stored on the account as `account.inviteNonce`; a `'reuse'` rotates it. A link issued **before** the re-invite then answers **`410` with `code: "INVITE_REPLACED"`** ("This invite was replaced by a newer one") — also when it was opened before the re-invite and is still paused, and also after the newer link was accepted. It never sets a password, a username, an MFA factor or a consent record, and never activates the account: every bundled accept-phase write re-checks that the link is still the current one, and the final acceptance is a single compare-and-set (`UserService.acceptInvitation`), so two links of one account can never both complete. Before 0.2 the old link stayed valid until its own TTL. `'reuse'` still **replaces** the pending row's roles and `prepareUser` extras with the new invite's — nothing is merged.
:::

`@aooth/user` adds two optional account fields for this, `account.invitedBy` and `account.inviteNonce` — **run your schema sync after upgrading** (two nullable columns). Rows created before the upgrade have no marker; their links keep working until the next re-invite.

In a multi-tenant app, refuse taking over a pending invite that another issuer (or tenant) owns. `pending.invitedBy` is the issuer of the invite already on the row:

```ts
protected override duplicateInviteCheck(input: {
  email: string;
  existingUser: UserCredentials | null;
  invitedBy?: string;
  app?: Record<string, unknown>;
  pending?: { invitedBy?: string };
}) {
  if (!input.existingUser) return "allow";
  if (!input.pending) return "reject"; // already accepted
  return input.pending.invitedBy === input.invitedBy ? "reuse" : "reject";
}
```

Without such an override, a `'reuse'` that crosses issuers logs a one-time warning.

## Accept phase

The invitee opens the link (an anonymous resume of the same run): already-accepted / cancelled / replaced checks → optional username pick → set password → MFA enrolment when required → consents → the account is activated → finish (auto-login when `autoLoginOnInvite`, default `true`; otherwise a redirect to `loginUrl`). `account.verifiedEmail` is recorded only when the handle looks like an email address and the link was not returned to the issuer.

| Situation                              | Response                                                                               |
| -------------------------------------- | -------------------------------------------------------------------------------------- |
| account deleted (invite cancelled)     | `410`, `code: "INVITE_CANCELLED"`                                                      |
| a newer invite replaced this link      | `410`, `code: "INVITE_REPLACED"`                                                       |
| already accepted (state still present) | "already accepted" finish envelope — the run ends there (no password step, no session) |
| accepted by another run while paused   | `410`, `code: "INVITE_ALREADY_ACCEPTED"`                                               |
| reuse forced onto an accepted account  | `409`, `code: "USER_ALREADY_EXISTS"`                                                   |

Your own `extra-step` override runs in the accept phase **before** the acceptance write (`unset-pending-invitation`), so whatever it writes can still belong to a link that turns out to be superseded. Keep such writes idempotent, or move them to `afterInvitationAccepted()`, which runs only after the acceptance succeeded.

The `HttpError` bodies carry the message `code` next to the text, so an SPA can branch on it. The texts are overridable — see [Messages](./messages).

## DOs and DON'Ts

- **DO** return every required column from `prepareUser` — and handle `email === undefined` there (the same hook serves self-signup and federated sign-up).
- **DO** validate tenant / scope input in `resolveInviteContext`; it comes from the client's start request.
- **DO** run your schema sync after upgrading (`account.invitedBy`, `account.inviteNonce`).
- **DON'T** replace `WfTriggerProvider.outlets` without keeping `createInviteOutlet()` if you use `'deliver'` or `'return-link'`.
- **DON'T** build a separate "resend invite" flow — invite the same email again.

## See also

- [Workflows — Invite](./workflows#invite-auth-invite-start) — the flow in context of the other workflows.
- [REST Controllers — post-redemption](./controllers#get-auth-invite-post-redemption) — re-clicked links after the run finished.
- [Messages](./messages) — overriding the invite texts.
- [Email & SMS Senders](/auth/delivery) — the `EmailSender` behind `'outlet-email'`.
