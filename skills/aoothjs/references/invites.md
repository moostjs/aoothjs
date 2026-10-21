# Invites (`auth/invite/start`)

Admin (role grants `auth.invite`, action `start`) creates a pending user + single-use link; invitee resumes the link anonymously, sets a password, account activates. Flow context: [workflows.md](workflows.md).

## Quick start

```ts
import { AuthWorkflow, type AuthWfCtx } from "@aooth/auth-moost";
import { HttpError } from "@moostjs/event-http";
import { Controller, Inherit } from "moost";

@Inherit()
@Controller()
class AppAuth extends AuthWorkflow {
  constructor(users: UserService, auth: AuthCredential, consents: ConsentStore) {
    super(
      {
        inviteDelivery: "return-link", // or 'outlet-email' (default) / 'deliver'
        inviteLinkUrl: (token, { userId }) =>
          `${FRONTEND}/invite?wfs=${token}${userId ? `&uid=${userId}` : ""}`,
      },
      users,
      auth,
      consents,
    );
  }
  // start request: { wfid: "auth/invite/start", input: { formData: { tenantId } } }
  protected override async resolveInviteContext(_ctx: AuthWfCtx, start?: Record<string, unknown>) {
    const tenantId = String(start?.tenantId ?? "");
    if (!(await issuerMayInviteInto(tenantId))) throw new HttpError(403, "Not your tenant");
    return { tenantId }; // → ctx.admin.app (server-only)
  }
  protected override prepareUser(input: { app?: Record<string, unknown> }) {
    return { tenantId: input.app?.tenantId, roles: [] }; // EVERY required column
  }
}
```

## Invariants

| #   | Rule                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| --- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1   | **Required user columns come from `prepareUser`.** aooth writes only what it owns (username, account state, admin-picked roles when non-empty). A NOT-NULL `tenantId`, a `roles: []` default, etc. must be returned there. Falsy return = "no extras" (user still created, link still sent). Same hook serves signup / federated sign-up → tolerate `email === undefined`.                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| 2   | **Issue phase ending without a created user = `500`** (`assert-invite-created` step), never a silent `{ finished: true }`. Don't override `create-user` to skip creation.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| 3   | **App context:** `resolveInviteContext(ctx, startFormData)` runs once at `init-invite-admin` with the START request's `input.formData`; return value → `ctx.admin.app` (never wire-passed). Throw `HttpError` to refuse. Input is client data — authorize it.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| 4   | **Extra admin-form fields:** set `forms.invite` to a form that `extends InviteForm` (from `@aooth/auth-moost/atscript/models`; re-apply `@wf.context.pass 'public'`); fields beyond `email` / `roles` → `ctx.admin.form`. `prepareUser`, `inferAdminRoles`, `duplicateInviteCheck` all receive `{ invitedBy?, app?, form? }`.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| 5   | **`inviteDelivery`:** `'outlet-email'` (default) → `email` outlet, template `invite.magicLink`, needs `createAuthEmailOutlet` appended to `WfTriggerProvider.outlets`. `'deliver'` → `deliver({ kind: 'invite-link', channel: 'email', recipient, url, expiresInMs })`. `'return-link'` → nothing sent; issuer's trigger response carries `data: { inviteLink, userId }`. `'deliver'` / `'return-link'` REQUIRE `inviteLinkUrl` (else 500) and the default `invite` outlet (`createInviteOutlet()`; keep it if you replace `this.outlets`).                                                                                                                                                                                                                                                                                        |
| 6   | **`account.verifiedEmail` on accept** is recorded only for an email-shaped handle AND not under `'return-link'` (a click there proves nothing about the inbox).                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| 7   | **`inviteUsername: 'choose'`** → accept pauses on `InviteChooseUsernameForm` (`forms.inviteChooseUsername`) BEFORE the password; taken → re-pause, error `CHOOSE_USERNAME_TAKEN`; the pick REPLACES the login handle; invited email stays correspondence (`verifiedEmail`). Default `'email'` = email is the handle.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| 8   | **Re-invite supersedes (since 0.2).** Each link carries a nonce (`account.inviteNonce`); `'reuse'` rotates it → older links answer `410 { code: "INVITE_REPLACED" }` — even if already open/paused, even after the newer link was accepted — and never write (password, username, MFA) or activate; final acceptance is a CAS (`UserService.acceptInvitation(id, nonce)`), so only one link of an account can complete. An already-accepted invite ends at the "already accepted" envelope (the run stops there). Bundled accept writes (password, username, MFA, consents) all re-check first; a custom `extra-step` runs BEFORE acceptance → keep it idempotent or use `afterInvitationAccepted()`. `'reuse'` REPLACES roles + extras (no merge). Rows from before the upgrade (no nonce) keep working until the next re-invite. |
| 9   | **Schema sync after upgrading** — `@aooth/user` model gained nullable `account.invitedBy` + `account.inviteNonce`.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| 10  | **Multi-tenant takeover guard:** `duplicateInviteCheck({ email, existingUser, invitedBy?, app?, form?, pending? })` — `pending.invitedBy` = issuer of the invite already on the row. Return `'reject'` when it differs from `invitedBy` (or the tenant differs). Without an override a cross-issuer `'reuse'` only logs a one-time warning.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| 11  | **Invite `HttpError` bodies carry `code`**: `409 USER_ALREADY_EXISTS`, `410 INVITE_CANCELLED`, `410 INVITE_REPLACED`. Branch on `code`, not text (texts are overridable — [messages.md](messages.md)).                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| 12  | **Re-clicked link after the run finished** → SPA falls through to `GET /auth/invite/post-redemption?uid=` ([controllers.md](controllers.md)): unknown and pending ids → same 404; rate limited `30/5m`; disable via `invitePostRedemptionEnabled() → false`.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |

## Key imports

```ts
import {
  AuthWorkflow,
  createInviteOutlet,
  INVITE_OUTLET,
  createAuthEmailOutlet,
  buildInviteAlreadyAcceptedEnvelope,
  parseInviteRoles,
} from "@aooth/auth-moost";
import type { AuthWorkflowOpts, AuthDeliveryPayload, AuthWfCtx } from "@aooth/auth-moost";
import { InviteForm, InviteChooseUsernameForm } from "@aooth/auth-moost/atscript";
```

## References

| Domain      | File                             | When                                                |
| ----------- | -------------------------------- | --------------------------------------------------- |
| Workflows   | [workflows.md](workflows.md)     | subclass recipe, other flows, `WfTriggerProvider`   |
| Controllers | [controllers.md](controllers.md) | `post-redemption` route, trigger allow lists        |
| Messages    | [messages.md](messages.md)       | invite texts / codes                                |
| User model  | [user-stores.md](user-stores.md) | `account.invitedBy` / `account.inviteNonce` columns |

## See also

Docs: https://aoothjs.dev/moost/invites · source: `packages/auth-moost/src/workflow/auth-workflow.ts`
