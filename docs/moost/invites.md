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

| Seam                                       | Receives                                                              | Use it to                                                                                                                            |
| ------------------------------------------ | --------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------ |
| `resolveInviteContext(ctx, startFormData)` | the start request's `input.formData`, plus the session                | resolve app context once (e.g. `{ tenantId }`). Kept server-side as `ctx.admin.app`. Throw an `HttpError` to refuse the invite.      |
| `forms.invite`                             | —                                                                     | a form that `extends InviteForm` with extra fields (e.g. a display name). The extra fields are kept server-side as `ctx.admin.form`. |
| `inferAdminRoles(input)`                   | `{ email, invitedBy?, app?, form? }`                                  | derive roles server-side; unioned with the admin-picked roles.                                                                       |
| `duplicateInviteCheck(input)`              | `{ email, existingUser, invitedBy?, app?, form?, pending?, resend? }` | decide `'allow' \| 'reject' \| 'reuse' \| 'resend'` — see [Re-invites](#re-invites).                                                 |
| `prepareUser(input)`                       | `{ email, roles, invitedBy?, app?, form? }`                           | return the extra columns of the new user row.                                                                                        |

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

Inviting an email that is still pending is a **re-invite**: the default `duplicateInviteCheck` verdict for a pending row is `'reuse'`; an accepted account is `'reject'` (`AOOTH_USER_ALREADY_EXISTS`). A re-invite sends a fresh link and updates the pending account:

- **Roles** — the re-invite's roles (picked, plus any `inferAdminRoles` adds) replace the old ones. A re-invite with no roles keeps the old ones, unless its `prepareUser` result has a `roles` key (an extra like any other, below).
- **Extras** — the re-invite's `prepareUser` result is written over the account: the keys it returns take their new values, keys it no longer returns keep their old values.
- **Issuer** — `account.invitedBy` becomes the re-inviting user.
- **A used link starts over** (since 0.2.24) — when the invitee already set a password through an earlier link but did not finish (say, they stopped at MFA enrolment), the account goes back to "never used" in the same write: a fresh random initial password, no MFA methods (and no default method), no trusted devices, and no `account.verifiedEmail` (the earlier holder may have proven an inbox of their own). A channel confirmed through an earlier link never became a login handle — that promotion waits for the acceptance. The earlier run answers `410 INVITE_REPLACED`. **Not reset**: the username (a pick under `inviteUsername: 'choose'` stays), consent records already stored, your own columns (say `backupCodes`) and whatever your `extra-step` wrote — reset those yourself if the earlier link may have set them.

The update is one compare-and-set write that applies only while the invite is still pending (`UserService.refreshInvitation`): a re-invite that meets an account accepted in the meantime — even one accepted while the re-invite runs — answers `409` (`AOOTH_USER_ALREADY_EXISTS`), sends nothing and leaves the account exactly as accepted.

### Resending an invite as it is {#resending-an-invite}

To send a fresh link without restating the invite — a "Resend invite" action in an admin UI — submit the admin form with the `resend` action and the pending invitee's email. `InviteForm` declares it as a data-carrying action (`@wf.action.withData`, never rendered), so a form that `extends InviteForm` has it too, and `<AsWfForm>`'s `action("resend", { email })` sends exactly this:

```bash
# 1. start the invite flow as the issuer
POST /auth/trigger  { "wfid": "auth/invite/start" }
# 2. submit the pending invitee's email with the resend action
POST /auth/trigger  { "wfs": "<wfs>", "input": { "action": "resend", "formData": { "email": "ann@example.com" } } }
```

The default `duplicateInviteCheck` answers this submit with `'resend'` (since 0.2.19): the account keeps its roles, extras and `invitedBy`, and a fresh link goes out through the configured `inviteDelivery`; roles submitted with it are ignored. Like a re-invite, a resend starts a used link over (since 0.2.24): an admin who resends an invite whose password was already set restarts the acceptance — the invitee sets a password (and enrols MFA) again through the new link. An invite accepted meanwhile answers `409` (`AOOTH_USER_ALREADY_EXISTS`); one revoked meanwhile — or never issued — answers `410` (`INVITE_CANCELLED`) and creates and sends nothing. Your start request carries the same app context (`input.formData`) as for an invite.

What to know before you offer it:

- **Your hooks don't run.** A resend calls neither `prepareUser` nor `inferAdminRoles`. An authorization check you do there (tenant, scope) must also be done in `duplicateInviteCheck`, which sees `resend: true`.
- **Any issuer can resend any pending invite.** By default whoever holds the invite permission can resend — and so replace the link of — any pending invite, whoever issued it. A multi-tenant app scopes that in `duplicateInviteCheck` (below).
- **No per-address cooldown.** A resend is limited only by the trigger route's [`aooth.trigger`](./rate-limit#bundled-limits) limit; each one sends a message.

**Kept roles must be grantable.** On a resend, and on a re-invite that picks no roles, the roles already on the pending invite are kept — so they are checked like picked roles: every one must be among the issuer's available roles, otherwise the form re-pauses with `AOOTH_INVALID_ROLE` on `roles` and nothing is sent. The check applies when the role picker is on with a whitelist: `resolveAdminForm` returns `collectRoles: true` (the default) and `getAvailableRoles()` returns a list (`invitableRoles` set, or your override). It does not apply with `collectRoles: false` (roles come from your server hooks then) or without a whitelist (`getAvailableRoles()` returns `undefined`, the open default that logs a warning).

::: warning Since 0.2: a re-invite supersedes every earlier link
Each issued link carries a fresh marker, stored on the account as `account.inviteNonce`; a `'reuse'` or a `'resend'` rotates it. A link issued **before** then answers **`410` with `code: "INVITE_REPLACED"`** ("This invite was replaced by a newer one") — also when it was opened before the re-invite and is still paused, and also after the newer link was accepted. It never sets a password, a username, an MFA factor or a consent record, and never activates the account: every bundled accept-phase write re-checks that the link is still the current one, and the final acceptance is a single compare-and-set (`UserService.acceptInvitation`), so two links of one account can never both complete. Before 0.2 the old link stayed valid until its own TTL.
:::

`@aooth/user` adds two optional account fields for this, `account.invitedBy` and `account.inviteNonce` — **run your schema sync after upgrading** (two nullable columns). Rows created before the upgrade have no marker; their links keep working until the next re-invite (on SQL stores since 0.2.7 — 0.2.0–0.2.6 answered them `410 INVITE_REPLACED`).

In a multi-tenant app, refuse taking over (or resending) a pending invite that another issuer (or tenant) owns. `pending.invitedBy` is the issuer of the invite already on the row; `resend` is `true` for a submit with the `resend` action:

```ts
protected override duplicateInviteCheck(input: {
  email: string;
  existingUser: UserCredentials | null;
  invitedBy?: string;
  app?: Record<string, unknown>;
  pending?: { invitedBy?: string };
  resend?: boolean;
}) {
  const own = input.pending !== undefined && input.pending.invitedBy === input.invitedBy;
  if (input.resend) return own ? "resend" : "reject";
  if (!input.existingUser) return "allow";
  if (!input.pending) return "reject"; // already accepted
  return own ? "reuse" : "reject";
}
```

Without such an override, a `'reuse'` that crosses issuers logs a one-time warning.

## Revoking an invite {#revoking-an-invite}

`UserService.revokeInvitation(userId)` cancels a pending invite: it deletes the still-pending invited account, so the link answers **`410` with `code: "INVITE_CANCELLED"`**. It returns `false` and deletes nothing when the invite was already accepted, or when the account changed while the revoke ran (a re-invite, an acceptance); it throws `UserAuthError("NOT_FOUND")` for an unknown id. The row is claimed in one compare-and-set write, and the delete only goes through while the row's `version` is still the one that write produced — so a racing accept or re-invite either fails or makes the revoke delete nothing. Both bundled stores support this conditional delete; a [custom store](/user/stores) must honour `delete(id, { expectedVersion })` for the same guarantee (one that ignores it leaves a window of one round-trip). The paused workflow state of the link stays in the store until its TTL; opening the link consumes it.

There is no bundled revoke route — mount one on your admin controller, behind the same ARBAC resource as the invite issue phase and your own tenant checks:

```ts
import { ArbacAction, ArbacResource } from "@aooth/arbac-moost";
import { userAuthErrorInterceptor } from "@aooth/auth-moost";
import { UserService } from "@aooth/user";
import { Body, HttpError, Post } from "@moostjs/event-http";
import { Controller, Intercept } from "moost";

@Controller("admin/invites")
@Intercept(userAuthErrorInterceptor) // unknown id → 404 NOT_FOUND
export class InviteAdminController {
  constructor(private readonly users: UserService) {}

  @Post("revoke")
  @ArbacResource("auth.invite")
  @ArbacAction("revoke")
  async revoke(@Body() body: { userId: string }): Promise<{ ok: true }> {
    // Multi-tenant: check the row's `account.invitedBy` / tenant before revoking.
    if (!(await this.users.revokeInvitation(body.userId))) {
      throw new HttpError(409, {
        message: "Invite already accepted",
        code: "INVITE_ALREADY_ACCEPTED",
      });
    }
    return { ok: true };
  }
}
```

## Showing what a link is for — `peekInvite` {#peek-invite}

To show "Ann invited you as an editor" on the invite page before the invitee does anything, read the link's token with `peekInvite(token, { trigger, users })` (since 0.2.7). It never consumes the link and returns a safe projection:

| Field       | Meaning                                                            |
| ----------- | ------------------------------------------------------------------ |
| `email`     | The invited address.                                               |
| `invitedBy` | User id of the issuer — when the invite was issued from a session. |
| `roles`     | Roles the invite grants — when it grants any.                      |
| `expiresAt` | When the link stops working (ms since epoch) — when known.         |

`expiresAt` is when the link stops working. Until the invitee sets a password, the bundled invite link expires exactly 7 days after it is issued: the invite pause carries its own lifetime, so the state is persisted with an explicit `ttl`, and a per-call `ttl` replaces the state strategy's default TTL (`wfStateEncapsulatedTtlMs()`, a `defaultTtl` of your `HandleStateStrategy`). Opening the link does not change it (since 0.2.21): every pause before the password is set — the username pick, the password form and their retries — expires at that same moment, whatever the default TTL (shorter, longer or none), so `expiresAt` stays the same across opens. Once the password is set the link stops working ([below](#after-the-password)), and `peekInvite` reads it as `null` — as it does the token of the run past its password, which is no invite link. `expiresAt` is absent when nothing bounds the state, and when the state strategy cannot report its expiry: the built-in strategies do (through `expiresAtFor`), a custom `WfStateStrategy` must implement `expiresAtFor(options?, now?)` — the epoch ms a persist with those options expires, `0` for never — for `expiresAt` to be present.

It returns `null` — one answer for all — for an unknown, expired or malformed token, a token that is not an invite link, a link already used to set the password, and an invite that was replaced by a re-invite, accepted or revoked. The token is resolved exactly as opening the link resolves it, including hashed handles (`hashHandles`), so pass the `wfs` value from the link as it is.

There is no bundled route — mount one, and rate-limit it like invite redemption:

```ts
import { peekInvite, Public, RateLimit, WfTriggerProvider } from "@aooth/auth-moost";
import { UserService } from "@aooth/user";
import { Get, HttpError, Query } from "@moostjs/event-http";
import { Controller } from "moost";

@Controller("invite")
export class InviteInfoController {
  constructor(
    private readonly trigger: WfTriggerProvider,
    private readonly users: UserService,
  ) {}

  @Get("info")
  @Public()
  @RateLimit("30/5m", { id: "app.invite-info" })
  async info(@Query("wfs") wfs: string | undefined) {
    const invite = wfs ? await peekInvite(wfs, { trigger: this.trigger, users: this.users }) : null;
    if (!invite) throw new HttpError(404, "Invite not found");
    return invite; // resolve `invitedBy` to a display name here, if you show one
  }
}
```

For other workflows, `WfTriggerProvider.peek(token)` returns the paused state behind any resume token (or `null`) without consuming it. The state holds server-only context — project what you need; never return it as it is.

## Refusing a link before it is used — `beforeResume` {#before-resume}

To let a public route resume the invitee's link without being able to start invites, list `auth/invite/start` under `resumeOnly` on that trigger (see [Workflows — trigger allow lists](./workflows#trigger-allow-lists-start-and-resume)). The issuing route keeps the flow in `allow`, not `startOnly`: the issuer submits `InviteForm` there, which is a resume.

`peekInvite` is for showing what a link is for. To refuse opening a link for a reason of your own — the address already joined the tenant another way, the tenant was closed — use the [`beforeResume` trigger hook](./workflows#trigger-hooks) (since 0.2.18) on the route that accepts the links. It runs after the access lists and before the link is consumed; throw an `HttpError` and the client gets exactly that error, while the link stays usable. The state's context holds the invited address (`email`) and what `resolveInviteContext` returned (`admin.app`):

```ts
import {
  AuthController,
  type AuthWfCtx,
  DEFAULT_AUTH_WORKFLOWS,
  Public,
  WfTrigger,
} from "@aooth/auth-moost";
import { HttpError, Post } from "@moostjs/event-http";
import { normalizeWfId } from "@moostjs/event-wf";
import { Controller, Inherit } from "moost";

@Inherit()
@Controller("auth")
class AppAuthController extends AuthController {
  @Post("trigger")
  @Public()
  @WfTrigger({
    allow: [...DEFAULT_AUTH_WORKFLOWS], // invites are still issued here
    beforeResume: async (state) => {
      if (normalizeWfId(state.schemaId) !== "auth/invite/start") return;
      const ctx = state.context as AuthWfCtx;
      // `email` is set only once the issuer's InviteForm is accepted, so the
      // issuer's own submits pass; every later resume is the invitee's link.
      if (!ctx.email) return;
      const tenantId = ctx.admin?.app?.tenantId as string | undefined;
      if (tenantId && (await tenants.hasMember(tenantId, ctx.email))) {
        throw new HttpError(409, { message: "Already a member", code: "APP_ALREADY_MEMBER" });
      }
    },
  })
  override triggerWf(): void {}
}
```

The hook runs on every resume the route admits — sign-in forms and the issuer's form included — so check the flow first. It runs when the link is opened and again on every later submit of the accept phase (each one is a resume). It judges the link as read before it is consumed: a concurrent request in between goes unseen, so a check that must still hold when the account is activated belongs in the flow's steps as well.

## Accept phase

The invitee opens the link (an anonymous resume of the same run): already-accepted / cancelled / replaced checks → optional username pick → set password → MFA enrolment when required → consents → the account is activated → finish (auto-login when `autoLoginOnInvite`, default `true`; otherwise a redirect to `loginUrl`). `account.verifiedEmail` is recorded only when the handle looks like an email address and the link was not returned to the issuer.

| Situation                                                                                                | Response                                                                                                                                                                                                      |
| -------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| account deleted (invite cancelled)                                                                       | `410`, `code: "INVITE_CANCELLED"`                                                                                                                                                                             |
| a newer invite replaced this link                                                                        | `410`, `code: "INVITE_REPLACED"`                                                                                                                                                                              |
| the link was already used to set the password (since 0.2.24)                                             | `410`, `code: "INVITE_LINK_USED"` — see [below](#after-the-password)                                                                                                                                          |
| already accepted — an invite accepted before 0.2.24 (or issued before 0.2), its link state still present | "already accepted" finish envelope — the run ends there (no password step, no session). A link of an invite accepted since 0.2.24 answers `INVITE_LINK_USED` (encapsulated) or `WF_EXPIRED` (durable) instead |
| accepted by another run while paused                                                                     | `410`, `code: "INVITE_ALREADY_ACCEPTED"`                                                                                                                                                                      |
| reuse forced onto an accepted account                                                                    | `409`, `code: "AOOTH_USER_ALREADY_EXISTS"`                                                                                                                                                                    |

### Once the password is set {#after-the-password}

Until the invitee sets a password, the link works for whoever holds it, as issued: opening it again, a refused password, a missing required consent or a refused username re-pause on the same link and keep its 7 days. The password submit then claims the invite for its run (since 0.2.24): `UserService.claimInvitation` checks the password and, in one compare-and-set write applied only while the invite is pending, its password is still the initial one and the account carries this link's marker, writes the password and moves the account's link marker to one only that run holds. From then on:

- **The run continues only in the browser that set the password.** With a durable `store` it continues under a fresh `wfs` that only the password submit's response carries; the emailed token's state is never written again. With the encapsulated `store` every pause has a new token anyway.
- **The emailed link stops working**, whatever is submitted: it never sets the password again, enrols a factor or signs anyone in. A durable emailed token answers `410 WF_EXPIRED` (its state is gone) — [`GET /auth/invite/post-redemption?uid=`](./controllers#get-auth-invite-post-redemption) then answers the "link already used" envelope; an encapsulated one answers `410 INVITE_LINK_USED` ("This invitation link has already been used. Sign in, or ask for a new invitation.").
- **Two holders at the password form**: the first submit wins and writes; the other writes nothing — it gets `410 WF_EXPIRED` with a durable `store` (both hold the one token, which the first submit used up), `410 INVITE_LINK_USED` with the encapsulated one.
- **Every later pause of the run expires with the link at the latest** — at the state strategy's default when that is sooner, at the link's own expiry (7 days from issue) otherwise, so also with no default at all. A strategy that cannot report its expiry (no `expiresAtFor`, or a bundled strategy whose `persist` you override) is left uncapped and keeps its own expiry. Runs that set the password before 0.2.24 are capped the same way. Before, a pause after the password never expired under a strategy without a default (the encapsulated default), though it can still finish the acceptance and sign in.
- **To start over**, the issuer re-invites or [resends](#resending-an-invite) — the account goes back to "never used" (see [re-invites](#re-invites) for what that resets) and a new link goes out.

**Keep the current token per tab, not in the URL.** Your client must send the `wfs` of the latest response — the bundled `<AsWfForm>` does. Past the password that is no longer the link's token, so a page that reads `?wfs=` from the URL on every load would resend the dead emailed token after a reload. With `<AsWfForm>` (`@atscript/vue-wf` 0.1.187), let it keep the token in `sessionStorage` and drop the link from the URL once it has been used:

```vue
<AsWfForm
  path="/auth/trigger"
  name="auth/invite/start"
  :initial-token="link"
  persist-token="session"
  @link-used="dropLink"
/>
<!-- dropLink: router.replace({ query: { ...route.query, wfs: undefined } }) -->
```

The token then lives per tab (`wf:<name>`), survives a reload and never reaches the URL or the history; the saved token wins over no link or the same link, a different link starts from itself, and the entry is removed when the run is over. A client of your own does the same: keep the latest token in `sessionStorage`, prefer it over the URL on load, and remove the link's token from the URL after the first answer. Don't put the post-password token into the URL or the history: it continues the acceptance and can sign the invitee in.

Runs paused **after** the password before 0.2.24 recorded no claim: their emailed link (with a durable `store`, the same token as the browser's) keeps working until the run finishes or the state's TTL ends, as before. A link of the encapsulated `store` whose password was set before 0.2.24 can no longer set it again (`410 INVITE_LINK_USED`).

Your own `extra-step` override runs in the accept phase **before** the acceptance write (`unset-pending-invitation`), so whatever it writes can still belong to a link that turns out to be superseded. Keep such writes idempotent, or move them to `afterInvitationAccepted()`, which runs only after the acceptance succeeded.

The `HttpError` bodies carry the message `code` next to the text, so an SPA can branch on it. The texts are overridable — see [Messages](./messages).

## DOs and DON'Ts

- **DO** return every required column from `prepareUser` — and handle `email === undefined` there (the same hook serves self-signup and federated sign-up).
- **DO** validate tenant / scope input in `resolveInviteContext`; it comes from the client's start request.
- **DO** run your schema sync after upgrading (`account.invitedBy`, `account.inviteNonce`).
- **DO** send the `wfs` of the latest response on every submit, and keep it per tab in `sessionStorage` (`<AsWfForm @token>`), not in the URL — past the password the emailed token no longer continues the run, and the current one must not land in the history.
- **DON'T** replace `WfTriggerProvider.outlets` without keeping `createInviteOutlet()` if you use `'deliver'` or `'return-link'`.
- **DON'T** build a separate "resend invite" flow, or re-send a stored link — submit the admin form with the [`resend` action](#resending-an-invite); re-invite the same email to change its roles.
- **DON'T** read the workflow-state table yourself to show invite details — use [`peekInvite`](#peek-invite); it applies the store's handle hashing and the replaced-invite check.
- **DON'T** gate a link with a `peekInvite` / `peek()` call of your own in front of the trigger — refuse it in [`beforeResume`](#before-resume), which runs after the access lists, right before the link is consumed.
- **DON'T** revoke with `deleteUser` — it deletes an account even when its invite was accepted meanwhile; use `revokeInvitation`.

## See also

- [Workflows — Invite](./workflows#invite-auth-invite-start) — the flow in context of the other workflows.
- [REST Controllers — post-redemption](./controllers#get-auth-invite-post-redemption) — re-clicked links after the run finished.
- [Messages](./messages) — overriding the invite texts.
- [Email & SMS Senders](/auth/delivery) — the `EmailSender` behind `'outlet-email'`.
