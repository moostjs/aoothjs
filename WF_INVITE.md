# WF_INVITE — invite / accept-invite workflow design

Sibling of [WF.md](WF.md), [WF_LOGIN.md](WF_LOGIN.md), [WF_RECOVERY.md](WF_RECOVERY.md). DI / options-class / `init` step / no-`setupAuthWorkflows` shape is covered generically in [WF.md](WF.md) — not repeated here.

---

## Goal

A flexible "admin invites a user → user accepts → user is in" workflow that:

- Pre-creates a `pendingInvitation` user record so role assignment, auditing, and queries work the moment the admin hits "send"
- Lets consumers plug in **their own form schema** for accept-time profile fields (full name, phone, anything) without subclassing
- Lets consumers plug in a **transform-and-persist callback** for maximum flexibility on how the gathered fields land in storage
- Supports **re-invite** for admins when the original link expired or the user lost it
- Supports **invite cancellation** before acceptance
- Supports **shareable-link mode** (admin gets a link, sends it however they want — no automatic email)
- Has an explicit admin-auth contract (no more "consumer's responsibility" docblock disclaimer)
- Optional async `getAvailableRoles()` callback for the admin form's role picker (or omit entirely for role-less flows)
- Confirmation page at the end (mirrors the WF_RECOVERY `freshLoginRequired` shape)

Workflow ids: `auth.invite` (admin → user new invite) + `auth.reInvite` (admin re-sends to existing pending user) + `auth.cancelInvite` (admin revokes a sent invite).

---

## Three related workflows

Same options class, same step bodies, different schemas.

| Workflow id         | Purpose                                                                                                    | Schema entry                                            |
| ------------------- | ---------------------------------------------------------------------------------------------------------- | ------------------------------------------------------- |
| `auth.invite`       | Full new-invite flow: admin form → pre-create user → email → user accepts                                  | Starts at `prepareAvailableRoles`                       |
| `auth.reInvite`     | Admin re-sends to an existing `pendingInvitation: true` user                                               | Starts at `loadPendingUser`; reuses email + accept tail |
| `auth.cancelInvite` | Admin cancels a pending invite (deletes the pending user record + revokes any in-flight magic-link tokens) | Standalone — single step `cancelInvite`                 |

The user-side accept tail (`checkPendingInvitation` → … → `confirmation`) is shared between `invite` and `reInvite` schemas.

---

## `InviteWorkflowOptions` — full shape

```ts
@Injectable()
export class InviteWorkflowOptions {
  // ── Admin auth (replaces the docblock disclaimer) ────────────────────────
  requireAdminAuth = true;
  // When true, admin-side steps (`prepareAvailableRoles`, `adminInviteForm`,
  // `preCreateUser`, `sendInviteEmail`, `cancelInvite`, `loadPendingUser`)
  // assert that an authenticated admin context is present (via useAuth().isAuthenticated()).
  // Subject to ARBAC at the route level too — recommended.

  adminAuthCheck?: () => Promise<boolean>;
  // Optional override. When undefined, defaults to `useAuth().isAuthenticated()`.
  // Apps with custom admin gating (e.g. role check) supply a predicate here.

  // ── Admin invite form fields ─────────────────────────────────────────────
  collectFirstName = true;
  collectLastName = true;
  collectRoles = true; // tied to getAvailableRoles below

  getAvailableRoles?: () => Promise<Array<{ id: string; label: string }>>;
  // When undefined AND collectRoles=true → admin form shows a free-text roles input.
  // When provided → admin form shows a multi-select with the returned options.
  // When collectRoles=false → roles never asked (set programmatically via inferRoles below).

  inferRoles?: (input: {
    email: string;
    firstName?: string;
    lastName?: string;
  }) => Promise<string[]>;
  // Optional. Called after the admin form submits, before preCreateUser.
  // Lets the consumer derive roles from email domain, AD lookup, etc., without admin choice.
  // Result is merged with admin-selected roles (collectRoles=true) or used standalone.

  // ── Pre-create-user shape & persistence ──────────────────────────────────
  prepareUser?: (input: PreparedUserInput) => Promise<Record<string, unknown>>;
  // Called in preCreateUser step. Returns extra fields to merge into the user record
  // (e.g. tenantId, departmentId). Same hook as today's `MoostAuthWorkflowConfig.prepareUser`,
  // moved here per WF.md.

  // ── Send mode ────────────────────────────────────────────────────────────
  sendMode: "email" | "shareableLink" | "choice" = "email";
  // 'email': admin enters email; library sends the magic link.
  // 'shareableLink': library returns the magic-link URL to the admin (no email sent);
  //   admin shares it however they want (Slack, in-app message, paper, etc.).
  // 'choice': admin picks per-invite via a select-mode step.

  inviteTokenTtlMs = 7 * 24 * 60 * 60_000; // 7 days

  // ── Accept-side custom profile form ──────────────────────────────────────
  acceptProfileForm?: TAtscriptAnnotatedType;
  // Consumer-supplied .as form schema for the profile-collection step.
  // Auto-wired into `collectProfile` step. Render whatever fields the app needs:
  // fullName, phone, displayName, department, marketingOptIn, etc.
  // When undefined → step is SKIPPED (just password collection happens).

  applyProfile?: (input: { username: string; profile: Record<string, unknown> }) => Promise<void>;
  // ESCAPE HATCH for max flexibility. Called after acceptProfileForm submits + after
  // the user record exists. Receives the raw profile data; consumer transforms +
  // persists to wherever (UserService.update, separate profile table, external CRM, ...).
  // When undefined AND acceptProfileForm provided → fields are merged into the user record
  // via UserService update with a default deep-merge. Most apps will supply this for control.

  // ── Idempotency on magic-link click ──────────────────────────────────────
  alreadyAcceptedRedirectUrl = "/login";
  // When user clicks the magic link a second time (account already activated),
  // workflow short-circuits and redirects here instead of erroring.

  // ── Post-accept ──────────────────────────────────────────────────────────
  freshLoginRequired = false;
  // Default: auto-login after accept (today's behavior). Mirrors WF_RECOVERY's same opt.
  // Set true to redirect to login page instead.
  loginUrl = "/login";

  showConfirmation = true;
  // When true, after user finishes the accept flow they see a confirmation page
  // ("Account created — sign in" or "Welcome <name>") before being redirected/auto-logged.
  confirmationMessage = "Your account has been created.";

  // ── Cancellation ─────────────────────────────────────────────────────────
  allowCancel = true;
  // Enables `auth.cancelInvite` workflow id. Admin can revoke pending invites.
  // Cancellation is HARD DELETE: the pending user row is removed from the DB.
  // If the invitee subsequently clicks their (now-orphaned) magic link, the
  // `checkPendingInvitation` step sees no user record and returns 410 Gone
  // ("This invite has been cancelled."). No `softCancel` mode — keeping a
  // tombstoned user row open without a clear semantic invariant ("can they be
  // re-invited? what about their roles?") is asking for footguns. If a consumer
  // needs audit history of cancelled invites, they should subscribe to the
  // `invite.cancelled` audit event and persist the data themselves.

  // ── Anti-duplicate (no rate-limit; check by user state) ──────────────────
  // Duplicate-invite protection is structural, NOT rate-limit-based:
  //   - If a user record exists with `pendingInvitation: true` for the email,
  //     `auth.invite` rejects with 409 "Invite already pending — use reInvite to resend."
  //   - If a user record exists with `pendingInvitation: false` (already accepted),
  //     `auth.invite` rejects with 409 "User already exists."
  // Admin must explicitly reach for `auth.reInvite` (resend) or `auth.cancelInvite`
  // (revoke + start over). No silent overwrite, no silent no-op.

  duplicateCheck?: (input: {
    email: string;
    existingUser: UserCredentials | null;
  }) => Promise<DuplicateAction>;
  // Optional escape hatch for apps with non-standard duplicate semantics
  // (e.g. multi-tenant where same email can invite into different tenants).
  // Receives the email + the result of `users.getUser(email)` (null if not found);
  // returns one of: 'allow' | 'reject' | 'reuseAsReInvite'. Default behavior is the
  // structural rule above when this callback is undefined.

  // ── Rate limiting (admin-side per-admin spam guard) ──────────────────────
  rateLimit: { count: number; windowMs: number } | null = { count: 50, windowMs: 60 * 60_000 };
  // Per-ADMIN cap (not per-invitee — duplicate protection above handles that).
  // Default: max 50 invites per hour per admin. Set null to disable.
  // Uses shared `WorkflowRateLimitStore` interface with recovery (see WF.md).

  // ── Audit ────────────────────────────────────────────────────────────────
  auditEvents = true;
  // Emits: invite.created (admin → email), invite.resent (admin → reInvite),
  // invite.accepted (user → password set), invite.cancelled (admin → cancel).

  constructor(opts: Partial<InviteWorkflowOptions> = {}) {
    Object.assign(this, opts);
  }
}

export interface PreparedUserInput {
  email: string;
  firstName?: string;
  lastName?: string;
  roles: string[];
  invitedBy?: string; // admin userId
}
```

---

## Workflow context shape

```ts
export interface InviteWfCtx {
  opts: InviteWorkflowOptions;

  // Admin-side (Phase A):
  invitedBy?: string; // admin's userId from auth context
  availableRoles?: Array<{ id: string; label: string }>;
  email?: string;
  username?: string; // typically same as email; consumer can override
  firstName?: string;
  lastName?: string;
  roles?: string[];
  selectedSendMode?: "email" | "shareableLink"; // when sendMode === 'choice'
  shareableLinkUrl?: string; // populated when sendMode === 'shareableLink' so admin sees it

  // User-side (Phase B):
  alreadyAccepted?: boolean; // detected at checkPendingInvitation; triggers idempotent redirect
  passwordSet?: boolean;
  profile?: Record<string, unknown>; // populated by collectProfile step (when acceptProfileForm present)
}
```

---

## Step catalog

### Phase A — Admin side (`auth.invite` schema)

| #   | Step id                 | Default state | Gated by                                      | Notes                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| --- | ----------------------- | ------------- | --------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1   | `init`                  | ON            | —                                             | Implicit; copies `this.opts` into `ctx.opts`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| 2   | `assertAdminAuth`       | ON            | `opts.requireAdminAuth`                       | Calls `opts.adminAuthCheck?.() ?? useAuth().isAuthenticated()`. Captures `ctx.invitedBy`. Throws 401/403 on failure.                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| 3   | `prepareAvailableRoles` | conditional   | `opts.collectRoles && opts.getAvailableRoles` | Calls `getAvailableRoles()`; populates `ctx.availableRoles` so the form below can render a picker.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| 4   | `selectSendMode`        | conditional   | `opts.sendMode === 'choice'`                  | Form: pick email vs shareable link. Sets `ctx.selectedSendMode`.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| 5   | `adminInviteForm`       | ON            | —                                             | Consumer-defined form fields based on `opts.collectFirstName`/`collectLastName`/`collectRoles` + the `availableRoles` from #3. **Duplicate check:** loads existing user by email; runs `opts.duplicateCheck?.(...)` (escape hatch) or applies the default structural rule — `pendingInvitation: true` → 409 "Invite already pending, use reInvite"; `pendingInvitation: false` → 409 "User already exists"; not found → continue. Admins get clear errors (no anti-enumeration on this side). Stores `email`/`firstName`/`lastName`/`roles` in ctx. Alt action: `cancel` (aborts). |
| 6   | `inferRolesStep`        | conditional   | `opts.inferRoles`                             | Calls `opts.inferRoles(...)`; merges result with `ctx.roles`.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| 7   | `preCreateUser`         | ON            | —                                             | Calls `opts.prepareUser?.(...)` for extras → `users.createUser(email, undefined, { ...extras, firstName, lastName, roles, pendingInvitation: true })`. **Key invariant:** the user row exists in DB after this step, with `pendingInvitation: true`, no password. They cannot log in until they accept. Audit `invite.created` fires here.                                                                                                                                                                                                                                         |
| 8a  | `sendInviteEmail`       | conditional   | resolved mode is `'email'`                    | Emits `outletEmail(...)` ONCE; magic-link URL points at the user-side schema's start step. Sets `linkSent: true`.                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| 8b  | `returnShareableLink`   | conditional   | resolved mode is `'shareableLink'`            | Builds the magic-link URL via `buildMagicLinkUrl('invite', token)`; populates `ctx.shareableLinkUrl`; finishes admin-side with `useWfFinished().set({ type: 'data', value: { url: ctx.shareableLinkUrl } })` so admin's UI can display + copy it.                                                                                                                                                                                                                                                                                                                                  |

### Phase B — User accept-side (shared between `auth.invite` and `auth.reInvite`)

Triggered when the user clicks the magic link (resumes the workflow at this point).

| #   | Step id                  | Default state | Gated by                                | Notes                                                                                                                                                                                                                                                                                                                                                                                                        |
| --- | ------------------------ | ------------- | --------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| 9   | `checkPendingInvitation` | ON            | —                                       | Loads user by username from the magic-link token. Three outcomes: (a) user not found (cancelled by admin between send and click) → 410 Gone "This invite has been cancelled."; (b) user found, `pendingInvitation: false` → set `ctx.alreadyAccepted = true` → short-circuit to `idempotentRedirect`; (c) user found, `pendingInvitation: true` → continue. Guards both cancellation and double-click cases. |
| 10  | `idempotentRedirect`     | conditional   | `ctx.alreadyAccepted`                   | `useWfFinished().set({ type: 'redirect', value: opts.alreadyAcceptedRedirectUrl })`.                                                                                                                                                                                                                                                                                                                         |
| 11  | `preparePasswordRules`   | ON            | —                                       | Loads `getTransferablePolicies()` into ctx for the form to render rules.                                                                                                                                                                                                                                                                                                                                     |
| 12  | `createPasswordForm`     | ON            | —                                       | `SetPasswordForm` (with policy rules in ctx). Validates passwords match + policy. Calls `users.setPassword(...)`. Sets `ctx.passwordSet = true`. Alt action: `cancel` (logs out, clears partial state — does NOT delete the user; admin can `reInvite` later).                                                                                                                                               |
| 13  | `collectProfile`         | conditional   | `opts.acceptProfileForm`                | Renders the consumer-supplied `acceptProfileForm` schema. On submit: stores raw input in `ctx.profile`. The form schema is auto-wired — consumer just defines a `.as` interface with the fields they want.                                                                                                                                                                                                   |
| 14  | `applyProfile`           | conditional   | `opts.acceptProfileForm && ctx.profile` | Calls `opts.applyProfile?.(...)` if provided (escape hatch — consumer transforms + persists wherever). When undefined, defaults to a `users.update(username, profile)` deep-merge.                                                                                                                                                                                                                           |
| 15  | `unsetPendingInvitation` | ON            | —                                       | Flips `pendingInvitation = false` on the user row.                                                                                                                                                                                                                                                                                                                                                           |
| 16  | `activateUser`           | ON            | —                                       | `users.activateAccount(username)`. Audit `invite.accepted` fires here.                                                                                                                                                                                                                                                                                                                                       |
| 17a | `confirmation`           | conditional   | `opts.showConfirmation`                 | Returns a "your account has been created" data response (with `opts.confirmationMessage` for the body); UI shows it; user clicks through to login OR is auto-logged depending on the next step.                                                                                                                                                                                                              |
| 17b | `freshLoginFinish`       | conditional   | `opts.freshLoginRequired`               | `useWfFinished().set({ type: 'redirect', value: opts.loginUrl })`.                                                                                                                                                                                                                                                                                                                                           |
| 17c | `autoLoginFinish`        | conditional   | `!opts.freshLoginRequired`              | Issues tokens via `AuthCredential`, writes cookies, returns `buildLoginResponse(...)`.                                                                                                                                                                                                                                                                                                                       |

### `auth.reInvite` schema (admin re-sends)

| #   | Step id                                                                      | Notes                                                                                                                                                                                                     |
| --- | ---------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1   | `init` + `assertAdminAuth`                                                   | Same as Phase A.                                                                                                                                                                                          |
| 2   | `loadPendingUser`                                                            | Form: just email. Loads user, asserts `pendingInvitation === true` (else 409 "already accepted, no resend possible"). Populates ctx from existing user record. Audit `invite.resent` fires.               |
| 3   | `sendInviteEmail` OR `returnShareableLink`                                   | Same as Phase A #8a / #8b. New magic-link token issued (old one's TTL governs whether the original still works; consumer can opt to revoke old link via `revokeOldOnReinvite: true` opt — TBD if needed). |
| —   | (terminates here; user-side resumes at Phase B when they click the new link) |                                                                                                                                                                                                           |

### `auth.cancelInvite` schema

| #   | Step id                    | Notes                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| --- | -------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1   | `init` + `assertAdminAuth` |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| 2   | `cancelInvite`             | Form: email. Loads user; asserts `pendingInvitation === true` (else 409 — can't cancel a fully-accepted user, that's a deactivation, not a cancellation). **Hard delete:** `users.deleteUser(username)` removes the row entirely. Revokes any active magic-link tokens for this invite (best-effort — magic-link `wfs` tokens have their own TTL; the structural check in `checkPendingInvitation` is the real guarantee). Audit `invite.cancelled` fires with snapshot of the deleted user data. |

---

## Custom-profile form mechanism

The "auto-wire your form into a step" mechanism. Consumer flow:

```ts
// 1. Consumer defines a .as schema:
@form
export interface MyAcceptProfileForm {
  fullName: string
  phone?: string
  jobTitle?: string
  marketingConsent?: boolean
}

// 2. Consumer wires it via the options class:
moost.setProvideRegistry(createProvideRegistry(
  [InviteWorkflowOptions, () => new InviteWorkflowOptions({
    acceptProfileForm: MyAcceptProfileForm,
    applyProfile: async ({ username, profile }) => {
      // Maximum flexibility: transform + persist however
      await myCrmClient.upsert({ email: username, ...profile })
      await usersTable.update(username, { fullName: profile.fullName })
    },
  })],
))
```

`collectProfile` step (#13) auto-renders the form using moost-wf's standard `httpInputRequired(opts.acceptProfileForm, ctx)` machinery. No subclassing, no per-app wiring code — drop in a schema, get a step.

When `acceptProfileForm` is undefined, steps #13 + #14 are skipped entirely (no profile collection happens; the workflow is just password-set + activate).

---

## Alt-action catalog

| Form                         | Alt action key                       | Default | Behavior                                                                                        |
| ---------------------------- | ------------------------------------ | ------- | ----------------------------------------------------------------------------------------------- |
| `selectSendMode`             | `cancel`                             | ON      | Aborts admin-side workflow                                                                      |
| `adminInviteForm`            | `cancel`                             | ON      | Aborts                                                                                          |
| `loadPendingUser` (reInvite) | `cancel`                             | ON      | Aborts                                                                                          |
| `cancelInvite` form          | (no alt; cancellation IS the action) | —       | —                                                                                               |
| `createPasswordForm`         | `cancel`                             | ON      | Aborts; user record stays `pendingInvitation: true`; admin can `reInvite` later                 |
| `collectProfile`             | `skip`                               | OFF     | Default OFF — when ON, lets the user accept without filling profile; admin can require it later |

---

## Defaults summary (out-of-the-box behavior)

With **no consumer overrides**, the workflow does:

- Admin auth required (true)
- Collect first name + last name + roles (free-text)
- Email-only send mode
- 7-day magic link
- No profile form on accept (just password)
- Auto-login after accept (no fresh-login redirect)
- Show confirmation message
- Allow cancellation
- Rate limit: 50/hour per admin
- Audit all four events

That's a reasonable "drop in and use" baseline. Apps that need richer flows turn on `acceptProfileForm` + `applyProfile`, supply `getAvailableRoles`, switch to `shareableLink` mode, etc.

---

## Tasks (invite-specific, on top of WF.md common refactor)

1. **Define `InviteWorkflowOptions`** with the full shape above.
2. **Implement three workflows** — `auth.invite`, `auth.reInvite`, `auth.cancelInvite` — sharing the accept-tail steps via composed schemas.
3. **Pre-create user with `pendingInvitation: true`** — extend the user model / store contract to support this flag if not already present (`@aoothjs/user`'s `UserCredentials` should expose it; `UsersStoreMemory` + `UsersStoreAtscriptDb` from ISSUE-20 should respect it).
4. **Auto-wire `acceptProfileForm`** — moost-wf's form-injection machinery should already support this; verify and document the contract.
5. **Implement `applyProfile` escape hatch + default deep-merge fallback.**
6. **Idempotent magic-link click handling** — `checkPendingInvitation` short-circuits when already accepted.
7. **Shareable-link mode** — `returnShareableLink` finishes admin-side with the URL in the response payload so admin's UI can display + copy.
8. **`getAvailableRoles` + `inferRoles` callbacks** — wire both into the admin-form rendering and the post-form merge.
9. **Audit events** — emit `invite.created`, `invite.resent`, `invite.accepted`, `invite.cancelled` through the same audit channel as recovery (Moost event emitter / hook).
10. **Rate limit** — share `RecoveryRateLimitStore` interface (rename to `WorkflowRateLimitStore`) since both recovery + invite use the same shape.
11. **Tests** —
    - Default flow end-to-end (admin invite → user accepts via magic link → auto-login)
    - `sendMode: 'shareableLink'` returns URL to admin
    - `sendMode: 'choice'` lets admin pick
    - `acceptProfileForm` + `applyProfile` end-to-end with custom schema
    - `getAvailableRoles` populates picker; `inferRoles` merges
    - Re-invite happy path
    - Re-invite refuses on already-accepted user
    - Cancel-invite removes pending user + revokes link
    - Idempotent magic-link click (twice → second redirects)
    - `freshLoginRequired: true` skips auto-login
    - Admin-auth required (default) blocks unauth callers
    - Rate-limit cap fires on 51st invite within an hour
12. **e2e demo** — convert from current 3-step to the new shape; add a custom profile form demonstrating `applyProfile` writing to a separate table.
