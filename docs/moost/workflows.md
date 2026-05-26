# Workflows

This page is the canonical reference for the three bundled `@moostjs/event-wf` workflows — `LoginWorkflow`, `RecoveryWorkflow`, `InviteWorkflow`. It covers each workflow's step phases, the unified `WfFinished` envelope contract, the protected extension surface, the `wf-trigger` machinery that drives them via `/auth/trigger`, and the subclassing pattern.

## The recipe

All three workflow classes share the same scaffolding:

```ts
@Public()
@Injectable("FOR_EVENT")
@Controller()
@Workflow("auth.<flow>")
@WorkflowSchema<Ctx>([
  /* step catalog */
])
class LoginWorkflow {
  constructor(opts: LoginWorkflowOpts, users: UserService, auth: AuthCredential) {
    /* ... */
  }

  @Step("init")
  protected init(ctx: Ctx) {
    /* ... */
  }

  // ... protected method overrides for senders / audit / role inference
}
```

::: warning Step IDs are workflow-scoped, but `@Step('id')` is registered globally
`@moostjs/event-wf` registers every `@Step('id')` into a single global registry across the moost app — identical IDs declared on two different workflow classes silently collide. Prefix your step IDs with the workflow's domain (e.g. `myFlowInit`, `myFlowVerify`) when adding steps to a workflow subclass.
:::

::: warning Workflow class `@Public()` is critical
Without it the global `arbacAuthorizeInterceptor` resolves workflow-events to `(resource=workflow-class, action=step-name)` and **denies** anonymous logins. The `@Public()` on the workflow class is what lets unauthenticated callers run the login flow. (Invite's Phase A re-applies `@ArbacResource('auth.invite') @ArbacAction('start')` to gate admin-only initiation — see [InviteWorkflow](#inviteworkflow-three-wfids).)
:::

::: warning Subclasses MUST re-declare the constructor signature
TypeScript emits fresh `design:paramtypes` per class — a subclass that doesn't re-declare the constructor signature gets paramtypes `[]`, and Moost's DI can't resolve the constructor at instantiation time. `@Inherit()` carries the base class's `@Workflow` / `@WorkflowSchema` / `@Step` metadata, but it does not carry the TS-emitted reflection metadata. You must write the ctor yourself.
:::

## `LoginWorkflow` — wfid `auth.login`

The main happy-path workflow: credentials → enrollment → MFA → device trust → password change → terms/profile/consent → tenant/persona → concurrency → finalize.

### What the user sees

A login run pauses on one or more of these forms before issuing tokens. Skipped pauses are determined by the user's account state and your subclass overrides.

1. **Credentials** — username + password. Always shown. Alt-actions (`forgotPassword`, `signup`, `magicLink`, per-SSO `sso-${id}`) finish the run early via `finishWfWithRedirect(url, { reason })`.
2. **Email / phone enrollment** — when your subclass requires it and the account is missing a confirmed address.
3. **MFA challenge** — when the user has a confirmed MFA method. A picker is shown when there are multiple methods; backup codes are available as a fallback.
4. **MFA enrollment** — when your subclass requires enrollment and the user has no methods yet.
5. **Forced password change** — when the user's password is flagged initial or expired.
6. **Terms acceptance / profile completion / consent prompts** — when [`resolveProfile`](#extension-hooks) returns `{ required: true }` and there are fields to collect.
7. **Pending consents** — appears inline on whichever form is open when [`ConsentStore.getPendingConsents`](#consentstore-pending-consents-persistence) returns descriptors.
8. **Tenant / persona selection** — when your subclass returns multiple options.
9. **Concurrency-limit prompt** — when your subclass sets a max-sessions policy and it's exceeded.

The run finishes by issuing access tokens (or redirecting to a fresh-login page, depending on your subclass).

Any user-initiated abort (`Cancel`, `Logout`, decline-terms) aborts the run and the engine emits a structured `aborted` envelope.

### Protected extension surface

| Method                                          | Default                                                        | Override for                                                      |
| ----------------------------------------------- | -------------------------------------------------------------- | ----------------------------------------------------------------- |
| `deliver(payload)`                              | no-op                                                          | Forward MFA pincodes / magic links to your email / SMS sender.    |
| `audit(event)`                                  | no-op                                                          | Wire your audit sink.                                             |
| `loadTrustedDevice(userId, cookieValue)`        | reads from in-memory map                                       | DB-backed trusted-device store.                                   |
| `storeTrustedDevice(userId, deviceId, opts)`    | writes to in-memory map                                        | Same.                                                             |
| `revokeTrustedDevice(userId, deviceId)`         | removes from in-memory map                                     | Same.                                                             |
| `issueTrustedDevice(userId)`                    | generates HMAC-signed cookie                                   | Custom cookie format.                                             |
| `applyProfile(input)`                           | calls `users.update(username, profile)`                        | Custom profile persistence.                                       |
| `applyConsentMarketing(input)`                  | calls `users.update(username, { account: { consents: ... } })` | Same.                                                             |
| `loadTenants(userId)`                           | returns `[]`                                                   | Tenant picker source.                                             |
| `loadPersonas(userId)`                          | returns `[]`                                                   | Persona picker source.                                            |
| `logoutOtherSessions(userId, currentSessionId)` | no-op                                                          | Concurrency-limit kick.                                           |
| `assessRiskStepUp(ctx)`                         | returns `false`                                                | Risk engine integration.                                          |
| `resolveRedirect(ctx)`                          | returns `null`                                                 | Where to send the user after issue (referrer / home / dashboard). |
| `buildRecoveryUrl(opts)`                        | returns `'/recover?...'`                                       | Where the `forgotPassword` alt-action redirects.                  |
| `snapshotOpts(opts)`                            | strips form classes                                            | Custom serialization (rare).                                      |

### Extension hooks

Beyond the `protected` overrides above, `LoginWorkflow` exposes additional `protected` hooks for per-tenant / per-user / per-request decisions that the per-app `LoginWorkflowOpts` cannot express. The headline one is **`resolveProfile(ctx)`**, which controls whether Phase 6's `profile-complete` step fires:

```ts
class MyLoginWorkflow extends LoginWorkflow {
  // Require profile-complete only for users missing a firstName.
  protected override async resolveProfile(ctx: LoginWfCtx): Promise<{ required: boolean }> {
    if (!ctx.username) return { required: false };
    const user = await this.users.findByUsername(ctx.username);
    return { required: !user?.firstName };
  }
}
```

Other `protected` override points exist on the class (device-trust policy, enrollment policy, MFA config, multi-context picker source, session-concurrency policy, OTP disclosure copy, …). Check IDE autocomplete on your `extends LoginWorkflow` subclass or the type definitions for the full list — every public extension point is a `protected` method you can `override`.

### `LoginWorkflowOpts` — key fields

| Field                    | Default                  | Notes                                                                          |
| ------------------------ | ------------------------ | ------------------------------------------------------------------------------ |
| `deviceTrust.cookieName` | `'aooth_trusted_device'` | Cookie name for the trusted-device token.                                      |
| `deviceTrust.ttlMs`      | `24 * 60 * 60_000`       | Trusted-device cookie + record TTL.                                            |
| `deviceTrust.bindsTo`    | `'cookie'`               | `'cookie'` or `'cookie+ip'`. `cookie+ip` is stricter — see [Config](./config). |
| `forms.<formName>`       | bundled `.as` defaults   | Replace any of the 16 bundled form schemas with your own atscript type.        |

::: tip Per-request / per-tenant / per-user behaviour
Anything that varies by request (which alternate-credentials options to show, whether to force MFA enrollment, whether to require profile completion, the session concurrency policy, etc.) is NOT on this opts shape. Override the matching `protected` method on your `LoginWorkflow` subclass — see [Extension hooks](#extension-hooks).
:::

## `RecoveryWorkflow` — wfid `auth.recovery`

Password reset via magic link or OTP, with optional second-factor verification, post-reset session revocation, and either a fresh-login redirect or an auto-login finish.

### What the user sees

1. **Identifier** — email or username. Anti-enumeration: unknown identifiers produce the same response as known ones.
2. **Delivery mode** — when both magic-link and OTP are configured, the user picks.
3. **OTP entry** — when OTP mode is active. Supports `resend`, `useDifferentTransport`, `backToLogin`.
4. **Magic-link sent** — when magic-link mode is active. The run continues when the user clicks the link.
5. **Known-factor verification** — when configured, the user proves a second factor (phone last-4 or current TOTP) before reset.
6. **New password** — sets the password and revokes existing sessions (configurable).
7. **Finish** — either a redirect to fresh-login or an auto-login envelope, depending on your subclass.

### `RecoveryWorkflowOpts` — key fields

| Field              | Default                | Notes                                                                  |
| ------------------ | ---------------------- | ---------------------------------------------------------------------- |
| `forms.<formName>` | bundled `.as` defaults | Replace any of the 5 bundled form schemas with your own atscript type. |

::: tip Per-request / per-tenant / per-user behaviour
Anything that varies by request (delivery mode, OTP transports, whether to require a known factor before reset, whether to revoke sessions, whether to force fresh-login afterwards, etc.) is NOT on this opts shape. Override the matching `protected` method on your `RecoveryWorkflow` subclass — see [Extension hooks](#extension-hooks).
:::

### Protected extension surface

| Method                             | Default                   | Override for                                                                                           |
| ---------------------------------- | ------------------------- | ------------------------------------------------------------------------------------------------------ |
| `deliver(payload)`                 | no-op                     | Send OTP emails / SMS. (Magic-link mode uses the email outlet on the trigger route, not this method.)  |
| `audit(event)`                     | no-op                     | Wire your audit sink.                                                                                  |
| `emailToUserId(email)`             | returns `email` unchanged | **MUST override** when `username !== email`. Resolves a recovery-step email to the canonical username. |
| `verifyRecoveryFactor(ctx, input)` | validates phone/totp      | Extend for security questions, hardware tokens, etc.                                                   |

## `InviteWorkflow` — three wfids

Registers `auth.invite`, `auth.reInvite`, `auth.cancelInvite`.

### What the admin sees (Phase A — gated by `@ArbacResource('auth.invite') @ArbacAction('start')`)

1. **Send mode** — when both `email` and `shareableLink` are configured, the admin picks.
2. **Invite form** — email, optional name, optional roles. Roles are server-side-validated against your `getAvailableRoles()` allow-list.
3. **Magic link emitted** — either an email is sent (idempotent — re-entry never double-sends), or a shareable link is returned to the admin.

### What the invitee sees (Phase B — anonymous magic-link resume)

1. **Already-accepted notice** — if the invite was already redeemed, the invitee gets a choice (`Go to sign-in` / `Request a new invite`).
2. **Cancelled-invite notice** — if an admin cancelled the invite between send and click, the run ends with a clear message.
3. **Set password** — initial password for the new account.
4. **Profile** — when your subclass returns a custom profile form.
5. **Confirmation banner** — optional welcome message before tokens issue.
6. **Finish** — either a redirect to fresh-login or an auto-login envelope, depending on your subclass.

### `auth.cancelInvite`

One-step admin operation. Looks up the user by email, verifies the invite is still pending (not yet accepted), deletes the pending user record, and emits a `{ cancelled: true, email }` envelope. Disable by returning early from your subclass's cancel hook if you don't want admins to be able to cancel sent invites.

### `InviteWorkflowOpts` — key fields

| Field              | Default                | Notes                                                                  |
| ------------------ | ---------------------- | ---------------------------------------------------------------------- |
| `forms.<formName>` | bundled `.as` defaults | Replace any of the 7 bundled form schemas with your own atscript type. |

::: tip Per-request / per-tenant / per-user behaviour
Anything that varies by request (send mode, magic-link TTL, whether to force fresh-login, the post-accept confirmation banner, whether `auth.cancelInvite` is enabled, etc.) is NOT on this opts shape. Override the matching `protected` method on your `InviteWorkflow` subclass — see [Extension hooks](#extension-hooks).
:::

### Protected extension surface

| Method                  | Default                                 | Override for                                                                                                             |
| ----------------------- | --------------------------------------- | ------------------------------------------------------------------------------------------------------------------------ |
| `deliver(payload)`      | no-op                                   | Used by the manual-send fallback. The default magic-link send path goes through `outletEmail` (the trigger-side mailer). |
| `audit(event)`          | no-op                                   | Wire your audit sink.                                                                                                    |
| `prepareUser()`         | returns `{}`                            | Populate consumer-required user fields (e.g. `tenantId`) before `users.createUser` runs.                                 |
| `getAvailableRoles()`   | returns `[]`                            | Drive the `InviteForm` role-picker options.                                                                              |
| `inferRoles(input)`     | returns `input.roles`                   | Add implicit roles based on the invite payload.                                                                          |
| `applyProfile(input)`   | calls `users.update(username, profile)` | Custom profile persistence.                                                                                              |
| `duplicateCheck(email)` | calls `users.findByUsername(email)`     | Custom duplicate detection.                                                                                              |
| `getProfileForm()`      | returns `null`                          | Return your own `.as` type to enable the profile-collection step.                                                        |
| `snapshotOpts(opts)`    | strips form classes                     | Custom serialization (rare).                                                                                             |

## `ConsentStore` — pending consents + persistence

All three workflows resolve a `ConsentStore` from the DI container as the seam for the customer-defined consent universe and persistence sink. On every workflow run the store's `getPendingConsents(username, { workflow })` decides which consents are still outstanding for the user; the bundled forms surface them inline as a `consents: string[]` field on whichever form the user is currently filling out — the field self-hides when there are no pending consents.

```ts
interface ConsentDescriptor {
  id: string; // 'terms', 'marketing', 'jurisdiction-gdpr', …
  text: string; // user-facing label / disclosure text (markdown links allowed)
  required?: string; // when set, the consent is mandatory; the string IS the error message
  version?: string; // stamped onto persisted ConsentEvent for versioned policies
}
```

The default `ConsentStore` is no-op — extend it and register the replacement via `createReplaceRegistry`:

```ts
import { ConsentStore, type ConsentDescriptor, type ConsentEvent } from "@aooth/auth-moost";
import { Injectable } from "moost";

@Injectable() // SINGLETON
class MyConsentStore extends ConsentStore {
  override async getPendingConsents(
    username: string | undefined,
    _ctx: { workflow: string },
  ): Promise<ConsentDescriptor[]> {
    if (!username) return [];
    const accepted = await db.consents.find({ username, id: "terms" });
    if (accepted.some((e) => e.version === "v2")) return [];
    return [
      {
        id: "terms",
        text: "I accept the updated [Terms](/terms) and [Privacy](/privacy)",
        required: "You must accept the updated terms to continue",
        version: "v2",
      },
    ];
  }

  override async save(username: string, events: ConsentEvent[]): Promise<void> {
    await db.consents.insertMany(events.map((e) => ({ ...e, username })));
  }
}

app.setReplaceRegistry(createReplaceRegistry([ConsentStore, MyConsentStore]));
```

| Method                                                           | Default      | Override for                                                                                  |
| ---------------------------------------------------------------- | ------------ | --------------------------------------------------------------------------------------------- |
| `getPendingConsents(username, { workflow, channel? })`           | returns `[]` | Drive `ctx.pendingConsents` per workflow / channel / user history.                            |
| `save(username, events)`                                         | no-op        | Persist captured `ConsentEvent[]` to your audit table / event store.                          |
| `read(username, { id? })`                                        | returns `[]` | Read consent history (used by `getPendingConsents` impls that compute "accepted version vN"). |
| `recordOtpChannelConsent(username, channel, target, disclosure)` | no-op        | Persist OTP-channel disclosure-with-target (transactional OTPs only; default is sufficient).  |

## The `WfFinished` envelope contract

All three workflows go through one of these envelope helpers from `@atscript/moost-wf`. Every helper produces the unified `WfFinished` wire envelope `{ finished: true, data?, message?, end?, aborted?, reason? }`:

| Helper                                                                     | Wire envelope produced                                                                                                   | Use when                                                                                      |
| -------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------ | --------------------------------------------------------------------------------------------- |
| `finishWfWithData(data, message?)`                                         | `{ finished: true, data, message? }`                                                                                     | Returning a structured payload to the SPA (e.g. `{ sent: true }` after dispatching an email). |
| `finishWfWithMessage(level, text)`                                         | `{ finished: true, message: { level, text } }`                                                                           | Display-only finish — informational notice without any data payload.                          |
| `finishWfWithRedirect(target, { autoMs?, skipLabel?, message?, reason? })` | `{ finished: true, message?, end: { mode: 'immediate' \| 'auto', action: { type: 'redirect', target, reason? }, ... } }` | Sending the user somewhere else after the run finishes (sign-in page, dashboard, etc.).       |
| `finishWfWithChoice({ message?, primary?, options? })`                     | `{ finished: true, data?, message?, end: { mode: 'manual', primary?, options? } }`                                       | Asking the user to pick a next action (e.g. "Go to sign-in" / "Request a new invite").        |
| `finishWfAborted(reason, { message?, end? })`                              | `{ finished: true, aborted: true, reason, message?, end? }`                                                              | User-initiated abort (`Cancel`, `Logout`, decline-terms). SPA renders an `aborted` envelope.  |

### Raw envelope path for cookies

The high-level helpers above do **not** accept cookies. For paths that need to attach cookies (login `issue`, recovery `autoLoginFinish`, invite `autoLoginFinish`), workflows use the raw `useWfFinished().set(...)` slot directly. The slot input shape (`{ type, value, cookies }`) is the `@wooksjs/event-wf` API — distinct from the `WfFinished` wire envelope it carries in `value`:

```ts
const envelope: WfFinished = { finished: true, data: auth.buildLoginResponse(...) };
useWfFinished().set({
  type: "data",
  value: envelope,            // ← the WfFinished wire envelope
  cookies: auth.buildFinishedCookies(issue),
});
```

`buildFinishedCookies(issue)` builds the cookies map from the `IssueResult`, respecting the `enableCookie` flag. See [AuthGuard & useAuth](./auth-guard#buildfinishedcookies-issue-wffinishedresponse-cookies).

## `wf-trigger` — workflow trigger machinery

### `WfTrigger({ allow?, token? })`

A method decorator that wraps `defineAfterInterceptor` at `INTERCEPTOR` priority. When the wrapped handler returns `undefined`, the interceptor instantiates `WfTriggerProvider` and replies with its `handle(opts)`. Subclasses that need to short-circuit return any non-`undefined` value (see [Pattern B](./controllers#pattern-b-replace-triggerwf-entirely)).

`opts.allow` is an array of wfids to whitelist. The trigger rejects requests for wfids outside `allow` with a 400.

`opts.token` overrides the token wire — by default `{ read: ['body', 'query', 'cookie'], write: 'body', name: 'wfs' }`.

### `WfTriggerProvider`

The `@Injectable()` singleton owning workflow state + outlets + token wire. Default configuration:

```ts
this.state = new HandleStateStrategy({ store: WfStateStoreMemory() });
this.outlets = [createAsHttpOutlet()];
this.tokenWire = { read: ["body", "query", "cookie"], write: "body", name: "wfs" };
```

Production consumers subclass it to swap state store (`new AsWfStore({ table })`) and add outlets:

```ts
@Injectable()
class MyWfTriggerProvider extends WfTriggerProvider {
  constructor(wf: MoostWf) {
    super(wf);
    this.state = new HandleStateStrategy({ store: dbWfStore });
    this.outlets = [
      ...this.outlets,
      createAuthEmailOutlet({
        emailSender,
        buildMagicLinkUrl: (kind, token) => `${env.FRONTEND_URL}/redeem?wfs=${token}`,
        magicLinkTtlMs: (kind) =>
          kind === "invite.magicLink" ? 7 * 24 * 60 * 60_000 : 60 * 60_000,
      }),
    ];
  }
}

app.setReplaceRegistry(createReplaceRegistry([WfTriggerProvider, MyWfTriggerProvider]));
```

### `createAuthEmailOutlet(deps)`

Builds the email outlet that delivers magic links. Wraps `@moostjs/event-wf`'s `createEmailOutlet(send)` and translates the workflow token into an `AuthEmailEvent`:

```ts
interface AuthEmailEvent {
  kind: AuthEmailKind; // 'recovery.magicLink' | 'invite.magicLink' | ...
  recipient: string;
  url: string;
  expiresAt: number;
  username?: string;
  metadata?: Record<string, unknown>;
}
```

`deps`:

| Field                                  | Purpose                                                        |
| -------------------------------------- | -------------------------------------------------------------- |
| `emailSender: EmailSender`             | Your sender — receives the `AuthEmailEvent`.                   |
| `buildMagicLinkUrl: BuildMagicLinkUrl` | `(kind, token) => string`. Constructs the URL the user clicks. |
| `magicLinkTtlMs: (kind) => number`     | Per-kind TTL. Drives the `expiresAt` field on the event.       |

## Workflow context invariants

::: warning Use `delete ctx.field` not `ctx.field = undefined`
`AsWfStore` validates `state.context` against a JSON-anyOf schema and chokes on explicit `undefined` entries. The compiled schema treats `undefined` as a distinct type from "absent". Always use `delete ctx.someField`.
:::

::: warning Form classes are stripped from `ctx.opts` via `snapshotOpts()`
Forms are class references (not POJOs), so they cannot be serialized into the wf state store. `snapshotOpts()` runs once at `init` and strips the `forms.*` keys before `ctx.opts` is persisted. If you override `snapshotOpts`, preserve the form-stripping logic — otherwise the wf state store will fail to serialize.
:::

## Error patterns — retriable vs terminal

Workflow `@Step` bodies throw exactly two error shapes. Pick by asking: **can the user fix this from the form they are looking at?** If yes → `wf.requireInput`. If no → `HttpError`.

| Shape                                                             | Behaviour                                                                                                                                                                                | Use for                                                                                                                                                |
| ----------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `throw wf.requireInput({ errors, formMessage? })` — **retriable** | Engine re-persists state under the SAME `wfs` handle and re-renders the form payload with per-field errors. The user can fix the input and resubmit. The `wfs` token survives the throw. | Bad password, wrong OTP code, mismatched confirm-password, duplicate email, missing required consent, account lockout, "session limit reached".        |
| `throw new HttpError(<status>, <msg>)` — **terminal**             | The token IS consumed; the SPA renders a final error. The workflow run is over.                                                                                                          | `500` state corruption, `501` not implemented (magic-link / passkey / SSO stubs), `410` cancelled invite, `403` feature disabled, `409` CAS exhausted. |

`wf` is the handle returned by `useAtscriptWf(FormSchema)`. The form payload + `@wf.context.pass` keys are auto-included in the re-render response, so the SPA's next render of the form sees the fresh ctx without an additional round-trip.

### Side-by-side

```ts
// ✅ Retriable — user can correct the input on the same form.
try {
  await this.users.login(ctx.username, input.password);
} catch (err) {
  if (err instanceof UserAuthError) {
    if (err.type === "LOCKED") {
      throw wf.requireInput({ formMessage: "Account locked, please try again later" });
    }
    throw wf.requireInput({ formMessage: "Invalid credentials" });
  }
  throw err;
}

// ✅ Retriable — per-field error binds to LoginCredentialsForm.password.
throw wf.requireInput({ errors: { confirmPassword: "Passwords do not match" } });

// ❌ Terminal — workflow state lost a required field; not a client error.
if (!ctx.username) throw new HttpError(500, "Workflow state corrupted: missing username");

// ❌ Terminal — feature was disabled by your subclass; user has no way to fix from the form.
if (!this.isCancellationEnabled()) {
  throw new HttpError(403, "Invite cancellation is disabled");
}

// ❌ Terminal — admin cancelled the invite between send and click; the user's
//    magic link is now dead. No form to retry from.
if (!existing) throw new HttpError(410, "This invite has been cancelled");
```

::: warning Don't throw `HttpError(4xx)` for user-fixable input errors
`HttpError(<4xx>)` is terminal — the workflow run is over and the form cannot be retried. Use `wf.requireInput` for any error a user can correct from the form they are looking at (wrong password, duplicate email, password policy violation, missing required consent). See [Workflow state tokens (`wfs`)](#workflow-state-tokens-wfs) for the persistence invariant.
:::

## Workflow state tokens (`wfs`)

The `wfs` URL / body / cookie token is the single resume handle for a paused workflow run. The token wire is configured per workflow trigger — by default `{ read: ['body', 'query', 'cookie'], write: 'body', name: 'wfs' }` (see [`WfTriggerProvider`](#wftriggerprovider)).

### Stable across retries, refresh, bookmark, multi-tab

The token stays alive across:

- **Form submissions that throw `wf.requireInput`** (wrong password, invalid OTP, duplicate email, missing required consent). The URL `wfs=…` remains live; the user fixes input and resubmits without a fresh round-trip to mint a new token.
- **Browser refresh.** The URL's `wfs=…` is still valid; the workflow resumes at the current pause.
- **Bookmarking and revisiting.** Same as refresh.
- **Multi-tab.** Concurrent submissions on the same token are serialised — the winner advances the workflow; the loser receives the form re-render under the same handle, and its NEXT refresh succeeds.

### When tokens rotate

The token mints fresh only at three boundaries:

1. **Workflow start.** No incoming `wfs` token → the engine mints one when the first step pauses.
2. **Workflow finish.** No token is persisted — the workflow is gone. Any subsequent `POST /auth/trigger` with the now-dead token returns 410 Gone (terminal — no recovery from this state).
3. **Workflow id change.** Replaying a token from `auth.login` against `auth.recovery` mints a fresh one.

### HTTP outlets vs. out-of-band outlets

The stable-token semantics above apply to HTTP outlets — the SPA submitting against `/auth/trigger`. Out-of-band outlets (`createAuthEmailOutlet` — magic links delivered by email) keep their own delivery semantics: the email is sent ONCE per invocation; the workflow ctx tracks `linkSent` so a step re-entry doesn't double-send. The recipient-clicked URL carries the `wfs` token that the recipient's browser then drives through the HTTP outlet as usual.

```ts
// Refresh / bookmark / retry-on-retriable-error all reuse this exact URL.
GET /wf?id=auth.login&wfs=8b34cef0-…

// SPA POSTs to /auth/trigger with the same token until the workflow finishes
// or fails terminally.
POST /auth/trigger    { wfs: '8b34cef0-…', input: { username, password } }
//                      ↑ same token across `wf.requireInput` re-renders
```

## Subclassing pattern — full template

```ts
import { LoginWorkflow, type LoginWorkflowOpts, type DeliverPayload } from "@aooth/auth-moost";
import { AuthCredential } from "@aooth/auth";
import { UserService } from "@aooth/user";
import { Inherit, Injectable, Controller } from "moost";

const myLoginOpts: LoginWorkflowOpts = {
  mfa: { enabled: true, transports: ["email", "totp"] },
  alternateCredentials: { forgotPassword: true },
  guards: { passwordInitial: true },
};

@Inherit() // flows @Workflow / @WorkflowSchema / @Step / @Public
@Injectable("FOR_EVENT") // re-applied: moost@0.6.x does NOT inherit @Injectable
@Controller() // re-applied: same reason
class MyLoginWorkflow extends LoginWorkflow {
  // RE-DECLARED constructor — TS emits design-paramtypes per class
  constructor(users: UserService, auth: AuthCredential) {
    super(myLoginOpts, users, auth);
  }

  protected override async deliver(payload: DeliverPayload): Promise<void> {
    if (payload.channel === "email") {
      await myEmailSender.send({
        /* ... */
      });
    } else {
      await mySmsSender.send({
        /* ... */
      });
    }
  }

  protected override async audit(event): Promise<void> {
    await auditTable.insert(event);
  }

  protected override async resolveRedirect(ctx): Promise<string | null> {
    return ctx.input?.next ?? "/dashboard";
  }
}

app.registerControllers(MyLoginWorkflow);
```

The same template applies to `RecoveryWorkflow` and `InviteWorkflow`. See [`packages/e2e-demo/src/app.ts`](https://github.com/moostjs/aoothjs/blob/main/packages/e2e-demo/src/app.ts) for all three side-by-side.

## SPA UI components — `AsConsentArray` + `AsPasswordRules`

Two Vue components from `@atscript/vue-aooth` are pre-wired into the bundled workflow forms. The forms reference them by name via `@ui.form.component '<ComponentName>'`; the SPA registers them on `<AsWfForm :components>` so `<AsForm>` resolves the name string to the actual Vue component at render time. **The string in `@ui.form.component` MUST match a key in the `:components` map** — otherwise the field renders as the default text input fallback.

| Form field                      | `@ui.form.component` | Component         | What it renders                                                                                                                                                                                                     |
| ------------------------------- | -------------------- | ----------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `consents` (on the active form) | `'AsConsentArray'`   | `AsConsentArray`  | One checkbox per `ctx.pendingConsents[]` descriptor. Bound to `consents: string[]` (ids of accepted descriptors). **Self-hides when `pendingConsents` is empty / unset** — no `@ui.form.fn.hidden` is needed.       |
| `SetPasswordForm.passwordRules` | `'AsPasswordRules'`  | `AsPasswordRules` | A phantom `ui.paragraph` display field that renders fulfillment dots against the live `data.newPassword`, re-evaluating on every keystroke. Backed by the same transferable policy expressions the server enforces. |

The `consents: string[]` field appears on whichever form the user is currently filling out (`LoginCredentialsForm`, `SetPasswordForm`, `ProfileCompleteForm`, `AskEmailForm`, `AskPhoneForm`, `TermsBumpForm`). Submitted ids are validated server-side against `ctx.pendingConsents` as the authoritative whitelist — see [`ConsentStore`](#consentstore-pending-consents-persistence).

### Wiring example

```vue
<!-- WfPage.vue (e2e-demo) -->
<script setup lang="ts">
import { AsWfForm } from "@atscript/vue-wf";
import { AsConsentArray, AsPasswordRules } from "@atscript/vue-aooth";

// Component-name strings here MUST match `@ui.form.component '<Name>'` in the `.as` schema.
const components = { AsConsentArray, AsPasswordRules };
</script>

<template>
  <AsWfForm
    path="/auth/trigger"
    name="auth.login"
    :components="components"
    @finished="onFinished"
    @error="onError"
  />
</template>
```

See [`packages/e2e-demo/src/ui/pages/WfPage.vue`](https://github.com/moostjs/aoothjs/blob/main/packages/e2e-demo/src/ui/pages/WfPage.vue) for the full SPA wiring including magic-link resume via `initialToken` + the variant-header pattern.

::: tip Component names are stable across form replacements
If you replace a bundled form via `opts.forms.setPassword = MySetPasswordForm`, keep the `@ui.form.component 'AsPasswordRules'` annotation on the `passwordRules` field if you want the live-fulfillment readout. The SPA's `:components` registration is keyed on the string, not on the form class.
:::

## See also

- [REST Controllers](./controllers) — the `/auth/trigger` endpoint that dispatches into these workflows.
- [Audit Log](./audit) — what events each workflow emits.
- [Config Reference](./config) — full option tables.
