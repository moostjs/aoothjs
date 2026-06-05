# Federated Login (OAuth2 / OIDC)

The Moost wiring for [`@aooth/idp`](../idp/): it turns the framework-agnostic provider clients + account-resolution core into a federated leg of the **login workflow**, so a "Sign in with Google" button ends in a normal `auth.issue` session — through the **same** login gates (MFA, consent, concurrency) as a password login.

Federated login is **merged into `auth/login/flow`** — there is no separate OAuth workflow and no OAuth login route. The login form offers the configured providers; one click bounces through the provider and re-enters the shared login tail. `@aooth/auth-moost` owns the workflow legs + the account-management routes; `@aooth/idp` owns the verified token exchange + `resolveUser`; the `(provider, subject) → userId` table lives in `@aooth/user`. See [IdP — Overview](../idp/) for the core and [Account Resolution](../idp/account-resolution) for the linking policy.

## Where it sits

```
/login (auth/login/flow form) → click "Continue with Google" (AsSsoProviders)
  → the data-carrying `sso` action ends the wf with a 302 (AuthWorkflow.beginSso):
       derive PKCE verifier + OIDC nonce from a fresh non-secret seed; sign
       {random:seed, provider, redirect} into `state`; double-submit the seed in
       a Lax httpOnly CSRF cookie; 302 → provider
  → provider → 302 → redirect_uri = <baseUrl>/auth/oauth/google/callback  (your SPA route)
       SPA reads { code, state } and POSTs them into…
  → POST /auth/trigger { name:'auth/login/flow', input.formData:{ code, state } }
       init-login sees the inbound `state` → routes to `sso-callback` (skips the
       password form): verify state (HS256) → CSRF double-submit → RE-DERIVE the
       verifier from state.random → provider.exchange (verified ID token) →
       resolveUser → ACCOUNT-STATE GATE → ctx.subject → shared login tail → issue
```

**STATELESS — no flow store.** The PKCE verifier + OIDC nonce are **derived** from a non-secret `seed` carried in the signed `state` (and double-submitted in the CSRF cookie), then **re-derived** at the callback. Nothing secret rides in the URL — only the single-use `code` does (strictly tighter than a classic public-SPA client, which holds the verifier too). Any pod can complete a callback another started. The interactive continuation (MFA / consent) reuses the ordinary `/auth/trigger` machinery, so there is nothing OAuth-specific in the SPA beyond the callback bridge.

## Wiring

```ts
import { OAuthController, FEDERATED_IDENTITY_STORE_TOKEN } from "@aooth/auth-moost";
import { FederatedLoginService, GoogleProvider, OAuthProviderRegistry } from "@aooth/idp";
import { FederatedIdentityStoreAtscriptDb } from "@aooth/user/atscript-db";

const registry = new OAuthProviderRegistry({
  baseUrl: process.env.PUBLIC_URL!, // redirect_uri = baseUrl + /auth/oauth/:provider/callback
  stateSecret: process.env.OAUTH_STATE_SECRET!,
  providers: [new GoogleProvider({ clientId, clientSecret })],
  policy: {
    emailMatch: "require-interactive-link",
    allowSignup: true,
    trustEmailVerifiedFrom: ["google"],
  },
});
const federatedStore = new FederatedIdentityStoreAtscriptDb({ table: federatedTable });
const federatedLogin = new FederatedLoginService({
  users: userService,
  federated: federatedStore,
  policy: registry.policy,
});

app.setProvideRegistry(
  createProvideRegistry(
    [AuthCredential, () => authCredential],
    [UserService, () => userService],
    [OAuthProviderRegistry, () => registry], // concrete → class token
    [FederatedLoginService, () => federatedLogin], // concrete → class token
    [FEDERATED_IDENTITY_STORE_TOKEN, () => federatedStore], // abstract → STRING token
  ),
);
app.registerControllers(OAuthController /* + AuthController, your AuthWorkflow subclass */);
```

`OAuthProviderRegistry` + `FederatedLoginService` are concrete classes → they bind by class reference. The **abstract** `FederatedIdentityStore` binds under the exported **string token** `FEDERATED_IDENTITY_STORE_TOKEN` — moost's class-reference ctor injection can't resolve an abstract paramtype (it falls back to instantiating a body-less class), so `@Inject(<token>)` is used internally and you provide under the same string. There is **no** flow store to wire (the round-trip is stateless).

To offer providers on the login form, return them from `resolveAlternateCredentials` as `ssoProviders: { id, label, icon? }[]` — see [the SSO button](#the-login-form-s-sso-button) below.

## The login form's SSO button {#the-login-form-s-sso-button}

The bundled `LoginCredentialsForm.ssoProvider` field renders through **`AsSsoProviders`** (from `@atscript/vue-aooth`, registered on `<AsWfForm :components>`): a one-click picker that paints each provider as a button labelled with its server-owned `text` ("Continue with Google"), applies the provider's `icon` class verbatim, and on click both selects the id and fires the field's **data-carrying** `sso` action — there is no separate submit button. The selected `ssoProvider` rides the partial submit (`@wf.action.withData 'sso'`), and `AuthWorkflow.beginSso` turns it into the provider 302.

Providers come from `ctx.public.altActions.ssoProviders`, which mirrors what `resolveAlternateCredentials(ctx)` returns:

```ts
protected resolveAlternateCredentials(ctx: AuthWfCtx) {
  return { ...super.resolveAlternateCredentials(ctx),
    ssoProviders: [{ id: "google", label: "Google", icon: "i-simple-icons:google" }] };
}
```

The field self-hides when the list is empty, and stays **optional** so a password login submits without it. The `icon` is a CSS class the consumer owns — icon strings referenced from server context are invisible to a static class extractor, so they must be safelisted (and the matching icon collection installed); see the `@atscript/vue-aooth` `AsSsoProviders` reference.

## `needs-link` — interactive account completion {#needs-link-interactive-account-completion}

When `resolveUser` returns **`needs-link`** (a verified federated email matches an EXISTING local account, under the default `require-interactive-link` policy), `sso-callback` does **not** issue. It stashes the candidate (`ctx.pendingLink`) WITHOUT setting `ctx.subject`, and the `prove-control` step pauses to prove control of the matched account before linking:

- **password mode** — the account has a real password → `ProveControlForm` re-collects it (the username is bound server-side from the candidate; the user never types it).
- **OTP fallback** — the account is passwordless → `ProveControlOtpForm` collects a code delivered to the account's **OWN confirmed email/SMS channel, NEVER the provider-supplied email** (the attacker controls the provider account, so a code there would be circular). A `resend` action re-sends to the same channel, gated by the standard pincode cooldown.
- **cancel** abandons the link (no account created, no session) with a generic terminal; a wrong proof re-pauses with a generic inline error.

On success: `linkIdentity` (cross-user `ALREADY_EXISTS` guarded) → account-state gate → set `ctx.subject` + `ctx.oauth` → the shared login tail runs exactly like any other login. Override the proof forms via `setupAuthWorkflows({ forms: { proveControl, proveControlOtp } })`.

## Routes (`OAuthController`)

The controller serves only the **authenticated account-management** routes — anonymous login is NOT here (it's the login form's SSO button → `beginSso`):

| Route                                   | Auth        | Does                                                                                                            |
| --------------------------------------- | ----------- | --------------------------------------------------------------------------------------------------------------- |
| `GET /auth/oauth/identities`            | self-scoped | List the current user's **connected accounts** — `FederatedIdentityStore.listForUser(userId)`, projected.       |
| `GET /auth/oauth/:provider/link`        | self-scoped | Begin an account **link** for the current user (`getUserId()` 401s anon). Binds `userId` into the signed state. |
| `DELETE /auth/oauth/:provider/:subject` | self-scoped | Disconnect a linked identity. Refuses to remove the last sign-in method; then revokes the user's sessions.      |
| `POST /auth/oauth/:provider/callback`   | public      | **`form_post` bounce** (Apple). 303-redirects the cross-site POST to the GET SPA callback — see below.          |

`identities` / `link` / `unlink` are `@Public()` self-scoped primitives (like `logout`/`status`) — they derive identity from the session, never from a parameter. Subclass + add `@ArbacAction(...)` to gate further (e.g. an admin cross-user view).

### Connected accounts (`GET /auth/oauth/identities`)

Returns one `ConnectedAccount` per linked provider identity — a display projection of the `FederatedIdentity` rows for the caller: `{ provider, subject, linkedAt, lastLoginAt?, email?, displayName?, avatarUrl? }`. The surrogate `id` and the caller's own `userId` are dropped; `(provider, subject)` is exactly the key the client passes back to `DELETE :provider/:subject` to disconnect a row. This is the read side of the same table `link`/`unlink`/`resolveUser` already own — there is no separate "connected accounts" store.

## The `redirect_uri` is YOUR route

`OAuthProviderRegistry.redirectUri(id)` is `baseUrl + /auth/oauth/:provider/callback`. In a SPA app that path is a **client route** you implement (the backend `OAuthController` has no `GET …/callback`) — it reads `code`/`state` from the URL and POSTs them into `/auth/trigger` as the START `input.formData` of `auth/login/flow`. Register the **exact** `redirect_uri` at the provider; `exchange()` re-sends it byte-for-byte. Register the SAME custom-component map on the callback page's `<AsWfForm>` as on the login page — a federated login can land on the MFA / consent / prove-control forms.

### `form_post` providers (Apple) — the POST bounce {#form-post-providers-apple}

A provider that uses `response_mode=form_post` (Apple, whenever `email`/`name` scope is requested) POSTs the callback `application/x-www-form-urlencoded` — a static SPA page can't read a POST body. For these the `OAuthController` registers a thin server route `POST /auth/oauth/:provider/callback` that **303-redirects** the POST to the _same_ SPA callback URL as a GET with `code`/`state`/`error` in the query. From there it is byte-identical to the Google/GitHub GET path — the SPA forwards `{ code, state }` to `/auth/trigger` and `sso-callback` does all verification.

The bounce is a **dumb transport adapter** — it verifies nothing (state, CSRF, and exchange all stay in `sso-callback`). The `POST` route and the SPA's `GET` route share the path but never collide (different methods). The Lax CSRF cookie is (correctly) not sent on the cross-site POST and is not read by the bounce; it rides the subsequent same-origin `/auth/trigger` XHR where the double-submit is checked. No SPA change is needed beyond the existing GET callback page.

## DOs / DON'Ts

- **DO** offer providers via `resolveAlternateCredentials().ssoProviders` and let the login form's `sso` action drive `beginSso` — a workflow-outlet response emits the raw 302 a top-level navigation needs.
- **DO** keep the `redirect_uri` callback a SPA bridge that POSTs `code`/`state` into `/auth/trigger` (`auth/login/flow`) — the federated leg is a workflow START, not a controller route.
- **DON'T** look for a flow store or a `/start` route — both are gone. The verifier is **derived** from the signed-state seed and re-derived at the callback (stateless), so a multi-pod deployment needs no shared OAuth store.
- **DON'T** expect the cookieless-demo behavior in a real app: the library's `redirect` step finishes login with a **redirect envelope** (the session — and the trusted-device cookie — ride the finish-envelope `cookies` map / Set-Cookie). The demo opts out (`resolveRedirect` returns `undefined` for `ctx.oauth`) only because it replays a Bearer token from `sessionStorage`.
- **DON'T** assume federated login skips MFA — a federated user reuses the password-login tail by `@Step` id, so MFA / consent / concurrency gates fire identically. The account-state (locked/inactive) gate runs **inside `sso-callback`** (and `prove-control`), before the subject is set, because `issue` does not re-gate.

## See also

- [IdP — Overview](../idp/) · [Providers](../idp/providers) · [Account Resolution & Linking](../idp/account-resolution) — the core this wires.
- [Workflows](./workflows) — the shared login tail the federated leg re-enters.
- [REST Controllers](./controllers) — `AuthController` + the `/auth/trigger` allow-list.
- [`@aooth/auth-moost` API](/api/auth-moost) — full export signatures (`OAuthController`, `ConnectedAccount`, `FEDERATED_IDENTITY_STORE_TOKEN`).
