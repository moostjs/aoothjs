# Federated Login (OAuth2 / OIDC)

The Moost wiring for [`@aooth/idp`](../idp/): it turns the framework-agnostic provider clients + account-resolution core into mounted HTTP routes and a workflow, so a "Sign in with Google" button ends in a normal `auth.issue` session — through the **same** login gates (MFA, consent, concurrency) as a password login.

`@aooth/auth-moost` owns the HTTP round-trip + the workflow; `@aooth/idp` owns the verified token exchange + `resolveUser`; the `(provider, subject) → userId` table lives in `@aooth/user`. See [IdP — Overview](../idp/) for the core and [Account Resolution](../idp/account-resolution) for the linking policy.

## Where it sits

```
"Sign in with Google" (top-level nav)
  → GET /auth/oauth/google/start           (OAuthController — plain 302)
       mint PKCE + nonce + anti-CSRF random; stash verifier+nonce server-side
       (OAuthFlowStore, keyed by random); sign {random,provider,redirect} into
       state; drop Lax httpOnly `aooth_oauth` cookie; 302 → provider
  → provider → 302 → redirect_uri = <baseUrl>/auth/oauth/google/callback   (your SPA route)
       SPA reads { code, state } and POSTs them into…
  → POST /auth/trigger { wfid:'auth/oauth/flow', input.formData:{ code, state } }
       oauth-exchange: verify state (HS256) → CSRF double-submit → single-use
       txn (PKCE verifier) → provider.exchange (verified ID token) → resolveUser
       → ACCOUNT-STATE GATE → ctx.subject → shared login tail → issue/redirect
```

The PKCE **verifier never reaches the browser** — only the single-use `code` does (strictly tighter than a classic public-SPA client, which holds the verifier too). The interactive continuation (MFA / consent) reuses the ordinary `/auth/trigger` machinery, so there is nothing OAuth-specific in the SPA beyond the callback bridge.

## Wiring

```ts
import {
  OAuthController,
  OAuthFlowStoreMemory,
  OAUTH_FLOW_STORE_TOKEN,
  FEDERATED_IDENTITY_STORE_TOKEN,
} from "@aooth/auth-moost";
import { FederatedLoginService, GoogleProvider, OAuthProviderRegistry } from "@aooth/idp";
import { FederatedIdentityStoreAtscriptDb } from "@aooth/user/atscript-db";

const registry = new OAuthProviderRegistry({
  baseUrl: process.env.PUBLIC_URL!, // redirect_uri = baseUrl + /auth/oauth/:provider/callback
  stateSecret: process.env.OAUTH_STATE_SECRET!,
  providers: [new GoogleProvider({ clientId, clientSecret })],
  policy: { emailMatch: "require-interactive-link", trustEmailVerifiedFrom: ["google"] },
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
    [OAUTH_FLOW_STORE_TOKEN, () => new OAuthFlowStoreMemory()], // abstract → STRING token
    [FEDERATED_IDENTITY_STORE_TOKEN, () => federatedStore], // abstract → STRING token
  ),
);
app.registerControllers(OAuthController /* + AuthController, your AuthWorkflow subclass */);
// `auth/oauth/flow` is already in DEFAULT_AUTH_WORKFLOWS, so the bundled
// `/auth/trigger` allow-list accepts it — no extra wiring on the trigger.
```

`OAuthProviderRegistry` + `FederatedLoginService` are concrete classes → they bind by class reference. The two **abstract** stores (`OAuthFlowStore`, `FederatedIdentityStore`) bind under the exported **string tokens** — moost's class-reference ctor injection can't resolve an abstract paramtype (it falls back to instantiating a body-less class), so `@Inject(<token>)` is used internally and you provide under the same strings.

## Routes (`OAuthController`)

| Route                                   | Auth        | Does                                                                                                     |
| --------------------------------------- | ----------- | -------------------------------------------------------------------------------------------------------- |
| `GET /auth/oauth/:provider/start`       | `@Public()` | Begin login. 302 to the provider. Optional `?redirect=<same-origin path>` for the post-login landing.    |
| `GET /auth/oauth/:provider/link`        | self-scoped | Begin an account **link** for the current user (`getUserId()` 401s anon). Binds `userId` server-side.    |
| `DELETE /auth/oauth/:provider/:subject` | self-scoped | Disconnect a linked identity. Refuses to remove the last sign-in method; then revokes the user sessions. |

`start` / `link` are `@Public()` self-scoped primitives (like `logout`/`status`) — anonymous start is the point, and link/unlink derive identity from the session, never a parameter. Subclass + add `@ArbacAction(...)` to gate further.

## The `redirect_uri` is YOUR route

`OAuthProviderRegistry.redirectUri(id)` is `baseUrl + /auth/oauth/:provider/callback`. In a SPA app that path is a **client route** you implement (the backend `OAuthController` has no `GET …/callback`) — it reads `code`/`state` from the URL and POSTs them into `/auth/trigger` as the start `input.formData` of `auth/oauth/flow`. Register the **exact** `redirect_uri` at the provider; `exchange()` re-sends it byte-for-byte.

## Server-side state (`OAuthFlowStore`)

`OAuthFlowStore` holds the in-flight PKCE verifier + nonce (+ the `/link` userId), keyed by the signed-state `random`, and is **single-use** (`take` removes the row — the replay defense). The bundled `OAuthFlowStoreMemory` is process-local: fine for one instance, but a **multi-pod deployment MUST override** with a shared store (Redis/DB), or a callback that lands on a different pod 404s the transaction. Same operational posture as the workflow state store's `HandleStateStrategy`.

## DOs / DON'Ts

- **DO** keep `start` a plain 302 controller and let the SPA bridge the callback into `/auth/trigger` — a workflow-outlet response can't emit the raw 302 a top-level navigation needs.
- **DO** swap `OAuthFlowStoreMemory` for a shared store in production (multi-pod) — the verifier MUST be server-side, never in the URL.
- **DON'T** expect the cookieless-demo behavior in a real app: the library's `redirect` step finishes OAuth with a **redirect envelope** (the session rides the Set-Cookie). The demo opts out (`resolveRedirect` returns `undefined` for `ctx.oauth`) only because it replays a Bearer token from `sessionStorage`.
- **DON'T** assume federated login skips MFA — a federated user reuses the password-login tail by `@Step` id, so MFA / consent / concurrency gates fire identically. The account-state (locked/inactive) gate runs **inside `oauth-exchange`**, before the subject is set, because `issue` does not re-gate.

## See also

- [IdP — Overview](../idp/) · [Providers](../idp/providers) · [Account Resolution & Linking](../idp/account-resolution) — the core this wires.
- [Workflows](./workflows) — the shared login tail `auth/oauth/flow` re-enters.
- [REST Controllers](./controllers) — `AuthController` + the `/auth/trigger` allow-list.
- [`@aooth/auth-moost` API](/api/auth-moost) — full export signatures.
