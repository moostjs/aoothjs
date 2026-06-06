# Authorization Server (CLI login + service SSO)

The **inbound twin** of [Federated Login](./oauth). There, aoothjs is the OAuth **client** of an external IdP ("Continue with Google"). Here, aoothjs is the OAuth/OIDC **authorization server** for its OWN clients — a local **CLI** on a loopback redirect, or a registered **first-party service** ("Sign in with the main app"). One authorization-code + PKCE flow drives a real interactive login (password, MFA, consent, even a mid-flow "Continue with Google"); the only thing that varies between the two cases is the injected **client/redirect policy** (and, for service SSO, whether an `id_token` is signed).

The framework-agnostic pieces — the two short-lived stores, the client/redirect policies, the `id_token` signer, the claims resolver, the token policy, and the error taxonomy — live in [`@aooth/auth/authz`](../api/auth#authz-subpath). This page is the moost HTTP layer: the `AuthorizeController` endpoints and the DI wiring.

## Where it sits

```
client opens browser →
  GET /auth/authorize?response_type=code&client_id?&redirect_uri&state
                       &code_challenge&code_challenge_method=S256&scope?&nonce?
    → policy.resolveClient(...)  ← TRUST GATE: authorize client + redirect_uri (+ scope) FIRST
    → PendingAuthorizationStore.create(...)  ← ALL authority fixed HERE (tokenPolicy, id_token
                                                intent, audience, granted scope, nonce)
    → 302 /login?authz=<opaque handle>       ← the SPA forwards the handle into auth/login/flow
  → user authenticates (password / MFA / consent / mid-flow SSO) →
      the login workflow's `mint-authz-code` terminal mints a single-use CODE bound to
      ctx.subject + the recorded authority, and 302s redirect_uri?code=&state=
  → POST /auth/token { grant_type, code, code_verifier, client_id?, client_secret? }
    → consume code (single-use) → verify PKCE → authenticate client (Tier 2) →
      mint access_token and/or id_token  ← minted HERE, off the browser
    → { token_type, access_token?, expires_in?, id_token?, userId }

# Tier 2 only:
GET /auth/.well-known/openid-configuration   → OIDC discovery (derived from the signer's issuer)
GET /auth/jwks                               → the signer's public JWKS
```

The grant's authority is **fixed at `/authorize` time** (the policy's [`TokenPolicy`](../api/auth#authz-subpath), `id_token` intent, `aud`, and granted scope are recorded on the pending authorization and copied onto the issued code), **never inferred at `/token`**. Nothing long-lived ever rides a redirect URL — only the single-use `code` does.

## Two tiers, one flow

|                          | Client / redirect policy                                                                                                                                                                          | What the token endpoint mints                                                                                                                |
| ------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------- |
| **Tier 1 — CLI**         | `LoopbackClientPolicy` — any `127.0.0.1` / `[::1]` / `localhost` redirect, any port (RFC 8252); public client, PKCE is the binding; no `client_id`.                                               | A full-authority `cli-session` **access token** for the main API (no `id_token`).                                                            |
| **Tier 2 — service SSO** | `RegisteredClientPolicy` — a static registry; each client has a `client_id`, an exact-match (or strict-prefix) `redirect_uri` allowlist, a `public`/`confidential` type, and what it may receive. | An **`id_token`** (RS256/ES256, `aud` = `client_id`), optionally also an access token. Consumable by the existing [`OidcProvider`](../idp/). |

Run both side by side with `CompositeClientPolicy`, which dispatches on the **presence of `client_id`** — a request with one is a registered client, one without is a loopback CLI.

## Wiring — Tier 1 (CLI loopback)

```ts
import {
  AuthorizeController,
  AUTH_CODE_STORE_TOKEN,
  CLIENT_REDIRECT_POLICY_TOKEN,
  PENDING_AUTHORIZATION_STORE_TOKEN,
} from "@aooth/auth-moost";
import {
  AuthCodeStoreMemory,
  LoopbackClientPolicy,
  PendingAuthorizationStoreMemory,
} from "@aooth/auth/authz";

app.setProvideRegistry(
  createProvideRegistry(
    [AuthCredential, () => authCredential],
    [UserService, () => userService],
    // All three are abstract/interface deps → they bind under STRING tokens
    // (moost's class-reference ctor injection can't resolve an abstract paramtype).
    [CLIENT_REDIRECT_POLICY_TOKEN, () => new LoopbackClientPolicy()],
    [PENDING_AUTHORIZATION_STORE_TOKEN, () => new PendingAuthorizationStoreMemory()],
    [AUTH_CODE_STORE_TOKEN, () => new AuthCodeStoreMemory()],
  ),
);
app.registerControllers(AuthorizeController /* + AuthController, your AuthWorkflow subclass */);
```

The memory stores are single-process; a multi-pod deployment swaps a durable atscript-db adapter under the **same** tokens. `AuthorizeController.loginPath()` defaults to `/login` — override it in a subclass for a custom login route. The CLI side is a minimal-dependency browser+loopback helper (generate `state` + PKCE → open the browser → await the one-shot loopback callback → verify `state` → `POST /auth/token`).

## Wiring — Tier 2 (first-party OIDC)

Tier 2 adds three things to the Tier-1 wiring: a **signer**, a **claims resolver**, and a `RegisteredClientPolicy` (here behind a `CompositeClientPolicy` so the CLI grant still works). The signer + claims resolver are supplied by **overriding two getters on a controller subclass**, not by DI tokens — see [the override seam](#the-signer-claims-override-seam) for why.

```ts
import {
  CompositeClientPolicy,
  IdTokenSigner,
  LoopbackClientPolicy,
  OidcClaimsResolver,
  RegisteredClientPolicy,
  scopeGrants,
} from "@aooth/auth/authz";
import { AuthorizeController /* …tokens… */ } from "@aooth/auth-moost";
import { Controller, Inherit, Inject } from "moost";

// 1. A signer holds ONE asymmetric keypair. `issuer` is `{origin}/auth` — the exact
//    value a relying OidcProvider is configured with, so `id_token.iss` / `doc.issuer`
//    match byte-for-byte. Keys are imported lazily; construction is cheap.
const signer = new IdTokenSigner({
  issuer: `${PUBLIC_ORIGIN}/auth`,
  kid: "main-1",
  alg: "RS256", // default; OidcProvider accepts RS256/ES256
  privateKey: PKCS8_PEM,
  publicKey: SPKI_PEM,
});

// 2. Profile claims, read from YOUR user record and gated by the granted scope.
//    The registered claims (iss/aud/sub/iat/exp/nonce) are owned by the controller.
//    `email`/`name` are NOT base `UserCredentials` fields — they're whatever YOUR
//    user model declares (the base type carries no `email`; a login-handle email
//    is a consumer field tagged `@aooth.user.email`). Read your own columns here.
class MyClaimsResolver extends OidcClaimsResolver {
  async resolveClaims(userId: string, scope: string | undefined) {
    const user = await userService.getUser(userId); // UserService<YourUserModel>
    const claims: Record<string, unknown> = {};
    if (scopeGrants(scope, "email") && user.email) {
      claims.email = user.email;
      claims.email_verified = true;
    }
    return claims;
  }
}
const claims = new MyClaimsResolver();

// 3. Composite policy — loopback CLI (no client_id) + a registry of first-party clients.
const policy = new CompositeClientPolicy({
  loopback: new LoopbackClientPolicy(),
  registered: new RegisteredClientPolicy({
    clients: [
      {
        clientId: "billing-app",
        redirectUris: ["https://billing.example.com/auth/callback"],
        type: "confidential",
        clientSecret: BILLING_SECRET, // confidential → secret checked in constant time at /token
        scopes: ["openid", "email", "profile"], // granted = requested ∩ allowed
      },
    ],
  }),
});

// 4. Subclass the controller to wire the signer + claims resolver. moost@0.6.x does
//    NOT inherit @Inject / design:paramtypes across `extends`, so re-declare the ctor
//    with the SAME three tokens and forward to super().
@Inherit()
@Controller("auth")
class OidcAuthorizeController extends AuthorizeController {
  constructor(
    auth: AuthCredential,
    @Inject(CLIENT_REDIRECT_POLICY_TOKEN) p: ClientRedirectPolicy,
    @Inject(PENDING_AUTHORIZATION_STORE_TOKEN) pending: PendingAuthorizationStore,
    @Inject(AUTH_CODE_STORE_TOKEN) codes: AuthCodeStore,
  ) {
    super(auth, p, pending, codes);
  }
  protected override getIdTokenSigner() {
    return signer;
  }
  protected override getOidcClaimsResolver() {
    return claims;
  }
}

app.setProvideRegistry(
  createProvideRegistry(
    [AuthCredential, () => authCredential],
    [UserService, () => userService],
    [CLIENT_REDIRECT_POLICY_TOKEN, () => policy],
    [PENDING_AUTHORIZATION_STORE_TOKEN, () => new PendingAuthorizationStoreMemory()],
    [AUTH_CODE_STORE_TOKEN, () => new AuthCodeStoreMemory()],
  ),
);
app.registerControllers(OidcAuthorizeController);
```

## Consuming it — "the inbound grant and the outbound provider are two ends of the same wire"

A first-party sibling service signs in against the main app with the **existing** [`OidcProvider`](../idp/) — no new client code. Point it at the same `issuer`; discovery resolves `/authorize`, `/token`, and `/jwks` automatically:

```ts
import { OidcProvider } from "@aooth/idp";

const provider = new OidcProvider({
  issuer: "https://main.example.com/auth", // = the signer's issuer
  clientId: "billing-app",
  clientSecret: BILLING_SECRET,
});
// front-channel (your code): build /authorize URL → user logs in → capture code at redirect_uri
const profile = await provider.exchange({ code, redirectUri, codeVerifier, expectedNonce: nonce });
// → verified NormalizedProfile { provider, subject, email?, emailVerified?, displayName?, raw }
```

The whole federated leg (`beginSso`, `sso-callback`, account resolution, login-gate re-entry) then works exactly as it does for Google — the main app is just another OIDC provider to the sibling.

## The signer / claims override seam {#the-signer-claims-override-seam}

The `id_token` signer and claims resolver are **optional** (a Tier-1-only CLI deployment wires neither — then discovery / `/auth/jwks` 404 and no `id_token` is minted). They are supplied by **overriding two protected getters** on an `AuthorizeController` subclass, _not_ by DI tokens:

```ts
protected getIdTokenSigner(): IdTokenSigner | undefined { /* default: undefined */ }
protected getOidcClaimsResolver(): OidcClaimsResolver { /* default: NoopOidcClaimsResolver */ }
```

**Why a getter and not a token:** an OPTIONAL `@Inject`/`@Optional` dependency **panics** in moost's `resolveMoost` route-table pass (triggered by `AuthController`'s `@MoostInit` refresh-cookie hook — it re-instantiates the controller graph to discover handler paths, and an unprovided optional dependency throws _"Class is not Injectable and not Optional"_). A plain method has nothing for the resolver to walk, so it sidesteps the pass entirely. The mandatory deps (stores, client policy) stay on string tokens — they're always provided, so they resolve cleanly in that pass.

## Stores — fix the authority early, single-use the code

| Store                       | Holds                                                                                                                                                                         | TTL                         | Notes                                                                             |
| --------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------- | --------------------------------------------------------------------------------- |
| `PendingAuthorizationStore` | the in-flight request, keyed by an opaque `handle`: `{ clientId?, redirectUri, codeChallenge, clientState?, scope?, nonce?, idToken?, accessToken?, audience?, tokenPolicy }` | ≈ the login-session ceiling | The `handle` rides the login-wf ctx and survives a "Continue with Google" detour. |
| `AuthCodeStore`             | the minted code, keyed by the code: `{ userId, codeChallenge, redirectUri, clientId?, scope?, nonce?, idToken?, accessToken?, audience?, tokenPolicy, expiresAt }`            | ≈ 30–60 s                   | **`consume()` is single-use + atomic** — a reuse / double-redeem misses.          |

Both ship abstract + in-memory (tests) + an atscript-db adapter. The login workflow's `mint-authz-code` terminal resolves them through the `AuthorizeRuntime` DI holder (a `@Step` body can't `@Inject` a string token, so it instantiates `AuthorizeRuntime`, whose ctor resolves the two tokens).

## DOs / DON'Ts

- **DO** keep the trust gate (`resolveClient`) first at `/authorize` — until it passes there is no validated redirect, so a failure is a benign `400`, never a reflected redirect.
- **DON'T** infer a grant's authority at `/token`. It is fixed at `/authorize` from the policy and recorded on the code; `/token` only verifies PKCE + client auth and mints.
- **DO** register exact-match `redirectUris`. Reach for `redirectPrefixes` only for a tightly-scoped path prefix on a trusted origin — it is boundary-checked (URL-normalized to kill `..` traversal + a path-boundary after the prefix), but exact match is the safe default.
- **DO** set the signer's `issuer` to exactly `{origin}/auth` — a relying `OidcProvider` compares `id_token.iss` / `doc.issuer` for **exact** string equality (a trailing slash is stripped at construction).
- **DON'T** wire an `id_token` client without a signer — the token endpoint returns `500 server_error` (a misconfiguration, not a client error) rather than mint an unsigned identity assertion.
- **DON'T** send a `client_id` on a loopback (Tier 1) `/token` request — a code minted for a public loopback client must carry **no** `client_id`; a spurious one is rejected `401` to keep the binding symmetric.
- **DO** mount the `AuthorizeController` subclass (not the base) when you override the getters — registering the base class would mint `sub`-only tokens with no signer.

## See also

- [Federated Login (OAuth)](./oauth) — the outbound twin (aoothjs as an OAuth client).
- [`@aooth/idp` — Overview](../idp/) — the `OidcProvider` that consumes a Tier-2 deployment.
- [API: `@aooth/auth` → `authz` subpath](../api/auth#authz-subpath) — signer, policies, stores, claims resolver.
- [API: `@aooth/auth-moost` → Authorization server](../api/auth-moost#authorization-server) — controller endpoints, runtime, DI tokens.
- [REST Controllers](./controllers) — `AuthController` (`/auth/status` etc.), whose `@MoostInit` hook the override seam works around.
