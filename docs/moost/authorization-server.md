# Authorization Server (CLI login, service SSO, MCP connectors)

The **inbound twin** of [Federated Login](./oauth). There, aoothjs is the OAuth **client** of an external IdP ("Continue with Google"). Here, aoothjs is the OAuth/OIDC **authorization server** for its OWN clients — a local **CLI** on a loopback redirect, a registered **first-party service** ("Sign in with the main app"), or a **self-registered connector** (an MCP client like a claude.ai custom connector that discovers the server, registers itself, and drives the user through login + consent). One authorization-code + PKCE flow drives a real interactive login (password, MFA, consent, even a mid-flow "Continue with Google"); the only thing that varies between the cases is the injected **client/redirect policy** (and, for service SSO, whether an `id_token` is signed).

The framework-agnostic pieces — the two short-lived stores, the client/redirect policies, the `id_token` signer, the claims resolver, the token policy, and the error taxonomy — live in [`@aooth/auth/authz`](../api/auth#authz-subpath). This page is the moost HTTP layer: the `AuthorizeController` endpoints and the DI wiring.

## Where it sits

```
client opens browser →
  GET /auth/authorize?response_type=code&client_id?&redirect_uri&state
                       &code_challenge&code_challenge_method=S256&scope?&nonce?
    → policy.resolveClient(...)  ← TRUST GATE: authorize client + redirect_uri (+ scope) FIRST
    → PendingAuthorizationStore.create(...)  ← ALL authority fixed HERE (tokenPolicy, id_token
                              intent, audience, granted scope, nonce) + a browser-binding secret
    → 302 /login?authz=<opaque handle>  + Set-Cookie: aooth_authz=<binding>  (httpOnly, Lax)
                                             ← the SPA forwards the handle into auth/login/flow
  → user authenticates (password / MFA / mid-flow SSO) →
      `authz-consent` terminal: re-verify the aooth_authz browser binding, then the user
          explicitly APPROVES the client (Deny → 302 redirect_uri?error=access_denied, no code) →
      `mint-authz-code` terminal mints a single-use CODE bound to ctx.subject + the recorded
          authority, and 302s redirect_uri?code=&state=
  → POST /auth/token { grant_type, code, code_verifier, client_id?, client_secret? }
    → consume code (single-use) → verify PKCE → authenticate client (Tier 2 / DCR) →
      mint access_token and/or id_token  ← minted HERE, off the browser
      (+ refresh_token when the grant's TokenPolicy opted in)
    → { token_type, access_token?, expires_in?, refresh_token?, id_token?, userId }
  → POST /auth/token { grant_type: "refresh_token", refresh_token, client_id, client_secret? }
    → authenticate client → verify the family's client binding → ROTATE
    → { token_type, access_token, expires_in, refresh_token, userId }

# Tier 2 only:
GET /auth/.well-known/openid-configuration   → OIDC discovery (derived from the signer's issuer)
GET /auth/jwks                               → the signer's public JWKS

# Discovery + registration (MCP connectors; signer NOT required):
GET  /auth/.well-known/oauth-authorization-server → RFC 8414 AS metadata (needs only getIssuer())
POST /auth/register                               → RFC 7591 dynamic client registration (when wired)
```

The grant's authority is **fixed at `/authorize` time** (the policy's [`TokenPolicy`](../api/auth#authz-subpath), `id_token` intent, `aud`, and granted scope are recorded on the pending authorization and copied onto the issued code), **never inferred at `/token`**. Nothing long-lived ever rides a redirect URL — only the single-use `code` does.

## Two tiers, one flow

|                          | Client / redirect policy                                                                                                                                                                                                                                                                                                                                                                                  | What the token endpoint mints                                                                                                                                                                                         |
| ------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Tier 1 — CLI**         | `LoopbackClientPolicy` — any `127.0.0.1` / `[::1]` / `localhost` redirect, any port (RFC 8252); public client, PKCE is the binding; no `client_id`.                                                                                                                                                                                                                                                       | A full-authority `cli-session` **access token** for the main API (no `id_token`).                                                                                                                                     |
| **Tier 2 — service SSO** | `RegisteredClientPolicy` — a static registry; each client has a `client_id`, an exact-match (or strict-prefix) `redirect_uri` allowlist, a `public`/`confidential` type, and what it may receive.                                                                                                                                                                                                         | An **`id_token`** (RS256/ES256, `aud` = `client_id`), optionally also an access token. Consumable by the existing [`OidcProvider`](../idp/).                                                                          |
| **MCP connectors — DCR** | `DynamicClientPolicy` — RFC 7591 self-registered clients from a `DynamicClientStore`, public (`"none"`, PKCE-bound) or confidential (`"client_secret_post"` — a server-minted secret, disclosed once, hash-stored, checked at `/token`); exact-match `https` redirects (loopback entries are port-agnostic per RFC 8252); granted scope = requested ∩ a **server** allow-list ∩ the registration's scope. | An **access token** with the configured `tokenPolicy` (e.g. `{ kind: "mcp-session", ttl: 30d }`), plus a **rotating `refresh_token`** when the policy sets `refresh`. **No `id_token`** — connectors are plain OAuth. |

Run them side by side with `CompositeClientPolicy`, which dispatches on the **presence and ownership of `client_id`** — no `client_id` is a loopback CLI; a `client_id` belongs to the static registry when it knows the id (`hasClient`, static-first so a dynamic registration can never shadow a static client), else to the dynamic policy. The same picker drives `authenticateClient` at `/token`.

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

The memory stores are single-process; a multi-pod deployment swaps the durable `PendingAuthorizationStoreAtscriptDb` / `AuthCodeStoreAtscriptDb` (from `@aooth/auth/atscript-db`, backed by the `@aooth/auth/atscript-db/pending-authorization` + `…/auth-code` models) under the **same** tokens — no controller change. `AuthorizeController.loginPath()` defaults to `/login` — override it in a subclass for a custom login route. The CLI side ships ready-made as [`@aooth/login-client`](/api/login-client) — a zero-dependency `authorize()` helper that does the whole round-trip (generate `state` + PKCE → open the browser → await the one-shot loopback callback → verify `state` → `POST /auth/token`), with headless/SSH support via `openBrowser: false` + `onUrl` and typed `AuthorizeError` codes.

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

## Wiring — MCP connectors (dynamic client registration) {#wiring-mcp-connectors}

Connector-style MCP clients (claude.ai custom connectors and anything implementing the MCP authorization spec) **cannot set headers** — the user pastes a resource URL and the client expects to _discover_ the authorization server (RFC 9728 + RFC 8414), _register itself_ (RFC 7591), and run the standard code + PKCE grant. Four pieces on top of the Tier-1 wiring:

```ts
import {
  CompositeClientPolicy,
  DynamicClientPolicy,
  DynamicClientRegistration,
  LoopbackClientPolicy,
} from "@aooth/auth/authz";
import { DynamicClientStoreAtscriptDb } from "@aooth/auth/atscript-db";
import { AuthorizeController, DYNAMIC_CLIENT_STORE_TOKEN /* …tokens… */ } from "@aooth/auth-moost";

// 1. The client store — durable (model: @aooth/auth/atscript-db/dynamic-client,
//    an empty-extension consumer model + syncSchema), or DynamicClientStoreMemory
//    for tests. One instance backs BOTH the policy and the registration op.
const dynamicClients = new DynamicClientStoreAtscriptDb({ table: db.getTable(MyDynamicClient) });

// 2. The registration operation behind POST /auth/register, with the abuse knobs:
//    a reject-when-full cap (used registrations are NEVER evicted — a connector
//    caches its client_id), lazy GC of never-used registrations, and an optional
//    guard hook (throw ClientRegistrationError to reject). Rate limiting stays
//    at your ingress.
const registration = new DynamicClientRegistration({
  store: dynamicClients,
  maxClients: 1000,
  unusedClientTtlMs: 24 * 60 * 60_000,
});

// 3. The policy — what a dynamic grant mints, and the SERVER-side scope bound
//    (never trust the registration's self-declared scope as the allow-set).
//    `refresh` opts the grant into the OAuth 2.1 refresh_token grant: the token
//    endpoint pairs a rotating refresh token with the access token, so the
//    connector silently refreshes at expiry instead of re-running consent.
const policy = new CompositeClientPolicy({
  loopback: new LoopbackClientPolicy(),
  dynamic: new DynamicClientPolicy({
    store: dynamicClients,
    tokenPolicy: {
      kind: "mcp-session",
      ttl: 60 * 60_000, // short access token …
      refresh: { ttl: 60 * 24 * 60 * 60_000 }, // … long rotating grant (60 d)
    },
    allowedScopes: ["read", "write"],
  }),
  // registered: …  ← add the Tier-2 registry too; static ids win the dispatch.
});

// 4. The controller subclass: the issuer (RFC 8414 works WITHOUT a signer) and
//    the registration getter. Inject the store under DYNAMIC_CLIENT_STORE_TOKEN
//    if you prefer DI; the BASE controller never injects it (optional @Inject
//    panics in moost's route pass — same seam as the signer).
@Inherit()
@Controller("auth")
class McpAuthorizeController extends AuthorizeController {
  constructor(/* …same 4 ctor params + super() as Tier 2… */) {
    /* … */
  }
  protected override getIssuer() {
    return `${PUBLIC_ORIGIN}/auth`; // byte-exact; NEVER derive from the Host header
  }
  protected override getDynamicClientRegistration() {
    return registration;
  }
  protected override scopesSupported() {
    return ["read", "write"];
  }
}
```

With that, `GET /auth/.well-known/oauth-authorization-server` serves RFC 8414 metadata (no signer needed — `getIssuer()` is the only requirement; with a Tier-2 signer wired it defaults to the signer's issuer and also advertises `jwks_uri`), `POST /auth/register` accepts registrations, and **both** discovery documents advertise `registration_endpoint` when a signer is also present. Registration normalizes per RFC 7591 §2: an unsupported grant is intersected away and the 201 echo of the **narrowed** set is the contract (the supported set is `authorization_code` + `refresh_token`, and the result must still include `authorization_code`); `token_endpoint_auth_method` defaults to `"none"` and also accepts `"client_secret_post"` — a **confidential** registration (what claude.ai's connector platform sends) is echoed once with the minted `client_secret` + `client_secret_expires_at: 0`, only the SHA-256 digest is stored, and the secret is then required on every token-endpoint call; an explicit ask for anything else (e.g. `client_secret_basic`) is rejected, never silently downgraded (narrow with `validation.allowedTokenEndpointAuthMethods: ["none"]` for a public-only deployment); `client_name` is sanitized (control/format/bidi characters stripped) and rendered on the consent prompt **as text, next to the validated redirect host** — the host is where the code is actually delivered, which a self-chosen name can't fake.

### Root-mounted discovery (what the controller cannot serve)

Two documents belong at the **HTTP-server root**, which a prefix-mounted controller can't register — mount them yourself from the exported builders (re-exported by `@aooth/auth-moost`):

```ts
import {
  buildAuthorizationServerMetadata, // RFC 8414 — the path-insertion form
  buildProtectedResourceMetadata, // RFC 9728 PRM (resource-server side)
  buildWwwAuthenticateBearerChallenge, // the 401 challenge header VALUE
} from "@aooth/auth-moost";

@Controller()
class WellKnownController {
  // RFC 8414 path-insertion form for an issuer mounted at /auth — clients try
  // this BEFORE the {issuer}/.well-known suffix form the controller serves.
  // Same builder + issuer ⇒ byte-identical documents.
  @Get(".well-known/oauth-authorization-server/auth")
  @Public()
  meta() {
    return buildAuthorizationServerMetadata({
      issuer: `${PUBLIC_ORIGIN}/auth`,
      registrationEndpoint: `${PUBLIC_ORIGIN}/auth/register`,
    });
  }

  // RFC 9728 — which authorization server guards this resource.
  @Get(".well-known/oauth-protected-resource")
  @Public()
  prm() {
    return buildProtectedResourceMetadata({
      resource: `${PUBLIC_ORIGIN}/mcp`,
      authorizationServers: [`${PUBLIC_ORIGIN}/auth`],
    });
  }
}

// And on the protected resource's 401 (this header starts the whole discovery):
res.setHeader(
  "WWW-Authenticate",
  buildWwwAuthenticateBearerChallenge({
    resourceMetadataUrl: `${PUBLIC_ORIGIN}/.well-known/oauth-protected-resource`,
  }),
);
```

The challenge builder is framework-light (a header-value string) and sanitizes every value (control characters stripped, quotes escaped) so attacker-influenced strings can't split the response. The demo's `makeMcpDemoController` (packages/e2e-demo) is the working reference for all three mounts.

::: warning Two deployment pitfalls (both observed against real claude.ai traffic)

**Bare-origin discovery + SPA catch-alls.** Connector clients also resolve `/.well-known/oauth-authorization-server` and `/.well-known/oauth-protected-resource` at the **bare origin**, ignoring the issuer's path component. If an SPA catch-all answers those paths with `200 text/html`, the client parses the HTML as the metadata document and aborts — a poisoned discovery that looks like a client-side mystery. Every path-issuer deployment must serve **both root aliases** (same builders, same issuer) and hard-404 every other `/.well-known/*` path before the catch-all.

**CORS.** Backend-side connectors (claude.ai) don't need it, but browser-based MCP clients (inspector-class) run discovery, DCR and the token exchange from the page. The metadata endpoints, `/register`, and `/token` need `Access-Control-Allow-Origin: *` plus OPTIONS preflight handling. `*` is correct there — they are public, credential-free surfaces (the "credential" is the request body, not a cookie) — and deliberately wrong for the cookie-carrying session endpoints; scope the header to the authz paths only.
:::

### The `resource` parameter (RFC 8707)

`/authorize` and `/token` accept `resource`. v1 **records + consistency-checks** it: a repeated or oversized value fails with `invalid_target` (never silently truncated), a mismatch between the two legs is `400 invalid_target`, and one-sided presence is accepted. There is **no audience enforcement** — access tokens are opaque credentials consumed by the same origin that minted them, so cross-resource confusion doesn't arise; the recorded value stays on the grant so a future multi-resource deployment can enforce it without re-minting.

### Connector token lifecycle — the `refresh_token` grant {#refresh-token-grant}

Set `refresh: { ttl? }` on the grant's `TokenPolicy` (default grant lifetime 30 days — `DEFAULT_AUTHZ_REFRESH_TTL_MS`) and the token endpoint pairs the access token with a **rotating refresh token**; `POST /auth/token` with `{ grant_type: "refresh_token", refresh_token, client_id, client_secret? }` redeems it. Like everything else in the policy, the refresh dimension is fixed at `/authorize` time and recorded on the pending authorization + code — never inferred at `/token`. The semantics:

- **Client-bound.** The family is stamped with the grant's `client_id` (`metadata.authzClientId`) and redeems only for that client, authenticated the same way as the code branch (a confidential client presents its secret). A browser-session refresh token — or another client's — is a plain `invalid_grant`, checked **before** anything rotates. Clientless Tier-1 loopback grants have nothing to bind to, so they **ignore** `refresh`.
- **One-time use with rotation** (OAuth 2.1 §4.3.1): every redemption returns a fresh access + refresh pair; the family's lifetime is a **fixed ceiling** (the policy's `refresh.ttl` from the original grant — rotation never extends it). A short (30 s) grace window tolerates a benign concurrent double-refresh; **replay beyond it revokes the whole family** — the standard theft response, riding `AuthCredential`'s existing family revocation.
- **Authority never widens.** `kind`, `payload`, and the policy's access-token `ttl` ride the credential family (the per-mint ttl is stamped as `metadata.accessTtl`), so a refreshed access token carries exactly the authority fixed at authorize time — with refresh available, set a **short** access `ttl` and let the refresh ttl carry the long-lived grant.
- **Response shape:** `{ token_type, access_token, expires_in, refresh_token, userId }` in the JSON body — connectors are header-transport clients; no cookies. Failures are RFC 6749 §5.2: `invalid_request` (no token), `invalid_client` (401 — missing/unauthenticated client), `invalid_grant` (unknown/rotated/foreign token).

There is still **no RFC 7009 revocation endpoint** — the revocation path is your own sessions surface: pick a dedicated `kind` (e.g. `mcp-session`) so connector grants show up under `listSessions(userId, { kind: "mcp-session" })` and users can revoke them (revocation kills the whole family, refresh included). Policies **without** `refresh` behave as before: access token only, re-consent at expiry. Operators MAY disable DCR entirely (don't wire the getter) and fall back to a statically pre-registered connector via `RegisteredClientPolicy` — its callback URL is fixed and the connector UI accepts a manually-entered client id — at the cost of "paste URL and it works" UX.

::: warning Schema migration
The `aooth_pending_authorizations` / `aooth_auth_codes` models gained nullable `clientName` / `resource` columns. Run your schema sync before serving connector traffic — connector clients **always** send `resource`, so an un-synced column fails at the `/authorize` insert.
:::

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

| Store                       | Holds                                                                                                                                                                                  | TTL                         | Notes                                                                                                                                                                                                                               |
| --------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `PendingAuthorizationStore` | the in-flight request, keyed by an opaque `handle`: `{ clientId?, redirectUri, codeChallenge, clientState?, scope?, nonce?, idToken?, accessToken?, audience?, tokenPolicy, binding }` | ≈ the login-session ceiling | The `handle` rides the login-wf ctx and survives a "Continue with Google" detour. `binding` is the per-request browser-binding secret ([Consent gate](#consent-gate-browser-binding)) — a custom durable store **must** persist it. |
| `AuthCodeStore`             | the minted code, keyed by the code: `{ userId, codeChallenge, redirectUri, clientId?, scope?, nonce?, idToken?, accessToken?, audience?, tokenPolicy, expiresAt }`                     | ≈ 30–60 s                   | **`consume()` is single-use + atomic** — a reuse / double-redeem misses.                                                                                                                                                            |

Both ship abstract + in-memory (tests) + an atscript-db adapter. The login workflow's `mint-authz-code` terminal resolves them through the `AuthorizeRuntime` DI holder (a `@Step` body can't `@Inject` a string token, so it instantiates `AuthorizeRuntime`, whose ctor resolves the two tokens).

## Consent gate & browser binding {#consent-gate-browser-binding}

Two defenses run **before** `mint-authz-code` mints a code, so a logged-in (or silently re-authenticated) browser cannot be walked into delivering a code to a client it never approved. Both are built in — you don't wire anything.

**1. Browser binding (the `aooth_authz` cookie).** `GET /auth/authorize` mints a high-entropy `binding` secret, records it on the pending authorization, and drops it as an `httpOnly; SameSite=Lax` `aooth_authz` cookie. The `authz-consent` step constant-time-matches that cookie against the stored secret before doing anything; a mismatch (or absence) fails closed — no prompt, no code. The opaque `authz` handle alone is a bearer ticket, so phishing it into a **different** browser would otherwise let an attacker's client receive a code minted for the victim. The binding closes that: the secret lives only in the browser that started the request, so the handle can be redeemed **only** in that browser. `SameSite=Lax` is deliberate — the cookie must still ride the top-level GET back from a "Continue with Google" detour.

**2. Explicit consent (the `authz-consent` step).** After authentication the run pauses on the bundled `AuthorizeConsentForm` (the `authzConsent` slot in [`opts.forms`](./workflows)): the user sees which client + scope is asking and must press **Authorize**. **Deny** (or abandoning) 302s the client back with `error=access_denied` and mints nothing. The form is a standard workflow form — it renders through `<AsWfForm>` with no bespoke component, and you override its copy by swapping `opts.forms.authzConsent` for an `extends AuthorizeConsentForm` subclass (import it from [`@aooth/auth-moost/atscript`](../api/auth-moost)).

The mint step runs **only** after consent stamps approval on the run, so a deny / binding failure leaves its own finish intact (a benign error, or the `access_denied` redirect) — `mint-authz-code` never overwrites it. `AuthorizeController` sets the cookie via the package-exported [`AUTHZ_BINDING_COOKIE`](../api/auth-moost) name + `authzBindingCookieAttrs` (parallel to the federated `OAUTH_CSRF_COOKIE`); reference the name if a reverse proxy filters cookies by allowlist.

### Consent-only for live sessions {#consent-only}

By default every authorize leg re-collects credentials, even seconds after the user logged into your app (`mode: 'always-reauth'`). Opt into the GitHub/Google-style behavior — a live browser session goes **straight to the consent screen** — by overriding one policy getter on your workflow subclass:

```ts
import type { AuthWfCtx, AuthzReauthPolicy } from "@aooth/auth-moost";

class AppAuthWorkflow extends AuthWorkflow {
  protected override resolveAuthzReauthPolicy(_ctx: AuthWfCtx): AuthzReauthPolicy {
    return { mode: "consent-only" };
  }
}
```

Under `consent-only`, `init-login` probes the trigger request's session (authz runs only — a plain login visit never probes): a valid credential binds the subject and the run skips the credentials form **and the MFA loop** (the session already proved its factors at login), pausing directly on `AuthorizeConsentForm` — which now names the acting identity ("Signed in as …") so a wrong-account grant is catchable. Every probe failure — no session, expired/garbage credential, deleted/locked/deactivated account — falls back silently to the credentials path with no 401 leak. Both consent-gate defenses above are untouched: the browser binding is checked before any prompt (a phished handle is inert even in a session-holding browser) and Authorize/Deny still gates the mint.

Two optional knobs on the policy:

- `maxSessionAgeMs` — GitHub-sudo-style freshness ceiling against the **session origin** (`SessionInfo.createdAt`, stable across refresh rotation). An older session — or a legacy token with no `sessionId` to prove its origin — falls back to credentials.
- `requireMfa: true` — keep the MFA challenge loop on the silent path (only the password form is skipped).

Silent-run semantics worth knowing: a silent consent is **not a login event** — `record-login` is skipped (no `lastLogin` stamp, no `afterLogin` hook, no `isFirstLogin`-gated steps), while account-hygiene gates (forced channel enrolment, terms bumps) still apply exactly as after a fresh login, seeded from the user row. Transport precondition: the flow trigger route must **see** the session credential — true for cookie-carried sessions on a same-origin SPA, or when your SPA replays the access token as a `Authorization: Bearer` header on trigger calls — and the [auth guard](./config) must be mounted on it.

## DOs / DON'Ts

- **DO** keep the trust gate (`resolveClient`) first at `/authorize` — until it passes there is no validated redirect, so a failure is a benign `400`, never a reflected redirect.
- **DON'T** infer a grant's authority at `/token`. It is fixed at `/authorize` from the policy and recorded on the code; `/token` only verifies PKCE + client auth and mints.
- **DO** register exact-match `redirectUris`. Reach for `redirectPrefixes` only for a tightly-scoped path prefix on a trusted origin — it is boundary-checked (URL-normalized to kill `..` traversal + a path-boundary after the prefix), but exact match is the safe default.
- **DO** set the signer's `issuer` to exactly `{origin}/auth` — a relying `OidcProvider` compares `id_token.iss` / `doc.issuer` for **exact** string equality (a trailing slash is stripped at construction).
- **DON'T** wire an `id_token` client without a signer — the token endpoint returns `500 server_error` (a misconfiguration, not a client error) rather than mint an unsigned identity assertion.
- **DON'T** send a `client_id` on a loopback (Tier 1) `/token` request — a code minted for a public loopback client must carry **no** `client_id`; a spurious one is rejected `401` to keep the binding symmetric.
- **DO** mount the `AuthorizeController` subclass (not the base) when you override the getters — registering the base class would mint `sub`-only tokens with no signer.
- **DO** serve `loginPath()` on the **same origin** as `/auth/authorize` — the `aooth_authz` binding cookie is host-scoped; a cross-origin login route never receives it, so `authz-consent` fails closed and no code is ever minted. ([Consent gate](#consent-gate-browser-binding).) The same applies to connector flows: the binding cookie is `SameSite=Lax`, so a login UI on a different registrable domain than the issuer fails closed — that needs a deliberate, separately-reviewed cookie change, not a quiet flip.
- **DO** persist the `binding` field in any custom durable `PendingAuthorizationStore` — the consent gate matches the cookie against it; drop it and every authorize request fails the binding check.
- **DON'T** derive `getIssuer()` from the request's Host header — the metadata document is cacheable, and a request-controlled host would be injected into every client's view of your endpoints. Configure it.
- **DON'T** treat a DCR registration's `scope` as the allow-set — it is attacker-supplied (it also feeds the consent copy). The grant is bounded by `DynamicClientPolicyOptions.allowedScopes`, the server-side list.
- **DO** size `maxClients` and keep `unusedClientTtlMs` on — `/register` is anonymous by spec. The cap rejects-when-full; never evict used registrations (a connector caches its `client_id`, and evicting it strands the user's connector).
- **DO** make the session credential reach the flow trigger route before flipping to `consent-only` — the probe reads the auth context the guard stashed for that request; a trigger the session cookie/bearer never reaches silently behaves like `always-reauth`. ([Consent-only](#consent-only).)

## See also

- [Federated Login (OAuth)](./oauth) — the outbound twin (aoothjs as an OAuth client).
- [`@aooth/idp` — Overview](../idp/) — the `OidcProvider` that consumes a Tier-2 deployment.
- [API: `@aooth/auth` → `authz` subpath](../api/auth#authz-subpath) — signer, policies, stores, claims resolver.
- [API: `@aooth/auth-moost` → Authorization server](../api/auth-moost#authorization-server) — controller endpoints, runtime, DI tokens.
- [REST Controllers](./controllers) — `AuthController` (`/auth/status` etc.), whose `@MoostInit` hook the override seam works around.
