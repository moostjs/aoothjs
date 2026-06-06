# Authorization server (CLI login + service SSO) — @aooth/auth-moost + @aooth/auth/authz

aoothjs AS an OAuth/OIDC **provider** for its OWN clients — the inbound twin of [federated login](oauth.md). One authorization-code + PKCE flow drives a real interactive login (password/MFA/consent, even mid-flow SSO); the only thing that varies is the injected **client/redirect policy** (+ whether an `id_token` signer is wired). Tier 1 = a CLI on a loopback redirect (access token); Tier 2 = a registered first-party service (`id_token`, "Sign in with the main app"), consumable by the existing [`OidcProvider`](idp.md). Framework-agnostic parts in `@aooth/auth/authz`; HTTP endpoints in `@aooth/auth-moost`.

## Quick start (Tier 2 — Tier 1 = just `LoopbackClientPolicy`, no signer)

```ts
import {
  CompositeClientPolicy,
  IdTokenSigner,
  LoopbackClientPolicy,
  OidcClaimsResolver,
  RegisteredClientPolicy,
  scopeGrants,
  AuthCodeStoreMemory,
  PendingAuthorizationStoreMemory,
} from "@aooth/auth/authz";
import {
  AuthorizeController,
  CLIENT_REDIRECT_POLICY_TOKEN,
  PENDING_AUTHORIZATION_STORE_TOKEN,
  AUTH_CODE_STORE_TOKEN,
} from "@aooth/auth-moost";
import { Controller, Inherit, Inject } from "moost";

const signer = new IdTokenSigner({
  issuer: `${ORIGIN}/auth`,
  kid: "main-1",
  alg: "RS256",
  privateKey: PKCS8_PEM,
  publicKey: SPKI_PEM,
}); // issuer = {origin}/auth, EXACTLY
class Claims extends OidcClaimsResolver {
  async resolveClaims(userId: string, scope?: string) {
    const u = await userService.getUser(userId);
    return scopeGrants(scope, "email") && u.email ? { email: u.email, email_verified: true } : {};
  }
}
const policy = new CompositeClientPolicy({
  loopback: new LoopbackClientPolicy(),
  registered: new RegisteredClientPolicy({
    clients: [
      {
        clientId: "billing-app",
        redirectUris: ["https://billing.example.com/cb"],
        type: "confidential",
        clientSecret: SECRET,
        scopes: ["openid", "email", "profile"],
      },
    ],
  }),
});

// moost@0.6.x does NOT inherit @Inject across `extends` → re-declare the ctor.
@Inherit()
@Controller("auth")
class OidcAuthorize extends AuthorizeController {
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
    return new Claims();
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
app.registerControllers(OidcAuthorize); // the SUBCLASS, not the base
```

## Invariants

| #   | Rule                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| --- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1   | **One flow, two pluggable policies.** Authorization-code + PKCE (S256) + back-channel `/token` is canonical for BOTH tiers. Tier 1 = `LoopbackClientPolicy` (any `127.0.0.1`/`[::1]`/`localhost` redirect, any port, public/no `client_id`, PKCE is the binding). Tier 2 = `RegisteredClientPolicy` (static registry; `client_id` + exact-match `redirectUris` allowlist + `public`/`confidential`). `CompositeClientPolicy` dispatches on **presence of `client_id`**.                                 |
| 2   | **Authority is fixed at `/authorize`, never at `/token`.** `policy.resolveClient` decides `tokenPolicy` + `id_token` intent + `aud` + granted `scope` (`requested ∩ allowed`); these are recorded on the `PendingAuthorizationStore` entry and copied onto the issued code. `/token` ONLY verifies PKCE + client auth and mints.                                                                                                                                                                        |
| 3   | **Trust gate FIRST.** `authorize` calls `resolveClient` before anything else — until it passes there is no validated `redirect_uri`, so a failure is a benign `400`, never a reflected redirect. Param errors AFTER the gate fail-soft to the validated redirect (`?error=`).                                                                                                                                                                                                                           |
| 4   | **`id_token` signer + claims resolver are GETTERS, not DI tokens.** An optional `@Inject`/`@Optional` dep PANICS in moost's `resolveMoost` route-table pass (triggered by `AuthController`'s `@MoostInit` refresh-cookie hook → _"Class is not Injectable and not Optional"_). Override `getIdTokenSigner()` / `getOidcClaimsResolver()` on a subclass; a method has nothing to resolve. The mandatory deps (policy + 2 stores) stay on string tokens (always provided → resolve cleanly in that pass). |
| 5   | **Register the SUBCLASS, not the base.** The base `AuthorizeController` returns `undefined` signer → `discovery`/`jwks` 404 + `sub`-only tokens. Re-declare the ctor with the SAME three `@Inject` tokens + `super(...)` (moost@0.6.x doesn't inherit `@Inject`/`design:paramtypes` across `extends`).                                                                                                                                                                                                  |
| 6   | **Signer `issuer` = `{origin}/auth`, EXACTLY.** A relying `OidcProvider` compares `id_token.iss` / discovery `doc.issuer` for exact string equality (RFC 8414). The signer canonicalises (strips a trailing slash) once so `iss` / `issuer` / derived endpoint URLs are byte-identical. `kid` is stamped in the JWS header AND the JWKS entry.                                                                                                                                                          |
| 7   | **`discovery` derives every endpoint from the signer's `issuer`** (`/authorize`, `/token`, `/jwks`), so a relying party configured with the same `issuer` resolves them automatically. Route is the dot-segment `@Get(".well-known/openid-configuration")` → `/auth/.well-known/openid-configuration` (registers fine in moost).                                                                                                                                                                        |
| 8   | **`OidcClaimsResolver` supplies PROFILE claims only** (`email`/`email_verified`/`name`), gated by `scopeGrants(scope, "email"\|"profile")`. The registered claims (`iss`/`aud`/`sub`/`iat`/`exp`/`nonce`) are owned by the controller. Default `NoopOidcClaimsResolver` → `sub`-only.                                                                                                                                                                                                                   |
| 9   | **Token-endpoint client binding is symmetric.** A code minted for a registered client MUST be redeemed with the matching `client_id` (+ `client_secret` for confidential — constant-time check); a code minted for a loopback CLI must carry NO `client_id` (a spurious one → `401 invalid_client`). An `id_token` client with no signer wired → `500 server_error` (misconfig, never mint unsigned).                                                                                                   |
| 10  | **Two short-lived stores, abstract + memory + atscript-db.** `PendingAuthorizationStore` (in-flight, keyed by opaque `handle`, ≈ login-session TTL; the handle rides the login-wf ctx and survives an SSO detour) + `AuthCodeStore` (single-use, `consume()` atomic, ≈30–60 s). Multi-pod → durable adapter under the same tokens. The login-wf `mint-authz-code` step resolves them via the `AuthorizeRuntime` DI holder.                                                                              |
| 11  | **"The inbound grant and the outbound provider are two ends of the same wire."** A first-party service consumes a Tier-2 deployment with `new OidcProvider({ issuer: "{origin}/auth", clientId, clientSecret })` — zero new client code; the whole federated leg (`beginSso`/`sso-callback`) works unchanged.                                                                                                                                                                                           |
| 12  | **`redirectPrefixes` is boundary-checked** (URL-normalize to kill `..` traversal + a path boundary after the prefix). Still prefer exact-match `redirectUris` — prefixes only for a tightly-scoped path on a trusted origin.                                                                                                                                                                                                                                                                            |

## Key imports

```ts
import {
  AuthorizeController,
  AuthorizeRuntime,
  CLIENT_REDIRECT_POLICY_TOKEN,
  PENDING_AUTHORIZATION_STORE_TOKEN,
  AUTH_CODE_STORE_TOKEN,
} from "@aooth/auth-moost";
import {
  IdTokenSigner,
  OidcClaimsResolver,
  NoopOidcClaimsResolver,
  scopeGrants,
  LoopbackClientPolicy,
  RegisteredClientPolicy,
  CompositeClientPolicy,
  isLoopbackRedirectUri,
  PendingAuthorizationStore,
  PendingAuthorizationStoreMemory,
  AuthCodeStore,
  AuthCodeStoreMemory,
  AuthorizeError,
} from "@aooth/auth/authz";
import type {
  ClientRedirectPolicy,
  ResolvedClient,
  RegisteredClient,
  TokenPolicy,
  IdTokenClaims,
  IdTokenAlg,
  AuthorizeErrorCode,
} from "@aooth/auth/authz";
import { OidcProvider } from "@aooth/idp"; // the relying party that consumes a Tier-2 deployment
```

## See also

- [oauth.md](oauth.md) — the OUTBOUND twin (aoothjs as an OAuth client / federated login).
- [idp.md](idp.md) — `OidcProvider.exchange`, the §7 id-token validation a relying party runs.
- [controllers.md](controllers.md) — `AuthController` (`@MoostInit` refresh-cookie hook the getter seam works around).
- Docs: [Authorization Server](https://aoothjs.dev/moost/authorization-server) · API: [`@aooth/auth/authz`](https://aoothjs.dev/api/auth#authz-subpath).
