# @aooth/idp

Framework-agnostic OAuth2 / OIDC federated-login core for [aoothjs](https://github.com/moostjs/aoothjs).

This is the **phase 2** layer of the [External IdP RFC](../../IDP.md): the portable
pieces that have no framework dependency — provider clients, PKCE/state primitives,
ID-token verification, and the account-resolution algorithm. The moost wiring
(`OAuthController`, the provider-login workflow, DI binding) lives in `@aooth/auth-moost`
(phase 3).

## What's here

- **`IdentityProvider`** — the provider abstraction (`authorizationUrl` / `exchange`).
- **`OidcProvider`** — generic OpenID Connect: discovery, remote JWKS, and the full
  OIDC Core 3.1.3.7 ID-token validation (pinned algs, `iss`/`aud`/`azp`, `exp`/`iat`/`nbf`
  with clock skew, `nonce`, `at_hash`). Fails **closed** on JWKS/discovery errors.
- **`GoogleProvider`** — `OidcProvider` pinned to Google's issuer + `RS256`.
- **`FakeIdentityProvider`** — deterministic, network-free, for unit + e2e tests.
- **`OAuthProviderRegistry`** — holds the providers + `FederatedPolicy` + shared
  signing/verification config; resolves `:provider`; builds the fixed `redirect_uri`.
- **PKCE / state** — `createPkcePair`, `generateNonce`, and `signState`/`verifyState`
  (a compact HS256 JWT binding random + provider + redirect + optional verifier/nonce).
- **`FederatedLoginService`** — `resolveUser(profile)` (known → email-match → new) and
  `linkIdentity` (interactive-link completion with the cross-user guard).

## Install

```bash
pnpm add @aooth/idp @aooth/user @aooth/auth
```

`@aooth/idp` depends on the concrete `UserService` (`@aooth/user`) and the shared
`Clock` (`@aooth/auth`), and uses [`jose`](https://github.com/panva/jose) for all
JWT/JWKS work.

## Security

Account matching by email is account-takeover sensitive — the default
`FederatedPolicy.emailMatch` is `require-interactive-link` (never silently merge).
See [IDP.md §4 / §7](../../IDP.md) for the full posture.
