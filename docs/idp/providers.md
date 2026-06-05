# Providers

A provider turns an external IdP into a uniform two-method contract: build the authorization URL, then exchange the returned `code` for a **verified, normalized profile**. `@aooth/idp` ships a generic OIDC provider, a Google preset, a GitHub (OAuth2) provider, an Apple (Sign in with Apple) provider, and a deterministic fake for tests.

## The contract

```ts
interface IdentityProvider {
  readonly id: string; // 'google', 'oidc:<issuer>', … — also the federated `provider` column
  authorizationUrl(args): Promise<string>; // the 302 target
  exchange(args): Promise<NormalizedProfile>; // code → tokens → verify → normalize
}
```

`exchange()` returns a `NormalizedProfile`:

```ts
interface NormalizedProfile {
  provider: string;
  subject: string; // the IdP's stable `sub` — the durable join key
  email?: string;
  emailVerified?: boolean;
  displayName?: string;
  avatarUrl?: string;
  raw: unknown; // transient — never persisted on the federated row
}
```

See the [API reference](/api/idp) for the full `authorizationUrl` / `exchange` argument shapes.

## `OidcProvider` — generic OpenID Connect

```ts
import { OidcProvider } from "@aooth/idp";

const provider = new OidcProvider({
  issuer: "https://accounts.example.com", // exact issuer — discovered + validated
  clientId: process.env.OIDC_CLIENT_ID!,
  clientSecret: process.env.OIDC_CLIENT_SECRET!,
  // scopes default to ['openid', 'email', 'profile']
});
```

On first use it fetches `${issuer}/.well-known/openid-configuration` (cached), then resolves the JWKS via `jose`'s `createRemoteJWKSet`. To skip discovery (tests, or a non-discovery IdP) pass `authorizationEndpoint` + `tokenEndpoint` + `jwksUri` explicitly, or inject a `discovery` document / a `jwks` resolver.

### ID-token validation (OIDC Core 3.1.3.7)

`exchange()` runs the **full** validation list, not just signature + expiry:

| Check         | Behavior                                                                                                                                                          |
| ------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Signature     | Verified against the provider JWKS.                                                                                                                               |
| `alg`         | Pinned to the configured asymmetric set (default `['RS256','ES256']`). `none` / HS\* are **rejected** — guards the `alg:none` / RS256→HS256 key-confusion bypass. |
| `iss`         | Must exactly equal the configured issuer.                                                                                                                         |
| `aud`         | Must contain `clientId`.                                                                                                                                          |
| `azp`         | When `aud` has more than one entry, `azp` must equal `clientId`.                                                                                                  |
| `exp/iat/nbf` | Checked with a bounded `clockToleranceSec` (default `5`).                                                                                                         |
| `nonce`       | When an `expectedNonce` is passed, `id_token.nonce` must match.                                                                                                   |
| `at_hash`     | When an access token **and** the `at_hash` claim are both present, the hash is verified.                                                                          |

Failures map to typed `OAuthError`s: claim/signature failures → `ID_TOKEN_INVALID`; JWKS/discovery fetch failures → `JWKS_FAILED` (**fail closed** — never a silent accept); token-endpoint network/5xx/`code`-reuse → `EXCHANGE_FAILED`. See [Errors](./account-resolution#errors).

## `GoogleProvider`

A thin `OidcProvider` pinned to Google's issuer and `RS256`:

```ts
import { GoogleProvider } from "@aooth/idp";

const google = new GoogleProvider({
  clientId: process.env.GOOGLE_CLIENT_ID!,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET!,
});
// provider.id === 'google'; everything else (discovery, JWKS, §7 validation) is inherited.
```

`email_verified` is taken **strictly** from the boolean ID-token claim — a non-boolean value yields `emailVerified: undefined` (no string-truthiness coercion). Whether you trust it for auto-linking is a policy decision — see [Account resolution](./account-resolution).

## `GithubProvider` — OAuth2 (no OIDC)

GitHub is pure OAuth2 — there is **no** ID token, JWKS, or nonce. After the authorization-code + PKCE exchange, the profile is read from GitHub's REST API:

```ts
import { GithubProvider } from "@aooth/idp";

const github = new GithubProvider({
  clientId: process.env.GH_CLIENT_ID!,
  clientSecret: process.env.GH_CLIENT_SECRET!,
  // scopes default to ['read:user', 'user:email']
});
// provider.id === 'github'
```

`exchange()` redeems the `code` (the token endpoint is asked for JSON), then `GET /user` and `GET /user/emails`. `subject` is `String(user.id)` (the stable numeric id), `displayName` is `name ?? login`, and `avatarUrl` is `avatar_url`.

**`emailVerified` is strict** (the account-takeover-sensitive bit): it is `true` **only** when the user's **primary** `/user/emails` entry is GitHub-verified. A non-primary or unverified address — or a fall-back to the public `/user` email when the `user:email` scope is absent — yields `emailVerified: false`. So a GitHub email is never trusted as proof-of-control unless it is the verified primary. GitHub is deliberately **out** of the recommended `trustEmailVerifiedFrom` default.

> GitHub's REST API rejects requests without a `User-Agent`; the provider sends one (`'aoothjs'` by default, override via `userAgent`). Endpoints are overridable (`tokenEndpoint` / `userEndpoint` / `emailsEndpoint`) for GitHub Enterprise.

## `AppleProvider` — Sign in with Apple (OIDC + `form_post`)

Apple **is** an OpenID Connect provider (issuer `https://appleid.apple.com`), so `AppleProvider` extends `OidcProvider` and inherits the full §7 ID-token validation, JWKS rotation, discovery, and PKCE. It overrides only what Apple does differently:

```ts
import { AppleProvider } from "@aooth/idp";

const apple = new AppleProvider({
  clientId: process.env.APPLE_SERVICES_ID!, // the Services ID (OAuth client_id / aud)
  teamId: process.env.APPLE_TEAM_ID!, // 10-char Developer Team ID
  keyId: process.env.APPLE_KEY_ID!, // the .p8 key's Key ID
  privateKey: process.env.APPLE_PRIVATE_KEY!, // the .p8 EC P-256 key, PKCS#8 PEM
  // scopes default to ['openid', 'email'] (name is deferred — see below)
});
// provider.id === 'apple'
```

| What Apple does differently   | How `AppleProvider` handles it                                                                                                                                                                                                                                                    |
| ----------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **No static client secret**   | The `client_secret` is a short-lived **ES256 JWT** signed with the `.p8` key (`iss=teamId`, `sub=clientId`, `aud=https://appleid.apple.com`, header `kid`). Minted on demand and cached until ~1 min before its `exp` (default TTL 1 h, `clientSecretTtlSec`).                    |
| **`response_mode=form_post`** | Required whenever `email`/`name` scope is requested, so the callback is a cross-site **POST**. `AppleProvider` declares it on the authorize URL; `@aooth/auth-moost`'s `OAuthController` bounces that POST back to the normal GET callback (see [moost — OAuth](../moost/oauth)). |
| **String `email_verified`**   | Apple violates OIDC by sending `email_verified` as the string `"true"`/`"false"`; `AppleProvider` coerces it after the base's strict boolean-only pass.                                                                                                                           |

> The user's **name** arrives only on the _first_ authorization, in the `form_post` `user` field (never in the ID token). v1 deliberately does **not** capture it, so `displayName` is `undefined` for Apple — collect a display name post-signup if you need one.

## `FakeIdentityProvider` — deterministic, no network

For unit tests (and the integration test harness): `exchange()` resolves a `code` to a pre-registered profile, so a full resolve flow runs offline.

```ts
import { FakeIdentityProvider } from "@aooth/idp";

const fake = new FakeIdentityProvider({ id: "google" }).setProfile("code-1", {
  subject: "sub-1",
  email: "ada@example.com",
  emailVerified: true,
  raw: {},
});
const profile = await fake.exchange({ code: "code-1", redirectUri: "x", codeVerifier: "v" });
// { provider: 'google', subject: 'sub-1', email: 'ada@example.com', emailVerified: true, raw: {} }
```

It is the trusted test double — it does **not** verify the nonce. The real OIDC nonce / JWKS / `at_hash` assertions are exercised against `OidcProvider` with `jose`.

## DOs / DON'Ts

- **DO** keep the `redirect_uri` fixed per provider (`baseUrl` + the callback path) and exact-match-registered at the IdP — `OAuthProviderRegistry.redirectUri(id)` builds it. The `exchange()` `redirectUri` must byte-equal the one used at authorization time.
- **DON'T** add a generic / custom OIDC issuer to `trustEmailVerifiedFrom` unless it owns and strictly verifies the email and never recycles the `sub`↔email binding.
- **DON'T** persist `NormalizedProfile.raw` or the provider's access/refresh tokens — they're transient.

## See also

- [Account resolution & linking](./account-resolution) — what happens to a verified profile.
- [API reference](/api/idp) — full signatures.
- [Auth — Tokens](../auth/tokens) — the `jose`-backed credential issuance the resolved user flows into.
