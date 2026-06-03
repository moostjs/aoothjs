# Providers

A provider turns an external IdP into a uniform two-method contract: build the authorization URL, then exchange the returned `code` for a **verified, normalized profile**. `@aooth/idp` ships a generic OIDC provider, a Google preset, and a deterministic fake for tests.

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
