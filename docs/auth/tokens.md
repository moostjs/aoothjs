# Tokens (JWT)

Tokens and sessions are **the same machinery** in `@aoothjs/auth` — same orchestrator, same store interface. The only difference is the `method` tag on `AuthCredential` and, usually, which store you pick. This page covers the two stateless stores: `CredentialStoreJwt` (signed) and `CredentialStoreEncapsulated` (encrypted).

## Stateful vs. stateless

| Aspect          | Stateful (Memory, Redis, AtscriptDb) | Stateless (JWT, Encapsulated)               |
| --------------- | ------------------------------------ | ------------------------------------------- |
| Token format    | Opaque UUID                          | Signed or encrypted blob carrying the state |
| Validation cost | One store roundtrip                  | Crypto verify only                          |
| Revocation      | Row delete                           | `DenylistStore` by `jti` + per-user epoch   |
| Enumeration     | `listForUser` works                  | Returns `[]` — cannot enumerate             |
| `maxConcurrent` | Enforced                             | Silently a no-op                            |
| Multi-instance  | Trivial                              | Needs distributed denylist & epoch          |

::: tip Choose by deployment shape
Single-instance apps with a database → stateful. High-fan-out APIs where each pod must validate without a DB hit → stateless JWT with a Redis-backed denylist.
:::

## `CredentialStoreJwt`

JWTs via `jose`. The token _is_ the state — the store signs at `persist`, verifies at `retrieve`, and uses a `DenylistStore` plus an in-memory per-user epoch map for revocation.

### Construction

```ts
import { CredentialStoreJwt, DenylistStoreMemory, AuthCredential } from "@aoothjs/auth";

const auth = new AuthCredential({
  store: new CredentialStoreJwt({
    algorithm: "HS256",
    secret: process.env.JWT_SECRET!,
    issuer: "my-app",
    audience: "my-app",
    denylist: new DenylistStoreMemory(),
  }),
  accessTtl: 15 * 60 * 1000,
  refresh: { ttl: 30 * 24 * 3600 * 1000, rotation: "always" },
});
```

### Options

```ts
interface CredentialStoreJwtOptions {
  algorithm?: JwtAlgorithm; // default 'HS256'
  secret?: string | Uint8Array | CryptoKey;
  privateKey?: CryptoKey;
  publicKey?: CryptoKey;
  issuer?: string;
  audience?: string;
  denylist?: DenylistStore;
  clock?: Clock;
}
```

| Option       | Required when                          | Purpose                                                                            |
| ------------ | -------------------------------------- | ---------------------------------------------------------------------------------- |
| `algorithm`  | always (or omit for `HS256`)           | Pins JWT `alg` header. See the algorithm table below.                              |
| `secret`     | `algorithm` is `HS*`                   | Symmetric secret. String → UTF-8 encoded. `Uint8Array`/`CryptoKey` passed through. |
| `privateKey` | `algorithm` is `RS*` / `ES*` / `EdDSA` | Used at `persist` (signing).                                                       |
| `publicKey`  | same as `privateKey`                   | Used at `retrieve` (verification).                                                 |
| `issuer`     | optional                               | Sets `iss` claim; checked at verify.                                               |
| `audience`   | optional                               | Sets `aud` claim (single string only); checked at verify.                          |
| `denylist`   | optional                               | Required for `revoke` / `consume` / `update`.                                      |
| `clock`      | optional                               | Injectable clock — drives `currentDate` for `jwtVerify`.                           |

### Algorithms

| Algorithm                           | Family          | Key shape                                          |
| ----------------------------------- | --------------- | -------------------------------------------------- |
| `HS256` (default), `HS384`, `HS512` | HMAC            | `secret` (string / Uint8Array / CryptoKey)         |
| `RS256`, `RS384`, `RS512`           | RSA-PKCS1-v1_5  | `privateKey` + `publicKey` (RSA, ≥ 2048 bits)      |
| `ES256`, `ES384`, `ES512`           | ECDSA           | `privateKey` + `publicKey` (P-256 / P-384 / P-521) |
| `EdDSA`                             | Ed25519 / Ed448 | `privateKey` + `publicKey`                         |

**Validation at construction**:

- HS\* without `secret` → `AuthError('INVALID_CONFIG')`.
- Asymmetric without both keys → `AuthError('INVALID_CONFIG')`.

```ts
// HS256 + secret
new CredentialStoreJwt({ algorithm: "HS256", secret: process.env.JWT_SECRET! });

// RS256 + keypair
import { importPKCS8, importSPKI } from "jose";
const privateKey = await importPKCS8(process.env.JWT_PRIV!, "RS256");
const publicKey = await importSPKI(process.env.JWT_PUB!, "RS256");
new CredentialStoreJwt({ algorithm: "RS256", privateKey, publicKey });

// EdDSA — small keys, fast verify
import { generateKeyPair } from "jose";
const { privateKey, publicKey } = await generateKeyPair("EdDSA");
new CredentialStoreJwt({ algorithm: "EdDSA", privateKey, publicKey });
```

::: tip HS\* vs. asymmetric
Use `HS*` when one process both signs and verifies. Use `RS*` / `ES*` / `EdDSA` when verifiers are distinct from issuers — public keys can ship to clients or partner services that need to verify without holding the signing key.
:::

### Wire format (for external verifiers)

When another service or library verifies these tokens directly (not via `auth.validate`), it sees standard JWT claims:

| Claim   | Source                         | Notes                                                                                         |
| ------- | ------------------------------ | --------------------------------------------------------------------------------------------- |
| `sub`   | `state.userId`                 | Subject.                                                                                      |
| `iat`   | `floor(state.issuedAt / 1000)` | RFC 7519: seconds.                                                                            |
| `exp`   | `floor(expiresAtMs / 1000)`    | RFC 7519: seconds.                                                                            |
| `jti`   | `randomUUID()`                 | Used as the denylist key.                                                                     |
| `iss`   | option                         | Only when configured.                                                                         |
| `aud`   | option                         | Only when configured.                                                                         |
| `state` | the rest                       | aoothjs-internal claim carrying the rest of the credential. External verifiers can ignore it. |

### Algorithm-confusion defense

`jose.jwtVerify` is called with an explicit allowlist:

```ts
await jwtVerify(token, key, { algorithms: [this.algorithm] });
```

This defeats the classic algorithm-confusion attack where an attacker forges a token with `alg: 'none'` or swaps an `RS256` token for `HS256` using the public key as a symmetric secret. **Never widen this allowlist.** The store pins exactly one algorithm per instance.

::: warning Pin one algorithm
The store accepts exactly the algorithm configured at construction. To rotate algorithms, run two stores in parallel — old for verify-only on legacy tokens, new for fresh issuance — never widen one store's `algorithms`.
:::

### Validation behavior

Every failure mode collapses to `null`. The store **never throws on validation**:

- Bad signature → `null`.
- Expired (`exp` < `clock.now()`) → `null`.
- Wrong `iss` / `aud` → `null`.
- `jti` in denylist → `null`.
- `state.iatMs < epoch[userId]` → `null`.
- Malformed JWT → `null`.

This is by design — `AuthCredential.validate` is a hot-path Boolean gate. Callers that need a reason should encode it elsewhere.

### Revocation on JWT

Stateless stores cannot delete the token (the client holds it), so revocation works in two layers:

1. **Per-credential** — `revoke(token)` adds the `jti` to the `DenylistStore` until `expiresAt`. After natural expiry the denylist entry can be cleaned up.
2. **Per-user** — `revokeAllForUser(userId)` bumps `epochs[userId] = clock.now()`. The next `validate` call rejects every token with `iatMs < epoch`.

::: warning JWT epoch map is in-memory
`CredentialStoreJwt` keeps the epoch map in process memory by default. A restart resets it; multi-instance deployments lose it across pods. For durable per-user revocation, back the epoch map externally (Redis hash, atscript table) — see [Stores](./stores).
:::

### `CredentialStoreJwt` and refresh

JWT is a stateless store, so the rotation interaction matters:

| `rotation`  | Works on JWT?                       | Requires denylist? |
| ----------- | ----------------------------------- | ------------------ |
| `'none'`    | yes                                 | no                 |
| `'always'`  | yes                                 | yes                |
| `'sliding'` | degraded — see [Refresh](./refresh) | yes                |

Without a `denylist`, `'always'` and `'sliding'` throw `STATELESS_OPERATION_UNSUPPORTED` on the first call to `consume`. With a denylist, they work as documented but the epoch map remains in-memory.

## `CredentialStoreEncapsulated`

When you want the token to carry the state but you also want **confidentiality**, not just integrity. The token is encrypted with AES-256-GCM; only the holder of the key can decrypt it.

### Construction

```ts
import { CredentialStoreEncapsulated } from "@aoothjs/auth";
import { randomBytes } from "node:crypto";

const key = randomBytes(32); // 32 bytes — skips the KDF path
const store = new CredentialStoreEncapsulated({ secret: key });
```

### Options

```ts
interface CredentialStoreEncapsulatedOptions {
  secret: string | Buffer | Uint8Array;
  denylist?: DenylistStore;
  clock?: Clock;
}
```

| Option     | Notes                                                                                                          |
| ---------- | -------------------------------------------------------------------------------------------------------------- |
| `secret`   | String → scrypt-derived to 32 bytes. `Uint8Array` of length 32 → used directly. Any other length → scrypt KDF. |
| `denylist` | Required for `revoke` / `consume` / `update`.                                                                  |
| `clock`    | Injected clock.                                                                                                |

### Token output

Tokens are URL-safe `base64url` strings. Decryption is authenticated — any tampering returns `null` from `validate`, never throws.

### Key derivation

When you pass a string `secret`, the store derives a 32-byte key via scrypt with a fixed library-level salt. That salt is for domain separation, **not** per-deployment uniqueness — `secret: "hunter2"` derives the same key on every machine.

::: tip Skip the KDF — pass a 32-byte buffer
Best practice: generate a 32-byte random key per environment and pass it directly. The store uses it as-is and avoids the scrypt step on every construction.

```ts
// node: pre-bake a key and store it as env (base64 / hex)
const key = Buffer.from(process.env.ENC_KEY_B64!, "base64");
new CredentialStoreEncapsulated({ secret: key });
```

:::

### When to use Encapsulated over JWT

| Want                                                                         | Use                                                            |
| ---------------------------------------------------------------------------- | -------------------------------------------------------------- |
| Public-key verification, third-party consumers                               | `CredentialStoreJwt` (RS\* / ES\*)                             |
| State must be opaque to the holder (confidential claims, sensitive metadata) | `CredentialStoreEncapsulated`                                  |
| Smallest possible token                                                      | `CredentialStoreEncapsulated` — no header / signature overhead |
| Standards compatibility (libraries that already speak JWT)                   | `CredentialStoreJwt`                                           |

Both stores share the same revocation semantics — `jti` denylist + per-user epoch. Encapsulated tokens are slightly smaller because there's no JWT header or signature, only the IV and auth tag.

## When stateless is the right choice

A stateless store is right when:

1. **No central DB on the validate path.** Pod-local validation, no Redis hit per request.
2. **Tokens cross trust boundaries.** Partner services can verify with a public key (RS\* / ES\* / EdDSA) without holding the signing key.
3. **TTL is short.** Revocation latency is bounded by TTL — short TTL means a forgotten denylist entry can't leak access for long.

It's wrong when:

1. **You need `listForUser`.** Stateless stores cannot enumerate. Active-sessions UIs need stateful.
2. **You need durable cross-pod revocation without an external store.** The in-memory epoch map is per-process.
3. **`maxConcurrent` matters.** It's a no-op without enumeration.

For a deployment that needs both short-lived stateless access tokens and durable revocation, pair `CredentialStoreJwt` with `DenylistStoreRedis` and back the epoch map with the same Redis client. See [Stores](./stores).

## Side-by-side example

```ts
import {
  AuthCredential,
  CredentialStoreJwt,
  CredentialStoreEncapsulated,
  DenylistStoreMemory,
} from "@aoothjs/auth";
import { randomBytes } from "node:crypto";

// Stateless JWT — public verification by third parties (asymmetric)
const jwtAuth = new AuthCredential({
  store: new CredentialStoreJwt({
    algorithm: "EdDSA",
    privateKey,
    publicKey,
    issuer: "auth.example.com",
    audience: "api.example.com",
    denylist: new DenylistStoreMemory(),
  }),
  accessTtl: 5 * 60 * 1000,
  refresh: { ttl: 7 * 24 * 3600 * 1000, rotation: "always" },
});

// Stateless encrypted — confidential claims
const encAuth = new AuthCredential({
  store: new CredentialStoreEncapsulated({
    secret: randomBytes(32),
    denylist: new DenylistStoreMemory(),
  }),
  accessTtl: 5 * 60 * 1000,
});
```

See the JWT store source at [packages/auth/src/credential-store-jwt.ts](https://github.com/moostjs/aoothjs/blob/main/packages/auth/src/credential-store-jwt.ts) and the encapsulated store at [packages/auth/src/credential-store-encapsulated.ts](https://github.com/moostjs/aoothjs/blob/main/packages/auth/src/credential-store-encapsulated.ts).
