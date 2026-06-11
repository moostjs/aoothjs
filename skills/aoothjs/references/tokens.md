# Tokens & sessions

Reference for the two stateless stores (`CredentialStoreJwt`, `CredentialStoreEncapsulated`), the JWT claim layout they emit, and the `method: 'session' | 'token'` discriminator that distinguishes long-lived sessions from short-lived bearer tokens. The stateful stores (`Memory`, `Redis`, `AtscriptDb`) are covered in [stores.md](./auth-stores.md).

## Contents

- [`CredentialStoreJwt` options](#credentialstorejwt-options)
- [Algorithm matrix](#algorithm-matrix)
- [JWT claim layout](#jwt-claim-layout)
- [Verification semantics](#verification-semantics)
- [`CredentialStoreEncapsulated`](#credentialstoreencapsulated)
- [Sessions vs tokens](#sessions-vs-tokens)

## `CredentialStoreJwt` options

`CredentialStoreJwtOptions`:

| Field         | Type                                | Default   | Meaning                                        |
| ------------- | ----------------------------------- | --------- | ---------------------------------------------- |
| `algorithm?`  | `JwtAlgorithm`                      | `'HS256'` | See the [algorithm matrix](#algorithm-matrix). |
| `secret?`     | `string \| Uint8Array \| CryptoKey` | unset     | HS\*: required.                                |
| `privateKey?` | `CryptoKey \| Uint8Array`           | unset     | Asymmetric: required.                          |
| `publicKey?`  | `CryptoKey \| Uint8Array`           | unset     | Asymmetric: required.                          |
| `issuer?`     | `string`                            | unset     | `'iss'` claim.                                 |
| `audience?`   | `string`                            | unset     | `'aud'` claim.                                 |
| `denylist?`   | `DenylistStore`                     | unset     | Required for `revoke` / `consume` / `update`.  |
| `clock?`      | `Clock`                             | unset     | Testability.                                   |

Exact shape: [docs api](https://aoothjs.dev/api/auth#credentialstorejwt-tpayload).

Missing HS `secret` → `AuthError('INVALID_CONFIG')`. Missing asymmetric `privateKey` or `publicKey` → `AuthError('INVALID_CONFIG')`. `clock` propagates from `AuthCredential` only if you wire it explicitly — pass the same instance to both for deterministic tests.

## Algorithm matrix

| Algorithm                   | Family     | Key material                        | When                                                                                |
| --------------------------- | ---------- | ----------------------------------- | ----------------------------------------------------------------------------------- |
| `HS256` (default)           | HMAC-SHA   | `secret: string \| Uint8Array` ≥32B | Single-deployment apps. Simplest. Symmetric — leak = forge.                         |
| `HS384` / `HS512`           | HMAC-SHA   | `secret` ≥48B / ≥64B                | Same use case, stronger hash. No perf benefit on short tokens.                      |
| `RS256` / `RS384` / `RS512` | RSA-PKCS#1 | PKCS#8 PEM (2048+ bits)             | Multiple services verify, only the issuer signs. Wide tool support.                 |
| `ES256` / `ES384` / `ES512` | ECDSA      | EC keys (P-256 / P-384 / P-521)     | Same as RS* but smaller tokens, faster verify. Prefer over RS* for new deployments. |
| `EdDSA`                     | Ed25519    | Ed25519 keys                        | Smallest, fastest, modern. Use when client libs support it.                         |

`jose` imports: `importPKCS8` for private, `importSPKI` for public, `generateKeyPair` for boot-time fresh keys. Aoothjs accepts the resulting `CryptoKey` or a raw `Uint8Array` (DER bytes) directly.

## JWT claim layout

Issued payload (`jose.SignJWT`):

| Claim   | Source                                                                         | Notes                                                                                                                                |
| ------- | ------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------ |
| `sub`   | `state.userId`                                                                 | Always set. Used by the per-user revocation epoch.                                                                                   |
| `iat`   | `floor(state.issuedAt / 1000)`                                                 | Second-resolution per RFC 7519.                                                                                                      |
| `exp`   | `floor(expiresAtMs / 1000)`                                                    | Second-resolution.                                                                                                                   |
| `jti`   | `randomUUID()`                                                                 | Denylist key. Persisted into the denylist on `revoke` / `consume` / `update`.                                                        |
| `iss`   | `options.issuer`                                                               | Only when configured.                                                                                                                |
| `aud`   | `options.audience`                                                             | Only when configured.                                                                                                                |
| `state` | `{ iatMs, expMs, kind?, claims?, metadata?, parentCredentialId?, rotatedAt? }` | Custom claim. `iatMs` / `expMs` mirror `iat` / `exp` at ms precision so `CredentialState.issuedAt` / `expiresAt` round-trip exactly. |

Verified state is rebuilt as:

```ts
{
  userId: payload.sub,
  issuedAt: state.iatMs ?? payload.iat * 1000,
  expiresAt: state.expMs ?? payload.exp * 1000,
  kind: state.kind,                     // 'access' | 'refresh' | undefined
  metadata: state.metadata,
  parentCredentialId: state.parentCredentialId,
  rotatedAt: state.rotatedAt,
  ...state.payload,                     // consumer's typed payload fields, merged FLAT
}
```

The ms-mirror fallback to `iat * 1000` lets externally minted tokens (no `state.iatMs`) still validate.

## Verification semantics

`jwtVerify` is called with:

```ts
{
  algorithms: [this.algorithm],
  issuer: this.issuer,
  audience: this.audience,
  currentDate: new Date(this.clock.now()),
}
```

- **Algorithm pinning** — `jose` infers a set from key shape by default; pinning blocks the algorithm-confusion attack. See [invariants.md](invariants.md) #17.
- **Clock injection** — every "is this expired" decision reads from the same `Clock`. Fake the clock to test expiry.
- **Errors collapse to `null`** — bad signature, expired, malformed, wrong `iss`/`aud`, non-string input all return `null` from `retrieve`. The store **never throws** during validation. The orchestrator throws `AuthError` only on `refresh` reuse, concurrency limits, or config issues.

## `CredentialStoreEncapsulated`

AES-256-GCM. Token = `base64url(iv(12) || ciphertext || authTag(16))` of `JSON.stringify({ ...state, jti })`. Opaque to clients — there is no JWT structure to inspect.

`CredentialStoreEncapsulatedOptions`:

| Field       | Type                             | Default      | Meaning                                                 |
| ----------- | -------------------------------- | ------------ | ------------------------------------------------------- |
| `secret`    | `string \| Buffer \| Uint8Array` | — (required) | 32B buffer = direct key; else scrypt KDF (rules below). |
| `denylist?` | `DenylistStore`                  | unset        | —                                                       |
| `clock?`    | `Clock`                          | unset        | —                                                       |

Exact shape: [docs api](https://aoothjs.dev/api/auth#credentialstoreencapsulated-tpayload).

KDF rules:

| Secret shape                        | KDF run?                    | Notes                                          |
| ----------------------------------- | --------------------------- | ---------------------------------------------- |
| `Buffer` / `Uint8Array` exactly 32B | No                          | Used directly as the AES-256 key. Recommended. |
| `Buffer` / `Uint8Array` ≠ 32B       | `scrypt(buf, KDF_SALT, 32)` | KDF expands or contracts to 32B.               |
| `string`                            | `scrypt(str, KDF_SALT, 32)` | Always — string secrets never bypass KDF.      |

`KDF_SALT = Buffer.from('aoothjs-auth-encapsulated-v1', 'utf8')`. The salt is **fixed library-wide on purpose** — a per-instance random salt would break every previously issued token across process restarts. Weak-passphrase deployments must supply a 32B random buffer to skip KDF entirely.

Decryption failures (tampered ciphertext, bad authTag, malformed base64, malformed JSON) all collapse to `null`. Same posture as JWT.

## Sessions vs tokens

`method: 'session' | 'token'` on `AuthCredentialOptions` is **just a label** carried into every `AuthContext`. Default `'token'`. The machinery is identical.

> For the multi-device "active sessions" model (listing signed-in devices, per-device revoke, `sessionId` token-families) see [sessions.md](sessions.md) — a different concept from this `method` label.

Conventional choices:

| Use case                                    | `method`    | Store                                                | `accessTtl`                 |
| ------------------------------------------- | ----------- | ---------------------------------------------------- | --------------------------- |
| Stateless API bearer tokens                 | `'token'`   | `CredentialStoreJwt`                                 | 5 min – 1 h                 |
| Server-side sessions                        | `'session'` | `CredentialStoreMemory` / `Redis` / `AtscriptDb`     | Hours to weeks              |
| Single-use magic links                      | `'token'`   | Any stateful store, OR stateless **with** a denylist | Minutes — TTL is the gate   |
| Long-lived refresh paired with short access | `'token'`   | Any                                                  | Short access + long refresh |

`AuthContext.credentialId` is always `sha256(accessToken)` regardless of `method`. Safe to use as a session id in databases, audit logs, or revocation UIs.
