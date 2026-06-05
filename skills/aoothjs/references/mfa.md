# mfa

Pure-Node TOTP / HOTP primitives, SHA-256 MFA-code helpers for email/SMS challenges, and HMAC-bound trusted-device tokens. Backup codes are **not** a bundled primitive.

## Contents

- [What this package owns (and what it doesn't)](#what-this-package-owns-and-what-it-doesnt)
- [TOTP](#totp)
- [TOTP enrollment + QR](#totp-enrollment--qr)
- [otpauth URI for QR codes](#otpauth-uri-for-qr-codes)
- [`generateMfaCode` + `hashMfaCode` + `verifyMfaCode`](#generatemfacode--hashmfacode--verifymfacode)
- [Backup codes](#backup-codes)
- [Trusted-device tokens](#trusted-device-tokens)

## What this package owns (and what it doesn't)

**Wired here:**

- TOTP secret generation, otpauth URI generation, code generation, and constant-time window verification.
- One-time MFA code helpers (`generateMfaCode` + `hashMfaCode` + `verifyMfaCode`) for email/SMS challenges — challenge **state machine** lives in `@aooth/auth`.
- `UserService.verifyTotpSetupCode` (enroll-confirm) + `verifyMfa` (login-time), both reading the user's stored `totp` secret.
- Trusted-device token minting + HMAC verification (`UserService.issueTrustedDevice` / `verifyTrustedDevice`).
- `UserService.verifyMfa` shares the lockout counter with `login` (see [user-service.md § The login sequence](./user-service.md#the-login-sequence)).

**NOT here:**

- No email / SMS transport — `MfaMethod.value` is stored verbatim, delivery is `@aooth/auth`'s job.
- No WebAuthn / FIDO2.
- **No backup / recovery codes.** No `generateBackupCodePlaintext` export, no `UserService.generateBackupCodes` / `consumeBackupCode`. See [Backup codes](#backup-codes).
- `verifyMfa` is TOTP-only; non-TOTP method names participate in `addMfaMethod` / `confirmMfaMethod` bookkeeping but are not verified by this package.
- **No HTTP enrollment flow.** The bundled, ARBAC-gated "add a second factor" workflow (`auth/add-mfa/flow`) that orchestrates `addMfaMethod` + `confirmMfaMethod` for a signed-in user — pick transport → enter address / scan QR → verify pincode — lives in `@aooth/auth-moost`. See [workflows.md § add-mfa (invariant 16)](workflows.md#invariants). The unenroll direction is `UserService.removeMfaMethod(userId, name)` — no bundled flow.

## TOTP

```ts
import { generateTotpSecret, generateTotpUri, generateTotpCode, verifyTotpCode } from "@aooth/user";

const secret = generateTotpSecret(); // 20-byte base32-encoded, padding stripped, uppercased
const uri = generateTotpUri(secret, "MyApp", "alice@example.com");
const code = generateTotpCode(secret); // current step's 6-digit code
const ok = verifyTotpCode(secret, "123456");
```

### `generateTotpSecret(bytes = 20) → string`

Cryptographically-random `randomBytes`, base32-encoded with `=` padding stripped, uppercased to match the `otpauth://` URI convention (RFC 4648).

### `generateTotpCode(secret, config?) → string`

RFC-4226 HOTP at the current TOTP step. `TotpConfig`:

```ts
interface TotpConfig {
  period?: number; // seconds per step — default 30
  digits?: number; // code length — default 6
  window?: number; // verify-only — default 1 (verify ±1 step)
  clock?: () => number;
}
```

Counter is `Math.floor((clock() / 1000) / period)`. Dynamic truncation per RFC 4226 §5.3. Output is zero-padded to `digits`.

### `verifyTotpCode(secret, code, config?) → boolean`

- Decodes the base32 secret once and reuses the key across window checks.
- **Rejects mismatched-length submissions** (`code.length !== digits`) before reaching `timingSafeEqual`, which requires equal-length buffers. This also closes a length-probe side channel.
- Walks the **entire** `[-window..window]` range unconditionally — an early-window match doesn't return faster than a late-window one. `matched` is set on hit, but the loop runs to completion.

```ts
verifyTotpCode(secret, code, { window: 2, clock: () => fixedNow });
```

Pass a `clock` for deterministic tests.

## TOTP enrollment + QR

The enroll-confirm verifier is `UserService.verifyTotpSetupCode(id, code, config?)` — it verifies the first code against the user's **unconfirmed** `totp` method and flips it to `confirmed: true` in one call (throws `MFA_INVALID` on a bad code). Use it instead of a manual `verifyTotpCode` + `confirmMfaMethod` pair. Service methods key on the surrogate `id`; `username` below is only the TOTP URI label.

```ts
const secret = generateTotpSecret();
const uri = generateTotpUri(secret, "MyApp", username); // username = display label
await svc.addMfaMethod(id, { name: "totp", value: secret, confirmed: false });
// render `uri` as a QR → user scans → submits first code
await svc.verifyTotpSetupCode(id, submittedCode, { window: 1 });
```

In the moost stack, the bundled `EnrollConfirmForm.qrCode` field carries the `otpauth://` URI plus `@ui.form.component 'AsQrCode'`, so the SPA's `AsQrCode` component (from `@atscript/vue-aooth`) renders the scannable QR + manual base32 secret. See [spa-components.md](./spa-components.md).

## otpauth URI for QR codes

```ts
generateTotpUri(secret, "MyApp", "alice@example.com", { period: 30, digits: 6 });
// → otpauth://totp/MyApp:alice%40example.com?secret=...&issuer=MyApp&algorithm=SHA1&digits=6&period=30
```

| Param       | Source                                                         |
| ----------- | -------------------------------------------------------------- |
| label       | `${encodeURIComponent(issuer)}:${encodeURIComponent(account)}` |
| `secret`    | the base32 secret (verbatim — already URL-safe)                |
| `issuer`    | encoded `issuer`                                               |
| `algorithm` | always `SHA1` (Google Authenticator / etc.)                    |
| `digits`    | `config?.digits ?? 6`                                          |
| `period`    | `config?.period ?? 30`                                         |

Only SHA1 is emitted — the wider ecosystem (Authenticator, 1Password, Authy) all rely on it. If your verifier accepts other HMAC algorithms, you're on your own; `verifyTotpCode` here also assumes SHA1.

## `generateMfaCode` + `hashMfaCode` + `verifyMfaCode`

For email / SMS / out-of-band challenges where the user types a code you delivered.

```ts
import { generateMfaCode, hashMfaCode, verifyMfaCode } from "@aooth/user";

const plaintext = generateMfaCode(); // 6 digits — default
const plaintext8 = generateMfaCode(8);
const hash = hashMfaCode(plaintext); // SHA-256 hex
sendByEmail(plaintext);

// ... later, on the verify step ...
const ok = verifyMfaCode(submitted, hash); // constant-time, SHA-256 hex compare
```

| Function                                 | Behavior                                                                                                                   |
| ---------------------------------------- | -------------------------------------------------------------------------------------------------------------------------- |
| `generateMfaCode(length = 6)`            | Cryptographically-random digits-only string. Charset `"0123456789"`.                                                       |
| `hashMfaCode(code) → hex`                | SHA-256, hex-encoded. Stable comparable output regardless of input case/format.                                            |
| `verifyMfaCode(submitted, expectedHash)` | Re-hashes `submitted`, decodes both to buffers, `timingSafeEqual`s. Returns `false` for empty hashes or length mismatches. |

These power the challenge-ticket pattern used by `@aooth/auth` (the package stores `{ codeHash, expiresAt }` and verifies the user-submitted plaintext via `verifyMfaCode`).

## Backup codes

**Not bundled.** There is no `generateBackupCodePlaintext` export and no `UserService.generateBackupCodes` / `consumeBackupCode` method. `UserCredentials.backupCodes?: string[]` exists as a reserved slot, but no shipped API reads or writes it.

Compose recovery codes from the primitives above: generate random codes yourself, hash each with `hashMfaCode`, store the hashes via `users.update(id, { backupCodes })`, and verify a submitted code with `verifyMfaCode` against the stored hashes (removing the matched hash). Wrap consume in a store-layer transaction if you need strict one-shot semantics.

## Trusted-device tokens

```ts
import { UserService } from "@aooth/user";

const svc = new UserService(store, {
  deviceTrust: { secret: process.env.DEVICE_TRUST_SECRET! },
});

const record = svc.issueTrustedDevice("user_alice", {
  ip: "203.0.113.4",
  ttlMs: 30 * 24 * 3600 * 1000,
  name: "alice's MacBook",
});
await svc.addTrustedDevice("alice", record);

// later, on a fresh login...
const trusted = await svc.verifyTrustedDevice("alice", req.cookies.dt, req.ip);
```

**Token:** opaque HMAC-signed string bound to the user (and optionally their IP). The HMAC key is `config.deviceTrust.secret` — `issue` / `verify` throw a plain `Error` if it's unset. Expiry (`clock() + ttlMs`) is enforced on `verifyTrustedDevice`. Persistence: `addTrustedDevice` appends, `revokeTrustedDevice` filters, `listTrustedDevices` returns the full list.

`verifyTrustedDevice` succeeds when **all** hold:

1. The token signature verifies.
2. A persisted record matches `token` exactly.
3. `record.expiresAt > clock()`.
4. `record.ip === undefined || record.ip === ip` (IP-binding when the record carries an `ip`).

IP-binding is opt-in per-token: omit `ip` on `issue` and `verify` accepts any IP on subsequent calls for that record. Pin to an IP only when you want strict device-per-network semantics.
