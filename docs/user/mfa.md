# MFA Primitives

`@aooth/user` ships **primitives**, not a delivery system. This page documents what's in the package — TOTP secret/URI/code/verify, one-time MFA-code helpers, backup codes, trusted devices — and what's deliberately out of scope.

## What's here vs. what's not

| Capability                                                                 | Where it lives                                  |
| -------------------------------------------------------------------------- | ----------------------------------------------- |
| TOTP secret generation, otpauth URI, code generation, constant-time verify | `@aooth/user/mfa/totp`                          |
| SHA-256 one-time-code hash + verify (for email/SMS challenges)             | `@aooth/user/mfa/codes`                         |
| Backup-code plaintext generation (alphabet, formatting)                    | `@aooth/user/mfa/backup-codes`                  |
| `UserService.verifyMfa` (TOTP) + lockout-counter sharing                   | `@aooth/user/user-service`                      |
| Trusted-device HMAC tokens + IP binding                                    | `@aooth/user/user-service`                      |
| **Email / SMS delivery**                                                   | Your transport layer (or `@aooth/auth` senders) |
| **Challenge state machine** ("issue OTP → wait → verify within N min")     | `@aooth/auth` + `@aooth/auth-moost` workflows   |
| **WebAuthn / FIDO2**                                                       | Not provided                                    |

The split is deliberate: this package keeps the primitives pure so you can compose them into any workflow (HTTP, CLI, custom).

## TOTP

Sources: [`packages/user/src/mfa/totp.ts`](https://github.com/moostjs/aoothjs/blob/main/packages/user/src/mfa/totp.ts).

### Generate a secret

```ts
import { generateTotpSecret } from "@aooth/user";

const secret = generateTotpSecret(); // 20 random bytes, base32-encoded, unpadded, uppercase
const secret32 = generateTotpSecret(32); // optional byte length
```

The output is the **base32-encoded** secret as plain ASCII — that's the format authenticator apps expect. Store it in `MfaMethod.value`.

### Build the otpauth URI (for QR codes)

```ts
import { generateTotpUri } from "@aooth/user";

const uri = generateTotpUri(secret, "AcmeCorp", "alice@acme.dev", {
  period: 30, // default 30 s
  digits: 6, // default 6
});
// → "otpauth://totp/AcmeCorp:alice@acme.dev?secret=...&issuer=AcmeCorp&algorithm=SHA1&digits=6&period=30"
```

Render it through any QR encoder (`qrcode`, `qrcode-svg`) on enrollment. The algorithm is fixed at **SHA1** — that's what every consumer authenticator app supports universally.

### Generate / verify codes

```ts
import { generateTotpCode, verifyTotpCode } from "@aooth/user";

const code = generateTotpCode(secret); // RFC-4226 HOTP at the current TOTP step
verifyTotpCode(secret, code); // → true
verifyTotpCode(secret, code, { window: 1 }); // ± 1 step (≈ ±30 s) for clock drift
verifyTotpCode(secret, code, { period: 60 }); // 60 s steps
```

`verifyTotpCode` walks the full `[-window..+window]` range; verification is constant-time and length-checked, so a mismatched-length code returns `false` without leaking timing or step information.

### Wiring into a user

```ts
// 1. enrollment
const secret = generateTotpSecret();
const uri = generateTotpUri(secret, "AcmeCorp", username);
await users.addMfaMethod(username, { name: "totp", value: secret, confirmed: false });
// render uri as QR → user scans → enters first code

// 2. confirm
if (verifyTotpCode(secret, submittedCode, { window: 1 })) {
  await users.confirmMfaMethod(username, "totp");
}

// 3. login-time verify (uses the user's stored secret internally)
await users.verifyMfa(username, submittedCode, { window: 1 });
```

`UserService.verifyMfa` reads the stored `totp` method, calls `verifyTotpCode` under the hood, and **shares the lockout counter with `login`** — combined `login + verifyMfa` failures count toward the same `failedLoginAttempts`, not two separate counters.

## One-time MFA codes (email / SMS)

For challenges where you mail a 6-digit code, hash it before storing the expected value.

```ts
import { generateMfaCode, hashMfaCode, verifyMfaCode } from "@aooth/user";

// at challenge issue
const code = generateMfaCode(); // default 6 digits, crypto-random
const expectedHash = hashMfaCode(code); // SHA-256 hex
// send `code` to user via email/SMS, persist `expectedHash` with a TTL

// at submit
verifyMfaCode(submitted, expectedHash); // timingSafeEqual after re-hash
```

`generateMfaCode(length)` accepts a custom length; output is digits-only.

::: tip Persistence is your problem
This package does **not** persist the issued challenge or its TTL. Use `@aooth/auth` (or your own short-lived KV) for the challenge state machine. The primitives here are pure.
:::

## Backup codes

```ts
import { generateBackupCodePlaintext } from "@aooth/user";

const codes = generateBackupCodePlaintext(10);
// → ["XK7P-M2N3-AB", "9QHF-DTUV-2W", ...]
```

| Property      | Value                                                          |
| ------------- | -------------------------------------------------------------- |
| Default count | `10`                                                           |
| Alphabet      | `ABCDEFGHJKMNPQRSTUVWXYZ23456789` (no `I`, `O`, `L`, `0`, `1`) |
| Format        | `XXXX-XXXX-XX` (3 groups, dash-separated)                      |
| Length        | 10 alphabet chars + 2 dashes = 12 chars                        |
| Source        | `crypto.randomBytes`                                           |

The alphabet drops visually ambiguous characters so users transcribing from paper don't confuse `O` with `0` or `I` with `1`.

### Service-level wrappers

```ts
// generate + persist hashes; return plaintext ONCE
const plaintext = await users.generateBackupCodes("alice", 10);
// show `plaintext` to the user immediately; never persist it

// consume on use
const ok = await users.consumeBackupCode("alice", submitted);
```

`generateBackupCodes` replaces the **entire** existing batch — there's no append. Only hashes (`hashMfaCode`-style SHA-256) are stored in `backupCodes[]`.

::: warning `consumeBackupCode` is not atomic
The service reads `backupCodes`, finds a matching hash, removes it, writes the trimmed array back. Two concurrent consumes of the same code can both succeed against most stores. Wrap in a transaction at the store layer if strict one-shot semantics matter.
:::

## Trusted devices

A trusted-device token lets a user skip MFA on a remembered device. The package mints an opaque HMAC token; you store it (cookie, localStorage) and present it on subsequent logins.

```ts
const users = new UserService(store, {
  deviceTrust: { secret: process.env.DEVICE_TRUST_SECRET },
});

// issue
const record = users.issueTrustedDevice("user-id-123", {
  ip: req.ip, // optional — binds the token to this IP
  ttlMs: 30 * 24 * 60 * 60_000, // 30 days
  name: "My Laptop",
});
await users.addTrustedDevice("alice", record);
res.cookie("trusted_device", record.token, { httpOnly: true });

// verify on a later request
const ok = await users.verifyTrustedDevice("alice", req.cookies.trusted_device, req.ip);
if (ok) skipMfa();
```

The token is an opaque HMAC-signed string bound to the user (and optionally their IP).

| Check in `verifyTrustedDevice`          | Behavior                         |
| --------------------------------------- | -------------------------------- |
| Signature mismatch                      | `false` (counterfeit / tampered) |
| `expiresAt < now`                       | `false` (expired)                |
| Issued with `ip` and request IP differs | `false` (IP binding)             |
| Token not in `trustedDevices[]`         | `false` (revoked)                |

::: warning Requires `deviceTrust.secret`
`issueTrustedDevice` throws a plain `Error` if `config.deviceTrust.secret` is unset. Set it in production before exposing trust-this-device UI.
:::

`revokeTrustedDevice` removes a specific token. `listTrustedDevices` returns the raw records (token, ip, issuedAt, expiresAt, name) for a "manage your devices" page.

## Masking for UI

When showing the user a "send code to" picker, you want the masked target, not the raw email/phone.

```ts
import { maskEmail, maskPhone, maskMfaValue } from "@aooth/user";

maskEmail("alice@acme.dev"); // → "a***e@acme.dev"
maskPhone("+15551234567"); // → "+1******4567"
maskMfaValue({ name: "email", confirmed: true, value: "alice@acme.dev" });
// → "a***e@acme.dev"
```

`UserService.getAvailableMfaMethods(mfa)` runs `maskMfaValue` for each confirmed method and returns `{ name, masked }[]` — safe to send to the client.

## See also

- [`UserService.verifyMfa`](./service#verifymfa) — the lockout-aware verify path.
- [Credentials Model — `mfa` sub-object](./credentials#mfa-mfadata).
- `@aooth/auth` — challenge state machine, email/SMS senders.
