# Password Hashing

`PasswordHasher` is the scrypt-based hasher behind `UserService`. This page documents pepper, history rotation, `generatePassword`, scrypt cost tuning, and how to surface policy errors after a failed change.

Source: [`packages/user/src/password/hasher.ts`](https://github.com/moostjs/aoothjs/blob/main/packages/user/src/password/hasher.ts).

## API

```ts
import { PasswordHasher } from "@aooth/user"

new PasswordHasher(config?: PasswordConfig)

hasher.hash(password: string): Promise<string>
hasher.verify(password: string, encodedHash: string): Promise<boolean>
hasher.generatePassword(length?: number /* default 16 */): string
```

## Config

| Field           | Type     | Default | Effect                                                           |
| --------------- | -------- | ------- | ---------------------------------------------------------------- |
| `pepper`        | `string` | `""`    | Prepended to the password before scrypt. App-wide secret.        |
| `historyLength` | `number` | `0`     | How many old hashes `UserService` keeps in `password.history[]`. |
| `scryptN`       | `number` | `16384` | scrypt cost (CPU/memory). Power of two.                          |
| `scryptR`       | `number` | `8`     | scrypt block size.                                               |
| `scryptP`       | `number` | `1`     | scrypt parallelization.                                          |
| `keyLength`     | `number` | `64`    | Derived key length, bytes.                                       |

Most consumers don't construct `PasswordHasher` directly — `UserService` does it from `config.password`. Use `users.getPasswordHasher()` if you need direct access.

## Self-describing hashes

Hashes carry their scrypt parameters inline, so raising `scryptN` in config tomorrow doesn't break yesterday's hashes — `verify` always runs scrypt with the parameters baked into the stored value. Existing records re-hash at the current cost the next time the user changes their password.

## Hash + verify example

```ts
import { PasswordHasher } from "@aooth/user";

const hasher = new PasswordHasher({ pepper: process.env.PEPPER });

const stored = await hasher.hash("S3cret!");

await hasher.verify("S3cret!", stored); // → true
await hasher.verify("wrong", stored); // → false
await hasher.verify("S3cret!", "not-a-hash"); // → false (no throw)
```

`verify` returns `false` for any parse failure or mismatch; it never throws on bad input.

## Pepper

The **pepper** is a static, app-wide string prepended to the password before scrypt runs:

```
scrypt(pepper + password, salt, N, r, p, keyLength)
```

It's stored separately from the DB (env var, secrets manager, KMS) so that a database dump alone is not enough to mount an offline attack. Without the pepper an attacker has to brute-force scrypt **and** guess the pepper.

::: warning Pepper is irrecoverable
Losing the pepper invalidates **every** stored hash — there's no salvage path. Treat it like a DB master key:

- Store in a secrets manager (Vault, AWS SM, GCP SM).
- Mount as env var; never commit it.
- Rotate via app-level dual-write: read with both old and new peppers during transition, write with new, retire old after every active user has logged in.

The hasher does not know rotation natively — that's an app-layer concern.
:::

## Password history

`UserService.changePassword` and `UserService.setPassword` enforce no-reuse against the current hash **plus** every entry in `password.history[]`. The checks run in parallel via `Promise.all`.

```ts
const users = new UserService(store, {
  password: { historyLength: 5 },
});

await users.changePassword("alice", "old", "old");
// throws PASSWORD_IN_HISTORY (same as current)

await users.changePassword("alice", "old", "new1");
await users.changePassword("alice", "new1", "new2");
// password.history[] now: [hash(old), hash(new1)]

await users.changePassword("alice", "new2", "old");
// throws PASSWORD_IN_HISTORY
```

Setting `historyLength: 0` disables history checks entirely (current hash is still checked).

## `generatePassword`

```ts
hasher.generatePassword(length?: number): string  // default 16
```

Uses crypto-random selection and guarantees at least one character from each enabled category (lowercase, uppercase, digit, special). Category-chars are not in fixed positions.

```ts
hasher.generatePassword(); // → "kF2#mPq8N&xL3$wY"
hasher.generatePassword(24); // → 24 chars, same guarantees
```

`UserService.createUser(username)` (no password argument) uses this and sets `password.isInitial = true` so the auth layer can force a change on first login.

## Cost tuning

The defaults (`N=16384, r=8, p=1, keyLength=64`) target ~50 ms on a modern x86 server core. Raise `scryptN` to a higher power of two (32768, 65536, ...) to slow the hash as hardware improves:

```ts
// 2026 defaults — about ~100 ms per hash
const users = new UserService(store, {
  password: { scryptN: 32768, pepper: process.env.PEPPER },
});
```

Because the hash string carries N/r/p/l, **existing hashes still verify**. They get re-written at the new cost the next time the user changes their password. If you need a forced re-hash, run a job that calls `setPassword` for every user (e.g. on a forced password reset).

## Surfacing policy errors after `changePassword` fails

When `changePassword` (or `setPassword`) fails the policy check, it throws `UserAuthError` with `type: 'POLICY_VIOLATION'`. The `details.errors: string[]` field carries one human-readable message per failing rule, taken from each policy's `errorMessage` (or `description` as fallback).

```ts
import { UserAuthError } from "@aooth/user";

try {
  await users.changePassword(username, current, next);
} catch (err) {
  if (err instanceof UserAuthError && err.type === "POLICY_VIOLATION") {
    // err.details?.errors → ["Must be at least 12 characters", "Must contain a number"]
    return res.status(422).json({ errors: err.details?.errors ?? [] });
  }
  throw err;
}
```

For a richer UI (per-rule pass/fail state, not just the failing ones), call `users.checkPolicies(candidate)` against the candidate password as the user types — that returns the full `{ passed, policies: [{ description, passed }], errors }` shape without throwing.

## Testing

Production scrypt is slow on purpose. For tests, drop the cost so each hash takes single-digit ms:

```ts
const FAST_SCRYPT = { scryptN: 1024, scryptR: 1, scryptP: 1, keyLength: 32 };
const users = new UserService(new UserStoreMemory(), { password: FAST_SCRYPT });
```

Because hashes are self-describing, production-cost hashes and test-cost hashes coexist in the same process without breaking verification.

::: danger Never ship FAST_SCRYPT to production
`N=1024` is trivially brute-forceable. Gate behind `process.env.NODE_ENV === "test"`.
:::

## See also

- [`UserService` reference](./service) — how `changePassword` / `setPassword` / `createUser` use the hasher.
- [Password Policies](./policy) — what guards the _content_ of a password.
- [`packages/user/src/password/hasher.ts`](https://github.com/moostjs/aoothjs/blob/main/packages/user/src/password/hasher.ts) — source.
