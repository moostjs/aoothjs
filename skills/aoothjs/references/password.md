# password

Scrypt-based hasher with a self-describing hash string, an optional pepper, history rotation, and a transferable string-rule policy engine.

## Contents

- [`PasswordHasher`](#passwordhasher)
- [Hash-string format](#hash-string-format)
- [Pepper](#pepper)
- [History rotation](#history-rotation)
- [`generatePassword`](#generatepassword)
- [`PasswordPolicy`](#passwordpolicy)
- [Built-in policy factories](#built-in-policy-factories)
- [Custom policies](#custom-policies)
- [`getTransferablePolicies` + client-side pre-validation](#gettransferablepolicies--client-side-pre-validation)
- [`PolicyCheckResult` shape](#policycheckresult-shape)

## `PasswordHasher`

```ts
import { PasswordHasher } from "@aoothjs/user";

const hasher = new PasswordHasher({
  pepper: process.env.PASSWORD_PEPPER ?? "",
  scryptN: 16384,
  scryptR: 8,
  scryptP: 1,
  keyLength: 64,
});

const encoded = await hasher.hash("Strong-Pass-1!");
const ok = await hasher.verify("Strong-Pass-1!", encoded);
```

| Method                        | Behavior                                                                                                                                              |
| ----------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------- |
| `hash(password)`              | Generates a 32-byte salt, prepends `pepper`, runs `crypto.scrypt`, returns the self-describing string.                                                |
| `verify(password, encoded)`   | Parses N/r/p/keyLength + salt + hash out of `encoded`, re-derives with `pepper + password`, `timingSafeEqual`s the derived buffer against the stored. |
| `generatePassword(length=16)` | Cryptographically-random string with ≥1 char from each category (lower / upper / digit / special). Fisher-Yates shuffled.                             |

Defaults match `PasswordConfig` defaults: `N=16384, r=8, p=1, keyLength=64, saltLength=32`.

## Hash-string format

```
$scrypt$N=16384,r=8,p=1,l=64$<salt-base64url>$<derived-base64url>
```

The N/r/p/l (keyLength) params travel with the hash. `verify` reads them off the string instead of trusting the current `hasher` config — so you can raise cost in config and old hashes still verify with their original parameters. Hashes produced by older deployments keep working without a migration.

`parseHash` rejects strings that don't start with `$scrypt$`, don't carry the four required params, or don't have three `$`-separated sections — `verify` returns `false` in all of those cases (no throw).

## Pepper

`PasswordConfig.pepper` is a static, app-wide string prepended to every password before scrypt:

```
derivedKey = scrypt(pepper + password, salt, ...)
```

The pepper is **NOT** stored in the DB. Persist it in your secret manager / env / KMS. Critical invariants:

- Lose the pepper → every stored hash becomes unverifiable. Treat it like a long-lived signing secret.
- Rotate by re-hashing each user's password the next time they log in (verify with the old pepper, hash with the new — handled at a higher layer, not built-in).
- Two services that share a user store MUST share the same pepper, or they cannot verify each other's hashes.

## History rotation

`PasswordConfig.historyLength` (default `0`) controls how many prior hashes are kept on `password.history[]`:

- `0` — history is wiped to `[]` on every change; `PASSWORD_IN_HISTORY` only fires against the current hash.
- `N > 0` — on `changePassword` / `setPassword`, the new array is `[currentHash, ...oldHistory].slice(0, N)`. New password is checked against `currentHash + every history entry` in parallel via `Promise.all(hashes.map(h => verify(new, h)))` — any match throws `PASSWORD_IN_HISTORY`.

History is per-user (not global) and lives on `user.password.history`. Resetting history on a user record requires a direct store update.

## `generatePassword`

```ts
hasher.generatePassword(); // length 16
hasher.generatePassword(24);
```

Guarantees ≥1 char from each of:

```
lower    "abcdefghijklmnopqrstuvwxyz"
upper    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
digit    "0123456789"
special  "!@#$%^&*()-_=+"
```

Minimum length is clamped to 8 (`length = Math.max(length, 8)`). All randomness is `crypto.randomBytes`; final order is Fisher-Yates shuffled with a fresh byte stream so the category positions are not predictable.

Used by `UserService.createUser(username)` (no password argument) — the generated password is hashed and stored with `password.isInitial = true`; plaintext is returned only as the by-product of the password flow you wrap around it.

## `PasswordPolicy`

```ts
import { PasswordPolicy } from "@aoothjs/user";

const p = new PasswordPolicy({
  rule: "v.length >= 12", // string OR function
  description: "Minimum length 12",
  errorMessage: "Password must be at least 12 characters",
});

await p.evaluate("hunter2"); // false
p.transferable; // true
```

`PasswordPolicyDef`:

```ts
{
  rule: string | PasswordPolicyEvalFn;
  description?: string;
  errorMessage?: string;
}

type PasswordPolicyEvalFn =
  (password: string, context?: PasswordPolicyContext) => boolean | Promise<boolean>;

interface PasswordPolicyContext {
  passwordData?: PasswordData;       // user's current password row (history, lastChanged, ...)
  passwordConfig?: PasswordConfig;   // the resolved password config
}
```

**String rules** are compiled once per process via a shared `FtringsPool<boolean, { v, context? }>` from `@prostojs/ftring`:

- Variable `v` — the candidate password.
- Variable `context` — the optional `PasswordPolicyContext` (`{ passwordData, passwordConfig }`).
- Two policies defining the same rule string share one compiled function (the pool dedupes by rule string).

**Function rules** are stored as-is and invoked directly. `policy.transferable` is `false` — they will not be returned by `getTransferablePolicies()`.

`normalizePolicies(policies)` is the helper `UserService` uses internally — it wraps every plain `PasswordPolicyDef` in a `PasswordPolicy` instance and leaves existing instances alone.

## Built-in policy factories

All return `PasswordPolicyDef` with a **string** rule so they remain transferable to the client.

| Factory                               | Rule                                                | Description (default args)                       |
| ------------------------------------- | --------------------------------------------------- | ------------------------------------------------ |
| `ppHasMinLength(min = 8)`             | `v.length >= ${min}`                                | `Minimum length 8`                               |
| `ppHasUpperCase(n = 1)`               | `(v.match(/[A-Z]/g) \|\| []).length >= ${n}`        | `At least 1 uppercase character`                 |
| `ppHasLowerCase(n = 1)`               | `(v.match(/[a-z]/g) \|\| []).length >= ${n}`        | `At least 1 lowercase character`                 |
| `ppHasNumber(n = 1)`                  | `(v.match(/\d/g) \|\| []).length >= ${n}`           | `At least 1 number`                              |
| `ppHasSpecialChar(n = 1)`             | `(v.match(/[^A-Za-z0-9]/g) \|\| []).length >= ${n}` | `At least 1 special character`                   |
| `ppMaxRepeatedChars(maxRepeated = 2)` | `/(.)\1{${maxRepeated},}/.test(v) === false`        | `No more than 2 consecutive repeated characters` |

Wire into the service:

```ts
const svc = new UserService(store, {
  password: {
    policies: [
      ppHasMinLength(12),
      ppHasUpperCase(),
      ppHasLowerCase(),
      ppHasNumber(),
      ppHasSpecialChar(),
      ppMaxRepeatedChars(2),
    ],
  },
});
```

## Custom policies

**String-form** — preferred, stays transferable:

```ts
const noEmailLocalpart: PasswordPolicyDef = {
  rule: "context.passwordData ? !v.toLowerCase().includes((context.passwordData.lastChanged + '').slice(0, 4)) : true",
  description: "Password must not echo identifying data",
  errorMessage: "Password must not contain identifying data",
};
```

**Function-form** — needed for breached-password APIs, regex builders that don't ftring-encode cleanly, or anything requiring async I/O:

```ts
const noBreached: PasswordPolicyDef = {
  rule: async (password) => !(await isInBreachCorpus(password)),
  description: "Password must not appear in a public breach",
  errorMessage: "This password appeared in a known breach",
};
```

`transferable` is `false` for function rules — `getTransferablePolicies()` will silently drop them. If you need both server-only and client-shippable rules, declare two policies.

## `getTransferablePolicies` + client-side pre-validation

`UserService.getTransferablePolicies(): TransferablePolicy[]` returns:

```ts
interface TransferablePolicy {
  rule: string; // the same `v`/`context` namespace
  description?: string;
  errorMessage?: string;
}
```

Ship the array to the client and evaluate against `{ v: typedPassword, context }` using the same `@prostojs/ftring` machinery — the rule strings are identical to the ones the server compiles. The client preview is advisory; the server runs the full policy set again on `changePassword` / `setPassword`.

## `PolicyCheckResult` shape

`UserService.checkPolicies(password, passwordData?) → Promise<PolicyCheckResult>` returns:

```ts
{
  passed: boolean,                                       // AND across all policies
  policies: { description: string, passed: boolean }[],  // one entry per configured policy, in order
  errors: string[],                                      // `errorMessage` of each failed policy
}
```

`changePassword` / `setPassword` throw `UserAuthError("POLICY_VIOLATION", errors.join("; "), { policies })` when `passed === false`. The structured `details.policies` lets a UI render per-rule checkmarks without re-running the policy engine.
