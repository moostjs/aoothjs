# password

Scrypt-based hasher with a self-describing hash string, an optional pepper, history rotation, and a function-based policy engine whose rules can be sent to the client (`definePasswordPolicy`).

## Contents

- [`PasswordHasher`](#passwordhasher)
- [Hash-string format](#hash-string-format)
- [Pepper](#pepper)
- [History rotation](#history-rotation)
- [`generatePassword`](#generatepassword)
- [`PasswordPolicy`](#passwordpolicy)
- [`definePasswordPolicy`](#definepasswordpolicy)
- [Built-in policy factories](#built-in-policy-factories)
- [Custom policies](#custom-policies)
- [`getTransferablePolicies` + client-side pre-validation](#gettransferablepolicies--client-side-pre-validation)
- [`PolicyCheckResult` shape](#policycheckresult-shape)

## `PasswordHasher`

```ts
import { PasswordHasher } from "@aooth/user";

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

Memory-hard costs work: the hasher sizes scrypt `maxmem` to `N × r` (cap 1 GiB), so `scryptN: 2 ** 17` (OWASP) hashes and verifies. Before 0.1.78 any `N × r ≥ 2^18` (e.g. `scryptN: 32768` with `r: 8`) threw `ERR_CRYPTO_INVALID_SCRYPT_PARAMS` — bump to ≥ 0.1.78 before raising cost.

Hashes are self-describing: the scrypt parameters (N, r, p, keyLength) are baked into the stored value, so `verify` always re-runs scrypt with the parameters from the hash — not the current `hasher` config. You can raise cost without invalidating older hashes; `verify` returns `false` (never throws) for any malformed input.

## Pepper

`PasswordConfig.pepper` is a static, app-wide secret mixed into every password before scrypt. See [invariants.md](invariants.md) #14. Two services that share a user store MUST share the same pepper; rotation requires app-level dual-write (verify with old, write with new) and is not built in.

## History rotation

`PasswordConfig.historyLength` (default `0`) controls how many prior hashes are kept on `password.history[]`. `0` disables history (current hash is still checked). For `N > 0`, `changePassword` / `setPassword` keep the most recent `N` hashes and throw `PASSWORD_IN_HISTORY` if the new password matches any of them. History is per-user.

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
import { PasswordPolicy, definePasswordPolicy } from "@aooth/user";

const p = new PasswordPolicy(
  definePasswordPolicy({
    rule: (v: string, min: number) => v.length >= min,
    args: [12],
    description: "Minimum length 12",
    errorMessage: "Password must be at least 12 characters",
  }),
);

await p.evaluate("hunter2"); // false
p.transferable; // true — it has a serialized form
```

`PasswordPolicyDef`:

| Field           | Type                   | Default  | Meaning                                                                         |
| --------------- | ---------------------- | -------- | ------------------------------------------------------------------------------- |
| `rule`          | `PasswordPolicyEvalFn` | required | Called directly on the server (no sandbox, no eval). Function only.             |
| `serialized?`   | `string`               | —        | Client copy `(v) => …`, built by `definePasswordPolicy`. Absent = backend-only. |
| `description?`  | `string`               | —        | —                                                                               |
| `errorMessage?` | `string`               | —        | —                                                                               |

`PasswordPolicyEvalFn` is `(password: string, context?: PasswordPolicyContext) => boolean | Promise<boolean>`. `PasswordPolicyContext`:

| Field             | Type             | Default | Meaning                                                               |
| ----------------- | ---------------- | ------- | --------------------------------------------------------------------- |
| `passwordData?`   | `PasswordData`   | —       | User's current password row (`history` = hashes, `lastChanged`, ...). |
| `passwordConfig?` | `PasswordConfig` | —       | The resolved password config.                                         |

Exact shapes: [docs api](https://aoothjs.dev/api/user#policy-types).

`policy.transferable` is `serialized !== undefined`. `normalizePolicies(policies)` is the helper `UserService` uses internally. It wraps every plain `PasswordPolicyDef` in a `PasswordPolicy` instance and leaves existing instances alone.

> **String rules are gone (since 0.1.4).** Before 0.1.4, `rule` also accepted an `@prostojs/ftring` string expression (`"v.length >= 8"`). That sandbox does not block prototype-chain escapes (`constructor.constructor("return process")()`), so a rule string coming from config or an admin UI was an RCE vector. String rules were removed and there is no opt-in to bring them back. If you see `{ rule: "..." }` in old code, rewrite it with `definePasswordPolicy({ rule, args })` or a `ppHas*` factory. TypeScript rejects a string `rule`, and evaluating one throws a `TypeError`.

## `definePasswordPolicy`

```ts
function definePasswordPolicy<A extends readonly unknown[]>(opts: {
  rule: (v: string, ...args: A) => boolean | Promise<boolean>;
  args?: A;
  description?: string;
  errorMessage?: string;
}): PasswordPolicyDef;
```

It builds both tiers from one function:

- Backend `rule` = `(v) => rule(v, ...args)`. `PasswordPolicyContext` is **not** forwarded.
- `serialized` = `` `(v) => (${rule.toString()})(v, ${args.map(JSON.stringify).join(", ")})` ``, set only when `args` is passed. `args: []` gives a transferable rule with no parameters.
- No `args` means backend-only: `serialized` is undefined, `transferable` is false, and the client skips it.
- The client copy is bundler-safe because arguments are passed by position, so a minifier renaming the rule's parameters is harmless.
- **Constraint:** the rule body may reference only its own parameters and plain JS globals (regex literals, `String` methods). It cannot close over imports, module-level constants or helpers, and it cannot use `this`, because the shipped source would not resolve them. `args` must be JSON-serializable.

## Built-in policy factories

All are built with `definePasswordPolicy`, so they are transferable to the client.

| Factory                               | Rule `(v, arg) => …`                                                      | Description (default args)                       |
| ------------------------------------- | ------------------------------------------------------------------------- | ------------------------------------------------ |
| `ppHasMinLength(min = 8)`             | `v.length >= min`                                                         | `Minimum length 8`                               |
| `ppHasUpperCase(n = 1)`               | `(v.match(/[A-Z]/g) \|\| []).length >= n`                                 | `At least 1 uppercase character`                 |
| `ppHasLowerCase(n = 1)`               | `(v.match(/[a-z]/g) \|\| []).length >= n`                                 | `At least 1 lowercase character`                 |
| `ppHasNumber(n = 1)`                  | `(v.match(/\d/g) \|\| []).length >= n`                                    | `At least 1 number`                              |
| `ppHasSpecialChar(n = 1)`             | `(v.match(/[^A-Za-z0-9]/g) \|\| []).length >= n`                          | `At least 1 special character`                   |
| `ppMaxRepeatedChars(maxRepeated = 2)` | no run of > `maxRepeated` identical chars (`/(.)\1{maxRepeated,}/` fails) | `No more than 2 consecutive repeated characters` |

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

**Transferable.** Use this when the rule depends only on the password plus JSON-serializable values:

```ts
const noCommonWords = definePasswordPolicy({
  rule: (v: string, words: string[]) => !words.some((w) => v.toLowerCase().includes(w)),
  args: [["password", "qwerty", "letmein"]],
  description: "No common words",
  errorMessage: "Password must not contain common words",
});
```

**Backend-only.** Use this for breached-password APIs, async I/O, imports, or anything that reads `PasswordPolicyContext`. Pass a raw def with a function `rule` (it receives `(password, context)`), or call `definePasswordPolicy` without `args`:

```ts
const noBreached: PasswordPolicyDef = {
  rule: async (password) => !(await isInBreachCorpus(password)),
  description: "Password must not appear in a public breach",
  errorMessage: "This password appeared in a known breach",
};
```

Backend-only policies are silently left out of `getTransferablePolicies()`. The client preview passes them, and the server then rejects the password on submit. If you need both a server-only check and a client-shippable one, declare two policies.

## `getTransferablePolicies` + client-side pre-validation

`UserService.getTransferablePolicies(): TransferablePolicy[]` returns the transferable policies (those with `serialized`) as `TransferablePolicy`:

| Field           | Type     | Default  | Meaning                                                    |
| --------------- | -------- | -------- | ---------------------------------------------------------- |
| `rule`          | `string` | required | The `serialized` function literal: `(v) => (…)(v, …args)`. |
| `description?`  | `string` | —        | —                                                          |
| `errorMessage?` | `string` | —        | —                                                          |

Exact shape: [docs api](https://aoothjs.dev/api/user#policy-types).

On the client, compile each rule once and call it with the typed password. The client has no `context`:

```ts
const fn = new Function(`return (${policy.rule})`)() as (v: string) => boolean;
fn(typedPassword); // boolean
```

The `AuthWorkflow`'s `prepare-password-rules` step puts this list on `ctx.password.policies`, and `<AsPasswordRules>` (`@atscript/vue-aooth`) evaluates it. Compiling the rules needs a CSP that allows `'unsafe-eval'`. The client preview is advisory; the server runs the full policy set again on `changePassword` / `setPassword`.

## `PolicyCheckResult` shape

`UserService.checkPolicies(password, passwordData?) → Promise<PolicyCheckResult>` returns:

| Field      | Type                                         | Default | Meaning                                    |
| ---------- | -------------------------------------------- | ------- | ------------------------------------------ |
| `passed`   | `boolean`                                    | —       | AND across all policies.                   |
| `policies` | `{ description: string, passed: boolean }[]` | —       | One entry per configured policy, in order. |
| `errors`   | `string[]`                                   | —       | `errorMessage` of each failed policy.      |

Exact shape: [docs api](https://aoothjs.dev/api/user#policy-types).

`changePassword` / `setPassword` throw `UserAuthError("POLICY_VIOLATION", errors.join("; "), { policies })` when `passed === false`. The structured `details.policies` lets a UI render per-rule checkmarks without re-running the policy engine.
