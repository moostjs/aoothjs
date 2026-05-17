# Password Policies

A **password policy** is a single rule that says "this password is acceptable" or "no". `UserService` runs every configured policy on `changePassword` / `setPassword` and throws `POLICY_VIOLATION` (with structured `details`) if any fail.

The engine has two design constraints:

1. **Transferable by default** — string-rule policies can be shipped to the client for live form validation, so the user sees the same errors before submission.
2. **Escape-hatch via function** — for anything a string DSL can't express (network calls, dictionary lookups, complex regex), pass a function.

Sources: [`packages/user/src/password/policy.ts`](https://github.com/moostjs/aoothjs/blob/main/packages/user/src/password/policy.ts), [`policies.ts`](https://github.com/moostjs/aoothjs/blob/main/packages/user/src/password/policies.ts).

## Shape

```ts
interface PasswordPolicyDef {
  rule: string | PasswordPolicyEvalFn;
  description?: string; // shown in PolicyCheckResult / POLICY_VIOLATION details
  errorMessage?: string; // user-friendly failure message
}

type PasswordPolicyEvalFn = (
  password: string,
  context?: PasswordPolicyContext,
) => boolean | Promise<boolean>;

interface PasswordPolicyContext {
  passwordData?: PasswordData; // current password.lastChanged / history etc.
  passwordConfig?: PasswordConfig; // resolved password config (pepper, scryptN, ...)
}
```

`PasswordPolicy` is the compiled wrapper; you usually pass `PasswordPolicyDef` values into `UserServiceConfig.policies` and let the service compile them.

```ts
import { PasswordPolicy } from "@aoothjs/user";
const p = new PasswordPolicy({ rule: "v.length >= 8" });
await p.evaluate("hello"); // → false
await p.evaluate("hello-world"); // → true
p.transferable; // → true (string rule)
```

## The string DSL — `@prostojs/ftring`

A string rule is a JS expression compiled once and cached, so repeating the same rule across policies doesn't double-compile.

Available variables inside the expression:

| Var       | Type                                 | What it is                                    |
| --------- | ------------------------------------ | --------------------------------------------- |
| `v`       | `string`                             | The password being evaluated.                 |
| `context` | `{ passwordData?, passwordConfig? }` | Extra inputs (see above). May be `undefined`. |

```ts
const policies: PasswordPolicyDef[] = [
  { rule: "v.length >= 12", description: "at least 12 characters" },
  { rule: "/[A-Z]/.test(v) && /[a-z]/.test(v)", description: "upper + lower" },
  {
    rule: "!context?.passwordData?.history?.includes(v)",
    description: "not used recently",
  },
];
```

Because it's a real JS expression, you have the full standard library — `.includes`, regex, ternaries, optional chaining. The expression must return a truthy/falsy value.

::: warning No side effects
A string rule should be pure. The pool caches by source, so identical strings share state. Reaching for `Math.random()` or `Date.now()` inside a rule will produce unpredictable evaluations across calls.
:::

## Function rules — non-transferable escape hatch

When the DSL isn't enough — a network call, a dictionary check, multi-line logic — pass a function. The trade-off: function rules can't be serialized to the client.

```ts
{
  rule: async (password) => {
    const breached = await haveIBeenPwned(password)
    return !breached
  },
  description: "not in HIBP breach database",
}
```

Function rules see the same `(password, context)` signature.

## Built-in factories

All return `PasswordPolicyDef` with **string** rules, so they're transferable. Names start with `pp` ("password policy").

| Factory                             | Default         | Rule (effectively)                                                              |
| ----------------------------------- | --------------- | ------------------------------------------------------------------------------- |
| `ppHasMinLength(min=8)`             | `min=8`         | `v.length >= min`                                                               |
| `ppHasUpperCase(n=1)`               | `n=1`           | regex count `>= n` for `[A-Z]`                                                  |
| `ppHasLowerCase(n=1)`               | `n=1`           | regex count `>= n` for `[a-z]`                                                  |
| `ppHasNumber(n=1)`                  | `n=1`           | regex count `>= n` for `[0-9]`                                                  |
| `ppHasSpecialChar(n=1)`             | `n=1`           | regex count `>= n` for non-alphanumerics                                        |
| `ppMaxRepeatedChars(maxRepeated=2)` | `maxRepeated=2` | rejects any run longer than `maxRepeated` (e.g. `"aaab"` fails `maxRepeated=2`) |

```ts
import {
  UserService,
  ppHasMinLength,
  ppHasUpperCase,
  ppHasLowerCase,
  ppHasNumber,
  ppHasSpecialChar,
  ppMaxRepeatedChars,
} from "@aoothjs/user";

const users = new UserService(store, {
  policies: [
    ppHasMinLength(12),
    ppHasUpperCase(1),
    ppHasLowerCase(1),
    ppHasNumber(1),
    ppHasSpecialChar(1),
    ppMaxRepeatedChars(3),
  ],
});
```

Source: [`packages/user/src/password/policies.ts`](https://github.com/moostjs/aoothjs/blob/main/packages/user/src/password/policies.ts).

## How `UserService` runs policies

`changePassword` / `setPassword`:

1. Call `checkPolicies(newPassword, passwordData)` — runs every policy, collects results.
2. If any policy returns `false`, throw `UserAuthError("POLICY_VIOLATION", ..., { policies: [{ description, passed, errorMessage }, ...] })`.
3. Then check history (`PASSWORD_IN_HISTORY`).

```ts
try {
  await users.changePassword("alice", oldp, newp);
} catch (e) {
  if (e instanceof UserAuthError && e.type === "POLICY_VIOLATION") {
    return e.details.policies
      .filter((p: any) => !p.passed)
      .map((p: any) => p.errorMessage ?? p.description);
  }
  throw e;
}
```

You can also pre-flight with `users.checkPolicies(candidate)` — same checks, returns `PolicyCheckResult`, throws nothing.

```ts
const result = await users.checkPolicies("hunter2");
if (!result.passed) showHints(result.policies);
```

## Transferable policies — client-side pre-validation

`getTransferablePolicies()` filters to **string-rule** policies and returns them in serializable form:

```ts
interface TransferablePolicy {
  rule: string;
  description?: string;
  errorMessage?: string;
}

users.getTransferablePolicies(); // → TransferablePolicy[]
```

Ship this to the client (REST endpoint, inline in HTML, embedded in a Moost workflow form). On the client, evaluate each rule with the **same** `v` / `context` namespace:

```ts
// client/policy.ts
import type { TransferablePolicy } from "@aoothjs/user";

const compiled = policies.map((p) => ({
  ...p,
  fn: new Function("v", "context", `return (${p.rule})`),
}));

export function check(password: string): { description?: string; passed: boolean }[] {
  return compiled.map((p) => ({
    description: p.description,
    errorMessage: p.errorMessage,
    passed: !!p.fn(password, {}),
  }));
}
```

::: warning Function rules are silently dropped
`PasswordPolicy.transferable` is purely `typeof rule === "string"`. A function-based policy is enforced on the server but never reaches `getTransferablePolicies()` output — clients will pass it visually then fail at submission. Mirror server-only checks in your UI separately, or make them string rules.
:::

## Custom policies

Anything that's a clean expression should be a string. Reach for a function only when you need IO, complex multi-step logic, or imports.

```ts
// good — transferable
const noUsername: PasswordPolicyDef = {
  rule: "!context?.passwordData?.username || !v.includes(context.passwordData.username)",
  description: "doesn't include your username",
};

// fine — non-transferable
const noDictWord: PasswordPolicyDef = {
  rule: async (v) => !(await dict.has(v.toLowerCase())),
  description: "not a dictionary word",
};
```

`PasswordPolicyContext.passwordData` is the user's current `PasswordData`. Inject extra fields by extending the type on your end — the engine only reads `.history` and `.lastChanged` in built-ins, but the value is passed verbatim to your rule.

## Pre-built recommended baseline

```ts
import {
  ppHasMinLength,
  ppHasUpperCase,
  ppHasLowerCase,
  ppHasNumber,
  ppHasSpecialChar,
  ppMaxRepeatedChars,
} from "@aoothjs/user";

export const recommendedPolicies = [
  ppHasMinLength(12),
  ppHasUpperCase(1),
  ppHasLowerCase(1),
  ppHasNumber(1),
  ppHasSpecialChar(1),
  ppMaxRepeatedChars(3),
];
```

Reach for `min=14` or `min=16` if your threat model includes offline cracking.

## See also

- [Password Hashing](./password) — what happens once a policy passes.
- [Errors](./errors) — the shape of `POLICY_VIOLATION` `details`.
- [`packages/user/src/password/policy.ts`](https://github.com/moostjs/aoothjs/blob/main/packages/user/src/password/policy.ts) — engine source.
