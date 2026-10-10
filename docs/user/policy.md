# Password Policies

A **password policy** is a single rule that says "this password is acceptable" or "no". `UserService` runs every configured policy on `changePassword` / `setPassword` and throws `POLICY_VIOLATION` (with structured `details`) if any fail.

Every policy is a plain function that runs directly on the server. Build policies with `definePasswordPolicy`: from a single function it produces both the server check and a serialized copy you can send to the client for live form validation. That way the user sees the same errors before they submit.

::: warning String rules were removed in 0.1.4
Before 0.1.4, `rule` could be a string expression compiled by `@prostojs/ftring`, e.g. `{ rule: "v.length >= 8" }`. That sandbox did not block prototype-chain escapes (`constructor.constructor("return process")()`), so any rule string that came from configuration or an admin UI could execute arbitrary code on the server. String rules were removed for this reason. `rule` now accepts a function only: TypeScript rejects a string, and evaluating one at runtime throws a `TypeError`. To migrate, rewrite each string rule as a `definePasswordPolicy({ rule, args })` call, or use one of the `ppHas*` factories.
:::

Sources: [`packages/user/src/password/policy.ts`](https://github.com/moostjs/aoothjs/blob/main/packages/user/src/password/policy.ts), [`policies.ts`](https://github.com/moostjs/aoothjs/blob/main/packages/user/src/password/policies.ts).

## Shape

```ts
interface PasswordPolicyDef {
  rule: PasswordPolicyEvalFn; // runs on the server, no sandbox
  serialized?: string; // client copy, built by definePasswordPolicy; absent = backend-only
  description?: string; // shown in PolicyCheckResult / POLICY_VIOLATION details
  errorMessage?: string; // user-friendly failure message
}

type PasswordPolicyEvalFn = (
  password: string,
  context?: PasswordPolicyContext,
) => boolean | Promise<boolean>;

interface PasswordPolicyContext {
  passwordData?: PasswordData; // current hash, history hashes, lastChanged, isInitial
  passwordConfig?: PasswordConfig; // resolved password config (pepper, scryptN, ...)
}
```

`PasswordPolicy` is the runtime wrapper. Usually you pass `PasswordPolicyDef` values into `password.policies` in the `UserService` config, and the service wraps them for you.

```ts
import { PasswordPolicy, definePasswordPolicy } from "@aooth/user";

const p = new PasswordPolicy(
  definePasswordPolicy({
    rule: (v: string, min: number) => v.length >= min,
    args: [8],
  }),
);
await p.evaluate("hello"); // → false
await p.evaluate("hello-world"); // → true
p.transferable; // → true (has a serialized form)
```

## `definePasswordPolicy` — one source, two tiers

```ts
function definePasswordPolicy<A extends readonly unknown[]>(opts: {
  rule: (v: string, ...args: A) => boolean | Promise<boolean>;
  args?: A;
  description?: string;
  errorMessage?: string;
}): PasswordPolicyDef;
```

- **Server side:** `rule` is called directly as `rule(password, ...args)`. There is no sandbox and no `eval`.
- **Client side:** when you pass `args`, the policy gets a `serialized` string, `(v) => (<rule source>)(v, <args as JSON>)`. `getTransferablePolicies()` sends this string to the client. Arguments are passed by position, so the serialized form keeps working when a bundler or minifier renames the function's parameters.
- **Backend-only:** if you omit `args`, the policy has no `serialized` form and `transferable` is `false`. The client skips it and only the server enforces it. Use `args: []` for a transferable rule that takes no arguments.

```ts
import { definePasswordPolicy } from "@aooth/user";

const policies = [
  definePasswordPolicy({
    rule: (v: string, min: number) => v.length >= min,
    args: [12],
    description: "at least 12 characters",
    errorMessage: "Password must be at least 12 characters long",
  }),
  definePasswordPolicy({
    rule: (v: string) => /[A-Z]/.test(v) && /[a-z]/.test(v),
    args: [], // transferable, no parameters
    description: "upper + lower",
  }),
];
```

::: warning Transferable rules must be self-contained
The rule's source text is what gets sent to the client, so a transferable rule may reference only its own parameters plus plain JS globals (regex literals, `String` methods, `Math`). It cannot close over imports, module-level constants or helpers, and it cannot use `this`. Pass any values the rule needs through `args`. They are embedded as JSON, so they must be JSON-serializable.
:::

`definePasswordPolicy` passes the password plus your `args` to `rule`, and nothing else. To read `PasswordPolicyContext` (e.g. `passwordData.lastChanged`), write a raw backend-only policy instead (see below).

## Backend-only rules

For checks that can't or shouldn't run in the browser, such as a network call, a dictionary lookup or reading the stored password data, pass a raw `PasswordPolicyDef` with a function `rule` and no `serialized`. You can also call `definePasswordPolicy` without `args`. Raw functions receive `(password, context)`:

```ts
const notBreached: PasswordPolicyDef = {
  rule: async (password) => !(await haveIBeenPwned(password)),
  description: "not in HIBP breach database",
};
```

## Built-in factories

All factories are built with `definePasswordPolicy`, so they are transferable. Names start with `pp` ("password policy").

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
} from "@aooth/user";

const users = new UserService(store, {
  password: {
    policies: [
      ppHasMinLength(12),
      ppHasUpperCase(1),
      ppHasLowerCase(1),
      ppHasNumber(1),
      ppHasSpecialChar(1),
      ppMaxRepeatedChars(3),
    ],
  },
});
```

Source: [`packages/user/src/password/policies.ts`](https://github.com/moostjs/aoothjs/blob/main/packages/user/src/password/policies.ts).

## How `UserService` runs policies

`changePassword` / `setPassword`:

1. Call `checkPolicies(newPassword, passwordData)` — runs every policy, collects results.
2. If any policy returns `false`, throw `UserAuthError("POLICY_VIOLATION", message, { policies: [{ description, passed }, ...] })`. The `message` is the failing policies' `errorMessage`s joined with `"; "`.
3. Then check history (`PASSWORD_IN_HISTORY`).

```ts
try {
  await users.changePassword("alice", oldp, newp);
} catch (e) {
  if (e instanceof UserAuthError && e.type === "POLICY_VIOLATION") {
    return (e.details?.policies as { description: string; passed: boolean }[])
      .filter((p) => !p.passed)
      .map((p) => p.description);
  }
  throw e;
}
```

You can also pre-flight with `users.checkPolicies(candidate)` — same checks, returns `PolicyCheckResult`, throws nothing.

```ts
const result = await users.checkPolicies("hunter2");
if (!result.passed) showHints(result.policies);
```

## Transferable policies — client-side pre-validation {#transferable-policies}

`getTransferablePolicies()` returns only the transferable policies, meaning those that have a `serialized` form, in a wire-safe shape:

```ts
interface TransferablePolicy {
  rule: string; // the serialized function literal: "(v) => (...)(v, ...args)"
  description?: string;
  errorMessage?: string;
}

users.getTransferablePolicies(); // → TransferablePolicy[]
```

Send this list to the client, e.g. from a REST endpoint, inline in HTML, or in a Moost workflow form. The `AuthWorkflow`'s `prepare-password-rules` step and `<AsPasswordRules>` already do this for you. Each `rule` is a complete function literal that takes the password as its only argument. Compile it once and call it:

```ts
// client/policy.ts
import type { TransferablePolicy } from "@aooth/user";

export function compilePolicies(policies: TransferablePolicy[]) {
  const compiled = policies.map((p) => ({
    ...p,
    fn: new Function(`return (${p.rule})`)() as (v: string) => boolean,
  }));
  return (password: string) =>
    compiled.map((p) => ({
      description: p.description,
      errorMessage: p.errorMessage,
      passed: !!p.fn(password),
    }));
}
```

Rule text only ever comes from your own server code, never from user input. Compiling it does require a Content-Security-Policy that allows `'unsafe-eval'` on the page that runs it.

::: warning Backend-only policies are not sent
A policy without `serialized` (a raw function `rule`, or `definePasswordPolicy` without `args`) is enforced on the server but never appears in `getTransferablePolicies()`. In the browser such a check looks like it passed and then fails on submit. Either make it transferable or mirror it in your UI separately.
:::

## Custom policies

Make a rule transferable when it depends only on the password and a few JSON values. Keep it backend-only when it needs I/O, imports or `PasswordPolicyContext`.

```ts
import { definePasswordPolicy, type PasswordPolicyDef } from "@aooth/user";

// transferable: self-contained, values passed through args
const noForbiddenWords = definePasswordPolicy({
  rule: (v: string, words: string[]) => !words.some((w) => v.toLowerCase().includes(w)),
  args: [["password", "qwerty", "letmein"]],
  description: "no common words",
});

// backend-only: async I/O
const noDictWord: PasswordPolicyDef = {
  rule: async (v) => !(await dict.has(v.toLowerCase())),
  description: "not a dictionary word",
};

// backend-only: reads the stored password data via context
const notInitial: PasswordPolicyDef = {
  rule: (v, context) => !context?.passwordData?.isInitial || v.length >= 16,
  description: "16+ characters when replacing a generated password",
};
```

`PasswordPolicyContext.passwordData` is the user's current `PasswordData`, and it is passed to your rule as is. Note that `history` holds scrypt hashes, not plaintext passwords. Reuse is checked separately after the policies pass, which surfaces as `PASSWORD_IN_HISTORY`.

## Pre-built recommended baseline

```ts
import {
  ppHasMinLength,
  ppHasUpperCase,
  ppHasLowerCase,
  ppHasNumber,
  ppHasSpecialChar,
  ppMaxRepeatedChars,
} from "@aooth/user";

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
