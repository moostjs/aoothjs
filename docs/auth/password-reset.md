# Password Reset

`@aooth/auth` ships the **primitives** for password reset. The full workflow — the HTTP routes, the rate limits, the audit trail, the multi-step form, the freshly-logged-in countdown — lives in [`@aooth/auth-moost`](../moost/workflows). This page covers what you'd compose if you were building it yourself.

There are four steps, and each maps to a primitive in this package or in `@aooth/user`.

## The four-step recipe

| Step            | Primitive                                                                                | Package                       |
| --------------- | ---------------------------------------------------------------------------------------- | ----------------------------- |
| 1. Token        | `generateMagicLinkToken()`                                                               | `@aooth/auth`                 |
| 2. Storage      | `CredentialStore.persist(state, ttl)` + `consume(token)`                                 | `@aooth/auth`                 |
| 3. Delivery     | `EmailSender.send({ kind: 'recovery.magicLink', ... })`                                  | `@aooth/auth` (interface)     |
| 4. Verification | `store.consume(token)` → `users.changePassword` → `auth.revokeAllForUser` → `auth.issue` | `@aooth/auth` + `@aooth/user` |

### Step 1 — generate the token

```ts
import { generateMagicLinkToken } from "@aooth/auth";

const token = generateMagicLinkToken(); // 43 chars, base64url, URL-safe
```

32 bytes of CSPRNG. See [Magic Links](./magic-links#the-token) for the format details.

### Step 2 — store it with a TTL

`AuthCredential.store` is `private readonly`, so keep your own reference to the store after construction and call `persist` / `consume` on it directly:

```ts
const store = new CredentialStoreAtscriptDb({ table });
const auth = new AuthCredential({ store, accessTtl: 15 * 60 * 1000 });

await store.persist(
  {
    userId,
    issuedAt: now,
    expiresAt: now + ttl,
    kind: "magic.recovery", // free string — your discriminator
  },
  ttl, // 10–15 min is typical
);
```

Use the same `CredentialStore` you already have — the magic-link token lives in the same table / Redis namespace / JWT denylist as the rest of your credentials. See [Magic Links — Storage pattern](./magic-links#storage-pattern).

::: danger Don't reuse `kind: 'access'` for single-use tokens
When a single-use token is persisted with `kind: 'access'` (or no `kind`), it can be presented as a bearer token to `auth.validate()` — the validator only filters on `kind === 'refresh'` and lets everything else through. A leaked or mis-routed recovery token then becomes a working access token.

Always either:

1. Persist with a **distinct `kind`** (`'magic.recovery'`, `'magic.login'`, `'magic.invite'`, etc.) and check it explicitly after `consume`, OR
2. Discriminate by `metadata.label` and have your auth guard reject any unknown label.

```ts
// guard
const state = await auth.validate(presentedToken);
if (!state) throw new HttpError(401);
if (state.kind && state.kind !== "access") throw new HttpError(401); // reject magic kinds
```

:::

### Step 3 — send the email

```ts
await emailSender.send({
  kind: "recovery.magicLink",
  recipient: user.email,
  url: buildMagicLinkUrl("recovery.magicLink", token),
  expiresAt: now + ttl,
  username: user.email,
});
```

`EmailSender` is an interface — the package ships no implementation. See [Delivery](./delivery) for the contract and example SES / SendGrid implementations.

### Step 4 — verify, change password, re-issue

```ts
const state = await store.consume(token); // use the same `store` reference from step 2
if (!state || state.kind !== "magic.recovery") {
  throw new HttpError(401, "invalid or expired link");
}

await users.changePassword(state.userId, newPassword);
await auth.revokeAllForUser(state.userId); // log out everywhere
const { accessToken } = await auth.issue(state.userId, {/* claims */}); // auto-login
```

`consume` is **atomic** — retrieve and revoke in one operation. Two concurrent submissions of the same link cannot both succeed.

## The full minimal flow

```ts
import {
  AuthCredential,
  CredentialStoreAtscriptDb,
  generateMagicLinkToken,
  type EmailSender,
  type BuildMagicLinkUrl,
} from "@aooth/auth";

declare const users: {
  findUserIdByEmail(email: string): Promise<string | null>;
  changePassword(userId: string, newPassword: string): Promise<void>;
};
declare const emailSender: EmailSender;
declare const table: import("@aooth/auth/atscript-db").AuthCredentialTable;

// Bind the store separately — `AuthCredential.store` is `private readonly`.
const store = new CredentialStoreAtscriptDb({ table });
const auth = new AuthCredential<{ roles: string[] }>({
  store,
  accessTtl: 15 * 60 * 1000,
});

const buildMagicLinkUrl: BuildMagicLinkUrl = (_kind, token) =>
  `https://app.example.com/auth/recovery/finish?t=${token}`;

// ─── start of recovery ──────────────────────────────────────
async function startRecovery(email: string) {
  const userId = await users.findUserIdByEmail(email);
  if (!userId) return; // don't leak existence

  const token = generateMagicLinkToken();
  const now = Date.now();
  const ttl = 15 * 60 * 1000;

  await store.persist({ userId, issuedAt: now, expiresAt: now + ttl, kind: "magic.recovery" }, ttl);
  await emailSender.send({
    kind: "recovery.magicLink",
    recipient: email,
    url: buildMagicLinkUrl("recovery.magicLink", token),
    expiresAt: now + ttl,
  });
}

// ─── finish of recovery ─────────────────────────────────────
async function finishRecovery(token: string, newPassword: string) {
  const state = await store.consume(token);
  if (!state || state.kind !== "magic.recovery") {
    throw new HttpError(401, "invalid or expired link");
  }

  await users.changePassword(state.userId, newPassword);
  await auth.revokeAllForUser(state.userId);
  const { accessToken } = await auth.issue(state.userId, {
    roles: ["user"], // typed payload field, flat
    metadata: { ip: "…", userAgent: "…" },
  });
  return { userId: state.userId, accessToken };
}
```

That's the entire recovery flow — about 40 lines on top of the primitives.

## Why `revokeAllForUser` before `issue`

The order matters. If you `issue` first then `revokeAllForUser`, you've just revoked the credential you wanted the user to log in with. The correct order:

1. `consume(token)` — kill the magic link.
2. `changePassword(userId)` — update the credential.
3. `revokeAllForUser(userId)` — bump the per-user revocation epoch (or delete every row). Every previously-issued access and refresh token is dead.
4. `issue(userId, …)` — issue a fresh credential. Its `iatMs` is `>=` the epoch, so it survives the gate.

This is the same-millisecond `>=` pattern from [Refresh](./refresh#why-matters). It only works because the gate is `>=` not `>`.

::: tip Why log out everywhere after a password change
The password is the recovery mechanism. If an attacker stole sessions before the legitimate user noticed, they're still inside. A password change must invalidate all of them — otherwise the reset is theatre.
:::

::: warning Don't skip `revokeAllForUser`
Even if your access tokens are short-lived, the **refresh** tokens are not. A stale refresh token survives a password change unless `revokeAllForUser` is called. Always cascade.
:::

## Token TTL choice

| Use case                   | TTL       |
| -------------------------- | --------- |
| Password reset link        | 10–15 min |
| Login magic link           | 5–10 min  |
| Invite (first-time signup) | 24–72 h   |
| Re-verify email            | 1–24 h    |

Short TTLs reduce the exploit window for an intercepted email. Avoid sending two pending tokens to the same user — the older one should be revoked when the new one is issued (`store.revoke` on the previous token), or rely on the user clicking the most recent.

## Same-tenant defense in depth

For multi-tenant apps, double-check that the `userId` decoded from the consumed state belongs to the tenant in the current request context:

```ts
const state = await store.consume(token);
if (!state || state.kind !== "magic.recovery") throw new HttpError(401);
if (state.tenantId !== currentTenantId) throw new HttpError(401); // typed payload field, flat
```

`@aooth/auth-moost` does this for you via the recovery flow's resolver chain. Rolling your own — remember to check it explicitly.

## What `@aooth/auth-moost` adds on top

If you're using moost, the unified [`AuthWorkflow`](../moost/workflows)'s `recoveryFlow` (wfid `auth/recovery/flow`) wraps these primitives with:

- A single `/auth/trigger` entry point (no per-step routes — the flow is driven by the wf state token).
- A multi-step `WfFinished` envelope (countdown auto-redirect, magic-link **or** OTP delivery).
- `recoveryStateTtlMs` capping the request-to-reset window; per-request policy via `resolveXxx(ctx)` getters.
- No account-existence oracle: an identifier no code can go to gets the same answer as an existing account (below).
- Post-reset session revocation + `autoLoginOnRecover` (auto-login vs fresh-login redirect).

### No enumeration

The recovery flow's answers do not tell whether an account exists:

- **One-time code (the default).** Every identifier gets the same code step: the same token prefix, response and form, one persisted pause with the same expiry (`recoveryStateTtlMs`), and the same answers to every code (`AOOTH_INVALID_CODE`, the attempt limit and `AOOTH_TOO_MANY_CODE_ATTEMPTS`, `AOOTH_CODE_EXPIRED`, the resend wait). No code goes to an identifier that matches no account a code can go to — unknown, an inactive account (a pending invitation, a deactivated user), or with registered-channel delivery an account without a deliverable channel — and no code is accepted for it. A locked account still receives its code: recovery is how it unlocks itself (`resolveLockout`).
- **Nothing about the account is in the state before the code is verified.** The account is looked up from the typed identifier when a code is sent and again when one is checked, never stored — so a client-held (encapsulated) token carries nothing that differs between accounts, and neither does its length or the response's: they are the same for known, unknown, inactive and registered-channel accounts, whatever the length of their addresses, under the default encapsulated strategy and a durable store. Encapsulated states are padded to 256-byte buckets. Pending consents are staged only after verification, and with registered-channel delivery the code form shows no destination.
- **The code rules answer alike for every identifier.** Recovery codes follow the [one-time code rules](../moost/workflows#one-time-codes) — bound to what they were sent for, attempt limit and single use enforced on the server, server-side resend wait and failure budgets. Their destination is the typed identifier, known or not, so every one of those limits answers the same for an identifier with no account. A recovery code is bound to the account and the address it went to: if the identifier resolves to another account by the time the code is entered (a renamed username, an address moved to another account, an account deleted and recreated), or its registered channel changed, the code is answered as wrong.
- **The same reads.** A known and an unknown identifier make the same user-store reads: one identifier lookup, then one account read with one-time-code delivery to the typed address, two with registered-channel delivery (the second picks the channel) — of a placeholder row for an unknown or inactive one — and call the same delivery resolvers (an error a resolver throws on the placeholder is "no account"). A resolver you override must keep the reads equal itself.
- **[Magic links](../moost/workflows#magic-links)** give the same answer to every identifier and never return the link to the requester.

The one difference left is time: a real account waits for its code (or link) to be sent. Use an `EmailSender` / `SmsSender` that queues (returns before the message goes out) if response time must not depend on delivery. Every send attempt — real or not — also counts against the bundled per-IP [`aooth.send`](../moost/rate-limit#bundled-limits) limit.

If your needs match the workflow's shape, use it. If they don't, the primitives on this page are what's underneath — and they're stable.

## See also

- [Magic Links](./magic-links) — token + URL + storage primitives.
- [Refresh](./refresh#why-matters) — the same-ms `>=` epoch gate.
- [Delivery](./delivery) — `EmailSender` contract for the recovery email.
- [Moost — Workflows](../moost/workflows) — `AuthWorkflow`'s recovery flow shipped on top of these primitives.
- [User — Password Hashing](../user/password) — `changePassword` and policy validation.
