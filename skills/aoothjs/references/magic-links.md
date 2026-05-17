# Magic links

The auth package ships only the primitives — token generation + persistence contract + transport interface. The workflow that wires email delivery and resume routing lives in `@aooth/auth-moost` (see moost reference ([moost.md](./moost.md))); this page documents the standalone usage and the recipe both workflows follow.

## Contents

- [Token format](#token-format)
- [Persistence pattern](#persistence-pattern)
- [Single-use guarantee](#single-use-guarantee)
- [Stateless requirement](#stateless-requirement)
- [`BuildMagicLinkUrl`](#buildmagiclinkurl)
- [Recovery flow recipe](#recovery-flow-recipe)
- [Transport contract](#transport-contract)

## Token format

```ts
import { generateMagicLinkToken } from "@aooth/auth";

const token = generateMagicLinkToken();
// → 43-char base64url string, e.g. 'xJ3p...A2k'
```

- 32 bytes of CSPRNG entropy (256 bits) via `node:crypto.randomBytes`.
- `base64url`-encoded → 43 chars, exclusively `[A-Za-z0-9_-]`, **no padding**.
- URL-safe — no `+`, `/`, or `=`, no escaping needed in path / query.
- Strong against online guessing even with short TTLs (5–15 min typical).

The token is the **raw bearer credential** — store its hash, not the plain value, if you persist it outside the credential store. Aoothjs's stores already hash internally (`Memory` keys by token directly but never logs; `Redis` uses the token as a key suffix; `AtscriptDb` keys the row by the token PK).

## Persistence pattern

Magic links reuse the same `CredentialStore` machinery as access / refresh tokens. The workflow `persist`s a `CredentialState` with a short TTL; the resume handler `consume`s it.

```ts
import { AuthCredential, CredentialStoreMemory, generateMagicLinkToken } from "@aooth/auth";

const store = new CredentialStoreMemory();
const MAGIC_LINK_TTL = 15 * 60 * 1000; // 15min

// Workflow step: issue the link.
async function issueRecoveryLink(userId: string, email: string) {
  const token = generateMagicLinkToken();
  // Persist directly through the store — bypasses AuthCredential.issue() so
  // we set our own token id rather than letting the store generate one.
  // For stores that DO own token-id generation (Memory / Redis / AtscriptDb),
  // call store.persist() and use the returned id instead.
  //
  // SECURITY WARNING: `kind: 'access'` here means the magic-link token is
  // ALSO a valid bearer access token — `AuthCredential.validate()` only
  // filters out `kind === 'refresh'` (see auth-credential.ts validate()),
  // it does NOT filter on the `metadata.label` discriminator. Any holder of
  // the magic-link token can pass it as `Authorization: Bearer <token>` and
  // pass authentication. If you need the link to be redemption-only, persist
  // with a distinct `kind` (e.g. `'magic.recovery'`) and check it on
  // `consume`, OR check `state.metadata?.label` explicitly before honoring
  // the bearer use. The shipped auth-moost workflows accept the bearer
  // collapse as the trade-off for using one store / one table.
  await store.persist(
    {
      userId,
      issuedAt: Date.now(),
      expiresAt: Date.now() + MAGIC_LINK_TTL,
      kind: "access",
      metadata: { label: "recovery.magicLink" },
    },
    MAGIC_LINK_TTL,
  );
  return token;
}

// Workflow step: redeem the link.
async function consumeRecoveryLink(token: string) {
  const state = await store.consume(token); // atomic retrieve + revoke
  if (!state) throw new Error("link expired or already used");
  return state.userId;
}
```

The shipped workflows in `@aooth/auth-moost` use this exact pattern with `kind: 'access'` + a `metadata.label` discriminator (`'recovery.magicLink'`, `'invite.magicLink'`, etc.).

## Single-use guarantee

`store.consume(token)` is the atomic primitive. Per-store implementation:

| Store                         | `consume`                                              | Notes                                                                 |
| ----------------------------- | ------------------------------------------------------ | --------------------------------------------------------------------- |
| `CredentialStoreMemory`       | `retrieve` then `revoke`                               | Single-process — no race against itself.                              |
| `CredentialStoreRedis`        | `retrieve` then `revoke`                               | Two round trips. Atomic enough for magic-link cadence.                |
| `CredentialStoreAtscriptDb`   | `retrieve` then `revoke` (via `deleteOne`)             | Same pattern. DB-level race exists in theory; in practice negligible. |
| `CredentialStoreJwt`          | Verify, denylist-add by `jti`. **Requires denylist.**  | Throws `STATELESS_OPERATION_UNSUPPORTED` without one.                 |
| `CredentialStoreEncapsulated` | Decrypt, denylist-add by `jti`. **Requires denylist.** | Same.                                                                 |

After `consume`, a replay of the same token returns `null` (`retrieve` finds nothing, or finds a denylist hit). The workflow MUST reject `null` — see the recipe below.

## Stateless requirement

Stateless stores (`Jwt`, `Encapsulated`) cannot single-use a token without a denylist — they have nowhere to record "this jti was consumed". Any of `revoke`, `consume`, `update` on a stateless store without `denylist` throws:

```ts
new AuthError(
  "STATELESS_OPERATION_UNSUPPORTED",
  `<op> requires a denylist on stateless <jwt|encapsulated> store`,
);
```

Wire `DenylistStoreMemory` for single-process apps; `DenylistStoreRedis` for multi-pod. Both shipped:

```ts
import { CredentialStoreJwt, DenylistStoreMemory } from "@aooth/auth";
import { DenylistStoreRedis } from "@aooth/auth/redis";

const store = new CredentialStoreJwt({
  algorithm: "HS256",
  secret: process.env.JWT_SECRET!,
  denylist: new DenylistStoreRedis({ redis, prefix: "aooth:dl" }),
});
```

The denylist key for stateless stores is the `jti` (random UUID per token), not the raw token string. Lifetime ≈ token TTL — the entry is written with `expiresAt - now` and Redis self-evicts.

## `BuildMagicLinkUrl`

The package does not assume your domain, scheme, or route shape. Consumers supply a builder:

```ts
type BuildMagicLinkUrl = (kind: AuthEmailKind, token: string) => string;

// Convention used by `@aooth/auth-moost` + `@atscript/vue-wf`:
const buildMagicLinkUrl: BuildMagicLinkUrl = (kind, token) => {
  switch (kind) {
    case "recovery.magicLink":
      return `https://app.example.com/auth/recovery?wfs=${token}`;
    case "invite.magicLink":
      return `https://app.example.com/auth/invite?wfs=${token}`;
    default:
      throw new Error(`No URL convention for ${kind}`);
  }
};
```

Passing the token as `?wfs=<token>` lets a frontend mount `<AsWfForm initialToken="...">` to resume the workflow (see `atscript-ui-wf` for the receiving side). The convention is yours — `wfs` is a recommendation, not a wire requirement.

## Recovery flow recipe

End-to-end shape — translate to your workflow framework (`@moostjs/event-wf`, plain HTTP routes, REST controller).

```ts
import { AuthCredential, CredentialStoreAtscriptDb, generateMagicLinkToken } from "@aooth/auth";
import type { EmailSender, BuildMagicLinkUrl } from "@aooth/auth";

const auth = new AuthCredential({ store, accessTtl: 60 * 60 * 1000 });

// Step 1 — request recovery
async function requestRecovery(
  email: string,
  deps: { emailSender: EmailSender; buildUrl: BuildMagicLinkUrl },
) {
  const userId = await lookupUserByEmail(email);
  if (!userId) return; // don't leak existence

  const token = generateMagicLinkToken();
  const expiresAt = Date.now() + 15 * 60 * 1000;
  // SECURITY WARNING: `kind: 'access'` makes this magic-link token
  // accept as a regular bearer token via `auth.validate()` — the only
  // kind filter there is `kind === 'refresh'`. If you do NOT want the
  // recipient to be able to call your API with the raw link token, use a
  // distinct `kind` like `'magic.recovery'` and reject it explicitly in
  // any custom auth guard (or check `state.metadata?.label` before
  // accepting the bearer use). The shipped auth-moost workflows accept
  // this collapse as a trade-off for using one shared store.
  await store.persist(
    {
      userId,
      issuedAt: Date.now(),
      expiresAt,
      kind: "access",
      metadata: { label: "recovery.magicLink" },
    },
    15 * 60 * 1000,
  );

  await deps.emailSender.send({
    kind: "recovery.magicLink",
    recipient: email,
    url: deps.buildUrl("recovery.magicLink", token),
    expiresAt,
    username: userId,
  });
}

// Step 2 — redeem
async function redeemRecovery(token: string, newPassword: string) {
  const state = await store.consume(token);
  if (!state) throw new Error("Link expired or already used");

  await setUserPassword(state.userId, newPassword);
  // Invalidate every other live session/token for this user.
  await auth.revokeAllForUser(state.userId);

  // Optional auto-login: issue a fresh credential.
  // Works on stateless stores because the epoch gate is `>=` (same-ms accept).
  return auth.issue(state.userId);
}
```

Three invariants in this recipe map to SKILL.md:

- `revokeAllForUser` before auto-login (#15) — every other session is killed.
- `issue` immediately after `revokeAllForUser` in the same ms (#4) — the `>=` epoch gate accepts the fresh token.
- `store.consume` returns `null` after first use (single-use #13 + stateless requirement).

## Transport contract

```ts
type AuthEmailKind =
  | "recovery.magicLink"
  | "invite.magicLink"
  | "mfa.code"
  | "login.pincode"
  | "recovery.pincode"
  | "invite.pincode"
  | "notifyNewDevice";

interface AuthEmailEvent {
  kind: AuthEmailKind;
  recipient: string;
  url?: string; // present for magic links; absent for codes / notify
  code?: string; // present for pincode / mfa.code
  expiresAt: number; // ms — convenient for templating
  username?: string;
  metadata?: Record<string, unknown>;
}

interface EmailSender {
  send(event: AuthEmailEvent): Promise<void>;
}
```

SMS uses the parallel `AuthSmsKind` + `AuthSmsEvent` + `SmsSender` triple. No `url` field on SMS — SMS magic-link delivery isn't supported; use pincode kinds for SMS.

The workflow `await`s `send`. Blocking transports must enqueue and return synchronously — otherwise issue / consume calls stall on SES / Twilio latency.

```ts
class QueuedEmailSender implements EmailSender {
  constructor(private queue: { enqueue(j: unknown): Promise<void> }) {}
  async send(event: AuthEmailEvent) {
    await this.queue.enqueue({ topic: "auth.email", event });
  }
}
```
