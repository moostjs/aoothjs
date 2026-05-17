# Magic Links

A magic link is a single-use URL that authenticates the holder. `@aooth/auth` ships the token generator and a `BuildMagicLinkUrl` type contract; the _storage_ of the token reuses the same `CredentialStore` you already configured.

This is a primitives-only page. The full login / invite / recovery workflows that consume magic links live in [`@aooth/auth-moost`](../moost/workflows) — this page covers what you'd build yourself.

## The token

```ts
function generateMagicLinkToken(): string;
```

- **Source** — 32 bytes from `crypto.randomBytes` (Node) / `crypto.getRandomValues` (Web Crypto).
- **Encoding** — `base64url`. 43 ASCII characters, no padding.
- **Alphabet** — `[A-Za-z0-9_-]`. URL-safe; no `+`, `/`, or `=` so the token can drop into a `?token=...` query string without escaping.

```ts
import { generateMagicLinkToken } from "@aooth/auth";

const token = generateMagicLinkToken();
// 'aBcD1234...43_chars_total...'
```

### Entropy and security

256 bits of CSPRNG entropy. Collision probability over 1 billion tokens is negligible. The token is **not** signed — its security comes entirely from the storage layer's atomic single-use guarantee.

::: warning Treat magic-link tokens as bearer credentials
Anyone who holds the token can claim the underlying state. TLS the URL. Don't log the token. Set a short TTL (5–15 minutes for login, longer for invites).
:::

## The URL contract

```ts
type BuildMagicLinkUrl = (kind: AuthEmailKind, token: string) => string;
```

A consumer-supplied function. The package never builds URLs — it doesn't know your domain, your route shape, or your query-param naming. You wire one function and the workflow uses it.

**Typical implementation**:

```ts
const buildMagicLinkUrl: BuildMagicLinkUrl = (kind, token) => {
  const base = process.env.PUBLIC_URL!;
  switch (kind) {
    case "recovery.magicLink":
      return `${base}/auth/recovery/finish?t=${token}`;
    case "invite.magicLink":
      return `${base}/auth/invite/accept?t=${token}`;
    default:
      return `${base}/auth/finish?t=${token}`;
  }
};
```

The `kind` discriminator is the same one used by `AuthEmailEvent` — see [Delivery](./delivery) for the full union.

## Storage pattern

The magic-link token is just another `CredentialState`. Persist it into the same `CredentialStore` you already configured, with an explicit TTL. Single-use is enforced by `store.consume(token)` — an atomic retrieve-and-revoke.

The state shape:

```ts
{
  userId: string;             // who the link authenticates as
  issuedAt: number;
  expiresAt: number;
  kind: 'magic.recovery',     // or whatever discriminator you pick
  claims: { /* anything */ },
  metadata: { ip, userAgent, /* … */ },
}
```

`kind` is a free string on `CredentialState` (the orchestrator only cares about `'access'` / `'refresh'`). Use it to disambiguate magic-link tokens from regular access tokens when reading the store directly.

::: danger Don't reuse `kind: 'access'` for magic-link tokens
When a magic-link token is persisted with `kind: 'access'` (or no `kind`), it can be presented as a bearer token to `auth.validate()` — the validator only filters on `kind === 'refresh'` and lets everything else through. A magic link sent via email then becomes a working access token until it's consumed.

Always either:

1. Persist with a **distinct `kind`** (`'magic.recovery'`, `'magic.login'`, `'magic.invite'`, etc.) and reject unknown kinds in your auth guard, OR
2. Discriminate by `metadata.label` and reject unknown labels in the guard.

```ts
// guard — reject any state that isn't a normal access token
const state = await auth.validate(bearer);
if (!state) throw new HttpError(401);
if (state.kind && state.kind !== "access") throw new HttpError(401);
```

:::

### Issue: persist + email

```ts
import { generateMagicLinkToken } from "@aooth/auth";

async function sendRecoveryMagicLink(userId: string, email: string) {
  const token = generateMagicLinkToken();
  const now = clock.now();
  const ttl = 15 * 60 * 1000;

  await store.persist(
    {
      userId,
      issuedAt: now,
      expiresAt: now + ttl,
      kind: "magic.recovery",
      claims: { purpose: "recovery" },
    },
    ttl,
  );

  await emailSender.send({
    kind: "recovery.magicLink",
    recipient: email,
    url: buildMagicLinkUrl("recovery.magicLink", token),
    expiresAt: now + ttl,
    username: userId,
  });
}
```

The token is the **opaque store key** — the same value goes both into `store.persist` and into the email URL. We deliberately use the existing `CredentialStore` rather than introducing a separate "magic links" store: same TTL semantics, same revocation cascade, same `listForUser` enumeration if your store supports it.

### Consume: single-use

```ts
async function finishRecovery(token: string) {
  const state = await store.consume(token); // atomic retrieve + revoke
  if (!state) throw new HttpError(401, "invalid or expired link");
  if (state.kind !== "magic.recovery") throw new HttpError(401, "wrong link kind");

  // The token is now dead — any reuse returns null.
  // Carry on with the recovery flow.
  return state.userId;
}
```

`store.consume` returns the state and **atomically** marks the token as used. A second call with the same token returns `null`. This is the only guarantee that prevents replay.

::: warning Always `consume`, never `retrieve`
Use `retrieve` only when you intend the token to remain valid. For magic links — always `consume`. Two requests racing on the same token will both call `consume`; exactly one wins, the other gets `null`.
:::

## Stateless stores need a denylist

`store.consume` requires the store to be able to _mark_ a token as used. Stateless stores (`Jwt`, `Encapsulated`) can't — the token is held by the client, not the server. They simulate `consume` by adding the token's `jti` to a `DenylistStore`. Without one, `consume` throws `STATELESS_OPERATION_UNSUPPORTED`.

```ts
import { CredentialStoreJwt, DenylistStoreRedis } from "@aooth/auth";

const store = new CredentialStoreJwt({
  secret: process.env.JWT_SECRET!,
  denylist: new DenylistStoreRedis({ redis }), // required for consume
});
```

For magic-link use cases specifically, **a stateful store is usually simpler**. JWT for an opaque single-use token is overkill — you get nothing from the signature (the value is opaque to the client anyway) and you pay for a denylist roundtrip on every consume. Use `CredentialStoreMemory` for dev, `CredentialStoreRedis` or `CredentialStoreAtscriptDb` for prod.

## Worked example — a minimal recovery flow

The structure of a magic-link-based password recovery, end to end. Real workflows do more (rate limit, CAPTCHA, audit) but the spine is this:

```ts
import {
  AuthCredential,
  CredentialStoreAtscriptDb,
  generateMagicLinkToken,
  type BuildMagicLinkUrl,
  type EmailSender,
} from "@aooth/auth";

// Bind the store separately — `AuthCredential.store` is `private readonly` and
// is not accessible from outside the class. Keep your own reference for the
// direct `persist` / `consume` calls magic-link flows need.
const store = new CredentialStoreAtscriptDb({ table });
const auth = new AuthCredential({
  store,
  accessTtl: 15 * 60 * 1000,
});

const buildMagicLinkUrl: BuildMagicLinkUrl = (kind, token) =>
  `https://app.example.com/auth/${kind.split(".")[0]}/finish?t=${token}`;

declare const emailSender: EmailSender;
declare const users: {
  /* @aooth/user UserService */
};

// --- Step 1: user submits "I forgot my password" ---
async function requestRecovery(email: string) {
  const userId = await users.findUserIdByEmail(email);
  if (!userId) return; // don't leak existence — silent success

  const token = generateMagicLinkToken();
  const now = Date.now();
  const ttl = 15 * 60 * 1000;

  await store.persist(
    {
      userId,
      issuedAt: now,
      expiresAt: now + ttl,
      kind: "magic.recovery",
    },
    ttl,
  );

  await emailSender.send({
    kind: "recovery.magicLink",
    recipient: email,
    url: buildMagicLinkUrl("recovery.magicLink", token),
    expiresAt: now + ttl,
    username: email,
  });
}

// --- Step 2: user clicks the link, sets a new password ---
async function finishRecovery(token: string, newPassword: string) {
  const state = await store.consume(token);
  if (!state || state.kind !== "magic.recovery") {
    throw new HttpError(401, "invalid or expired link");
  }

  // Validate + persist the new password
  await users.changePassword(state.userId, newPassword);

  // Log out every other device
  await auth.revokeAllForUser(state.userId);

  // Auto-login this device — survives the same-ms epoch gate
  const { accessToken } = await auth.issue(state.userId, {
    claims: {
      /* roles, tenant, … */
    },
    metadata: { ip: "...", userAgent: "..." },
  });
  return accessToken;
}
```

The `revokeAllForUser` + `issue` pair on the last few lines is the same-millisecond pattern from [Refresh](./refresh#why-matters): the new credential's `iatMs` is `>=` the epoch, so it survives. The user is logged out everywhere except this device.

::: tip The store you'd build for magic links is the store you already have
The `CredentialStore` interface is the right abstraction. Don't introduce a second table for magic-link tokens.
:::

## Don't roll your own

Three things that look easy but aren't:

1. **Atomicity** — "retrieve then delete" is a race window. Use `consume`, which is the store's responsibility.
2. **Constant-time comparison** — token lookup must not leak timing information. The provided stores use the underlying DB / Redis primitives, which are constant-time.
3. **TTL** — fix it at `persist` time, not at `consume`. A stale token must die at the storage layer.

The provided primitives handle all three. The package deliberately ships the token generator + URL contract + storage adapter rather than a "magic link service" — the service shape varies too much across apps, but those three primitives are universal.

## See also

- [Password Reset](./password-reset) — the same pattern, applied to recovery.
- [Delivery](./delivery) — the `EmailSender` interface and `AuthEmailKind` union.
- [Stores](./stores) — single-use semantics on each store.
- The token generator source at [packages/auth/src/magic-link.ts](https://github.com/moostjs/aoothjs/blob/main/packages/auth/src/magic-link.ts).
