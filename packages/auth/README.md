# @aoothjs/auth

Framework-agnostic auth primitives for the aoothjs ecosystem. An
`AuthCredential` orchestrator wraps pluggable `CredentialStore` implementations
(in-memory, JWT, encapsulated AES-GCM), with optional `DenylistStore` for
revoking stateless credentials. Also exposes email and magic-link primitives
consumed by workflow integrations such as `@aoothjs/auth-moost`.

## Install

```bash
pnpm add @aoothjs/auth @aoothjs/user
```

## Quickstart

```ts
import {
  AuthCredential,
  CredentialStoreMemory,
} from "@aoothjs/auth";

const auth = new AuthCredential({
  store: new CredentialStoreMemory(),
  method: "token",
  accessTtl: 60 * 60 * 1000,                    // 1h
  refresh: { ttl: 30 * 24 * 60 * 60 * 1000, rotation: "sliding" },
});

const issued = await auth.issue("alice");
// → { accessToken, refreshToken, accessExpiresAt, refreshExpiresAt }

const ctx = await auth.validate(issued.accessToken);
// → AuthContext | null
```

## `AuthCredential`

| Method                          | Purpose                                                                   |
| ------------------------------- | ------------------------------------------------------------------------- |
| `issue(userId, opts?)`          | Issue a new access (+ refresh) credential pair                            |
| `validate(accessToken)`         | Return `AuthContext` or `null` (consults denylist if configured)          |
| `refresh(refreshToken)`         | Rotate per `RefreshConfig` (`'none' \| 'always' \| 'sliding'`)            |
| `revoke(token)`                 | Revoke a single token (access or refresh)                                 |
| `revokeAllForUser(userId)`      | Revoke all credentials for a user                                         |
| `listForUser(userId)`           | List active access credentials (for a "your sessions" UI)                 |

Refresh-reuse after the grace window triggers best-effort revocation of all
credentials for the affected user — standard OAuth theft response.

### Refresh rotation

| Rotation   | Behavior                                                              |
| ---------- | --------------------------------------------------------------------- |
| `'none'`   | Refresh token survives across rotations; reuse permitted              |
| `'always'` | New refresh issued on every call; old token revoked immediately       |
| `'sliding'`| Like `'always'`, with a 30s grace window for in-flight refreshes      |

`'sliding'` is the recommended default — tolerates retry storms / racing
clients while still detecting reuse outside the grace window.

## Credential stores

| Store                          | Storage             | Stateless? | Notes                                              |
| ------------------------------ | ------------------- | ---------- | -------------------------------------------------- |
| `CredentialStoreMemory`        | in-memory Map       | no         | Tests / dev                                        |
| `CredentialStoreJwt`           | JWT (HS256/HS512/RS256) | yes    | HS+RS supported; `kid` rotation; alg-confusion blocked |
| `CredentialStoreEncapsulated`  | AES-256-GCM envelope| yes        | Opaque token; pure session-cookie deployments      |

Both stateless stores accept an optional `DenylistStore` for revocation
keyed on `jti`.

```ts
import {
  AuthCredential,
  CredentialStoreJwt,
  DenylistStoreMemory,
} from "@aoothjs/auth";

const auth = new AuthCredential({
  store: new CredentialStoreJwt({
    secret: process.env.JWT_SECRET!,
    algorithm: "HS256",
    issuer: "myapp",
    denylist: new DenylistStoreMemory(),
  }),
});
```

## Email + magic-link primitives

Used by workflow integrations (e.g. `@aoothjs/auth-moost`) but framework-
agnostic — any consumer can compose them into a custom flow.

### `EmailSender`

```ts
import type { EmailSender, AuthEmailEvent } from "@aoothjs/auth";

const sender: EmailSender = {
  async send(event: AuthEmailEvent) {
    // event.kind: 'recovery.magicLink' | 'invite.magicLink' | 'mfa.code'
    await myMailer.queue(event.recipient, event.kind, event);
  },
};
```

`AuthEmailEvent` is flat + serialisable:

```ts
interface AuthEmailEvent {
  kind: "recovery.magicLink" | "invite.magicLink" | "mfa.code";
  recipient: string;
  url?: string;        // magic-link events
  code?: string;       // mfa.code (v2; not emitted in v1)
  expiresAt: number;   // Unix ms
  username?: string;
  metadata?: Record<string, unknown>;
}
```

Aoothjs ships no transport implementation — wire SendGrid / SES / Twilio /
your own queue here. The workflow `await`s the call; push to a queue and
return for slow downstream transports.

### `generateMagicLinkToken()`

```ts
import { generateMagicLinkToken } from "@aoothjs/auth";

const token = generateMagicLinkToken();
// → 43-char base64url string (256 bits of CSPRNG entropy)
```

URL-safe; strong enough to resist online guessing under short TTLs.

### `BuildMagicLinkUrl`

```ts
import type { BuildMagicLinkUrl } from "@aoothjs/auth";

const buildMagicLinkUrl: BuildMagicLinkUrl = (kind, token) =>
  `https://app.example.com/wf/trigger?wfs=${token}`;
// kind: 'recovery' | 'invite'
```

Consumer-supplied URL builder. The recommended convention is `?wfs=<token>`
so the frontend can mount `<AsWfForm initialToken="...">` (from
`@atscript/vue-wf`) to resume a paused workflow.

## API surface

```ts
// Orchestrator
export { AuthCredential }
export type { AuthCredentialOptions, IssueOptions }

// Context + state types
export type { AuthContext, CredentialState, CredentialMetadata, IssueResult, RefreshConfig }

// Store interfaces
export type { CredentialStore, DenylistStore }

// In-memory implementations
export { CredentialStoreMemory, DenylistStoreMemory }

// Stateless implementations
export { CredentialStoreJwt, type CredentialStoreJwtOptions, type JwtAlgorithm }
export { CredentialStoreEncapsulated, type CredentialStoreEncapsulatedOptions }

// Errors
export { AuthError, type AuthErrorType }

// Email + magic-link primitives (consumer composes into flows)
export type { AuthEmailEvent, AuthEmailKind, EmailSender }
export type { BuildMagicLinkUrl, MagicLinkKind }
export { generateMagicLinkToken }

// Clock abstraction
export type { Clock }
export { defaultClock }
```
