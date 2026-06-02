# Sessions (active devices, per-session revoke)

A **session = a token family**: one login → one stable opaque `sessionId`, shared by the access token, its refresh token, and every rotation. Backs an "active sessions" / "where you're signed in" screen. Core APIs in `@aooth/auth`; HTTP surface in `@aooth/auth-moost`.

## Quick start

```ts
// core (@aooth/auth) — needs a STATEFUL store (Memory/Redis/AtscriptDb)
const auth = new AuthCredential({
  store,
  refresh: { ttl, rotation: "always" },
  trackLastSeen: "refresh",
});
await auth.issue("alice", { metadata: { ip, userAgent } }); // sessionId minted, metadata captured
const rows = await auth.listSessions("alice", { enrich }); // SessionInfo[] | EnrichedSession[]
await auth.revokeSession("alice", sessionId); // kill one device's family
await auth.revokeOtherSessions("alice", keepSessionId); // log out everywhere else → count

// moost (@aooth/auth-moost)
useAuth().getSessionId(); // "this device" (AuthContext.sessionId)
useAuth().listSessions({ enrich }); // facade, scoped to current user
app.registerControllers(AuthController, SessionsController); // GET/DELETE /auth/sessions
```

## Invariants

| #   | Rule                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| --- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1   | `issue()` mints `sessionId` once, stamps both access + refresh. `refresh()` copies it forward → **N refreshes = 1 session**, not N.                                                                                                                                                                                                                                                                                                                                                               |
| 2   | Legacy credentials without `sessionId` fall back to `fingerprint(token)` — same fallback in `validate()` (→ `AuthContext.sessionId`) and the `listSessions` grouper, so "this device" matching is consistent.                                                                                                                                                                                                                                                                                     |
| 3   | `listSessions` groups `store.listForUser` output by `sessionId` in memory → works on Redis/AtscriptDb with no store code. **Stateless stores (JWT/Encapsulated) return `[]`** (no `listForUser`). Same for `revokeSession`/`revokeOtherSessions` (no-op). Want a sessions screen ⇒ pick a stateful store.                                                                                                                                                                                         |
| 4   | `SessionInfo`: `createdAt` = min `issuedAt` of family; `expiresAt` = live refresh token's expiry (else access); `lastSeenAt` = max across family (falls back to `createdAt`); `metadata` = login-time facts. `current` is set by the **caller** (controller), never the store.                                                                                                                                                                                                                    |
| 5   | `trackLastSeen` default `false` (no extra writes). `'refresh'` stamps `lastSeenAt` on rotation (cheap). `'validate'` calls `store.touch(token, now)` per successful `validate()` (one write/request — document cost; needs a store implementing `touch`).                                                                                                                                                                                                                                         |
| 6   | Enrichment is **read-time + consumer-side**: pass `SessionEnricher` to `listSessions`; aooth ships NO UA-parser/GeoIP. `EnrichedSession extends SessionInfo` with `device/browser/os/location/geo`. No enricher → plain `SessionInfo[]`, dependency-free. Don't store derived fields.                                                                                                                                                                                                             |
| 7   | Capture `metadata` at issue time only — `refresh` carries it forward (no per-refresh recapture). In auth-moost, the `AuthWorkflow.resolveIssueMetadata(ctx)` hook does this (default IP+UA; `undefined` outside HTTP).                                                                                                                                                                                                                                                                            |
| 8   | `SessionsController` is opt-in by **registration**, NOT `@Public()`. ARBAC resource `auth.sessions`; actions `read` (self) / `revoke` / `readAny` (cross-user, admin). Routes: `GET /auth/sessions`, `GET /auth/sessions/of/:userId`, `DELETE /auth/sessions/:sessionId`, `DELETE /auth/sessions?others=true`. Bare `DELETE /auth/sessions` → **400** (use `/auth/logout` to end your _current_ device's session; per-session `DELETE /auth/sessions/:sessionId` or `?others=true` for the rest). |
| 9   | `useAuth()` facade (`listSessions`/`revokeSession`/`revokeOtherSessions`) reads the guard-stashed `AuthCredential` — off-request → `HttpError(500)`; `revokeOtherSessions()` with no current session → `HttpError(401)`.                                                                                                                                                                                                                                                                          |
| 10  | `SessionEnricherProvider` is a SINGLETON DI seam (default identity). Subclass + `setReplaceRegistry([SessionEnricherProvider, MyEnricher])` to add device/location.                                                                                                                                                                                                                                                                                                                               |
| 11  | Change-password revokes OTHER sessions and keeps the current device (`revokeOtherSessions(getSessionId())`); recovery uses `revokeAllForUser` (anonymous, nothing to keep).                                                                                                                                                                                                                                                                                                                       |
| 12  | The atscript-db credential store has no `deriveSubkey`, so `WfTriggerProvider.wfStateSecret()`'s default throws — override with `deriveWfStateSecret(env.SECRET)` (SHA-256 → exactly 32 bytes; a raw string is parsed as hex by `EncapsulatedStateStrategy`).                                                                                                                                                                                                                                     |

## Key imports

```ts
import { AuthCredential } from "@aooth/auth";
import type { SessionInfo, EnrichedSession, SessionEnricher } from "@aooth/auth";
import {
  SessionsController,
  SessionEnricherProvider,
  deriveWfStateSecret,
  useAuth,
} from "@aooth/auth-moost";
```

`SessionInfo`/`EnrichedSession`/`SessionEnricher` are re-exported from `@aooth/auth-moost` too.

## See also

- [tokens.md](tokens.md) — sessions-vs-tokens, `method: 'session' | 'token'`.
- [refresh.md](refresh.md) — `sessionId`/`metadata`/`claims` carried across rotation; `'refresh'` lastSeen stamping.
- [auth-stores.md](auth-stores.md) — `touch?` / `listSessions?` store capabilities, `CredentialState.sessionId`/`lastSeenAt`.
- [controllers.md](controllers.md) — `useAuth()`, `AuthController`, guard/ARBAC split.
- API: https://aoothjs.dev/auth/sessions · https://aoothjs.dev/moost/sessions
