# Sessions

A **session is a token family, not a token.** One login mints one stable, opaque `sessionId` that is shared by the access token, the refresh token, and every rotation thereafter. The session APIs let you list a user's signed-in devices, show per-device metadata, and revoke one device (or all-but-this-one) — the data an "active sessions" / "where you're signed in" screen needs.

This is the layer below the HTTP wiring: `@aooth/auth` produces the raw session data; [`@aooth/auth-moost`](../moost/sessions) exposes it over REST and ties "this device" to the current request.

```ts
import { AuthCredential, CredentialStoreMemory } from "@aooth/auth";

const auth = new AuthCredential({
  store: new CredentialStoreMemory(),
  refresh: { ttl: 7 * 24 * 60 * 60 * 1000, rotation: "always" },
});

// One login → one session, carried across every refresh.
const { accessToken } = await auth.issue("alice", {
  metadata: { ip: "1.2.3.4", userAgent: "Mozilla/5.0 …" },
});

const sessions = await auth.listSessions("alice");
// [{ sessionId, userId: 'alice', createdAt, expiresAt, metadata: { ip, userAgent } }]
```

## What a session is

`issue()` mints a random opaque `sessionId` once and stamps it on both the access and refresh credentials. `refresh()` copies it forward onto every rotated pair, so logging in once and refreshing N times stays **one** session — not N. The `sessionId` never leaks token material; it is safe to put in a URL or a UI.

Legacy credentials issued before `sessionId` existed fall back to the token's SHA‑256 fingerprint, so they still list as singleton sessions. The same fallback drives [`AuthContext.sessionId`](./credentials#the-credentialid-fingerprint), so "this device" matching is consistent for old and new tokens alike.

## Listing sessions

```ts
listSessions(userId: string, opts?: { enrich?: SessionEnricher }): Promise<SessionInfo[] | EnrichedSession[]>;
```

Collapses every credential of the user into **one `SessionInfo` row per family** (access + refresh + rotations deduped by `sessionId`), newest first by `lastSeenAt ?? createdAt`:

| Field        | Meaning                                                                 |
| ------------ | ----------------------------------------------------------------------- |
| `sessionId`  | Stable id of the family.                                                |
| `createdAt`  | `issuedAt` of the session's origin credential.                          |
| `expiresAt`  | Expiry of the live refresh token (or the access token if no refresh).   |
| `lastSeenAt` | Newest activity time across the family; absent unless tracked (below).  |
| `metadata`   | The `CredentialMetadata` captured at login (ip / userAgent / …).        |
| `current`    | Set by the caller, not the store — see [auth-moost](../moost/sessions). |

`listSessions` reads through the store's `listForUser` and groups in memory, so it works on Redis / atscript-db with no extra store code. **Stateless stores (JWT, Encapsulated) can't enumerate, so it returns `[]`** — same degradation as `listForUser`. This is the main reason to pick a [stateful store](./stores) when you want a sessions screen.

`listSessions` is the surface a sessions UI should consume. `listForUser` stays as-is for callers that want the flat per-credential `AuthContext` list.

## Read-time enrichment (device / location)

aooth stores only raw facts (`ip`, `userAgent`, timestamps) and ships **no** UA parser or GeoIP dependency. Derive display fields at read time by passing an enricher:

```ts
import type { SessionEnricher } from "@aooth/auth";

const enrich: SessionEnricher = (s) => ({
  ...s,
  browser: parseUA(s.metadata?.userAgent).browser, // your ua-parser
  location: geoip(s.metadata?.ip)?.city, // your GeoIP
});

const rows = await auth.listSessions("alice", { enrich }); // EnrichedSession[]
```

`EnrichedSession extends SessionInfo` with optional `device` / `browser` / `os` / `location` / `geo`. With no enricher the result is plain `SessionInfo[]` and the API stays dependency-free.

## Revoking sessions

```ts
revokeSession(userId: string, sessionId: string): Promise<void>;          // one device's whole family
revokeOtherSessions(userId: string, keepSessionId: string): Promise<number>; // all but one; returns count
```

`revokeSession` kills every token in one family — its access and refresh stop validating immediately; other sessions keep working. `revokeOtherSessions` is the "log out everywhere else" primitive: it revokes every family except `keepSessionId` and returns the number of sessions revoked. Both are no-ops on stores that can't enumerate. `revokeAllForUser` (kill everything, including the caller) stays for the nuclear case.

## Activity tracking (`lastSeenAt`)

Off by default — `lastSeenAt` is `undefined` and `listSessions` falls back to `createdAt`. Opt in via the constructor:

```ts
new AuthCredential({ store, trackLastSeen: "refresh" });
```

| `trackLastSeen`   | Behavior                                                                                                                                               |
| ----------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `false` (default) | No extra writes. `lastSeenAt` stays unset.                                                                                                             |
| `'refresh'`       | Stamp `lastSeenAt` on the credentials minted during `refresh()` — piggybacks the rotation write, no extra round-trip. Recommended.                     |
| `'validate'`      | `store.touch(token, now)` on **every** successful `validate()` — accurate, but one write per authenticated request. Document the cost before enabling. |

`'validate'` needs a store that implements the optional [`touch`](./stores#method-semantics) capability; it is a no-op on stores that don't.

## DOs and DON'Ts

- Pick a **stateful store** (Memory / Redis / atscript-db) if you want a sessions screen — stateless stores return `[]` from `listSessions`. Don't expect JWT/Encapsulated to enumerate.
- Capture `metadata` at **issue time** — `refresh` carries it forward, so login-time capture is enough; you don't re-capture per refresh. (In `@aooth/auth-moost` this is the `resolveIssueMetadata` hook.)
- Keep enrichment **consumer-side** — don't add a UA/geo dependency to your auth layer; pass a `SessionEnricher` at read time.
- Default `trackLastSeen` to `false` (or `'refresh'`) — reach for `'validate'` only when you accept a write per request.
- Don't store derived `device`/`location` — they're read-time only; raw `ip`/`userAgent` retention is already bounded by token expiry.

## See also

- [Credentials & Sessions](./credentials) — the `AuthContext` shape (now carrying `sessionId`) and the `AuthCredential` lifecycle.
- [Stores](./stores) — the optional `touch` / `listSessions` store capabilities and `CredentialState`'s `sessionId` / `lastSeenAt` fields.
- [Refresh & Rotation](./refresh) — how `sessionId` is carried across rotation and how `'refresh'` tracking stamps `lastSeenAt`.
- [auth-moost · Sessions](../moost/sessions) — `useAuth().getSessionId()`, the session facade, and the mountable `SessionsController`.
- [`@aooth/auth` API reference](../api/auth) — full signatures for `SessionInfo`, `EnrichedSession`, `SessionEnricher`.
