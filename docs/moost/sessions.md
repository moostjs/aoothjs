# Sessions

Exposes the [`@aooth/auth` session APIs](../auth/sessions) over HTTP: a mountable `SessionsController` for the "active sessions" screen, the `useAuth()` session facade for writing your own controller, and the "this device" identity that ties a `SessionInfo` to the current request.

Everything here needs a **stateful** credential store (Memory / Redis / atscript-db) — a stateless JWT store can't enumerate sessions, so the endpoints return `[]`. See [auth · Sessions](../auth/sessions).

## "This device" — `useAuth().getSessionId()`

```ts
getSessionId(): string | undefined;
```

Returns the `sessionId` of the token family that authenticated **this** request (from `AuthContext.sessionId`), or `undefined` when unauthenticated. Use it to flag the caller's own row `current: true` and as the `keepSessionId` for "log out everywhere else".

## The session facade — `useAuth()`

Self-scoped wrappers over the configured `AuthCredential`, for writing your own controller. Each resolves the current user via `getUserId()`:

```ts
const auth = useAuth();
await auth.listSessions({ enrich }); // SessionInfo[] | EnrichedSession[] for the current user
await auth.revokeSession(sessionId); // revoke one of the current user's sessions
await auth.revokeOtherSessions(); // log out everywhere else; keeps current; returns count
```

`revokeOtherSessions()` throws `HttpError(401)` if there is no current session to keep. These require the auth guard to have run on the request (it stashes the credential the facade reads); calling them off-request throws `HttpError(500)`.

## `SessionsController` — batteries-included REST

Optional, opt-in by registration. Mount it (or a subclass) alongside `AuthController`:

```ts
import { SessionsController } from "@aooth/auth-moost";

app.registerControllers(AuthController, SessionsController);
```

All routes live under the `auth.sessions` ARBAC resource — **not** `@Public()`. The auth guard rejects anonymous callers with 401, and ARBAC gates each action; grant a user the feature with `allow("auth.sessions", "*")`.

| Method + path                       | ARBAC action | Effect                                                |
| ----------------------------------- | ------------ | ----------------------------------------------------- |
| `GET /auth/sessions`                | `read`       | The caller's own sessions; own row flagged `current`. |
| `GET /auth/sessions/of/:userId`     | `readAny`    | Another user's sessions (admin oversight).            |
| `DELETE /auth/sessions/:sessionId`  | `revoke`     | Revoke one of the caller's sessions.                  |
| `DELETE /auth/sessions?others=true` | `revoke`     | Log out everywhere else, keep current.                |

A bare `DELETE /auth/sessions` (no `?others=true`) is a **400** — ending your _current_ device's session is what `POST /auth/logout` is for (it revokes this session's whole token family by `sessionId`). To end a _specific_ other device use `DELETE /auth/sessions/:sessionId`; to end every other device use `?others=true`. Grant ordinary users `read` + `revoke` (own sessions) and reserve the separate `readAny` action for admins who inspect other users.

## Capturing IP / User-Agent — `resolveIssueMetadata`

`SessionInfo.metadata` is only as rich as what login stored. `AuthWorkflow` captures it via an overridable hook on every `issue()` call:

```ts
protected resolveIssueMetadata(ctx: AuthWfCtx): CredentialMetadata | undefined {
  return { ip: this.resolveClientIp(), userAgent: this.resolveUserAgent() };
}
```

The default records IP + User-Agent (and returns `undefined` outside an HTTP context, e.g. unit tests). Override it to add a `label`, trim PII, etc. Rotation carries metadata forward, so login-time capture is enough. See [Workflows](./workflows).

## Read-time enrichment — `SessionEnricherProvider`

`SessionsController` maps each row through an injectable `SessionEnricherProvider` (default: identity — aooth ships no UA/geo dependency). Subclass + replace to add `device` / `browser` / `os` / `location`:

```ts
import { SessionEnricherProvider } from "@aooth/auth-moost";

@Injectable() // SINGLETON
class MyEnricher extends SessionEnricherProvider {
  override enrich(s: SessionInfo): EnrichedSession {
    return {
      ...s,
      browser: parseUA(s.metadata?.userAgent).browser,
      location: geoip(s.metadata?.ip),
    };
  }
}
app.setReplaceRegistry(createReplaceRegistry([SessionEnricherProvider, MyEnricher]));
```

## DOs and DON'Ts

- Mount `SessionsController` only when you want the bundled endpoints — registration is the opt-in; aooth never mounts it implicitly. Otherwise use the `useAuth()` facade and write your own.
- Gate `readAny` separately from `read` — grant cross-user visibility to admins only.
- Back the credential store with a **stateful** store, or every endpoint returns `[]`. Adopting the atscript-db store also means you must override `WfTriggerProvider.wfStateSecret()` with [`deriveWfStateSecret`](../api/auth-moost#derivewfstatesecret) — it has no secret to HKDF-derive from. See [Workflows](./workflows).
- Keep enrichment in `SessionEnricherProvider` — don't bake a UA/geo dependency into the auth layer.

## See also

- [auth · Sessions](../auth/sessions) — the underlying `listSessions` / `revokeSession` / `sessionId` / `trackLastSeen` model.
- [AuthGuard & useAuth](./auth-guard) — the rest of the `useAuth()` surface and how the guard populates context.
- [`@aooth/auth-moost` API reference](../api/auth-moost) — `SessionsController`, `SessionEnricherProvider`, `deriveWfStateSecret`, and the facade signatures.
