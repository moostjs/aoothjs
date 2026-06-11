# `@aooth/login-client` API Reference

Complete export reference for `@aooth/login-client`. See [Authorization Server](/moost/authorization-server) for the server half this package talks to — Tier 1 (CLI loopback) is the primary use case. Every public symbol lives in `packages/login-client/src/index.ts`. Zero runtime dependencies — Node built-ins + global `fetch` only.

## Functions

### `authorize`

```ts
async function authorize(opts: AuthorizeOptions): Promise<AuthorizeResult>;
```

The package's single entry point: obtains a token from an aoothjs authorization server by driving the user through a **browser login** and catching the redirect on a one-shot ephemeral **loopback** HTTP server (`127.0.0.1`, random port — the `gh auth login` pattern). Generates `state` + a PKCE S256 challenge, opens (or surfaces) the authorize URL, awaits the callback, verifies `state`, exchanges the code at `tokenUrl`, and optionally confirms the token against `statusUrl`. Throws `AuthorizeError` on every failure path. Also reusable as a generic "Sign in with the main app" hatch — only the `redirect_uri` differs; the flow is identical.

## Types

### `AuthorizeOptions`

```ts
interface AuthorizeOptions {
  authorizeUrl: string; // the server's GET /auth/authorize URL
  tokenUrl: string; // the server's POST /auth/token URL
  clientId?: string; // registered client id; OMIT for a public/loopback client (PKCE is the binding)
  scope?: string[]; // joined with spaces into the `scope` param
  openBrowser?: boolean; // default true; false for headless/SSH — pair with onUrl
  onUrl?: (url: string) => void; // ALWAYS invoked with the authorize URL (fallback print)
  statusUrl?: string; // optional GET confirmation with the bearer (e.g. /auth/status)
  timeoutMs?: number; // callback wait — default 300_000 (5 min)
  signal?: AbortSignal; // abort the wait early (e.g. SIGINT)
}
```

`onUrl` fires even when `openBrowser` is `true`, so a CLI can always print a "or open this URL" fallback line. On a `statusUrl` 200, the helper adopts its `userId` when the token response did not carry one; a non-200 throws `status_check_failed`. **Don't send `clientId` for a Tier 1 loopback login** — the server rejects a spurious `client_id` on a code minted for a public loopback client.

### `AuthorizeResult`

```ts
interface AuthorizeResult {
  accessToken: string; // send as `Authorization: Bearer <accessToken>`
  expiresIn?: number; // seconds, as reported by the token endpoint
  idToken?: string; // OIDC id_token when the server is a Tier-2 OIDC provider (opaque here)
  userId?: string; // from the token response or the statusUrl confirmation
}
```

### `AuthorizeError`

```ts
class AuthorizeError extends Error {
  readonly code: AuthorizeErrorCode;
  constructor(code: AuthorizeErrorCode, message: string);
}
```

Every `authorize()` failure throws this — branch on `.code`, not the message.

### `AuthorizeErrorCode`

```ts
type AuthorizeErrorCode =
  | "provider_denied" // callback carried ?error= (e.g. the user declined)
  | "state_mismatch" // callback state ≠ generated state (CSRF / instance mismatch)
  | "exchange_failed" // POST /token failed (non-2xx, network, malformed body)
  | "timeout" // no callback before timeoutMs (or `signal` aborted)
  | "status_check_failed"; // statusUrl confirmation returned non-200
```
