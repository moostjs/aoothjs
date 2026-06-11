# `@aooth/login-client` — CLI loopback login

Client half of the aoothjs [authorization server](authorization-server.md): one `authorize()` call drives a browser login + PKCE and returns a bearer token (the `gh auth login` pattern). Zero runtime deps — Node built-ins + global `fetch`.

## Quick start

```ts
import { authorize, AuthorizeError } from "@aooth/login-client";

try {
  const { accessToken, userId } = await authorize({
    authorizeUrl: "https://app.example.com/auth/authorize",
    tokenUrl: "https://app.example.com/auth/token",
    statusUrl: "https://app.example.com/auth/status", // optional bearer probe
    scope: ["api"],
    onUrl: (url) => console.log(`Open to sign in: ${url}`), // always fired — fallback line
    signal: abortOnSigint(), // your AbortSignal
  });
  saveToken(accessToken);
} catch (e) {
  if (e instanceof AuthorizeError && e.code === "timeout") process.exit(1);
  throw e;
}
```

Headless / SSH: `openBrowser: false` + print via `onUrl` — the loopback listener still catches the callback when the user opens the URL in any local browser session that can reach `127.0.0.1` of the CLI host.

## Invariants

| #   | Rule                                                                                                                                                                                            |
| --- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1   | **Omit `clientId` for Tier 1 loopback** — PKCE is the binding; the server rejects a spurious `client_id` on a loopback-minted code (`401`, binding symmetry).                                   |
| 2   | The loopback server is **one-shot** on `127.0.0.1` with an ephemeral port — no fixed-port config, nothing to register server-side (`LoopbackClientPolicy` accepts any loopback port, RFC 8252). |
| 3   | `onUrl` fires even with `openBrowser: true` — always print the fallback line.                                                                                                                   |
| 4   | Every failure throws `AuthorizeError` — branch on `.code` (`provider_denied` / `state_mismatch` / `exchange_failed` / `timeout` / `status_check_failed`), never on the message.                 |
| 5   | `statusUrl` (e.g. `/auth/status`) is a `GET` with the new bearer: non-200 → `status_check_failed`; on 200 its `userId` backfills `AuthorizeResult.userId` when the token response lacks one.    |
| 6   | Default wait is 5 min (`timeoutMs: 300_000`); pass `signal` to abort on SIGINT — both surface as `code: "timeout"`.                                                                             |
| 7   | `idToken` is populated only when the server is a Tier-2 OIDC provider — opaque to this helper (verify it with `@aooth/idp`'s `OidcProvider` if you are the consuming service).                  |
| 8   | Reusable beyond CLIs: a hosted first-party service runs the same flow with its own callback as `redirect_uri` (then it IS a registered client — send `clientId`).                               |

## Key imports

```ts
import { authorize, AuthorizeError } from "@aooth/login-client";
import type { AuthorizeOptions, AuthorizeResult, AuthorizeErrorCode } from "@aooth/login-client";
```

## References

| Domain                              | File                                               | When                                                                    |
| ----------------------------------- | -------------------------------------------------- | ----------------------------------------------------------------------- |
| Server half (authorize/token/OIDC)  | [authorization-server.md](authorization-server.md) | Wiring `/auth/authorize` + `/auth/token`, client policies, consent gate |
| Consuming the id_token as a service | [idp.md](idp.md)                                   | Verifying a Tier-2 `id_token` with `OidcProvider`                       |

## See also

Docs: https://aoothjs.dev/api/login-client. Source: `packages/login-client/src/index.ts`.
