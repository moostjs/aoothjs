# @aooth/auth/client — browser silent-refresh

Browser-safe subpath of `@aooth/auth`. One export: `createAuthedFetch` — a `fetch` wrapper that transparently refreshes a cookie-transport session. Imports nothing from the rest of `@aooth/auth` (no `jose`/Node crypto); safe to bundle for the browser.

## Quick start

```ts
import { createAuthedFetch } from "@aooth/auth/client";

const api = createAuthedFetch({
  refreshPath: "/auth/refresh", // match AuthController mount
  onLogout: () => location.assign("/login"),
});

const res = await api("/api/me"); // 401 → silent refresh → retried once
```

## Invariants

| #   | Rule                                                                                                                                                                                                                                       |
| --- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| 1   | Every call sets `credentials: "include"` (sends httpOnly session + refresh cookies). Caller `init.credentials` overrides it.                                                                                                               |
| 2   | A response status in `refreshOn` (default `[401]`) triggers `POST {refreshPath}`. Other statuses pass straight through — no refresh.                                                                                                       |
| 3   | **Single-flight**: N concurrent requests that all 401 share exactly ONE in-flight refresh. The promise is cleared on settle, so the next fresh 401 starts a new refresh.                                                                   |
| 4   | Refresh **success** → original request retried **once**. The retry never re-enters refresh, so a still-401 retry is returned as-is (no loop, no storm).                                                                                    |
| 5   | Refresh **failure** (non-OK response OR thrown network error) → `onLogout()` fired **once** (inside the single-flight, not per caller) → the original failing response is returned. No retry.                                              |
| 6   | `refreshPath` MUST match the real refresh route. The refresh cookie path is auto-scoped to `AuthController`'s mount, so a wrong `refreshPath` means the cookie isn't sent and refresh always 401s. Under a prefix use `/api/auth/refresh`. |
| 7   | The retry replays the original `init`. A one-shot `ReadableStream` body can't be re-read → not retry-safe. Use string / `FormData` / `Blob` bodies.                                                                                        |
| 8   | Returns a function with the **same signature as the wrapped `fetch`** (or the global). `DefaultFetch` resolves to the ambient `fetch` type when the consumer has the DOM lib, so the result is a real `Response` (`.json()` etc).          |
| 9   | Built for the httpOnly-cookie session (`enableBearer: false` server-side). NOT for bearer-token transport — bearer clients manage their own `Authorization` header.                                                                        |
| 10  | Pair with `GET /auth/status` as a page-load probe: 401 → wrapper refreshes → re-probes; still failing → genuinely logged out.                                                                                                              |

## Key imports

```ts
import { createAuthedFetch } from "@aooth/auth/client";
import type {
  CreateAuthedFetchOptions,
  FetchFn,
  MinimalResponse,
  MinimalRequestInit,
  DefaultFetch,
} from "@aooth/auth/client";
```

Options: `{ refreshPath?, onLogout?, fetch?, refreshOn? }`.

## See also

| Domain             | File                             | When                                                                              |
| ------------------ | -------------------------------- | --------------------------------------------------------------------------------- |
| Refresh & rotation | [refresh.md](refresh.md)         | server-side `/auth/refresh`, rotation modes, `reuseResponse`, reuse detection     |
| Controllers        | [controllers.md](controllers.md) | `/auth/refresh`, `/auth/status`, `/auth/logout`, auto-derived refresh cookie path |
| Sessions / devices | [sessions.md](sessions.md)       | `sessionId` token-family, per-device revoke                                       |

Reference docs: https://aoothjs.dev/auth/client. Source: `packages/auth/src/client/index.ts`.
