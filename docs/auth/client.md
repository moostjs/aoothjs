# Client (Browser Silent Refresh)

`@aooth/auth/client` is the **browser-safe** subpath of `@aooth/auth`. It ships one helper — `createAuthedFetch` — that wraps `fetch` so an SPA gets transparent token refresh on a cookie-transport session without ever touching token material.

It imports nothing from the rest of `@aooth/auth` (no `jose`, no Node crypto), so it is safe to bundle into a browser app.

```ts
import { createAuthedFetch } from "@aooth/auth/client";

const api = createAuthedFetch({
  refreshPath: "/auth/refresh", // match your AuthController mount
  onLogout: () => location.assign("/login"),
});

// Use it exactly like fetch. A 401 is refreshed and retried transparently.
const res = await api("/api/me");
const me = await res.json();
```

## What it does

On every call `api(input, init)`:

1. **Forwards credentials** — sets `credentials: "include"` (so the httpOnly session + refresh cookies are sent) unless you override it in `init`.
2. On a response whose status is in `refreshOn` (just `401` by default), runs a **single-flight refresh**: `POST {refreshPath}`. N concurrent requests that all see a 401 share **exactly one** in-flight refresh instead of stampeding the endpoint.
3. On refresh **success**, retries the original request **once** and returns that response.
4. On refresh **failure** (non-OK response or a network error), calls `onLogout()` **once** and returns the original failing response — no retry, no refresh storm.

The retried request never re-enters the refresh path, so a still-401 retry is returned as-is (an expired session can't loop).

## Options

```ts
createAuthedFetch({
  refreshPath, // string — refresh endpoint. Default '/auth/refresh'.
  onLogout, // () => void — fired once per failed refresh. Default: none.
  fetch, // FetchFn — underlying fetch. Default: the global `fetch`.
  refreshOn, // number[] — statuses that trigger refresh+retry. Default [401].
});
```

| Option        | Default           | Notes                                                                                                                                       |
| ------------- | ----------------- | ------------------------------------------------------------------------------------------------------------------------------------------- |
| `refreshPath` | `'/auth/refresh'` | Must match where `AuthController` is mounted. Under a prefix (`registerControllers(['api/auth', AuthController])`) use `/api/auth/refresh`. |
| `onLogout`    | `undefined`       | Called exactly once when a refresh attempt fails. Redirect to login or clear app state here. Never called on success.                       |
| `fetch`       | global `fetch`    | Pass a custom fetch (SSR, polyfill, instrumented). Passing the browser's `fetch` also gives you a precisely-typed `Response` back.          |
| `refreshOn`   | `[401]`           | Widen if your API signals "access expired" with another status (e.g. `[401, 419]`).                                                         |

`createAuthedFetch` returns a function with the **same signature as the `fetch` you passed** (or the global one), so it is a drop-in replacement — assign it to your API client and call it everywhere.

## Bootstrap probe

Pair it with `GET /auth/status` on page load to decide whether to render the app or the login screen. `/auth/status` returns `401` when there is no live access token; the wrapper then silently refreshes and re-probes:

```ts
const api = createAuthedFetch({ onLogout: () => location.assign("/login") });

async function boot() {
  const res = await api("/auth/status"); // 401 → silent refresh → retried once
  if (res.ok) return startApp(await res.json()); // { userId, claims, ... }
  location.assign("/login"); // refresh failed too → genuinely logged out
}
```

## DOs and DON'Ts

- **DO** point `refreshPath` at the real refresh route. The refresh cookie's path is [auto-scoped to that route](../moost/config), so the browser only sends it there — a wrong `refreshPath` means the cookie isn't attached and every refresh 401s.
- **DO** use string / `FormData` / `Blob` request bodies. The retry replays the original `init`; a one-shot `ReadableStream` body can't be re-read, so it won't survive a retry.
- **DON'T** put token logic in the SPA. With the default cookie transport (`enableBearer: false` server-side), there are no tokens in JS to manage — this helper is the entire client integration.
- **DON'T** expect `onLogout` per request. It fires once per failed refresh (single-flight), not once per concurrent 401.
- **DON'T** reach for this with bearer-token transport. It's built for the httpOnly-cookie session; bearer clients manage their own `Authorization` header.

## See also

- [Refresh & Rotation](./refresh) — what `POST /auth/refresh` does server-side, rotation modes, and reuse detection.
- [Config Reference](../moost/config) — the auto-derived refresh cookie path the client relies on.
- [REST Controllers](../moost/controllers) — `/auth/refresh`, `/auth/status`, `/auth/logout`.
- [API reference](/api/auth#client) — `createAuthedFetch` signature and the `FetchFn` / `MinimalResponse` types.
