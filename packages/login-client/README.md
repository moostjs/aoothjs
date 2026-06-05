# @aooth/login-client

Zero-dependency helper that logs a user in through their **browser** and hands a
token back to a local process — the `gh auth login` pattern, for any
[aoothjs](https://github.com/moostjs/aoothjs) authorization server.

It runs the authorization-code + PKCE flow against a one-shot **loopback**
redirect (`http://127.0.0.1:<ephemeral-port>/callback`), so nothing is ever
copy-pasted. Built on Node built-ins (`node:http`, `node:crypto`,
`node:child_process`) and global `fetch` only — **no runtime dependencies**.

## Install

```bash
npm i @aooth/login-client   # Node >= 18
```

## Use

```ts
import { authorize } from "@aooth/login-client";

const { accessToken, expiresIn, userId } = await authorize({
  authorizeUrl: "https://main.example.com/auth/authorize",
  tokenUrl: "https://main.example.com/auth/token",
  // clientId,                 // omit for a public/loopback client (PKCE is the binding)
  // scope: ["api"],
  // statusUrl: "https://main.example.com/auth/status",  // optional: confirm the token works
});

// send it: Authorization: Bearer <accessToken>
```

What it does: opens a one-shot `127.0.0.1` listener, generates `state` + PKCE,
opens the browser to `authorizeUrl`, awaits the single callback, **verifies
`state`** (the CSRF check), then `POST tokenUrl { code, code_verifier }` and
returns the token. It does **not** crypto-validate the token — that is the
server's opaque credential; TLS + PKCE + `state` are the binding.

### Headless / SSH

```ts
await authorize({
  authorizeUrl,
  tokenUrl,
  openBrowser: false,
  onUrl: (url) => console.log(`Open this URL to sign in:\n${url}`),
});
```

The loopback listener still catches the callback once the user opens the URL
elsewhere on the same machine.

## Options

| Option         | Default  | Notes                                                        |
| -------------- | -------- | ------------------------------------------------------------ |
| `authorizeUrl` | —        | the server's `GET /auth/authorize`                           |
| `tokenUrl`     | —        | the server's `POST /auth/token`                              |
| `clientId`     | —        | omit for a public/loopback client                            |
| `scope`        | —        | `string[]`, joined with spaces                               |
| `openBrowser`  | `true`   | set `false` + `onUrl` for headless                           |
| `onUrl`        | —        | always called with the authorize URL (print a fallback line) |
| `statusUrl`    | —        | optional bearer-confirm `GET`; adopts its `userId`           |
| `timeoutMs`    | `300000` | wait for the browser callback                                |
| `signal`       | —        | `AbortSignal` to cancel (e.g. on SIGINT)                     |

Failures throw an `AuthorizeError` with a `.code`
(`provider_denied` · `state_mismatch` · `exchange_failed` · `timeout` ·
`status_check_failed`).
