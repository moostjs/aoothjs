# Config Reference

This page is the complete configuration reference for the Moost integration layer: `AuthOptions` (consumed by `authGuardInterceptor`, `useAuth`, the `AuthController`, and the workflow finalize steps) plus the security-relevant tuning knobs of the three workflows. Workflow options have their full shape in [Workflows](./workflows); here we surface only the security-load-bearing fields.

## `AuthOptions`

```ts
import type { AuthOptions } from "@aooth/auth-moost";

app.applyGlobalInterceptors(
  authGuardInterceptor({
    cookie: { secure: false, sameSite: "lax" },
    enableBearer: true,
  }),
);
```

| Field                    | Default                          | Notes                                                                                                                                                                  |
| ------------------------ | -------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------- | -------- |
| `cookie.name`            | `'aooth_session'`                | Access cookie name.                                                                                                                                                    |
| `cookie.secure`          | `true`                           | HTTPS-only — flip to `false` for local HTTP dev.                                                                                                                       |
| `cookie.sameSite`        | `'lax'`                          | `'lax'                                                                                                                                                                 | 'strict' | 'none'`. |
| `cookie.httpOnly`        | `true`                           | JS access to the cookie is blocked.                                                                                                                                    |
| `cookie.path`            | `'/'`                            | Sent on every request.                                                                                                                                                 |
| `cookie.domain`          | `undefined`                      | Defaults to the request host.                                                                                                                                          |
| `refreshCookie.name`     | `'aooth_refresh'`                | Refresh cookie name.                                                                                                                                                   |
| `refreshCookie.path`     | `'/auth/refresh'`                | **Narrow path** so the refresh cookie isn't sent on other endpoints — CSRF-resistance.                                                                                 |
| `refreshCookie.secure`   | inherited from `cookie.secure`   |                                                                                                                                                                        |
| `refreshCookie.sameSite` | inherited from `cookie.sameSite` |                                                                                                                                                                        |
| `refreshCookie.httpOnly` | inherited from `cookie.httpOnly` |                                                                                                                                                                        |
| `refreshCookie.domain`   | inherited from `cookie.domain`   |                                                                                                                                                                        |
| `enableCookie`           | `true`                           | Master switch for cookie transport. When `false`, `writeCookies` / `clearCookies` are no-ops.                                                                          |
| `enableBearer`           | `true`                           | Master switch for bearer transport. When both are `true`, **bearer wins**. When `false`, `accessToken` and `refreshToken` are omitted from `AuthLoginResponse` bodies. |

::: warning Narrow refresh cookie path is deliberate
Browsers don't send the refresh cookie to any path outside `/auth/refresh` by default. That's why `/auth/logout` accepts a body `refreshToken` field — it can't read the cookie. Widening the path (e.g. to `/`) removes the CSRF-resistance benefit, and the refresh cookie is now exposed on every request.
:::

::: warning CSRF is your responsibility
The package does NOT bundle a CSRF strategy. `SameSite=Lax` on the access cookie is the default sole defence. For sensitive endpoints, add a CSRF-token interceptor that compares a custom header against a double-submitted cookie, or switch to `SameSite=Strict`. The bundled refresh cookie's narrow path is a CSRF mitigation specifically for token rotation, not a general defence.
:::

## Login workflow — security-load-bearing options

See [Workflows § LoginWorkflow](./workflows#loginworkflowopts-key-fields) for the full table. The security-relevant subset:

| Field                                    | Default            | Security implication                                                                                                                           |
| ---------------------------------------- | ------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------- | ------ | ------ | ----- | ------ |
| `mfa.enabled`                            | `true`             | Master switch. `false` disables every MFA step.                                                                                                |
| `mfa.pincodeTtlMs`                       | `5 * 60_000`       | OTP code lifetime. Shorter = stronger; longer = better UX in slow email environments.                                                          |
| `mfa.pincodeResendTimeoutMs`             | `30_000`           | Cooldown — prevents OTP-flooding.                                                                                                              |
| `mfa.pincodeLength`                      | `6`                | Digit count. 6 is OWASP-standard; 4 is too short for unrestricted retry; 8+ has UX cost.                                                       |
| `mfa.enrollRequired`                     | `false`            | Force enrollment if the user has zero factors.                                                                                                 |
| `deviceTrust.enabled`                    | `false`            | Master switch.                                                                                                                                 |
| `deviceTrust.bindsTo`                    | `'cookie'`         | `'cookie'` accepts the cookie alone as proof; `'cookie+ip'` binds to the source IP too. `cookie+ip` is stricter (IP changes invalidate trust). |
| `deviceTrust.ttlMs`                      | `24 * 60 * 60_000` | Trust window. Cap at 30 days or shorter.                                                                                                       |
| `deviceTrust.skipsMfa`                   | `true`             | A trusted device skips the MFA loop. Set `false` if MFA must run on every login regardless of trust.                                           |
| `sessionPolicy.concurrencyLimit.max`     | `null`             | When set, caps active sessions per user.                                                                                                       |
| `sessionPolicy.concurrencyLimit.onLimit` | `'reject'`         | `'reject'` returns 429; `'kickPrompt'` pauses on `ConcurrencyLimitForm` so the user picks.                                                     |
| `finalize.notifyNewDevice`               | `false`            | Whether to fire a "new device" notification on first login from an unrecognized device.                                                        |
| `finalize.redirect`                      | `'referer'`        | `'referer'                                                                                                                                     | 'home' | string | false | null`. |

## Recovery workflow — security-load-bearing options

| Field                           | Default       | Security implication                                                                                                                                                                      |
| ------------------------------- | ------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----- | ------------------------------------------------------------------------------ |
| `delivery.mode`                 | `'magicLink'` | `'magicLink'                                                                                                                                                                              | 'otp' | 'choice'`. Magic-link is more user-friendly but exposes a longer-lived secret. |
| `delivery.magicLinkTtlMs`       | `60 * 60_000` | Magic link lifetime. 1h is a reasonable default; shorten for high-security apps.                                                                                                          |
| `delivery.otp.ttlMs`            | `5 * 60_000`  | OTP lifetime.                                                                                                                                                                             |
| `delivery.otp.resendCooldownMs` | `60_000`      | Resend cooldown — prevents OTP-flooding.                                                                                                                                                  |
| `delivery.otp.codeLength`       | `6`           | Digit count.                                                                                                                                                                              |
| `preReset.requireKnownFactor`   | `false`       | Require a second known factor (phone last-4 or current TOTP) before allowing reset. Defence against email-account-compromise attacks.                                                     |
| `postReset.revokeAllSessions`   | `true`        | Kick every active session after reset. **Default ON** — flip OFF only for SPAs where the test fixture documents the "pre-existing session stays valid" branch. Production should keep ON. |
| `postReset.freshLoginRequired`  | `false`       | Force a fresh login (no auto-login). Combined with `revokeAllSessions=true`, this is the strongest post-reset posture.                                                                    |
| `audit.enabled`                 | `true`        | Whether to emit recovery audit events.                                                                                                                                                    |

::: warning `postReset.revokeAllSessions` defaults to `true` — keep it that way
A password reset that leaves sibling sessions valid is a known credential-theft-recovery weakness. The default kicks every active session. The demo opts out only to document the "pre-existing session stays valid" branch in its test suite — production consumers should leave the default on.
:::

## Invite workflow — security-load-bearing options

| Field                       | Default                | Security implication                                                                                               |
| --------------------------- | ---------------------- | ------------------------------------------------------------------------------------------------------------------ |
| `send.tokenTtlMs`           | `7 * 24 * 60 * 60_000` | Magic link lifetime (7 days). Long because invites are click-when-convenient. Shorten for higher-security tenants. |
| `accept.freshLoginRequired` | `false`                | Force fresh-login after acceptance (no auto-login).                                                                |
| `cancellation.allowed`      | `true`                 | Whether `auth.cancelInvite` is enabled. Set `false` to make invites uncancellable.                                 |
| `audit.enabled`             | `true`                 | Whether to emit invite audit events.                                                                               |

## CSRF — explicit non-feature

The package does **not** bundle a CSRF strategy:

| Default defence                     | Implication                                                                                                       |
| ----------------------------------- | ----------------------------------------------------------------------------------------------------------------- |
| Access cookie `SameSite=Lax`        | Form-based CSRF works for `GET`-style flows but not `POST` from third-party origins. Most real CSRF is mitigated. |
| Refresh cookie path `/auth/refresh` | Refresh cookie isn't sent on non-refresh endpoints. Protects token rotation specifically.                         |
| Bearer transport                    | Bearer tokens require explicit `Authorization` header — immune to CSRF entirely.                                  |

Consumers building public, browser-facing apps with cookie transport SHOULD add a CSRF-token interceptor that:

1. Sets a non-`HttpOnly` cookie carrying a per-session CSRF token.
2. Requires every `POST` / `PUT` / `PATCH` / `DELETE` to include the token in a custom header.
3. Compares the header value against the cookie value.

This is a five-line interceptor and is best left to the consumer because the token-store backend (in-memory vs Redis vs JWT-derived) varies per deployment.

## `ResolvedAuthOptions` — what `useAuth().options` returns

`resolveAuthOptions(opts)` merges the user-provided `opts` with the defaults table above, then attaches the resolved object to the event slot. `useAuth().options` returns this fully-merged shape:

```ts
interface ResolvedAuthOptions {
  cookie: { name; secure; sameSite; httpOnly; path; domain? };
  refreshCookie: { name; secure; sameSite; httpOnly; path; domain? };
  enableCookie: boolean;
  enableBearer: boolean;
}
```

All fields are present and non-optional in the resolved shape. The `refreshCookie.*` fields that inherit from `cookie.*` at config time are resolved to their concrete values at factory time.

## See also

- [AuthGuard & useAuth](./auth-guard) — the consumer of `AuthOptions`.
- [Workflows](./workflows) — full per-workflow option tables.
- [REST Controllers](./controllers) — how the cookies are written / cleared / read on each endpoint.
