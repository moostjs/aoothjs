# Config Reference

This page is the complete configuration reference for the Moost integration layer: `AuthOptions` (consumed by `authGuardInterceptor`, `useAuth`, the `AuthController`) plus the `AuthWorkflow` configuration model. The workflow has two configuration layers — **infrastructure** on `AuthWorkflowOpts`, and **security policy** on `protected resolveXxx(ctx)` getters. Full signatures live in the [API reference](/api/auth-moost); the override mechanics are in [Workflows](./workflows).

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

| Field                    | Default                            | Notes                                                                                                                                                                                          |
| ------------------------ | ---------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------- | -------- |
| `cookie.name`            | `'aooth_session'`                  | Access cookie name.                                                                                                                                                                            |
| `cookie.secure`          | `true`                             | HTTPS-only — flip to `false` for local HTTP dev.                                                                                                                                               |
| `cookie.sameSite`        | `'lax'`                            | `'lax'                                                                                                                                                                                         | 'strict' | 'none'`. |
| `cookie.httpOnly`        | `true`                             | JS access to the cookie is blocked.                                                                                                                                                            |
| `cookie.path`            | `'/'`                              | Sent on every request.                                                                                                                                                                         |
| `cookie.domain`          | `undefined`                        | Defaults to the request host.                                                                                                                                                                  |
| `refreshCookie.name`     | `'aooth_refresh'`                  | Refresh cookie name.                                                                                                                                                                           |
| `refreshCookie.path`     | _auto-derived_ (`'/auth/refresh'`) | **Narrow path** so the refresh cookie isn't sent on other endpoints — CSRF-resistance. Auto-derived from `AuthController`'s actual mounted route (see note below); set explicitly to override. |
| `refreshCookie.secure`   | inherited from `cookie.secure`     |                                                                                                                                                                                                |
| `refreshCookie.sameSite` | inherited from `cookie.sameSite`   |                                                                                                                                                                                                |
| `refreshCookie.httpOnly` | inherited from `cookie.httpOnly`   |                                                                                                                                                                                                |
| `refreshCookie.domain`   | inherited from `cookie.domain`     |                                                                                                                                                                                                |
| `enableCookie`           | `true`                             | Master switch for cookie transport. When `false`, `writeCookies` / `clearCookies` are no-ops.                                                                                                  |
| `enableBearer`           | `true`                             | Master switch for bearer transport. When both are `true`, **bearer wins**. When `false`, `accessToken` and `refreshToken` are omitted from `AuthLoginResponse` bodies.                         |

::: tip The refresh-cookie path follows the controller's mount prefix automatically
You don't set `refreshCookie.path` by hand. The auth guard resolves it **once at boot** from Moost's route table — it finds `AuthController`'s actual `refresh` route and scopes the cookie to it. Mount the controller at the root (`@Controller("auth")` → `/auth/refresh`) or under a prefix (`registerControllers(['api/auth', AuthController])` → `/api/auth/refresh`) and the cookie path tracks it, so the browser always sends the refresh cookie to the real endpoint.

Subclassed `AuthController`s resolve via the prototype chain. If the route can't be resolved unambiguously (no `AuthController` registered, or it's mounted more than once), the guard keeps the `/auth/refresh` default and logs a boot-time warning naming the mismatch — it never guesses. Setting `refreshCookie.path` explicitly always wins and skips derivation.
:::

::: warning Narrow refresh cookie path is deliberate
Browsers don't send the refresh cookie to any path outside its scoped path by default. That's why `/auth/logout` revokes the whole session family by `sessionId` (it can't read the refresh cookie) and only accepts a body `refreshToken` as a fallback. Widening the path (e.g. to `/`) removes the CSRF-resistance benefit, and the refresh cookie is now exposed on every request.
:::

::: warning CSRF is your responsibility
The package does NOT bundle a CSRF strategy. `SameSite=Lax` on the access cookie is the default sole defence. For sensitive endpoints, add a CSRF-token interceptor that compares a custom header against a double-submitted cookie, or switch to `SameSite=Strict`. The bundled refresh cookie's narrow path is a CSRF mitigation specifically for token rotation, not a general defence.
:::

## `AuthWorkflowOpts` — infrastructure knobs

Infrastructure-only configuration passed to the `AuthWorkflow` constructor. Every field is optional; defaults are applied by `mergeAuthWorkflowOpts`. **Security policy is NOT here** — see the resolver table below. Full shape: [API reference](/api/auth-moost#authworkflowopts-resolvedauthworkflowopts).

| Field                        | Default                  | Notes                                                                                           |
| ---------------------------- | ------------------------ | ----------------------------------------------------------------------------------------------- |
| `autoLoginOnInvite`          | `true`                   | Issue tokens directly after invite acceptance (vs redirect to fresh login).                     |
| `autoLoginOnRecover`         | `false`                  | Issue tokens directly after password reset (vs redirect to fresh login).                        |
| `mfa.pincodeLength`          | `6`                      | OTP digit count. 6 is OWASP-standard.                                                           |
| `mfa.pincodeTtlMs`           | `5 * 60_000`             | OTP code lifetime. Shorter = stronger.                                                          |
| `mfa.pincodeResendTimeoutMs` | `60_000`                 | Resend cooldown — throttles OTP-flooding.                                                       |
| `mfa.pincodeMaxAttempts`     | `5`                      | Wrong-code submissions per minted pincode before invalidation.                                  |
| `recoveryStateTtlMs`         | `60 * 60_000`            | Caps the window between OTP request and password reset (applied at every recovery pause).       |
| `loginUrl`                   | `'/login'`               | Canonical sign-in URL (post-accept / abort-to-login / post-reset redirects).                    |
| `totpIssuer`                 | `'aooth'`                | TOTP provisioning issuer label (the QR's `issuer`).                                             |
| `deviceTrust.cookieName`     | `'aooth_trusted_device'` | Trusted-device cookie name.                                                                     |
| `deviceTrust.ttlMs`          | `24 * 60 * 60_000`       | Trusted-device cookie + record TTL.                                                             |
| `deviceTrust.bindsTo`        | `'cookie'`               | `'cookie'` or `'cookie+ip'` (stricter — IP change invalidates trust).                           |
| `forms.<slot>`               | bundled `.as` defaults   | Replace any bundled form schema with your own atscript type. See [Atscript Models](./atscript). |

## Security policy — `resolveXxx(ctx)` getters, not opts

Everything that varies by request / tenant / user is a `protected resolveXxx(ctx)` method on `AuthWorkflow`, overridden in a subclass (see [Workflows — policy model](./workflows#the-policy-model)). Defaults below are the hardcoded resolver bodies.

| Resolver                                         | Default posture                                                     | Security implication                                                                                       |
| ------------------------------------------------ | ------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------- |
| `resolveMfaPolicy`                               | `{ mode: 'optional', availableTransports: ['sms','email','totp'] }` | `mode: 'required'` forces MFA; restrict `availableTransports` to drop a channel.                           |
| `resolveEnrollment`                              | `{ ensureEmail: false, ensurePhone: false }`                        | Force a confirmed email/phone before login completes.                                                      |
| `resolveDeviceTrust`                             | `{ enabled: false, optIn: true, skipsMfa: true }`                   | Off by default. When enabled, a trusted device skips the MFA loop unless `skipsMfa: false`.                |
| `resolveSessionPolicy`                           | `{}` — unlimited                                                    | Return `{ concurrencyLimit: { max, onLimit } }` to cap active sessions (`'reject'` vs `'kickPrompt'`).     |
| `resolveLockout`                                 | `{ mode: 'temporary' }`                                             | `'admin-only'` for privileged accounts (lock never self-expires); `'self-service'` allows reset to unlock. |
| `resolveGuards`                                  | `{ passwordInitial: true, passwordExpiry: true }`                   | Force a password change on first login / expiry; add `emailVerifiedRequired`.                              |
| `resolveFinalize`                                | `{ notifyNewDevice: false, redirect: false }`                       | Fire a new-device notice; set a post-login redirect target.                                                |
| `resolveOtpDisclosure`                           | generic TCPA/PECR/CASL/GDPR-safe copy per channel                   | Customize the disclosure paragraph shown beside the email/phone input.                                     |
| `resolvePostReset` / `resolveRecoveryAltActions` | post-reset = revoke-sessions + redirect                             | Control session revocation + redirect after a recovery reset.                                              |
| `resolveAdminForm` / `resolveAccept`             | invite admin form / accept-phase policy                             | Invite role whitelist (`getAvailableRoles`), post-accept confirmation + redirect.                          |

::: warning Reset must revoke sibling sessions
A password reset that leaves other sessions valid is a known credential-theft-recovery weakness. The bundled recovery flow revokes the user's other sessions after a reset; if you override `resolvePostReset`, preserve that behavior in production.
:::

::: tip There is no `audit.enabled` knob
The bundled `AuthWorkflow` does not emit audit events itself. The `AuditEvent` / `AuditEmitter` types are exported for wiring your own sink — see [Audit Log](./audit).
:::

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
- [Workflows](./workflows) — the `AuthWorkflowOpts` vs `resolveXxx` policy model + override mechanics.
- [API reference](/api/auth-moost) — full `AuthOptions` / `AuthWorkflowOpts` signatures.
- [REST Controllers](./controllers) — how the cookies are written / cleared / read on each endpoint.
