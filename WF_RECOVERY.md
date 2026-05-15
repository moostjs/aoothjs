# WF_RECOVERY — recovery / forgot-password workflow design

Sibling of [WF.md](WF.md) and [WF_LOGIN.md](WF_LOGIN.md). DI / options-class / `init` step / no-`setupAuthWorkflows` shape is covered generically in [WF.md](WF.md) — not repeated here.

---

## Goal

A flexible "I forgot my password" workflow that supports both magic-link and OTP delivery, configurable per app, with proper rate-limiting, anti-enumeration, optional session revocation on success, and an optional "fresh login required after reset" tail (instead of auto-login).

Workflow id: `auth.recovery`.

Triggered either:

- Directly via `/wf/trigger` with `wfid: 'auth.recovery'`
- From the login workflow's `forgotPassword` alt-action — which navigates to whatever URL the consumer set in `LoginWorkflowOptions.recoveryUrl` (typically a frontend page that triggers this workflow)

---

## Delivery modes — configurable

Two delivery mechanisms; pick one or offer both at runtime.

| Mode           | UX                                                                          | Mechanism                                                                               |
| -------------- | --------------------------------------------------------------------------- | --------------------------------------------------------------------------------------- |
| **Magic link** | User clicks link in email → lands on set-password page                      | One-shot `wfs` token in URL; engine resumes the workflow at `setPassword` step on click |
| **OTP**        | User receives a numeric code (email or SMS) → enters it → set-password page | Server-side pincode generation + verification (same primitive as login MFA pincode)     |

Both modes end at the same `setPassword` step. The mode is selected by `RecoveryWorkflowOptions.deliveryMode`.

---

## `RecoveryWorkflowOptions` — full shape

```ts
@Injectable()
export class RecoveryWorkflowOptions {
  // ── Delivery mode ────────────────────────────────────────────────────────
  deliveryMode: "magicLink" | "otp" | "choice" = "magicLink";
  // 'choice' lets the user pick at runtime via a select-mode step (only useful when both
  // are allowed — typical apps pick one and stick with it)

  // ── OTP transports (when deliveryMode includes OTP) ──────────────────────
  otpTransports: Array<"sms" | "email"> = ["email"];
  otpCodeLength = 6; // 4 / 6 / 8 — surfaced into ctx for UI
  otpTtlMs = 5 * 60_000; // 5 min code validity
  otpResendCooldownMs = 60_000; // 60s between resend allowed — surfaced into ctx for UI countdown

  // ── Magic-link (when deliveryMode includes magicLink) ────────────────────
  magicLinkTtlMs = 30 * 60_000; // 30 min link validity

  // ── Anti-enumeration ─────────────────────────────────────────────────────
  // Always ON — the workflow always responds with the generic "if an account exists..."
  // message regardless of whether the email matched. No opt to disable.

  // ── Email-to-userId mapping (moved from MoostAuthWorkflowConfig) ─────────
  emailToUserId?: (email: string) => Promise<string | null>;
  // When undefined, treats the email itself as the userId.

  // ── Rate limiting ────────────────────────────────────────────────────────
  rateLimit: { count: number; windowMs: number } | null = { count: 2, windowMs: 24 * 60 * 60_000 };
  // Default: max 2 recovery requests per email per 24h. Set null to disable.
  // Counter store is pluggable (DI: RecoveryRateLimitStore); ships in-memory default.

  // ── Pre-reset security gate (optional) ───────────────────────────────────
  requireKnownRecoveryFactor = false;
  // When true, after the email/OTP/link is verified, prompt for an additional factor:
  //   - last 4 of phone (if phone enrolled), OR
  //   - current MFA TOTP code (if TOTP enrolled), OR
  //   - a security question (if any configured)
  // Increases friction; recommended for high-security apps.

  // ── Post-reset behavior ──────────────────────────────────────────────────
  revokeAllSessions = true;
  // Default ON — recovery implies "I lost control"; kick all existing sessions for this user.
  // Bumps the per-user revocation epoch via UserService.

  freshLoginRequired = true;
  // Default ON — after successful reset, do NOT auto-issue tokens; redirect user to the
  // login page so they sign in fresh with the new password.
  // When false, auto-login (today's behavior) — issue tokens + cookies at the end.

  loginUrl = "/login"; // where to send the user when freshLoginRequired

  // ── Alt actions ──────────────────────────────────────────────────────────
  backToLoginAction = true;
  // Surfaces a "back to login" alt-action on every form-bearing step.

  // ── Audit ────────────────────────────────────────────────────────────────
  auditEvents = true;
  // Emits `recovery.requested` (always, even on unknown email) and `recovery.completed`
  // (only on successful reset).

  constructor(opts: Partial<RecoveryWorkflowOptions> = {}) {
    Object.assign(this, opts);
  }
}
```

---

## Workflow context shape

```ts
export interface RecoveryWfCtx {
  opts: RecoveryWorkflowOptions;

  // Phase 1 — request:
  email?: string;
  username?: string; // null when email unknown — drives anti-enumeration short-circuit
  rateLimited?: boolean; // true when rate-limit hit; flow short-circuits with same generic msg

  // Mode (when deliveryMode === 'choice'):
  selectedMode?: "magicLink" | "otp";

  // OTP-mode state:
  otpTransport?: "sms" | "email";
  otpCodeLength?: number; // copied from opts so the UI form knows the digit count
  pin?: string; // server-side; never serialized to client
  pinExpire?: number; // ms timestamp
  pinResendAllowedAt?: number; // ms timestamp; UI uses this for countdown

  // Magic-link state:
  linkSent?: boolean;

  // Pre-reset factor (when opts.requireKnownRecoveryFactor):
  factorVerified?: boolean;

  // Post-reset:
  passwordChanged?: boolean;
  sessionsRevoked?: boolean;
}
```

`otpCodeLength` and `pinResendAllowedAt` are intentionally on the ctx so the UI form has both pieces of data without an extra API call: the code length governs how many input boxes to render; the resend timestamp governs the countdown timer on the "resend" button.

---

## Step catalog

| #   | Step id            | Default state | Gated by                                                                                 | Notes                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| --- | ------------------ | ------------- | ---------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1   | `init`             | ON (always)   | —                                                                                        | Implicit; copies `this.opts` into `ctx.opts` (per WF.md convention)                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| 2   | `request`          | ON            | —                                                                                        | Form: `EmailIdentifierForm`. **Pre-fills the email/username field from the `?username=` query param** (carried in by the login workflow's `forgotPassword` alt-action so the user doesn't have to retype it). Resolves email → username via `opts.emailToUserId`. Checks rate limit. If unknown email OR rate-limited: short-circuits with generic "if an account exists..." message; later steps skipped via `ctx.username` guard. Emits `recovery.requested` audit event regardless. Alt action: `backToLogin`. |
| 3   | `selectMode`       | conditional   | `opts.deliveryMode === 'choice' && !ctx.selectedMode`                                    | Form: pick magicLink vs otp. Skipped when mode is fixed.                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| 4a  | `sendMagicLink`    | conditional   | mode resolved to `magicLink`                                                             | Emits `outletEmail(...)` ONCE; sets `linkSent: true`. Resume after click → advances. Magic link URL ends at the `setPassword` step (with optional `verifyFactor` between).                                                                                                                                                                                                                                                                                                                                        |
| 4b  | `sendOtp`          | conditional   | mode resolved to `otp`                                                                   | Generates pin, sends via `EmailSender` or `SmsSender` based on `ctx.otpTransport`. Sets `pinExpire`, `pinResendAllowedAt`, `otpCodeLength`.                                                                                                                                                                                                                                                                                                                                                                       |
| 5   | `checkOtp`         | conditional   | mode resolved to `otp`                                                                   | Form: pincode input. Validates against `ctx.pin` + `pinExpire`. Alt actions: `resend` (gated by `pinResendAllowedAt` — returns countdown error if too soon), `useDifferentTransport` (when `opts.otpTransports.length > 1` — loops back to `sendOtp` on the other channel), `backToLogin`.                                                                                                                                                                                                                        |
| 6   | `verifyFactor`     | conditional   | `opts.requireKnownRecoveryFactor && !ctx.factorVerified`                                 | Form: pick + verify a known factor (phone last-4 / TOTP code / security question). Same anti-enumeration shape — opaque error on mismatch.                                                                                                                                                                                                                                                                                                                                                                        |
| 7   | `setPassword`      | conditional   | `ctx.username && (ctx.linkSent OR ctx.pinVerified) && (factor check passed if required)` | Form: `SetPasswordForm` with policy rules surfaced from `getTransferablePolicies()`. Validates passwords match + policy. Calls `users.setPassword(ctx.username, newPassword)`. Sets `passwordChanged: true`. Alt action: `backToLogin` (cancels reset).                                                                                                                                                                                                                                                           |
| 8   | `revokeSessions`   | conditional   | `opts.revokeAllSessions && ctx.passwordChanged`                                          | Calls `auth.revokeAllForUser(ctx.username)` — bumps the per-user epoch so all existing tokens are rejected. Sets `sessionsRevoked: true`.                                                                                                                                                                                                                                                                                                                                                                         |
| 9   | `audit`            | conditional   | `opts.auditEvents && ctx.passwordChanged`                                                | Emits `recovery.completed { userId, deliveryMode, ip, sessionsRevoked }`.                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| 10a | `freshLoginFinish` | conditional   | `opts.freshLoginRequired`                                                                | `useWfFinished().set({ type: 'redirect', value: opts.loginUrl })` — user must log in again.                                                                                                                                                                                                                                                                                                                                                                                                                       |
| 10b | `autoLoginFinish`  | conditional   | `!opts.freshLoginRequired`                                                               | Issues tokens via `AuthCredential`, writes cookies, returns the same `buildLoginResponse(...)` payload as the login workflow.                                                                                                                                                                                                                                                                                                                                                                                     |

---

## Alt-action catalog

| Form           | Alt action key          | Default                               | Behavior                                                                                        |
| -------------- | ----------------------- | ------------------------------------- | ----------------------------------------------------------------------------------------------- |
| `request`      | `backToLogin`           | ON if `opts.backToLoginAction`        | Redirects to `opts.loginUrl`                                                                    |
| `selectMode`   | `backToLogin`           | ON                                    | Redirects to `opts.loginUrl`                                                                    |
| `checkOtp`     | `resend`                | ON                                    | Re-runs `sendOtp`; **gated** by `pinResendAllowedAt` — returns form error "wait Ns" if too soon |
| `checkOtp`     | `useDifferentTransport` | ON if `opts.otpTransports.length > 1` | Loops back to `sendOtp` on the other channel; resets `pin`                                      |
| `checkOtp`     | `backToLogin`           | ON                                    | Cancel + redirect                                                                               |
| `verifyFactor` | `backToLogin`           | ON                                    | Cancel + redirect                                                                               |
| `setPassword`  | `backToLogin`           | ON                                    | Cancel + redirect (password NOT changed)                                                        |

---

## Rate limiting

`RecoveryRateLimitStore` interface (DI; in-memory default ships, consumer can swap for Redis-backed):

```ts
export interface RecoveryRateLimitStore {
  consume(
    email: string,
    windowMs: number,
  ): Promise<{ allowed: boolean; remaining: number; resetAt: number }>;
}
```

Called once in `request` step before any email goes out. When `!allowed`, the workflow continues as if the email were unknown (anti-enumeration: a rate-limited recipient is indistinguishable from a non-existent one) — same generic finished response, `recovery.requested` audit event still fires (with `rateLimited: true` for ops visibility).

In-memory implementation is per-process; consumers running multiple instances must register a Redis-backed store or accept that rate-limit is per-instance.

---

## Anti-enumeration invariants (always-on, not configurable)

- Unknown email → generic finished response, no email sent
- Rate-limited known email → same generic finished response, no email sent
- Wrong OTP → "invalid code" form error, never "no such pending recovery"
- Magic-link with stale/invalid `wfs` → 410 Gone with generic "expired" message, never "no such workflow state"

---

## Tasks (recovery-specific, on top of WF.md common refactor)

1. **Define `RecoveryWorkflowOptions`** with full shape above.
2. **Define `RecoveryRateLimitStore` interface** + ship `RecoveryRateLimitStoreMemory` default. Document how to wire a Redis-backed implementation (mirrors `DenylistStoreRedis` from ISSUE-19).
3. **Implement step catalog** — 10 steps, gated per opts. New atscript form models needed: `OtpCodeForm` (with `codeLength` field), `RecoveryModeSelectForm`, `RecoveryFactorForm`. Reuse `EmailIdentifierForm` and `SetPasswordForm`.
4. **Wire OTP via `EmailSender`/`SmsSender` discriminated events** — add `recovery.pincode` to the email/SMS event union.
5. **Magic-link outlet** — keep current `outletEmail(...)` shape; verify TTL is per-call (currently attached as `expires`) and not class-definition-time `@StepTTL`.
6. **Audit hooks** — emit `recovery.requested` (with `rateLimited?` flag) and `recovery.completed` events through whatever audit channel the consumer wires (Moost event emitter / hook).
7. **Fresh-login vs auto-login branching** — two terminal steps; pick one via `opts.freshLoginRequired`.
8. **Tests** —
   - magicLink mode end-to-end (default)
   - otp mode + resend gating + cooldown
   - otp mode with two transports (email + sms) + `useDifferentTransport`
   - rate-limit cap (default 2/day) — third request short-circuits to generic response
   - `requireKnownRecoveryFactor` happy path + bad factor
   - `revokeAllSessions: true` revokes pre-reset tokens
   - `freshLoginRequired: true` redirects to login URL; `false` auto-logs in
   - anti-enumeration: unknown email vs rate-limited known email vs successful start all return identical client-visible response shape
9. **e2e demo** — keep magicLink mode (current behavior), add a second test app variant with otp mode for coverage.
