# E2E User Stories — Playwright Test Matrix

**Status:** Draft — needs scope decisions before tests are written.

This document plans the Playwright e2e buildout for `@aooth/e2e-demo`. It enumerates every meaningful **workflow variant × user state × branch path** the suite should cover, and tags each story with a priority tier so we can ship in waves.

The orchestrator-implement skill drives the work; this is the planning artifact that must be approved before tests are generated.

---

## 1. Scope Summary

| Workflow                                              | Variant profiles | Distinct branches | P0 stories | P1 stories | P2 stories |
| ----------------------------------------------------- | ---------------- | ----------------- | ---------- | ---------- | ---------- |
| `auth.login`                                          | 10 (A–J)         | ~80               | 12         | 20         | 25         |
| `auth.recovery`                                       | 7 (A–G)          | ~18               | 6          | 8          | 5          |
| `auth.invite` + `auth.reInvite` + `auth.cancelInvite` | 7 (A–G)          | ~20               | 7          | 8          | 5          |
| **Totals**                                            | **24 variants**  | **~118 branches** | **25**     | **36**     | **35**     |

**Priority tiering:**

- **P0** (~25 stories) — happy path + one alt-action + one validation error per workflow variant. Smoke-level coverage of every variant. ~6 hours to write.
- **P1** (~36 stories) — secondary branches: transport switching, resend cooldowns, expired tokens, idempotency, multi-step alt-actions. ~10 hours.
- **P2** (~35 stories) — exhaustive: every error path, anti-enumeration, locked-account 423, every option override, audit assertion. ~12 hours.

**Recommendation:** ship P0 first, then P1, then P2 only as gaps surface. Each tier should be a green PR before the next starts.

---

## 2. Demo Infrastructure Requirements (must land before test writing)

### 2.1 Variant-config switching

The demo currently has **one** hardcoded login config (`demoLoginOpts` in [src/app.ts](src/app.ts)). To exercise the matrix, the demo must expose **named variant presets** that Playwright can target.

**Recommended pattern:** add `?variant=<name>` query param on `/wf` route. The server reads it, looks up a registered preset config map, and constructs a fresh workflow controller with the selected opts. This avoids spinning 24 backend servers.

```ts
// src/variants.ts (new)
export const LOGIN_VARIANTS = {
  'minimal':       { mfa: { enabled: false }, alternateCredentials: { forgotPassword: true } },
  'mfa-totp':      { mfa: { transports: ['totp'], backupCodes: true } },
  'mfa-full':      { mfa: { transports: ['sms','email','totp'], backupCodes: true } },
  'enrollment':    { enrollment: { ensureEmail: true, ensurePhone: true } },
  'device-trust':  { deviceTrust: { enabled: true, optIn: true, skipsMfa: true } },
  'guards':        { guards: { passwordInitial: true, emailVerifiedRequired: true } },
  'acceptance':    { acceptance: { termsVersion: 'v1', profileCompleteRequired: true, consentMarketing: true } },
  'multi-context': { multiContext: { tenantSelect: true, personaSelect: true } },
  'concurrency':   { sessionPolicy: { concurrencyLimit: { max: 1, onLimit: 'kickPrompt' } } },
  'full':          { /* every flag */ },
};

export const RECOVERY_VARIANTS = { ... }; // 7 entries
export const INVITE_VARIANTS = { ... };   // 7 entries
```

The UI's `WfPage.vue` already reads `?id=<wfid>` from the route. Extend it to pass `?variant=<name>` to the trigger endpoint via a custom `fetchOptions.headers['x-wf-variant']` so the server picks the preset.

### 2.2 Seed user expansion

Existing 14 users cover the basics. We need to add:

| New user                | Purpose                                                    | Stories                        |
| ----------------------- | ---------------------------------------------------------- | ------------------------------ |
| `t1_locked`             | Account in `account.locked=true`                           | Login: 423 path                |
| `t1_multi_mfa`          | Email + SMS + TOTP all confirmed (default=TOTP)            | Profile C + Profile I          |
| `t1_pending`            | `pendingInvitation=true`, `account.active=false`           | reInvite + cancelInvite        |
| `t1_redeemed`           | `pendingInvitation=false`, fully active (from past invite) | reInvite 409, cancelInvite 409 |
| `t1_active_sessions`    | 2 issued sessions (concurrency test)                       | Profile H                      |
| `t1_terms_old`          | `termsAcceptedVersion='v0'` (older than configured 'v1')   | Profile F                      |
| `t1_profile_incomplete` | `profileMissingFields=['firstName','lastName']`            | Profile F                      |
| `t1_two_tenants`        | Member of tenant A + tenant B                              | Profile G                      |
| `_admin_inviter`        | Has `@ArbacAction('start')` on `auth.invite`               | All invite admin-side stories  |

### 2.3 Email/SMS capture HTTP endpoint

The demo's `app.emails[]` and `app.sms[]` arrays already buffer outgoing messages (for the in-process vitest harness). Playwright runs against a real HTTP server and needs a way to **read** those arrays.

Add a test-only endpoint:

```ts
// src/test-mailbox.ts (new, only mounted when DEMO_MODE=test)
@Controller("__test")
class TestMailboxController {
  @Get("emails") emails() {
    return app.emails;
  }
  @Get("sms") sms() {
    return app.sms;
  }
  @Delete("mailbox") reset() {
    app.emails.length = 0;
    app.sms.length = 0;
  }
}
```

Playwright tests await the mailbox endpoint to extract OTP codes / magic-link URLs from "sent" messages.

### 2.4 Per-test DB reset

Each Playwright spec must start with a known-good DB. Options:

- **(A)** spin a fresh backend per spec (cleanest, slow — ~30s × 60 specs = 30 min)
- **(B)** add `POST /__test/reset` that re-seeds + clears mailboxes (fast, 1 s per spec)
- **(C)** in-memory SQLite + Playwright `workerStorageState` (medium)

Recommend **(B)** with explicit `await reset()` in each spec's `beforeEach`. Matches the existing in-process harness pattern.

### 2.5 Playwright tooling

Per the infra audit:

- `@playwright/test` not installed — add to `packages/e2e-demo/devDependencies`
- Create `playwright.config.ts` with chromium-only, retries=0, single worker (until per-test reset is bulletproof)
- Create `test-e2e/` directory (separate from `test/` which is vitest)
- Add `test:e2e` and `test:e2e:ui` package.json scripts

---

## 3. Login Workflow Stories

### Variant profiles (from research agent)

| ID  | Profile          | Key opts                                                           |
| --- | ---------------- | ------------------------------------------------------------------ |
| L-A | Minimal          | password-only, no MFA, `forgotPassword: true`                      |
| L-B | Enrollment       | `ensureEmail+ensurePhone: true`, `mfa.transports=[email,sms,totp]` |
| L-C | MFA-full         | all 3 transports, backup codes on                                  |
| L-D | Device trust     | `deviceTrust.enabled+skipsMfa: true`                               |
| L-E | Password guards  | `passwordInitial+emailVerifiedRequired: true`, no MFA              |
| L-F | Acceptance gates | terms+profile+consent                                              |
| L-G | Multi-context    | tenant + persona pickers                                           |
| L-H | Concurrency      | `kickPrompt` policy                                                |
| L-I | Full             | every flag on                                                      |
| L-J | Redirect         | `finalize.redirect: 'home'`                                        |

### Stories (priority tagged)

| ID           | Tier | Variant    | Story                                                                                             | Render assertions                                                                                                                   |
| ------------ | ---- | ---------- | ------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------- |
| WF-LOGIN-001 | P0   | L-A        | alice signs in with correct password → tokens issued                                              | `LoginCredentialsForm` visible, `forgotPassword` button visible, `signup`/`magicLink` hidden, finish envelope carries `accessToken` |
| WF-LOGIN-002 | P0   | L-A        | wrong password → form re-renders with `__form: "Invalid credentials"`                             | error message present, form fields cleared appropriately                                                                            |
| WF-LOGIN-003 | P0   | L-A        | click "Forgot password?" → redirected to `/recover?username=<typed>`                              | URL contains typed username, recovery form loaded                                                                                   |
| WF-LOGIN-004 | P1   | L-A        | locked account `t1_locked` → 423 / friendly error                                                 | HTTP 423 surfaced as user-readable message                                                                                          |
| WF-LOGIN-005 | P2   | L-A        | brute-force lockout: 5 wrong passwords → account locks                                            | 5th attempt → 423; user notification                                                                                                |
| WF-LOGIN-006 | P0   | L-A+signup | with `signup: true`, "Sign up" button visible and routes to `/signup`                             | button visible, redirect to invite workflow                                                                                         |
| WF-LOGIN-007 | P0   | L-C        | charlie (3 MFA methods) → `Select2faForm` appears, pick SMS → `PincodeForm` → enter code → tokens | select2fa visible, `useBackupCode` visible (backupCodes on), pincode hint paragraph reads "Code sent to **\***0100"                 |
| WF-LOGIN-008 | P0   | L-C        | grace (1 TOTP only) → `MfaCodeForm` directly (no select2fa) → enter code → tokens                 | `useDifferentMethod` hidden (count=1), hint reads "Enter the current 6-digit code…"                                                 |
| WF-LOGIN-009 | P1   | L-C        | charlie clicks `useDifferentMethod` on pincode-check → loops back to select2fa                    | form sequence: select2fa → pincode → select2fa                                                                                      |
| WF-LOGIN-010 | P1   | L-C        | kate uses backup code instead of TOTP → tokens                                                    | `BackupCodeForm` visible, code accepted; second use fails                                                                           |
| WF-LOGIN-011 | P1   | L-C        | resend within timeout → "Please wait Ns" form error                                               | error message visible, no new email in mailbox                                                                                      |
| WF-LOGIN-012 | P1   | L-C        | resend after timeout → new code sent                                                              | mailbox has 2 emails, codes differ                                                                                                  |
| WF-LOGIN-013 | P2   | L-C        | wrong MFA code → `errors.code = "Invalid code"`                                                   | error visible, form re-renders                                                                                                      |
| WF-LOGIN-014 | P2   | L-C        | useBackupCode hidden when `mfa.backupCodes: false` (use variant L-C with override)                | `useBackupCode` button absent in DOM                                                                                                |
| WF-LOGIN-015 | P0   | L-B        | eve has no confirmed email → `AskEmailForm` pause → enter email → pincode → confirmed → tokens    | `AskEmailForm` autocomplete='email', pincode hint visible, email captured                                                           |
| WF-LOGIN-016 | P1   | L-B        | eve has confirmed email already → `AskEmailForm` skipped                                          | step never paused; proceeds to MFA                                                                                                  |
| WF-LOGIN-017 | P1   | L-B        | phone enrollment loop with `AskPhoneForm`                                                         | similar to email                                                                                                                    |
| WF-LOGIN-018 | P0   | L-D        | alice on new device → MFA → `rememberDevice` checked → 2nd login skips MFA                        | first session sets cookie; 2nd session finds cookie, skips MFA loop                                                                 |
| WF-LOGIN-019 | P1   | L-D        | `deviceTrust.optIn: false` → no `rememberDevice` checkbox shown                                   | checkbox absent in PincodeForm DOM                                                                                                  |
| WF-LOGIN-020 | P2   | L-D        | trusted cookie expires → MFA required again                                                       | wait past `ttlMs`; expect MFA loop                                                                                                  |
| WF-LOGIN-021 | P0   | L-E        | jack (`isInitial=true`) → `SetPasswordForm` pause → new password → tokens                         | password rules paragraph visible, mismatch error inline                                                                             |
| WF-LOGIN-022 | P1   | L-E        | jack clicks `logout` on SetPassword → aborts                                                      | finish envelope has `aborted: true`, no tokens                                                                                      |
| WF-LOGIN-023 | P0   | L-F        | frank → terms-accept → profile-complete → consent → tokens                                        | each form rendered in order; `TermsAcceptForm.accepted` required                                                                    |
| WF-LOGIN-024 | P1   | L-F        | frank declines terms → aborted                                                                    | no further forms shown                                                                                                              |
| WF-LOGIN-025 | P1   | L-F        | `ConsentMarketingForm.optIn` defaults to false (no tristate)                                      | checkbox visibly unchecked on first render                                                                                          |
| WF-LOGIN-026 | P0   | L-G        | grace → tenant-select → persona-select → tokens                                                   | both forms rendered, options populated                                                                                              |
| WF-LOGIN-027 | P2   | L-G        | only 1 tenant → tenant-select skipped                                                             | form never paused                                                                                                                   |
| WF-LOGIN-028 | P1   | L-H        | henry with 1 active session, `max=1` → kickPrompt                                                 | "Log out others" form visible                                                                                                       |
| WF-LOGIN-029 | P1   | L-H        | clicks "Cancel" on kickPrompt → aborted                                                           | no tokens issued                                                                                                                    |
| WF-LOGIN-030 | P2   | L-H        | `onLimit: 'reject'` → HTTP 429 immediately                                                        | no form, error banner                                                                                                               |
| WF-LOGIN-031 | P1   | L-J        | login completes → immediate redirect to `/`                                                       | URL after finish is `/`                                                                                                             |
| WF-LOGIN-032 | P2   | L-I        | iris through every step in order                                                                  | every step paused in correct sequence; final tokens + redirect                                                                      |

**Login total: 32 stories** (12 P0 + 12 P1 + 8 P2)

---

## 4. Recovery Workflow Stories

### Variant profiles

| ID  | Profile          | Key opts                                |
| --- | ---------------- | --------------------------------------- |
| R-A | Default          | `mode='magicLink'`, auto-login on reset |
| R-B | OTP email        | `mode='otp'`, `transports=['email']`    |
| R-C | OTP sms          | `mode='otp'`, `transports=['sms']`      |
| R-D | OTP both         | `transports=['email','sms']`            |
| R-E | Choice mode      | `mode='choice'`                         |
| R-F | Pre-reset factor | `preReset.requireKnownFactor: true`     |
| R-G | Fresh-login      | `postReset.freshLoginRequired: true`    |

### Stories

| ID              | Tier | Variant | Story                                                            | Render assertions                                                                                  |
| --------------- | ---- | ------- | ---------------------------------------------------------------- | -------------------------------------------------------------------------------------------------- |
| WF-RECOVERY-001 | P0   | R-A     | alice → enter email → magic link → click → set password → tokens | email captured with `kind: 'recovery.magicLink'`, `SetPasswordForm` shows `passwordPolicies` rules |
| WF-RECOVERY-002 | P0   | R-A     | unknown email → identical "if account exists" finish             | finish envelope generic, no email sent                                                             |
| WF-RECOVERY-003 | P1   | R-A     | password mismatch → `confirmPassword: "Passwords do not match"`  | error visible inline                                                                               |
| WF-RECOVERY-004 | P1   | R-A     | expired magic link → 410 on resume                               | error page or message                                                                              |
| WF-RECOVERY-005 | P0   | R-B     | alice → email OTP → enter code → set password → tokens           | `PincodeForm` hint reads "Code sent to **\***"                                                     |
| WF-RECOVERY-006 | P0   | R-C     | alice (sms enrolled) → SMS OTP → tokens                          | SMS mailbox has code                                                                               |
| WF-RECOVERY-007 | P1   | R-D     | switch transport email → sms via `useDifferentTransport`         | first email, then SMS in mailbox                                                                   |
| WF-RECOVERY-008 | P1   | R-D     | `useDifferentTransport` hidden when only 1 transport             | button absent                                                                                      |
| WF-RECOVERY-009 | P1   | R-B     | wrong OTP → `errors.code = "Invalid code"`                       | error visible                                                                                      |
| WF-RECOVERY-010 | P1   | R-B     | resend within cooldown → "Please wait Ns"                        | no new email                                                                                       |
| WF-RECOVERY-011 | P1   | R-B     | resend after cooldown → new code                                 | 2 emails, codes differ                                                                             |
| WF-RECOVERY-012 | P0   | R-E     | choice mode → `RecoveryModeSelectForm` → pick magicLink → flow A | mode form visible                                                                                  |
| WF-RECOVERY-013 | P1   | R-E     | choice mode → pick otp → flow B                                  | mode form visible, then PincodeForm                                                                |
| WF-RECOVERY-014 | P1   | R-F     | pre-reset factor (phone last-4) → match → set password           | `RecoveryFactorForm` visible, opaque error on wrong                                                |
| WF-RECOVERY-015 | P2   | R-F     | pre-reset factor wrong → "Invalid factor"                        | opaque error                                                                                       |
| WF-RECOVERY-016 | P0   | R-G     | freshLoginRequired → finish has 5s redirect, no tokens           | envelope has `next.trigger='auto'`, `data` absent                                                  |
| WF-RECOVERY-017 | P1   | R-A     | `backToLogin` from request step → redirect to `/login`           | finish envelope reason='user-cancelled'                                                            |
| WF-RECOVERY-018 | P2   | R-A     | post-reset old token rejected (revokeAllSessions=true)           | old session HTTP 401                                                                               |
| WF-RECOVERY-019 | P2   | R-A     | audit events emitted: `recovery.requested`, `recovery.completed` | mailbox endpoint or audit endpoint shows events                                                    |

**Recovery total: 19 stories** (6 P0 + 8 P1 + 5 P2)

---

## 5. Invite Family Stories

### Variant profiles

| ID  | Profile                                    | Key opts                                                 |
| --- | ------------------------------------------ | -------------------------------------------------------- |
| I-A | Email, no roles, auto-login                | minimal default                                          |
| I-B | Roles + profile collection                 | `getAvailableRoles`, `getProfileForm` wired              |
| I-C | Shareable link mode                        | `send.mode='shareableLink'`                              |
| I-D | Choice + fresh-login                       | `send.mode='choice'`, `freshLoginRequired: true`         |
| I-E | Audit enabled                              | `audit.enabled: true`                                    |
| I-F | Cancellation disabled / duplicate override | `cancellation.allowed: false`, `duplicateCheck` override |
| I-G | Short TTL + confirmation                   | `tokenTtlMs=1s`, `showConfirmation: true`                |

### Stories

| ID            | Tier | Variant | Story                                                                                         | Render assertions                                                            |
| ------------- | ---- | ------- | --------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------- |
| WF-INVITE-001 | P0   | I-A     | admin invites new email → mailbox has invite → invitee redeems → tokens                       | `InviteForm` no `roles` field; redemption sets password; auto-login envelope |
| WF-INVITE-002 | P1   | I-A     | admin invites existing user → 409                                                             | form re-renders with error                                                   |
| WF-INVITE-003 | P1   | I-A     | invitee cancels at password form → pending preserved                                          | user record still `pendingInvitation=true`                                   |
| WF-INVITE-004 | P2   | I-A     | expired link → 410                                                                            | error visible                                                                |
| WF-INVITE-005 | P0   | I-B     | role whitelist `['member','viewer','admin']` → admin picks valid → invitee redeems            | role picker shows 3 options; invalid role rejected                           |
| WF-INVITE-006 | P1   | I-B     | admin submits role not in whitelist → form error                                              | error visible inline                                                         |
| WF-INVITE-007 | P0   | I-B     | profile form pause after password → invitee fills displayName                                 | `InviteAcceptProfileForm` rendered with `skip` action                        |
| WF-INVITE-008 | P1   | I-B     | invitee clicks `skip` on profile form → no profile persisted                                  | applyProfile not called                                                      |
| WF-INVITE-009 | P1   | I-C     | shareable link mode → admin form completes, link displayed, link reusable                     | no email sent, link URL captured                                             |
| WF-INVITE-010 | P2   | I-C     | already-accepted link click → idempotent redirect with 2 options                              | "Go to sign-in" + "Request a new invite" buttons                             |
| WF-INVITE-011 | P0   | I-D     | choice → admin picks "email" → email sent                                                     | `InviteSendModeForm` visible                                                 |
| WF-INVITE-012 | P1   | I-D     | freshLoginRequired → redemption finish has no tokens, redirect to `/welcome`                  | envelope reason='fresh-login-required'                                       |
| WF-INVITE-013 | P0   | I-E     | reInvite on pending user → new email sent → audit `invite.resent`                             | `InviteEmailForm` accepts email, new mailbox entry                           |
| WF-INVITE-014 | P1   | I-E     | reInvite on already-accepted user → 409                                                       | error visible                                                                |
| WF-INVITE-015 | P0   | I-E     | cancelInvite on pending → user deleted → audit `invite.cancelled`                             | record gone, mailbox endpoint shows audit                                    |
| WF-INVITE-016 | P1   | I-E     | cancelInvite on already-accepted → 409                                                        | error visible                                                                |
| WF-INVITE-017 | P1   | I-F     | cancelInvite when `cancellation.allowed: false` → 403                                         | direct error, no form                                                        |
| WF-INVITE-018 | P2   | I-F     | duplicate user with `duplicateCheck='allow'` override → still 409 from store-level constraint | error surfaces                                                               |
| WF-INVITE-019 | P2   | I-G     | TTL=1s, click after 2s → 410                                                                  | error visible                                                                |
| WF-INVITE-020 | P2   | I-G     | `showConfirmation: true` → finish message "Your account has been created."                    | text visible in DOM                                                          |

**Invite total: 20 stories** (7 P0 + 8 P1 + 5 P2)

---

## 6. Render-Assertion Catalog (cross-cutting)

The Playwright value-add over the existing in-process vitest suite is **rendered-DOM verification**. Every story above must include at least one of these classes of assertion:

| Class                                 | Examples                                                                                                                              | Detection method                                                |
| ------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------- |
| **Conditional alt-action visibility** | `signup` hidden when `!altSignup`; `useDifferentMethod` hidden when `mfaMethodCount<2`; `useBackupCode` hidden when `!mfaBackupCodes` | `page.locator('button:has-text("Sign up")').isVisible()`        |
| **Computed paragraph text**           | MFA hint reads "Enter the current 6-digit code…" for TOTP, "Code sent to **\***0100 — check console" for SMS                          | `expect(page.locator('p[aria-live]')).toContainText(…)`         |
| **Default values (no tristate)**      | `rememberDevice` unchecked on first render (not indeterminate); `optIn` unchecked                                                     | `expect(checkbox).not.toBeChecked()`                            |
| **Autocomplete hints**                | username field has `autocomplete="username"`; password has `current-password`                                                         | `getAttribute('autocomplete')`                                  |
| **Validation errors inline**          | "Invalid code", "Passwords do not match" appear next to the right field                                                               | `page.locator('[data-field=code] .error').textContent()`        |
| **Form sequence**                     | Variants force forms in known order (e.g. credentials → mfa → terms → tokens)                                                         | snapshot test of visible form ID on each step                   |
| **Finish-envelope rendering**         | redirect vs. data vs. abort envelopes render distinct UI                                                                              | URL after finish; presence of success banner; absence of tokens |
| **Field absence**                     | role picker absent when `collectRoles: false`; `rememberDevice` checkbox absent when `deviceTrust.optIn: false`                       | `expect(locator).toHaveCount(0)`                                |
| **Test-mailbox content**              | OTP code matches what server sent; magic-link URL matches                                                                             | GET `/__test/emails`                                            |

---

## 7. Open Decisions (need user input before implementation starts)

1. **Tier scope.** Ship P0 only (~25 stories, ~6h), P0+P1 (~61 stories, ~16h), or all P0+P1+P2 (~96 stories, ~28h)?
2. **Variant routing.** Use `?variant=<name>` query param (recommended), or a per-variant URL path like `/wf/login-mfa-full`?
3. **Per-test reset.** `POST /__test/reset` re-seed (recommended) vs. fresh-backend-per-spec vs. in-memory worker storage?
4. **Browser matrix.** Chromium-only (recommended for first pass), or also firefox/webkit?
5. **CI.** Add to existing `pnpm test` (extending the workspace script) or run as a separate `pnpm test:e2e` job (recommended — keeps vitest fast)?
6. **Variant config in code or external?** Recommended: TypeScript map in `src/variants.ts` (typed, refactor-safe). Alternative: JSON file.

---

## 8. Implementation Plan (after decisions land)

Will be executed via orchestrator-implement with parallel agents per stage:

| Step    | Agent                                                                  | Files                                                         |
| ------- | ---------------------------------------------------------------------- | ------------------------------------------------------------- |
| 1       | Infra: install Playwright, add config, add `__test` mailbox controller | `package.json`, `playwright.config.ts`, `src/test-mailbox.ts` |
| 2       | Infra: variant config presets + UI variant param wiring                | `src/variants.ts`, `src/app.ts`, `src/ui/pages/WfPage.vue`    |
| 3       | Infra: seed expansion (add 9 new users)                                | `src/seed.ts`                                                 |
| 4       | P0 Login stories (parallel: 3 agents)                                  | `test-e2e/login-*.spec.ts`                                    |
| 5       | P0 Recovery stories                                                    | `test-e2e/recovery-*.spec.ts`                                 |
| 6       | P0 Invite stories                                                      | `test-e2e/invite-*.spec.ts`                                   |
| 7       | Simplify pass                                                          | all e2e test files + harness                                  |
| 8       | Cross-package test audit + workspace `pnpm test`                       | —                                                             |
| (later) | P1 / P2 batches                                                        | —                                                             |

Each step is its own PR. Steps 4–6 can parallelize once 1–3 land.
