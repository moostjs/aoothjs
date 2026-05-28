# E2E User Stories — Playwright Test Matrix

**Status:** Live — 85 specs green under `pnpm test:e2e`. This document is the catalogue + walkthrough guide for the running Playwright suite at [`packages/e2e-demo/test-e2e/`](test-e2e/).

It enumerates every workflow variant × user state × branch path the suite covers (sections 3–5), describes the runtime infrastructure (section 2), the render-assertion vocabulary (section 6), and the manual-walkthrough guides for the headline UX surfaces (sections 9–11 — **consent collection**, **password creation with live rules**, **OTP disclosure**).

---

## 1. Scope Summary

| Workflow                                              | Variant profiles    | P0 stories | P1 stories | P2 stories |
| ----------------------------------------------------- | ------------------- | ---------- | ---------- | ---------- |
| `auth.login`                                          | 11 (A–E, H–M)       | 13         | 19         | 9          |
| `auth.recovery`                                       | 7 (A–G) + 1 consent | 7          | 8          | 5          |
| `auth.invite` + `auth.reInvite` + `auth.cancelInvite` | 7 (A–G) + 1 consent | 7          | 9          | 5          |
| **Totals**                                            | **27 variants**     | **27**     | **36**     | **19**     |

**Final shipped count: 85 Playwright specs** (smoke + 84 stories) under `pnpm test:e2e` — every commit lands green.

**Priority tiering:**

- **P0** — happy path + one alt-action + one validation error per workflow variant. Smoke-level coverage.
- **P1** — secondary branches: transport switching, resend cooldowns, expired tokens, idempotency, multi-step alt-actions.
- **P2** — exhaustive: every error path, anti-enumeration, locked-account 423, every option override, audit assertion.

Phases 1–7 of the consent refactor added 7 new specs on top of the base matrix (BUMP-01, HACK-CONSENT-01, CONSENT-ARRAY-01, OTP-DISCLOSURE-01, PASSWORD-RULES-LIVE-01, INVITE-CONSENT-01, RECOVERY-CONSENT-01).

---

## 2. Demo Infrastructure Requirements (must land before test writing)

### 2.1 Variant-config switching

The demo currently has **one** hardcoded login config (`demoLoginOpts` in [src/app.ts](src/app.ts)). To exercise the matrix, the demo must expose **named variant presets** that Playwright can target.

**Recommended pattern:** add `?variant=<name>` query param on `/wf` route. The server reads it, looks up a registered preset config map, and constructs a fresh workflow controller with the selected opts. This avoids spinning 24 backend servers.

```ts
// src/variants.ts (post-Phase-7)
export const LOGIN_VARIANTS = {
  'minimal':       { mfa: { enabled: false }, alternateCredentials: { forgotPassword: true } },
  'mfa-totp':      { mfa: { transports: ['totp'] } },
  'mfa-full':      { mfa: { transports: ['sms','email','totp'] } },
  'enrollment':    { enrollment: { ensureEmail: true, ensurePhone: true } },
  'device-trust':  { deviceTrust: { enabled: true, optIn: true, skipsMfa: true } },
  'guards':        { guards: { passwordInitial: true, emailVerifiedRequired: true } },
  'consent-array': { mfaCtx: { mfaMode: 'disabled' } /* consent universe in VARIANT_PENDING_CONSENTS */ },
  'terms-bump':    { mfaCtx: { mfaMode: 'disabled' } /* + VARIANT_PENDING_CONSENTS['terms-bump'] */ },
  'acceptance':    { profile: { required: true } /* + VARIANT_PENDING_CONSENTS['acceptance'] */ },
  'concurrency':   { sessionPolicy: { concurrencyLimit: { max: 1, onLimit: 'kickPrompt' } } },
  'full':          { profile: { required: true }, /* + every flag + VARIANT_PENDING_CONSENTS['full'] */ },
};

// Consent universe — Phase 5 split this off `policy.acceptance` so the customer
// ConsentStore is the single source of truth. DemoConsentStore.getPendingConsents
// keys off the `x-wf-variant` header into this map.
export const VARIANT_PENDING_CONSENTS = {
  'consent-array':       [{ id: 'terms', text: 'I accept the Terms of Service', required: 'Terms are mandatory', version: 'v2' }, { id: 'marketing', text: 'Send me product updates' }],
  'terms-bump':          [{ id: 'terms', text: 'I accept the updated Terms', required: 'You must accept the terms', version: 'v3' }],
  'invite-terms':        [{ id: 'terms', text: 'I accept the Terms', required: 'Terms are mandatory', version: 'v1' }],
  'recovery-terms-bump': [{ id: 'terms', text: 'I accept the updated Terms', required: 'Terms are mandatory', version: 'v2' }],
  'acceptance':          [{ id: 'terms', required: 'You must accept the terms', version: 'v1' }, { id: 'marketing' }],
  'full':                [{ id: 'terms', required: 'You must accept the terms', version: 'v1' }, { id: 'marketing' }],
};

export const RECOVERY_VARIANTS = { ... }; // 7 entries + 'recovery-terms-bump'
export const INVITE_VARIANTS = { ... };   // 7 entries + 'invite-terms'
```

The UI's `WfPage.vue` already reads `?id=<wfid>` from the route. Extend it to pass `?variant=<name>` to the trigger endpoint via a custom `fetchOptions.headers['x-wf-variant']` so the server picks the preset.

### 2.2 Seed user expansion

Existing 14 users cover the basics. We need to add:

| New user             | Purpose                                                    | Stories                        |
| -------------------- | ---------------------------------------------------------- | ------------------------------ |
| `t1_locked`          | Account in `account.locked=true`                           | Login: 423 path                |
| `t1_multi_mfa`       | Email + SMS + TOTP all confirmed (default=TOTP)            | Profile C + Profile I          |
| `t1_pending`         | `pendingInvitation=true`, `account.active=false`           | reInvite + cancelInvite        |
| `t1_redeemed`        | `pendingInvitation=false`, fully active (from past invite) | reInvite 409, cancelInvite 409 |
| `t1_active_sessions` | 2 issued sessions (concurrency test)                       | Profile H                      |
| `t1_frank`           | Plain user used to exercise consent prompts (no MFA/trust) | L-K consent-array variants     |
| `_admin_inviter`     | Has `@ArbacAction('start')` on `auth.invite`               | All invite admin-side stories  |

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

| ID  | Profile           | Key opts                                                                                                                                                   |
| --- | ----------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------- |
| L-A | Minimal           | password-only, no MFA, `forgotPassword: true`                                                                                                              |
| L-B | Enrollment        | `ensureEmail+ensurePhone: true`, `mfa.transports=[email,sms,totp]`                                                                                         |
| L-C | MFA-full          | all 3 transports                                                                                                                                           |
| L-D | Device trust      | `deviceTrust.enabled+skipsMfa: true`                                                                                                                       |
| L-E | Password guards   | `passwordInitial+emailVerifiedRequired: true`, no MFA                                                                                                      |
| L-H | Concurrency       | `kickPrompt` policy                                                                                                                                        |
| L-I | Full              | every flag on                                                                                                                                              |
| L-J | Redirect          | `finalize.redirect: 'home'`                                                                                                                                |
| L-K | Consent capture   | `consent-array` / `terms-bump` variants drive `VARIANT_PENDING_CONSENTS` → `AsConsentArray` checkboxes on `TermsBumpForm` (Phase 5)                        |
| L-L | OTP disclosure    | `enrollment` variant — `AskEmailForm` / `AskPhoneForm` carry a generic disclosure paragraph; `recordOtpChannelConsent` fires post-pincode-verify (Phase 3) |
| L-M | Password rotation | `passwordExpiry: true` (default), `password.maxAgeMs: 365d`, no MFA                                                                                        |

### Stories (priority tagged)

| ID                         | Tier | Variant       | Story                                                                                                                                                                                    | Render assertions                                                                                                                                                          |
| -------------------------- | ---- | ------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| WF-LOGIN-001               | P0   | L-A           | alice signs in with correct password → tokens issued                                                                                                                                     | `LoginCredentialsForm` visible, `forgotPassword` button visible, `signup`/`magicLink` hidden, finish envelope carries `accessToken`                                        |
| WF-LOGIN-002               | P0   | L-A           | wrong password → form re-renders with `__form: "Invalid credentials"`                                                                                                                    | error message present, form fields cleared appropriately                                                                                                                   |
| WF-LOGIN-003               | P0   | L-A           | click "Forgot password?" → redirected to `/recover?username=<typed>`                                                                                                                     | URL contains typed username, recovery form loaded                                                                                                                          |
| WF-LOGIN-004               | P1   | L-A           | locked account `t1_locked` → 423 / friendly error                                                                                                                                        | HTTP 423 surfaced as user-readable message                                                                                                                                 |
| WF-LOGIN-005               | P2   | L-A           | brute-force lockout: 5 wrong passwords → account locks                                                                                                                                   | 5th attempt → 423; user notification                                                                                                                                       |
| WF-LOGIN-006               | P0   | L-A+signup    | with `signup: true`, "Sign up" button visible and routes to `/signup`                                                                                                                    | button visible, redirect to invite workflow                                                                                                                                |
| WF-LOGIN-007               | P0   | L-C           | charlie (3 MFA methods) → `Select2faForm` appears, pick SMS → `PincodeForm` → enter code → tokens                                                                                        | select2fa visible, pincode hint paragraph reads "Code sent to **\***0100"                                                                                                  |
| WF-LOGIN-008               | P0   | L-C           | grace (1 TOTP only) → `MfaCodeForm` directly (no select2fa) → enter code → tokens                                                                                                        | `useDifferentMethod` hidden (count=1), hint reads "Enter the current 6-digit code…"                                                                                        |
| WF-LOGIN-009               | P1   | L-C           | charlie clicks `useDifferentMethod` on pincode-check → loops back to select2fa                                                                                                           | form sequence: select2fa → pincode → select2fa                                                                                                                             |
| WF-LOGIN-011               | P1   | L-C           | resend within timeout → "Please wait Ns" form error                                                                                                                                      | error message visible, no new email in mailbox                                                                                                                             |
| WF-LOGIN-012               | P1   | L-C           | resend after timeout → new code sent                                                                                                                                                     | mailbox has 2 emails, codes differ                                                                                                                                         |
| WF-LOGIN-013               | P2   | L-C           | wrong MFA code → `errors.code = "Invalid code"`                                                                                                                                          | error visible, form re-renders                                                                                                                                             |
| WF-LOGIN-015               | P0   | L-B           | eve has no confirmed email → `AskEmailForm` pause → enter email → pincode → confirmed → tokens                                                                                           | `AskEmailForm` autocomplete='email', pincode hint visible, email captured                                                                                                  |
| WF-LOGIN-016               | P1   | L-B           | eve has confirmed email already → `AskEmailForm` skipped                                                                                                                                 | step never paused; proceeds to MFA                                                                                                                                         |
| WF-LOGIN-017               | P1   | L-B           | phone enrollment loop with `AskPhoneForm`                                                                                                                                                | similar to email                                                                                                                                                           |
| WF-LOGIN-018               | P0   | L-D           | alice on new device → MFA → `rememberDevice` checked → 2nd login skips MFA                                                                                                               | first session sets cookie; 2nd session finds cookie, skips MFA loop                                                                                                        |
| WF-LOGIN-019               | P1   | L-D           | `deviceTrust.optIn: false` → no `rememberDevice` checkbox shown                                                                                                                          | checkbox absent in PincodeForm DOM                                                                                                                                         |
| WF-LOGIN-020               | P2   | L-D           | trusted cookie expires → MFA required again                                                                                                                                              | wait past `ttlMs`; expect MFA loop                                                                                                                                         |
| WF-LOGIN-021               | P0   | L-E           | jack (`isInitial=true`) → `SetPasswordForm` pause → mismatch error → tokens on match                                                                                                     | `AsPasswordRules` rows visible (Phase 7), mismatch error inline; live-keystroke evaluation pinned by WF-PASSWORD-RULES-LIVE-01                                             |
| WF-LOGIN-EXPIRED-01        | P0   | L-M           | t1_stale (`lastChanged=1`, deep past) → `SetPasswordForm` pause (`password.changeReason='expired'`) → tokens on new password                                                             | Pins `@wf.context.pass 'password'` reaches client; pins schema-OR `(isPasswordInitial \|\| isPasswordExpired)`; pins post-change reset                                     |
| WF-LOGIN-022               | P1   | L-E           | jack clicks `logout` on SetPassword → aborts                                                                                                                                             | finish envelope has `aborted: true`, no tokens                                                                                                                             |
| WF-LOGIN-024               | P1   | L-K           | frank submits `TermsBumpForm` without ticking required terms row → form-level error, no tokens                                                                                           | `errors.consents` carries descriptor's `required` string verbatim; mandatory-by-message defense                                                                            |
| WF-LOGIN-025               | P1   | L-K           | optional marketing row renders unchecked + tickable; tick terms only + submit completes workflow                                                                                         | `AsConsentArray` renders 2 checkboxes (terms required + marketing optional); marketing event saved with `accepted:false`                                                   |
| WF-LOGIN-028               | P1   | L-H           | henry with 1 active session, `max=1` → kickPrompt                                                                                                                                        | "Log out others" form visible                                                                                                                                              |
| WF-LOGIN-029               | P1   | L-H           | clicks "Cancel" on kickPrompt → aborted                                                                                                                                                  | no tokens issued                                                                                                                                                           |
| WF-LOGIN-030               | P2   | L-H           | `onLimit: 'reject'` → HTTP 429 immediately                                                                                                                                               | no form, error banner                                                                                                                                                      |
| WF-LOGIN-031               | P1   | L-J           | login completes → immediate redirect to `/`                                                                                                                                              | URL after finish is `/`                                                                                                                                                    |
| WF-LOGIN-032               | P2   | L-I           | iris through every step in order (inline consent on `AskEmailForm` via inherited consents field)                                                                                         | every step paused in correct sequence; final tokens + redirect; `ConsentEvent[]` persisted at completion                                                                   |
| WF-LOGIN-033               | P1   | enrollment    | required + single transport totp → auto-pick lands on `EnrollConfirmForm`; code accepts → tokens                                                                                         | no `EnrollPickMethodForm` shown; `EnrollConfirmForm` carries TOTP secret + QR provisioning URI                                                                             |
| WF-LOGIN-034               | P1   | enrollment    | optional + `skip` from `EnrollPickMethodForm` → tokens issued, no `mfa.methods` persisted                                                                                                | `enrollMode: 'optional'` only; skip alt-action visible; user-row mfa methods stays empty                                                                                   |
| WF-LOGIN-035               | P1   | enrollment    | optional + `useDifferentMethod` from `EnrollAddressForm` → returns to picker, unconfirmed cleanup                                                                                        | EnrollAddressForm renders for `email`/`sms` only; unconfirmed row removed via `removeMfaMethod`                                                                            |
| WF-LOGIN-036               | P1   | enrollment    | optional + `resend` on `EnrollConfirmForm` → cooldown gates; post-cooldown re-mints fresh code                                                                                           | `enrollPincodeCooldown` ctx field gates resend; mailbox shows 2 distinct codes                                                                                             |
| WF-LOGIN-BUMP-01           | P1   | terms-bump    | standalone bump prompt fires when user has consents pending but no enrolment/profile carrier form on this login                                                                          | `TermsBumpForm` (extends WithInlineConsentForm) renders alone; `consent-log` records `{id:'terms', accepted:true, version:'v3'}`                                           |
| WF-LOGIN-HACK-CONSENT-01   | P1   | acceptance    | hand-rolled POST submits empty `consents:[]` on `TermsBumpForm` → server's mandatory-by-message defense throws `errors.consents = descriptor.required`                                   | bypassing the SPA's AsConsentArray render still hits the server-side required check; no tokens issued                                                                      |
| WF-CONSENT-ARRAY-01        | P0   | consent-array | t1_alice → `SetPasswordForm` (initial-password branch) renders 2 consents; first submit (no terms) errors; check both + submit → finish + `consent-log` carries both events              | `AsConsentArray` rows visible per descriptor; per-row error string matches descriptor's `required`; both `ConsentEvent`s persisted with `accepted` reflecting tick state   |
| WF-LOGIN-OTP-DISCLOSURE-01 | P1   | enrollment    | t1_alice phone-enrolment → `AskPhoneForm` carries `ctx.otpDisclosure` paragraph; post-pincode-verify the `recordOtpChannelConsent` hook fires with `{channel:'sms', target, disclosure}` | `/__test/otp-consent-log/t1_alice` returns the expected SMS audit record; protocol mapping `'phone' → 'sms'` pinned                                                        |
| WF-PASSWORD-RULES-LIVE-01  | P0   | guards        | t1_jack forced-password-change → `AsPasswordRules` renders 3 backend-supplied policies; `data-passed` per row updates live as user types                                                 | empty → all `false`; `"short"` → length:false, letter:true, digit:false; `"longenough1A!"` → all `true`; submit completes; pins `(_, data) => data.newPassword` reactivity |

**Login total: 41 stories** (13 P0 + 19 P1 + 9 P2)

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

| ID                     | Tier | Variant             | Story                                                                                                                                                     | Render assertions                                                                                                                                                                                                                       |
| ---------------------- | ---- | ------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| WF-RECOVERY-001        | P0   | R-A                 | alice → enter email → magic link → click → set password → tokens                                                                                          | email captured with `kind: 'recovery.magicLink'`, `SetPasswordForm` shows `password.policies` rules                                                                                                                                     |
| WF-RECOVERY-002        | P0   | R-A                 | unknown email → identical "if account exists" finish                                                                                                      | finish envelope generic, no email sent                                                                                                                                                                                                  |
| WF-RECOVERY-003        | P1   | R-A                 | password mismatch → `confirmPassword: "Passwords do not match"`                                                                                           | error visible inline                                                                                                                                                                                                                    |
| WF-RECOVERY-004        | P1   | R-A                 | expired magic link → 410 on resume                                                                                                                        | error page or message                                                                                                                                                                                                                   |
| WF-RECOVERY-005        | P0   | R-B                 | alice → email OTP → enter code → set password → tokens                                                                                                    | `PincodeForm` hint reads "Code sent to **\***"                                                                                                                                                                                          |
| WF-RECOVERY-006        | P0   | R-C                 | alice (sms enrolled) → SMS OTP → tokens                                                                                                                   | SMS mailbox has code                                                                                                                                                                                                                    |
| WF-RECOVERY-007        | P1   | R-D                 | switch transport email → sms via `useDifferentTransport`                                                                                                  | first email, then SMS in mailbox                                                                                                                                                                                                        |
| WF-RECOVERY-008        | P1   | R-D                 | `useDifferentTransport` hidden when only 1 transport                                                                                                      | button absent                                                                                                                                                                                                                           |
| WF-RECOVERY-009        | P1   | R-B                 | wrong OTP → `errors.code = "Invalid code"`                                                                                                                | error visible                                                                                                                                                                                                                           |
| WF-RECOVERY-010        | P1   | R-B                 | resend within cooldown → "Please wait Ns"                                                                                                                 | no new email                                                                                                                                                                                                                            |
| WF-RECOVERY-011        | P1   | R-B                 | resend after cooldown → new code                                                                                                                          | 2 emails, codes differ                                                                                                                                                                                                                  |
| WF-RECOVERY-012        | P0   | R-E                 | choice mode → `RecoveryModeSelectForm` → pick magicLink → flow A                                                                                          | mode form visible                                                                                                                                                                                                                       |
| WF-RECOVERY-013        | P1   | R-E                 | choice mode → pick otp → flow B                                                                                                                           | mode form visible, then PincodeForm                                                                                                                                                                                                     |
| WF-RECOVERY-014        | P1   | R-F                 | pre-reset factor (phone last-4) → match → set password                                                                                                    | `RecoveryFactorForm` visible, opaque error on wrong                                                                                                                                                                                     |
| WF-RECOVERY-015        | P2   | R-F                 | pre-reset factor wrong → "Invalid factor"                                                                                                                 | opaque error                                                                                                                                                                                                                            |
| WF-RECOVERY-016        | P0   | R-G                 | freshLoginRequired → finish has 5s redirect, no tokens                                                                                                    | envelope has `next.trigger='auto'`, `data` absent                                                                                                                                                                                       |
| WF-RECOVERY-017        | P1   | R-A                 | `backToLogin` from request step → redirect to `/login`                                                                                                    | finish envelope reason='user-cancelled'                                                                                                                                                                                                 |
| WF-RECOVERY-018        | P2   | R-A                 | post-reset old token rejected (revokeAllSessions=true)                                                                                                    | old session HTTP 401                                                                                                                                                                                                                    |
| WF-RECOVERY-019        | P2   | R-A                 | audit events emitted: `recovery.requested`, `recovery.completed`                                                                                          | mailbox endpoint or audit endpoint shows events                                                                                                                                                                                         |
| WF-RECOVERY-CONSENT-01 | P0   | recovery-terms-bump | recovery-terms-bump variant → `SetPasswordForm` shows `AsConsentArray`; tick + submit → `consent-log` carries `{id:'terms', accepted:true, version:'v2'}` | terms-version bump scenario (re-acceptance during password reset); magic-link resume preserves variant via `&variant=…` query (load-bearing — invitee/recoverer's resume request inherits the originator's variant header through this) |

**Recovery total: 20 stories** (7 P0 + 8 P1 + 5 P2)

---

## 5. Invite Family Stories

### Variant profiles

| ID  | Profile                                    | Key opts                                                 |
| --- | ------------------------------------------ | -------------------------------------------------------- |
| I-A | Email, no roles, auto-login                | minimal default                                          |
| I-B | Roles                                      | `getAvailableRoles` wired                                |
| I-C | Shareable link mode                        | `send.mode='shareableLink'`                              |
| I-D | Choice + fresh-login                       | `send.mode='choice'`, `freshLoginRequired: true`         |
| I-E | Audit enabled                              | `audit.enabled: true`                                    |
| I-F | Cancellation disabled / duplicate override | `cancellation.allowed: false`, `duplicateCheck` override |
| I-G | Short TTL + confirmation                   | `tokenTtlMs=1s`, `showConfirmation: true`                |

### Stories

| ID                   | Tier | Variant      | Story                                                                                                                                              | Render assertions                                                                                                                                                                                                                                    |
| -------------------- | ---- | ------------ | -------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| WF-INVITE-001        | P0   | I-A          | admin invites new email → mailbox has invite → invitee redeems → tokens                                                                            | `InviteForm` no `roles` field; redemption sets password; auto-login envelope                                                                                                                                                                         |
| WF-INVITE-002        | P1   | I-A          | admin invites existing user → 409                                                                                                                  | form re-renders with error                                                                                                                                                                                                                           |
| WF-INVITE-003        | P1   | I-A          | invitee cancels at password form → pending preserved                                                                                               | user record still `pendingInvitation=true`                                                                                                                                                                                                           |
| WF-INVITE-004        | P2   | I-A          | expired link → 410                                                                                                                                 | error visible                                                                                                                                                                                                                                        |
| WF-INVITE-005        | P0   | I-B          | role whitelist `['member','viewer','admin']` → admin picks valid → invitee redeems                                                                 | role picker shows 3 options; invalid role rejected                                                                                                                                                                                                   |
| WF-INVITE-006        | P1   | I-B          | admin submits role not in whitelist → form error                                                                                                   | error visible inline                                                                                                                                                                                                                                 |
| WF-INVITE-009        | P1   | I-C          | shareable link mode → admin form completes, link displayed, link reusable                                                                          | no email sent, link URL captured                                                                                                                                                                                                                     |
| WF-INVITE-010        | P2   | I-C          | already-accepted link click → idempotent redirect with 2 options                                                                                   | "Go to sign-in" + "Request a new invite" buttons                                                                                                                                                                                                     |
| WF-INVITE-011        | P0   | I-D          | choice → admin picks "email" → email sent                                                                                                          | `InviteSendModeForm` visible                                                                                                                                                                                                                         |
| WF-INVITE-012        | P1   | I-D          | freshLoginRequired → redemption finish has no tokens, redirect to `/welcome`                                                                       | envelope reason='fresh-login-required'                                                                                                                                                                                                               |
| WF-INVITE-013        | P0   | I-E          | reInvite on pending user → new email sent → audit `invite.resent`                                                                                  | `InviteEmailForm` accepts email, new mailbox entry                                                                                                                                                                                                   |
| WF-INVITE-014        | P1   | I-E          | reInvite on already-accepted user → 409                                                                                                            | error visible                                                                                                                                                                                                                                        |
| WF-INVITE-015        | P0   | I-E          | cancelInvite on pending → user deleted → audit `invite.cancelled`                                                                                  | record gone, mailbox endpoint shows audit                                                                                                                                                                                                            |
| WF-INVITE-016        | P1   | I-E          | cancelInvite on already-accepted → 409                                                                                                             | error visible                                                                                                                                                                                                                                        |
| WF-INVITE-017        | P1   | I-F          | cancelInvite when `cancellation.allowed: false` → 403                                                                                              | direct error, no form                                                                                                                                                                                                                                |
| WF-INVITE-018        | P2   | I-F          | duplicate user with `duplicateCheck='allow'` override → still 409 from store-level constraint                                                      | error surfaces                                                                                                                                                                                                                                       |
| WF-INVITE-019        | P2   | I-G          | TTL=1s, click after 2s → 410                                                                                                                       | error visible                                                                                                                                                                                                                                        |
| WF-INVITE-020        | P2   | I-G          | `showConfirmation: true` → finish message "Your account has been created."                                                                         | text visible in DOM                                                                                                                                                                                                                                  |
| WF-INVITE-021        | P1   | I-B          | invite-tail optional + `skip` from `EnrollPickMethodForm` → activated, no mfa enrolled                                                             | mirrors WF-LOGIN-034 but on the invite accept tail                                                                                                                                                                                                   |
| WF-INVITE-022        | P1   | I-B          | invite-tail optional + `useDifferentMethod` from `EnrollConfirmForm` (totp→sms) → loops + cleanup                                                  | unconfirmed totp row removed; sms enrolment completes                                                                                                                                                                                                |
| WF-INVITE-CONSENT-01 | P0   | invite-terms | invite-terms variant → `SetPasswordForm` shows `AsConsentArray`; tick + submit → `consent-log` carries `{id:'terms', accepted:true, version:'v1'}` | end-to-end invitee acceptance with consent capture; magic-link URL carries `&variant=invite-terms` so invitee's resume request inherits the admin's variant header (otherwise DemoConsentStore would see no header and return empty pendingConsents) |

**Invite total: 21 stories** (7 P0 + 9 P1 + 5 P2)

---

## 6. Render-Assertion Catalog (cross-cutting)

The Playwright value-add over the existing in-process vitest suite is **rendered-DOM verification**. Every story above must include at least one of these classes of assertion:

| Class                                 | Examples                                                                                                                                                   | Detection method                                                                             |
| ------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------- | ------------------------------------------------------------ |
| **Conditional alt-action visibility** | `signup` hidden when `!altSignup`; `useDifferentMethod` hidden when `mfaMethodCount<2`                                                                     | `page.locator('button:has-text("Sign up")').isVisible()`                                     |
| **Computed paragraph text**           | MFA hint reads "Enter the current 6-digit code…" for TOTP, "Code sent to **\***0100 — check console" for SMS                                               | `expect(page.locator('p[aria-live]')).toContainText(…)`                                      |
| **Default values (no tristate)**      | `rememberDevice` unchecked on first render (not indeterminate); `optIn` unchecked                                                                          | `expect(checkbox).not.toBeChecked()`                                                         |
| **Autocomplete hints**                | username field has `autocomplete="username"`; password has `current-password`                                                                              | `getAttribute('autocomplete')`                                                               |
| **Validation errors inline**          | "Invalid code", "Passwords do not match" appear next to the right field                                                                                    | `page.locator('[data-field=code] .error').textContent()`                                     |
| **Form sequence**                     | Variants force forms in known order (e.g. credentials → mfa → terms → tokens)                                                                              | snapshot test of visible form ID on each step                                                |
| **Finish-envelope rendering**         | redirect vs. data vs. abort envelopes render distinct UI                                                                                                   | URL after finish; presence of success banner; absence of tokens                              |
| **Field absence**                     | role picker absent when `collectRoles: false`; `rememberDevice` checkbox absent when `deviceTrust.optIn: false`                                            | `expect(locator).toHaveCount(0)`                                                             |
| **Test-mailbox content**              | OTP code matches what server sent; magic-link URL matches                                                                                                  | GET `/__test/emails`                                                                         |
| **Consent-log content**               | `ConsentEvent[]` shape `{id, accepted, version?, at}` per pending descriptor — one event per descriptor, accepted reflects tick state                      | GET `/__test/consent-log/<username>`                                                         |
| **OTP-consent-log content**           | `recordOtpChannelConsent` audit records — `{channel, target, disclosure, at}` per verified channel; protocol mapping `phone→sms` pinned                    | GET `/__test/otp-consent-log/<username>`                                                     |
| **AsConsentArray rendering**          | One checkbox row per `ctx.pendingConsents` descriptor; per-row error string matches descriptor's `required`; component self-hides on empty pendingConsents | `page.locator('.as-consent-array input[type=checkbox]')`                                     |
| **AsPasswordRules live evaluation**   | Per-row `data-passed="true                                                                                                                                 | false"`reflects compiled ftring-rule evaluation against`data.newPassword` on every keystroke | `page.locator('.as-password-rules-row[data-passed="true"]')` |

---

## 7. Decisions (resolved)

1. **Tier scope.** Shipped P0 + P1 + foundational P2 in waves; the 7-phase consent refactor (commits `3491990` → `4d04417`) added 7 additional specs.
2. **Variant routing.** `?variant=<name>` query param → `x-wf-variant` header → server picks the preset in the workflow controller constructor (FOR_EVENT scope).
3. **Per-test reset.** `POST /__test/reset` re-seeds + clears mailboxes + clears `consent-log` + clears `otp-consent-log`. ~1s per spec.
4. **Browser matrix.** Chromium-only (single project in `playwright.config.ts`).
5. **CI.** Separate `pnpm test:e2e` script (workflows ≠ vitest scope). Boot order: `DEMO_MODE=test SEED=true pnpm dev` in one terminal, `pnpm test:e2e` in the other.
6. **Variant config.** TypeScript map in `src/variants.ts` + `VARIANT_PENDING_CONSENTS` map in `src/app.ts` (consent universe is colocated with `DemoConsentStore` per Phase 5 design).

---

## 8. Implementation Log

Executed via `orchestrator-implement`. Each step a separate commit. Tests gate every step.

| Step                              | Status | Commits / Notes                                                                      |
| --------------------------------- | ------ | ------------------------------------------------------------------------------------ |
| Infra                             | done   | Playwright + `__test/*` endpoints + variant routing + seed expansion (~14 users now) |
| P0 + P1 Login / Recovery / Invite | done   | 41 + 20 + 23 specs                                                                   |
| Phase 1                           | done   | `3491990` — ConsentStore DI plumbing                                                 |
| Phase 2                           | done   | `7d4ad56` — `persist-consents` migrates to `ConsentStore.save`                       |
| Phase 3                           | done   | `f3b85f1` — OTP disclosure + `recordOtpChannelConsent` hook                          |
| Phase 4                           | done   | `89cc544` — `prepare-consents` @Step + `ctx.pendingConsents` transport               |
| Phase 5                           | done   | `c397b37` — `consents:string[]` dynamic carrier + `AsConsentArray`                   |
| Phase 6                           | done   | `be392b6` — retire `ctx.acceptance` / `resolveAcceptance`                            |
| Phase 7                           | done   | `4d04417` — `AsPasswordRules` SPA wire-up + `WF-PASSWORD-RULES-LIVE-01`              |

---

## 9. Manual walkthrough — Consent capture (Phase 5)

**Boot:** `cd packages/e2e-demo && DEMO_MODE=test SEED=true pnpm dev` (serves SPA + API on `http://localhost:3001`).

### 9.1 Single-form: required terms + optional marketing

1. Browse to `http://localhost:3001/wf?id=auth/login/flow&variant=consent-array`.
2. Sign in as `t1_alice` / `Password1!` (Fill button on the right autofills both).
3. The workflow lands on `SetPasswordForm` (Phase 7 `AsPasswordRules` rows visible) + `AsConsentArray` (Phase 5 checkboxes) inherited via `WithInlineConsentForm`.
4. Try clicking **Submit** without ticking anything → form-level error "Terms are mandatory" (the `required` string from the `terms` descriptor). The marketing row stays unchecked but doesn't block.
5. Tick the **"I accept the Terms of Service"** checkbox + leave **"Send me product updates"** unchecked + Submit.
6. Workflow finishes → JSON envelope at the top shows `accessToken`.
7. Inspect the audit record: `curl http://localhost:3001/__test/consent-log/t1_alice` → two events: `{id:'terms', accepted:true, version:'v2', at:…}` + `{id:'marketing', accepted:false, at:…}` (audit-friendly default — declined-optional events still persist).

### 9.2 Standalone re-prompt (terms-version bump)

1. Browse to `http://localhost:3001/wf?id=auth/login/flow&variant=terms-bump`.
2. Sign in as `t1_frank` / `Password1!`.
3. Workflow lands on **`TermsBumpForm`** — empty form except the single `AsConsentArray` row "I accept the updated Terms" (variant `terms-bump` returns ONE required descriptor `version:v3`).
4. Tick + Submit → finish envelope + `accessToken`.
5. `curl http://localhost:3001/__test/consent-log/t1_frank` → `[{id:'terms', accepted:true, version:'v3', at:…}]`.

### 9.3 Hack-attempt simulation (silent-drop defense)

1. Reset state: `curl -X POST -H "Content-Type: application/json" -d '{}' http://localhost:3001/__test/reset`.
2. Kick off the workflow programmatically:
   ```bash
   curl -X POST -H "Content-Type: application/json" -H "x-wf-variant: terms-bump" \
        -d '{"wfid":"auth/login/flow"}' http://localhost:3001/auth/trigger
   ```
3. Capture the returned `wfs` token, then submit credentials. Then on the TermsBumpForm submission, post a tampered payload:
   ```bash
   curl -X POST -H "Content-Type: application/json" -H "x-wf-variant: terms-bump" \
        -d '{"wfs":"<token>","input":{"formData":{"consents":["terms","forged-gdpr"]}}}' \
        http://localhost:3001/auth/trigger
   ```
4. Workflow completes — but `consent-log` records `[{id:'terms', accepted:true, version:'v3', at:…}]` only. The forged `'forged-gdpr'` id is **silently dropped** (server's `processInlineConsent` uses its own `ctx.pendingConsents` as the whitelist; out-of-set ids never reach `save()`).

### 9.4 Cross-leg consent (invite + recovery)

Invite and recovery workflows split across a magic-link boundary. The invitee/recoverer arrives in a fresh browser context — no header. The demo's [`buildMagicLinkUrl`](src/aooth.ts) reads the originator's `x-wf-variant` and rides it on the URL (`?wfs=<token>&variant=<name>`), so the SPA's WfPage forwards it on resume. This is what makes `WF-INVITE-CONSENT-01` and `WF-RECOVERY-CONSENT-01` work.

To exercise live:

1. Login as `admin@acme.test` / `Password1!` on `/wf?id=auth/login/flow&variant=minimal`.
2. Navigate to `/wf?id=auth/invite/start&variant=invite-terms`, invite `new-user@example.com`.
3. Open the [dev console](http://localhost:3001) running `pnpm dev` — find the `[email] invite.magicLink → new-user@example.com` line. The URL carries `&variant=invite-terms`.
4. Open that URL in an Incognito window. SetPasswordForm pauses with the `AsConsentArray` row for terms. Tick + fill password + Submit.

---

## 10. Manual walkthrough — Password creation with live rules (Phase 7)

**Boot:** same as section 9.

1. Browse to `http://localhost:3001/wf?id=auth/login/flow&variant=guards`.
2. Sign in as `t1_jack` / `Password1!`.
3. Walk through `AskEmailForm` (`jack@acme.test` is auto-pre-filled by the variant) → email-OTP `PincodeForm` (read code from dev console, e.g. `[email] login.pincode → jack@acme.test code=123456`).
4. Workflow lands on **`SetPasswordForm`**. Below the New password / Confirm password inputs there are 3 live-evaluated rule rows (the new `AsPasswordRules` Phase 7 component): "At least 8 characters", "Contains a letter", "Contains a digit".
5. **Type into New password and watch the rows toggle live:**
   - Empty → all 3 rows red/false.
   - `short` → length:red, letter:green, digit:red.
   - `longenough1A!` → all green.
6. Each row carries `data-passed="true|false"` for e2e assertion (`WF-PASSWORD-RULES-LIVE-01` pins exactly this).
7. Fill confirm password identically + Submit → tokens issued.

**Password rotation (`password-expired` variant):** browse to `http://localhost:3001/wf?id=auth/login/flow&variant=password-expired`, sign in as `t1_stale` / `Password1!`. The seed user's `password.lastChanged = 1` (epoch+1ms) is older than the configured `password.maxAgeMs` (365d) so the workflow lands on **`SetPasswordForm`** directly (MFA disabled on this variant). The wire envelope carries `password.changeReason: 'expired'` — surface it in the SPA to render a "Your password has expired" banner instead of the initial-password copy. Submit `NewerPass1!` in both fields → tokens issued.

**Customizing the policies:** edit `definePasswordPolicy` calls in [`packages/e2e-demo/src/aooth.ts`](src/aooth.ts) (around lines 76-95). Add e.g.:

```ts
definePasswordPolicy({
  rule: (p, [chars]) => /[!@#$%^&*]/.test(p),
  args: [['!@#$%^&*']],
  description: 'Contains a special character',
  errorMessage: 'Password must include a special character',
}),
```

The transferable form (`rule.toString()` + `description` + `errorMessage`) flows through `getTransferablePolicies()` → `ctx.password.policies` → `AsPasswordRules.policies` → `compileFieldFn(rule)` at runtime.

---

## 11. Manual walkthrough — OTP disclosure + audit (Phase 3)

**Boot:** same as section 9.

1. Browse to `http://localhost:3001/wf?id=auth/login/flow&variant=enrollment`.
2. Sign in as `t1_alice` / `Password1!`.
3. Workflow enters phone-enrolment first: **`AskPhoneForm`** renders with the generic disclosure paragraph below the phone input:
   > "By providing your phone number, you consent to receive one-time security codes from us via SMS. Message and data rates may apply."
4. Submit a phone number (e.g. `+15555550199`). `PincodeForm` pauses — read SMS code from dev console (`[demo SMS] login.pincode +15555550199 code=…`).
5. Submit the code → `recordOtpChannelConsent` hook fires server-side AFTER `confirmMfaMethod` flips the row to `confirmed:true`.
6. Inspect: `curl http://localhost:3001/__test/otp-consent-log/t1_alice` → `[{channel:'sms', target:'+15555550199', disclosure:'By providing your phone number…', at:…}]`. **Protocol mapping pinned** — the SPA's `'phone'` route-param maps to the persisted `'sms'` channel (carrier-aggregator audit APIs key by protocol).
7. Workflow continues to email enrolment with the email-channel disclosure variant.

**Customising the disclosure copy:** subclass `LoginWorkflow` and override `resolveOtpDisclosure(ctx, channel)` — see [`packages/auth-moost/CLAUDE.md`](../../packages/auth-moost/CLAUDE.md) §"OTP-channel disclosure".
