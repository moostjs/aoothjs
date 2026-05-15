# WF_LOGIN — login workflow design

Sibling of [WF.md](WF.md). This file documents the goal, the supported MFA channels, the full step catalog, the alt-action catalog, and the `LoginWorkflowOptions` shape for the redesigned `LoginWorkflow`.

---

## Goal

A comprehensive, opt-in-feature login flow. Defaults give a sane out-of-the-box experience; consumers turn on advanced features (channel enrollment, device trust, MFA enroll-required, terms acceptance, tenant/persona selection, risk step-up, etc.) by replacing the `LoginWorkflowOptions` provider entry — no subclassing required for the common cases.

Workflow id: `auth.login`.

---

## Supported MFA / 2FA transports

Three first-class second-factor mechanisms:

| Transport                            | Code source                                                                                         | Verification                                                                              | Rate limit                                                           |
| ------------------------------------ | --------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------- | -------------------------------------------------------------------- |
| **OTP via SMS**                      | Server-generated 6-digit pincode, sent via SMS gateway (consumer-supplied `SmsSender`)              | Server-side comparison against `ctx.pin` with `pinExpire` window                          | `pinTimeout` blocks resend for 60s                                   |
| **OTP via Email**                    | Server-generated 6-digit pincode, sent via `EmailSender`                                            | Same                                                                                      | Same                                                                 |
| **OTP via Authenticator App (TOTP)** | Client-side, RFC 6238 (Google Authenticator / 1Password / Authy) using user's enrolled `totpSecret` | `verifyTotpCode(secret, code)` — no `ctx.pin` storage; no resend (codes rotate every 30s) | None (rate-limit handled by `UserService.verifyMfa` lockout counter) |

The MFA selection step (`select2fa`) lists only methods the user has enrolled. If a user has all three, they pick at runtime; if only one, it's auto-selected. Backup codes are an alt-action escape hatch usable from any of the three.

Channel enrollment (collecting an email or phone number for a user who doesn't have one yet) flows into `set-mfa/<transport>` + `pincode/send/activate` + `pincode/confirm` to verify the channel works before treating it as enrolled.

### Per-transport configurability

Two options govern this independently:

```ts
mfaEnabled = true; // master switch
mfaTransports: Array<"sms" | "email" | "totp"> = ["sms", "email", "totp"];
```

Combinations:

| Goal                                               | Setting                                                                                              |
| -------------------------------------------------- | ---------------------------------------------------------------------------------------------------- |
| MFA off entirely (login flow has no second factor) | `mfaEnabled: false` (transports list ignored)                                                        |
| All three transports enabled                       | `mfaTransports: ['sms', 'email', 'totp']` (default)                                                  |
| Email-only OTP                                     | `mfaTransports: ['email']`                                                                           |
| SMS-only OTP                                       | `mfaTransports: ['sms']`                                                                             |
| Authenticator-app only                             | `mfaTransports: ['totp']`                                                                            |
| Email + TOTP, no SMS                               | `mfaTransports: ['email', 'totp']`                                                                   |
| Disable a transport at runtime by user role        | subclass `LoginWorkflow` and override the constructor / `prepare-mfa-options` step to filter further |

Effects of `mfaTransports`:

- **`prepare-mfa-options`** filters the user's enrolled methods to only those whose `kind` is in the list.
- **`select2fa`** is auto-skipped if the filtered list has 0 or 1 entries (auto-pick or no-op).
- **`mfa-enroll-required`** (when `opts.mfaEnrollRequired = true`) only offers transports in the list.
- **Boot-time validation:** if `'sms'` is in the list but no `SmsSender` is registered in DI, the workflow constructor throws — fail loud, not at first user attempt.

Disabling MFA entirely (`mfaEnabled: false`) skips the entire Phase 4 block (steps 5–11) regardless of `mfaTransports`.

---

## `LoginWorkflowOptions` — full shape

```ts
import type { Injectable } from "moost";

export type LoginRedirect = "referer" | "home" | ((ctx: LoginWfCtx) => string);

@Injectable()
export class LoginWorkflowOptions {
  // ── Phase 1: alt actions on the credentials form ──────────────────────────
  forgotPasswordAction = true; // default: ON
  signupAction = false;
  magicLinkAction = false;
  ssoActions: Array<{ id: string; label: string; url: string }> = [];
  // Passwordless magic-link login (alternate credential path INSIDE this workflow):
  magicLinkSkipsMfa = false; // when true, successful magic-link verify bypasses Phase 4
  magicLinkTtlMs = 30 * 60_000; // 30 min link validity
  recoveryUrl = "/recover"; // where forgotPassword navigates
  recoveryUrlBuilder?: (username?: string) => string;
  // Optional builder. When provided, takes precedence over `recoveryUrl`. Receives whatever the
  // user typed in the username field on the login form so the recovery page can pre-fill it.
  // Default builder when this is undefined: `${recoveryUrl}?username=${encodeURIComponent(username ?? '')}`
  signupUrl = "/signup"; // where signup navigates
  embedRecovery = false; // advanced: inline recovery in this flow instead of redirect

  // ── Phase 2: account-state guards ────────────────────────────────────────
  emailVerifiedRequired = false; // force email enrollment+verify if user has none
  passwordExpiryGuard = true; // honor PasswordPolicy.expiryDays
  passwordInitialGuard = true; // force change when password.isInitial

  // ── Phase 3: channel-enrollment loops ────────────────────────────────────
  ensureEmail = false; // loop until email captured + verified
  ensurePhone = false; // loop until phone captured + verified

  // ── Phase 4: MFA challenge ───────────────────────────────────────────────
  mfaEnabled = true; // master switch
  mfaTransports: Array<"sms" | "email" | "totp"> = ["sms", "email", "totp"];
  mfaBackupCodes = true; // alt-action escape hatch
  mfaEnrollRequired = false; // policy: MFA mandatory; force enroll if user has none
  pincodeTtlMs = 5 * 60_000; // 5 min
  pincodeResendTimeoutMs = 60_000; // resend gated 60s

  // Device trust — "remember this device, skip OTP/MFA next time"
  deviceTrust = false; // master switch
  deviceTrustOptIn = true; // if true: show "Remember this device" checkbox on the OTP/MFA form,
  //   user opts in per login. If false: silently trust every device (not recommended).
  deviceTrustCookieName = "aooth_trusted_device";
  deviceTrustTtlMs = 24 * 60 * 60_000; // default 24h ("the next day or so"); typical alternative: 30 days
  deviceTrustSkipsMfa = true; // when a valid trust cookie is present, skip Phase 4 entirely
  deviceTrustBindsTo: "cookie" | "cookie+ip" = "cookie"; // 'cookie+ip' rebinds on IP change (more secure, more friction)

  // ── Phase 5: forced password change ──────────────────────────────────────
  // (no opts — driven by passwordExpiryGuard / passwordInitialGuard from Phase 2)

  // ── Phase 6: acceptance & onboarding ─────────────────────────────────────
  termsAcceptVersion?: string; // when set, force acceptance if user.termsVersion !== this
  profileCompleteRequired = false;
  consentMarketing = false;

  // ── Phase 7: tenant / persona ────────────────────────────────────────────
  tenantSelect = false;
  personaSelect = false;

  // ── Phase 8: session policy ──────────────────────────────────────────────
  concurrencyLimit?: { max: number; onLimit: "reject" | "kickPrompt" };
  riskStepUp?: (ctx: LoginWfCtx) => Promise<{ require: boolean; reason?: string }>;

  // ── Phase 9: finalize ────────────────────────────────────────────────────
  auditLogin = true; // emit login.success event
  notifyNewDevice = false; // "new sign-in from X" email
  redirect: LoginRedirect = "referer";

  constructor(opts: Partial<LoginWorkflowOptions> = {}) {
    Object.assign(this, opts);
  }
}
```

---

## Workflow context shape

```ts
export interface LoginWfCtx {
  // Populated by the implicit `init` step:
  opts: LoginWorkflowOptions;

  // Populated by `credentials`:
  username?: string;
  isPasswordInitial?: boolean;

  // Channel state (populated by ensureEmail / ensurePhone loops):
  email?: string;
  emailConfirmed?: boolean;
  phone?: string;
  phoneConfirmed?: boolean;

  // MFA state:
  mfaEnrolledMethods?: Array<{
    kind: "sms" | "email" | "totp";
    masked: string;
    isDefault: boolean;
  }>;
  mfaMethod?: "sms" | "email" | "totp";
  mfaSaveAsDefault?: boolean;
  ignoreMfaDefault?: boolean; // set when user clicked "use different method"
  mfaChecked?: boolean;

  // Pincode state (sms/email only — TOTP is stateless):
  pin?: string;
  pinExpire?: number;
  pinTimeout?: number;
  pincodeForm?: { title: string; description: string; state: string }; // for masked-recipient UI

  // Device trust:
  deviceTrustToken?: string; // set when "remember this device" cookie validated
  newDevice?: boolean;

  // Terms / profile:
  termsAcceptedVersion?: string;
  profileMissingFields?: string[];

  // Tenant / persona:
  availableTenants?: Array<{ id: string; name: string }>;
  selectedTenantId?: string;
  availablePersonas?: Array<{ id: string; label: string }>;
  selectedPersonaId?: string;

  // Session policy:
  riskStepUpReason?: string;
  activeSessions?: number; // for concurrencyLimit kickPrompt
}
```

---

## Step catalog

Each step has: id, default state (ON / OFF / inline), the option flag(s) gating it, and notes. Order is the linear flow; conditional steps skip via `condition` callbacks reading `ctx.opts`.

### Phase 1 — Identification & credentials

Per-run, exactly one credential path fires. Default = password (`credentials`). Alternates are branches inside the SAME `auth.login` workflow (NOT separate workflows) — they pause after sending an email/redirect and resume the same workflow at the verification step. Same resume-from-magic-link primitive recovery + invite use.

| #   | Step id             | Default           | Gated by                                                                    | Notes                                                                                                                                                                        |
| --- | ------------------- | ----------------- | --------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1   | `init`              | ON (always)       | —                                                                           | Implicit step; copies `this.opts` into `ctx.opts`                                                                                                                            |
| 2a  | `credentials`       | ON (default path) | —                                                                           | Username + password form. Alt actions: `forgotPassword`, `signup`, `magicLink` (branches into 2b–2d inside this same workflow), `ssoCallback`                                |
| 2b  | `magicLinkRequest`  | OFF               | user picked `magicLink` alt-action OR `opts.credentialMode === 'magicLink'` | Form: email/username only (no password). Resolves to a username; anti-enumeration on unknown identifiers (generic "if an account exists, you'll receive an email" response). |
| 2c  | `magicLinkSend`     | conditional       | 2b succeeded                                                                | Emits `outletEmail(...)` ONCE with a `wfs` resume token; pauses workflow with "check your email" finished state.                                                             |
| 2d  | `magicLinkVerified` | conditional       | resumed from clicked link                                                   | Sets `ctx.usedMagicLink = true` and `ctx.username` from the token. Continues into the rest of the flow.                                                                      |
| 2e  | `passkey`           | OFF               | user picked passkey method                                                  | WebAuthn assertion in lieu of password. On success sets `ctx.username`.                                                                                                      |
| 2f  | `ssoCallback`       | OFF               | OAuth/OIDC callback hit                                                     | Consumer-supplied handler resolves the IdP response → sets `ctx.username`.                                                                                                   |

**`opts.magicLinkSkipsMfa: boolean` (default `false`)** — when `true`, successful magic-link verification (`ctx.usedMagicLink === true`) bypasses Phase 4. When `false` (default), MFA still runs because email possession alone isn't typically considered a strong second factor.

### Phase 2 — Account-state guards (auto-eval after credentials)

These don't get their own step; they're checked inline at the end of `credentials` and set ctx flags that condition later steps. Documented for completeness.

| Check             | Behavior                                                                             |
| ----------------- | ------------------------------------------------------------------------------------ |
| Locked            | Throw `HttpError(423, 'Account locked')` immediately                                 |
| Inactive          | Form-error: "Invalid credentials" (no enumeration)                                   |
| `passwordInitial` | Sets `ctx.isPasswordInitial = true` → triggers Phase 5                               |
| `passwordExpired` | Sets `ctx.isPasswordInitial = true` (same step path) when `opts.passwordExpiryGuard` |

### Phase 3 — Channel-enrollment loops

| #   | Step id              | Default | Gated by                                           | Notes                                                                                                                               |
| --- | -------------------- | ------- | -------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------- |
| 3   | `ensureEmail` (loop) | OFF     | `opts.ensureEmail \|\| opts.emailVerifiedRequired` | `while: !ctx.email \|\| !ctx.emailConfirmed`. Inner steps: `ask-email`, `set-mfa/email`, `pincode/send/activate`, `pincode/confirm` |
| 4   | `ensurePhone` (loop) | OFF     | `opts.ensurePhone`                                 | Same shape, SMS transport                                                                                                           |

### Phase 4 — MFA challenge

| #   | Step id                | Default        | Gated by                                                                                                | Notes                                                                                                                                                                                                                                                                                                                                   |
| --- | ---------------------- | -------------- | ------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 5   | `prepare-mfa-options`  | ON             | `opts.mfaEnabled && user has enrolled methods`                                                          | Loads enrolled methods (filtered by `opts.mfaTransports`), masks recipient, auto-picks default unless `ctx.ignoreMfaDefault`                                                                                                                                                                                                            |
| 6   | `select2fa`            | conditional    | `ctx.mfaEnrolledMethods.length > 1 && !ctx.mfaMethod`                                                   | Form: pick method + "save as default". Alt actions: `useBackupCode`, `useDifferentMethod` (sets `ignoreMfaDefault`)                                                                                                                                                                                                                     |
| 7   | `pincode-send-login`   | conditional    | `ctx.mfaMethod === 'sms' \|\| ctx.mfaMethod === 'email'`                                                | Generate pin, send via SMS or Email, set `pinExpire` + `pinTimeout`. Skipped for `totp`                                                                                                                                                                                                                                                 |
| 8   | `pincode-check-login`  | conditional    | same                                                                                                    | Verify pin code. Alt actions: `resend` (gated by `pinTimeout`), `useDifferentMethod`, `useBackupCode`                                                                                                                                                                                                                                   |
| 8   | `mfa-totp`             | conditional    | `ctx.mfaMethod === 'totp'`                                                                              | TOTP code form, calls `verifyTotpCode(secret, input.code)`. Alt actions: `useBackupCode`, `useDifferentMethod`                                                                                                                                                                                                                          |
| 9   | `mfa-backup-code`      | OFF (alt-only) | `opts.mfaBackupCodes && user clicked alt`                                                               | Verify a backup code via `consumeBackupCode`                                                                                                                                                                                                                                                                                            |
| 10  | `mfa-enroll-required`  | OFF            | `opts.mfaEnrollRequired && user has zero methods`                                                       | In-flow TOTP enroll: secret-issue → QR display → confirm code. Reuses `ensureEmail`/`ensurePhone` if user picks a channel-MFA                                                                                                                                                                                                           |
| 4.5 | `check-trusted-device` | conditional    | `opts.deviceTrust && opts.deviceTrustSkipsMfa`                                                          | Inline check at the start of Phase 4: if a valid `deviceTrustCookieName` cookie matches an entry in `DeviceTrustStore` for `ctx.username` (and IP if `deviceTrustBindsTo: 'cookie+ip'`), set `ctx.mfaChecked = true` so steps 5–8 are all skipped via their conditions. Cookie HMAC-signed with userId+issuedAt; verified in this step. |
| 11  | `device-trust`         | OFF            | `opts.deviceTrust && ctx.newDevice && (!opts.deviceTrustOptIn OR user checked the box on the MFA form)` | After successful MFA: persist the trust record in `DeviceTrustStore` and write the cookie (`deviceTrustTtlMs` lifetime). When `opts.deviceTrustOptIn`, the "Remember this device" checkbox lives on the OTP/MFA form (not a separate step) — this step just persists if the user checked it.                                            |

### Phase 5 — Forced password change

| #   | Step id                  | Default     | Gated by                | Notes                                                                   |
| --- | ------------------------ | ----------- | ----------------------- | ----------------------------------------------------------------------- |
| 12  | `prepare-password-rules` | conditional | `ctx.isPasswordInitial` | Loads `getTransferablePolicies()` into ctx for the form to render rules |
| 13  | `create-password-form`   | conditional | same                    | Form: new password + confirm. Alt action: `logout`                      |

### Phase 6 — Acceptance / onboarding

| #   | Step id             | Default | Gated by                                                                   | Notes                                                      |
| --- | ------------------- | ------- | -------------------------------------------------------------------------- | ---------------------------------------------------------- |
| 14  | `terms-accept`      | OFF     | `opts.termsAcceptVersion && user.termsVersion !== opts.termsAcceptVersion` | Form: T&C content + accept checkbox. Alt action: `decline` |
| 15  | `profile-complete`  | OFF     | `opts.profileCompleteRequired && ctx.profileMissingFields.length`          | Form: missing required fields                              |
| 16  | `consent-marketing` | OFF     | `opts.consentMarketing`                                                    | Optional opt-in form                                       |

### Phase 7 — Tenant / persona

| #   | Step id          | Default | Gated by                                                 | Notes                                                           |
| --- | ---------------- | ------- | -------------------------------------------------------- | --------------------------------------------------------------- |
| 17  | `tenant-select`  | OFF     | `opts.tenantSelect && ctx.availableTenants.length > 1`   | Form: pick tenant. Sets `ctx.selectedTenantId` for token claims |
| 18  | `persona-select` | OFF     | `opts.personaSelect && ctx.availablePersonas.length > 1` | Form: pick persona                                              |

### Phase 8 — Session policy

| #   | Step id             | Default | Gated by                                             | Notes                                                                      |
| --- | ------------------- | ------- | ---------------------------------------------------- | -------------------------------------------------------------------------- |
| 19  | `concurrency-limit` | OFF     | `opts.concurrencyLimit && ctx.activeSessions >= max` | If `onLimit: 'kickPrompt'`, form: choose to log out other devices          |
| 20  | `risk-step-up`      | OFF     | `opts.riskStepUp returned require: true`             | Triggers an additional pincode-send/check via the user's preferred channel |

### Phase 9 — Finalize

| #   | Step id             | Default | Gated by                                | Notes                                                                                 |
| --- | ------------------- | ------- | --------------------------------------- | ------------------------------------------------------------------------------------- |
| 21  | `issue`             | ON      | —                                       | Mint access + refresh tokens, write cookies (today's `issue` step)                    |
| 22  | `audit-login`       | ON      | `opts.auditLogin`                       | Emit `login.success` event with user + method + IP + tenantId                         |
| 23  | `notify-new-device` | OFF     | `opts.notifyNewDevice && ctx.newDevice` | Send "new sign-in from X" email via `EmailSender`                                     |
| 24  | `redirect`          | ON      | —                                       | Compute redirect URL via `opts.redirect`; finishes with `{ type: 'redirect', value }` |

---

## Alt-action catalog

| Form                             | Alt action key       | Default                     | Behavior                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| -------------------------------- | -------------------- | --------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `credentials`                    | `forgotPassword`     | ON                          | `useWfFinished().set({ type: 'redirect', value: opts.recoveryUrl + '?username=' + encodeURIComponent(input.username ?? '') })` — carries any username the user already typed into the login form so the recovery page can pre-fill it (saves the user from typing it twice). When `embedRecovery: true`, branches inline and copies `ctx.username = input.username` into the recovery flow's ctx directly. URL-template is configurable via `opts.recoveryUrlBuilder?: (username?: string) => string` for apps that want a different shape (e.g. `#/recover?u=...` for hash-routed SPAs). |
| `credentials`                    | `signup`             | OFF                         | Redirect to `opts.signupUrl`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| `credentials`                    | `magicLink`          | OFF                         | Branches inside the SAME `auth.login` workflow into Phase 2's `magicLinkRequest` → `magicLinkSend` → pause → resume at `magicLinkVerified`. Not a separate workflow — same resume-from-magic-link primitive used by recovery + invite.                                                                                                                                                                                                                                                                                                                                                    |
| `credentials`                    | `ssoCallback`        | per-provider                | List from `opts.ssoActions[]`; each is a redirect to the provider's URL                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| `select2fa`                      | `useBackupCode`      | ON if `opts.mfaBackupCodes` | Branch to `mfa-backup-code` step                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| `pincode-check-login`            | `resend`             | ON                          | Re-runs `pincode-send-login`; **gated** by `pinTimeout` (returns form error "wait Ns")                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| `pincode-check-login`            | `useDifferentMethod` | ON if user has >1 method    | Sets `ctx.ignoreMfaDefault = true; ctx.mfaMethod = undefined` → loops back to `select2fa`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| `pincode-check-login`            | `useBackupCode`      | ON if `opts.mfaBackupCodes` | Branch to `mfa-backup-code`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| `mfa-totp`                       | `useDifferentMethod` | ON if user has >1 method    | Same as above                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| `mfa-totp`                       | `useBackupCode`      | ON if `opts.mfaBackupCodes` | Branch to `mfa-backup-code`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| `create-password-form`           | `logout`             | ON                          | Aborts workflow; clears any partial session state                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| `terms-accept`                   | `decline`            | ON                          | Aborts workflow with friendly "you must accept to continue" message                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| `concurrency-limit` (kickPrompt) | `cancel`             | ON                          | Aborts with "session limit reached"                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |

---

## Constructor DI dependencies

```ts
@Injectable("FOR_EVENT")
@Controller()
@Public()
export class LoginWorkflow {
  constructor(
    private opts: LoginWorkflowOptions, // user-provided via DI
    private users: UserService, // mutating user lifecycle
    private auth: AuthCredential, // token issue
    private authConfig: MoostAuthConfig, // cookie attrs
    private mailer: EmailSender, // for email pincodes + notifyNewDevice
    private smsSender?: SmsSender, // optional; required if 'sms' in opts.mfaTransports
    private clock?: Clock, // for pincode TTL + token issue (test seam)
  ) {}
}
```

`SmsSender` is a new interface (mirrors `EmailSender`):

```ts
export interface SmsSender {
  send(event: {
    kind: "login.pincode" | "recovery.pincode" | "invite.pincode";
    recipient: string; // E.164 phone number
    code: string;
    ttlMs: number;
    userId?: string;
  }): Promise<void>;
}
```

Library does not ship a concrete SMS implementation (Twilio / SNS / etc. are consumer-specific) — only the interface. Consumers register their adapter via `setProvideRegistry([SmsSender, () => myTwilioSender])`. If `opts.mfaTransports` includes `'sms'` and no `SmsSender` is registered, `LoginWorkflow` constructor throws at boot.

---

## Tasks (login-specific, on top of WF.md common refactor)

1. **Define `LoginWorkflowOptions`** with the full shape above + defaults.
2. **Define `SmsSender` interface** + `EmailSender` `send(...)` discriminator union extension for new event kinds (`login.pincode`, `recovery.pincode`, `invite.pincode`, `notifyNewDevice`).
3. **Refactor `LoginWorkflow` constructor** to use DI for all deps.
4. **Implement step catalog** — 24 steps total, most gated by opts. Reuse the same atscript form models where possible; add new ones for the new forms (`Select2faForm`, `PincodeForm`, `AskEmailForm`, `AskPhoneForm`, `TermsAcceptForm`, `TenantSelectForm`, `PersonaSelectForm`, `ConcurrencyLimitForm`, etc.).
5. **Implement alt-action handling** — `@AltAction()` resolver on every form-bearing step; routing per the catalog above.
6. **Tests** —
   - Default opts: today's 3-step flow still works (credentials → mfa-totp → issue)
   - Each opt ON: feature path works
   - Each alt action: routing works
   - Locked/inactive/initial-password edge cases
   - SMS transport with mock `SmsSender`
   - Backup code via alt action from each of `select2fa` / `pincode-check-login` / `mfa-totp`
7. **e2e demo** — pick a representative subset (e.g. enable `mfaTransports: ['email', 'totp']`, `forgotPasswordAction: true`, `passwordInitialGuard: true`) and add Playwright coverage.
