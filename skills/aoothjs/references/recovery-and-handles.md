# Phone login, recovery channels & handle promotion (auth-moost)

Four opt-in `AuthWorkflow` seams that make a phone a first-class credential: log in by phone, choose the recovery OTP transport/destination, and auto-promote a confirmed channel into a login handle. All layered on the unified `AuthWorkflow` — see [workflows.md](workflows.md).

## Quick start — declare handles, then override the seams

```ts
// user.as — a handle column MUST carry @db.index.unique or it's warned-and-disabled
@db.index.unique 'phone_idx'
@aooth.user.phone
phone?: string          // now resolves at login + recovery via findByHandle

// subclass
import { getAoothUserHandleSpec } from "@aooth/arbac-moost/atscript";
const handles = getAoothUserHandleSpec(MyUserModel);   // boot-resolved once

class MyAuth extends AuthWorkflow {
  // M1: pick OTP transport for the TYPED identifier (address is always ctx.email)
  protected override resolveRecoveryChannel(ctx: AuthWfCtx): "email" | "sms" {
    return /^\+?[0-9][0-9\s().-]{6,}$/.test(ctx.email ?? "") ? "sms" : "email";
  }
  // M2: deliver to a channel already verified on the row (never to typed input)
  protected override resolveRecoveryDeliverySource(_ctx: AuthWfCtx): "typed" | "registered" {
    return "registered";
  }
  // promote a confirmed email/sms factor into its login-handle column
  protected override resolvePromoteHandleField(_ctx: AuthWfCtx, channel: "email" | "sms") {
    return channel === "email" ? handles.emailField : handles.phoneField;
  }
}
```

## Invariants

| #   | Rule                                                                                                                                                                                                                                                                                                                                                                                                 |
| --- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1   | **Login by phone needs NO code** — just `@aooth.user.phone` (+ `@db.index.unique`) on the model. `findByHandle` tries `username` then each handle field; the user types the phone into the **same** `username` field (lookup is value-based, not a separate input).                                                                                                                                  |
| 2   | **A handle annotation WITHOUT `@db.index.unique` is warned-and-disabled.** `getAoothUserHandleSpec(Model)` → `{ emailField, phoneField, handleFields, warnings }` drops it from `handleFields` and pushes a `warning`; that channel silently won't resolve logins or get promoted. Check `spec.warnings` at boot.                                                                                    |
| 3   | **M1 (`resolveRecoveryChannel`, default `"email"`) only picks the TRANSPORT** — the destination is always the typed identifier (`ctx.email`), so identifier == destination, no cross-account redirect. To accept a phone you MUST also swap `opts.forms.recoveryEmailIdentifier` for a phone-capable form (the bundled `EmailIdentifierForm` rejects non-emails).                                    |
| 4   | **M2 (`resolveRecoveryDeliverySource` → `"registered"`) delivers to a confirmed method ON THE ROW**, chosen by `selectRecoveryRegisteredMethod(user)` (sync helper, default SMS-first then email; skips TOTP / unconfirmed / value-less). Destination never comes from user input → can't redirect cross-account. Override the helper to change the pick (e.g. honour `mfa.defaultMethod`).          |
| 5   | **M2 preserves anti-enumeration.** No deliverable method → `request` emits the SAME generic finish as an unknown identifier and leaves `ctx.subject` unset. TOTP-only / method-less accounts are indistinguishable from unknown ones.                                                                                                                                                                |
| 6   | **M2 request→send TOCTOU is handled, not thrown.** A method deleted between the `request` guard and a resend → `RecoveryMethodUnavailableError` → `pincode-send` degrades to the generic finish (sets `ctx.aborted`; `pincode-check` is gated `!ctx.aborted`), never a distinguishable 500. The double row-load (request + each send) is the deliberate re-check — do NOT cache the target on `ctx`. |
| 7   | **`resolvePromoteHandleField(ctx, channel)` is OFF by default** (returns `undefined`). Override → return the handle field name for the channel. The `promote-to-handle` `@Step` runs once per flow after `enroll-confirm`, only for a freshly-confirmed `email`/`sms` channel (TOTP / skipped enrolments carry no address). Fires for login forced-enrol, invite, AND add-mfa.                       |
| 8   | **Promotion collisions are best-effort.** The handle column is unique-indexed; promoting a value another account owns is swallowed (that user stays MFA-only, the owner keeps the handle). Promotion never fails a flow.                                                                                                                                                                             |
| 9   | **Why override (not on-by-default)?** `AuthWorkflow` is generic over the user shape and holds no reference to the concrete annotated model — it can't resolve handle field names itself. Thread them in from the boot-resolved `getAoothUserHandleSpec`.                                                                                                                                             |

## Key imports

```ts
import { getAoothUserHandleSpec, type AoothUserHandleSpec } from "@aooth/arbac-moost/atscript";
// resolveRecoveryChannel / resolveRecoveryDeliverySource / selectRecoveryRegisteredMethod /
// resolvePromoteHandleField are protected methods on AuthWorkflow (@aooth/auth-moost) — override, not import.
```

## See also

- [workflows.md](workflows.md) — the recovery / login / add-mfa flows + `deliver(payload)` + the full extension-point set.
- [mfa.md](mfa.md) — TOTP / MFA-code primitives the enrolled methods are built on.
- Docs: https://aoothjs.dev/moost/recovery-and-handles — Phone, recovery channels & handle promotion.
