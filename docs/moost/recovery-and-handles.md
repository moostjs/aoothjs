# Phone login, recovery channels & handle promotion

Make a phone number a first-class credential — log in with it, recover an account through it, and have a freshly-confirmed channel become a login handle automatically. Three independent, opt-in capabilities, all layered on `AuthWorkflow` extension seams:

| Capability                                        | What it does                                                                                     | Seam                                                                                                  |
| ------------------------------------------------- | ------------------------------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------- |
| **Log in by phone**                               | A phone resolves the account the same way a username does                                        | model annotation only — no code                                                                       |
| **Recover by SMS (M1)**                           | The recovery OTP goes to the identifier the user _typed_ (email or phone)                        | [`resolveRecoveryChannel`](#recovery-channel-m1)                                                      |
| **Recover via a registered channel (M2)**         | The user types only an identifier; the OTP goes to a channel _already verified on the row_       | [`resolveRecoveryDeliverySource`](#registered-channel-recovery-m2) + `selectRecoveryRegisteredMethod` |
| **Promote a confirmed channel to a login handle** | After a user confirms an email/SMS factor, write the verified value into the login-handle column | [`resolvePromoteHandleField`](#promote-a-confirmed-channel-to-a-handle)                               |

This page is the integrator guide for those four seams. The recovery flow's overall shape (identifier → OTP → new password) lives in [Workflows — Recovery](./workflows#recovery-auth-recovery-flow); full signatures in the [API reference](/api/auth-moost). Login/recovery forms render via [SPA Components](./spa-components).

## Prerequisite — declare the handle on your model

"Handles" are the columns `findByHandle` resolves an account by, in addition to `username`. You name them on your `.as` user model with the `@aooth.user.email` / `@aooth.user.phone` annotations — **each on a column that also carries `@db.index.unique`:**

```ts
// user.as
@db.index.unique 'email_idx'
@aooth.user.email
email?: string

@db.index.unique 'phone_idx'
@aooth.user.phone
phone?: string
```

At boot, `@aooth/arbac-moost`'s plugin reads these annotations once via `getAoothUserHandleSpec(Model)` → `{ emailField, phoneField, handleFields, warnings }`, and wires `handleFields` into the `UserStore`. The annotation namespace is registered by the arbac-moost plugin — see [Atscript Models](./atscript).

::: warning Unique index is mandatory
A handle annotation **without** `@db.index.unique` is **warned-and-disabled**: `getAoothUserHandleSpec` pushes a `warning`, the field is dropped from `handleFields`, and that channel silently won't resolve logins or get promoted. A login handle must be unique or two accounts could claim the same phone. Check `spec.warnings` at boot if a handle "isn't working".
:::

## Log in by phone

No workflow change is required. `UserStore.findByHandle(value)` tries `username` first, then each configured `handleField` (email, then phone) — so once `phone` is an annotated, unique handle, a user types their phone into the **same** login `username` field and the account resolves. The login workflow, password check, MFA, and token issuance are all identical.

```ts
// the user types "+15555550101" into the LoginCredentialsForm `username` field
// findByHandle: username miss → email miss → phone hit → account resolved
```

- **DO** keep `username` as the form field name — the handle lookup is value-based, not field-based; there is no separate "phone" input.
- **DON'T** expect a non-unique phone to resolve — see the warning above.

## Recovery channel (M1)

In the default recovery model the OTP is delivered to **the identifier the user typed** — identifier _is_ the destination, so there is no cross-account redirect. `resolveRecoveryChannel(ctx)` only decides the _transport_ for that typed value:

```ts
protected resolveRecoveryChannel(_ctx: AuthWfCtx): "email" | "sms" | Promise<"email" | "sms"> {
  return "email"; // default
}
```

The default is `"email"`. The bundled `EmailIdentifierForm` validates its field as an email, so it only ever yields an email. To accept a phone, swap in a phone-capable identifier form (`opts.forms.recoveryEmailIdentifier`) and override `resolveRecoveryChannel` to pick the transport from the typed value's shape:

```ts
class MyAuth extends AuthWorkflow {
  // route SMS when the typed identifier looks like a phone number
  protected override resolveRecoveryChannel(ctx: AuthWfCtx): "email" | "sms" {
    const identifier = ctx.email ?? "";
    return /^\+?[0-9][0-9\s().-]{6,}$/.test(identifier) ? "sms" : "email";
  }
}
```

`ctx.email` is the typed identifier regardless of transport (the field is historically named `email`). The OTP delivery itself goes through your [`deliver(payload)`](./workflows#outbound-delivery-deliver-payload) override (`payload.kind === "recovery-pincode"`, `payload.channel === "sms" | "email"`).

- **DO** override the identifier form _and_ `resolveRecoveryChannel` together — the form must let a phone through validation before the channel resolver can route it.
- **DON'T** route SMS to an address the user didn't type — in M1 the destination is always `ctx.email`. To deliver to a _registered_ channel instead, use M2 (below).

## Registered-channel recovery (M2)

M2 inverts the trust model: the user submits only an **account identifier** (typically a username), and the OTP is delivered to a channel **already verified on the resolved row** — never to anything they typed. Because the destination comes off the account's own confirmed MFA method, M2 also cannot redirect cross-account, by a different mechanism than M1.

Arm it by overriding `resolveRecoveryDeliverySource` to return `"registered"` (default is `"typed"` = M1):

```ts
class MyAuth extends AuthWorkflow {
  protected override resolveRecoveryDeliverySource(_ctx: AuthWfCtx): "typed" | "registered" {
    return "registered"; // arm M2 (per-tenant: read a flag off ctx)
  }
}
```

The OTP recipient is then chosen by `selectRecoveryRegisteredMethod(user)` — a sync helper that defaults to **SMS-first, then email** ("phone-recovery-first"), skipping TOTP (no deliverable address), unconfirmed methods, and value-less methods:

```ts
// default — override to change the selection policy (e.g. honour mfa.defaultMethod)
protected selectRecoveryRegisteredMethod(user: UserCredentials): MfaMethod | null {
  const methods = user.mfa?.methods ?? [];
  const pick = (kind: "sms" | "email") =>
    methods.find((m) => m.confirmed && !!m.value && this.mfaKindOf(m.name) === kind);
  return pick("sms") ?? pick("email") ?? null;
}
```

::: tip Anti-enumeration is preserved
When the resolved account has **no deliverable confirmed method**, the `request` step emits the **same generic finish envelope** as an unknown identifier and leaves `ctx.subject` unset — so an attacker can't distinguish "no such account" from "account with no recoverable channel". TOTP-only and method-less accounts therefore look identical to unknown ones.
:::

::: warning The request→send race is handled, not thrown
A confirmed method can be deleted between the `request` guard and a later resend. M2 detects this at send time and **degrades to the same generic finish** rather than surfacing a distinguishable `500` — so the race can't be used to enumerate either. (The double row-load — once in `request`, once per send — is deliberate: re-reading is the re-check.)
:::

## Promote a confirmed channel to a handle

When a user confirms an email or SMS factor (login forced-enrolment, invite, or the standalone [add-mfa flow](./workflows#add-mfa-auth-add-mfa-flow)), `promote-to-handle` can copy that **verified** value into the corresponding login-handle column — so a phone proven via OTP immediately becomes a login + recovery handle. It's **off by default**; turn it on by overriding `resolvePromoteHandleField` to return the handle field for the channel:

```ts
import { getAoothUserHandleSpec } from "@aooth/arbac-moost/atscript";

// resolved once at boot from your concrete model's @aooth.user.* annotations
const handles = getAoothUserHandleSpec(MyUserModel);

class MyAuth extends AuthWorkflow {
  protected override resolvePromoteHandleField(
    _ctx: AuthWfCtx,
    channel: "email" | "sms",
  ): string | undefined {
    return channel === "email" ? handles.emailField : handles.phoneField;
  }
}
```

Returning `undefined` (the default) leaves the channel un-promoted. The `promote-to-handle` `@Step` runs once per flow, right after `enroll-confirm`, and only for a freshly-confirmed `email`/`sms` channel (TOTP and skipped enrolments carry no address, so they're never promoted).

::: tip Collisions are best-effort
The handle column is unique-indexed, so promoting a value **another account already owns** is swallowed — that user keeps the factor as MFA-only and the existing owner keeps the handle. Promotion never fails a flow.
:::

Why the override (rather than on by default)? `AuthWorkflow` is generic over the user shape and holds no reference to your _concrete_ annotated model, so it can't resolve the handle field names itself — you thread them in from the boot-resolved `getAoothUserHandleSpec`. See [`project handle resolution`](./atscript) for the annotation surface.

## DOs and DON'Ts

- **DO** put `@db.index.unique` on every `@aooth.user.*` handle column — without it the handle is warned-and-disabled.
- **DO** override the identifier form alongside `resolveRecoveryChannel` for phone recovery (M1) — the form gates which identifiers reach the resolver.
- **DO** prefer **M2** when you don't want the recovery OTP to follow a user-typed address — it pins delivery to a pre-verified channel.
- **DON'T** cache the M2 target on `ctx` — the per-send re-read is the TOCTOU re-check that keeps anti-enumeration intact.
- **DON'T** assume promotion is on — it's an explicit `resolvePromoteHandleField` override; the default is a no-op.

## See also

- [Workflows](./workflows) — the recovery / login / add-mfa flows these seams plug into, the `deliver(payload)` hook, and the full [extension-point catalog](./workflows#extension-point-catalog).
- [Atscript Models](./atscript) — the `@aooth.user.*` annotation namespace + `getAoothUserHandleSpec`.
- [User stores](/user/stores) — `findByHandle` and the `UserStore` handle-field contract.
- [API reference](/api/auth-moost) — `AuthWorkflow`'s override-seam surface; `resolveRecoveryChannel` / `resolveRecoveryDeliverySource` / `resolvePromoteHandleField` and the `selectRecoveryRegisteredMethod` helper are listed in its `resolveXxx` getter set.
