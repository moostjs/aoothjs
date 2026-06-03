# SPA Components

The bundled `AuthWorkflow` forms are **server-driven** atscript types — the server decides which form to render at each pause and ships it as an annotated schema. Your SPA renders them with `<AsWfForm>` from `@atscript/vue-wf` and registers a small set of companion Vue components by name. This page covers the **aooth-side contract**: which component-name strings the bundled forms emit, and how to wire them. The component packages themselves (`@atscript/vue-wf`, `@atscript/vue-aooth`, `@atscript/vue-form`) are documented in the [atscript-ui](https://ui.atscript.dev) docs.

## The contract: `@ui.form.component '<Name>'`

Three bundled form fields carry a `@ui.form.component '<Name>'` annotation naming a Vue component. `<AsForm>` (inside `<AsWfForm>`) resolves that **string** against the `:components` map you pass — so **the string in the `.as` schema MUST match a key in your `:components` map**, or the field falls back to the default renderer.

| Form field                       | `@ui.form.component` | Component (`@atscript/vue-aooth`) | Renders                                                             |
| -------------------------------- | -------------------- | --------------------------------- | ------------------------------------------------------------------- |
| `WithInlineConsentForm.consents` | `AsConsentArray`     | `AsConsentArray`                  | one checkbox per pending consent; self-hides when none pending      |
| `SetPasswordForm.passwordRules`  | `AsPasswordRules`    | `AsPasswordRules`                 | live password-policy fulfillment dots, re-evaluated per keystroke   |
| `EnrollConfirmForm.qrCode`       | `AsQrCode`           | `AsQrCode`                        | scannable TOTP `otpauth://` QR + the base32 secret for manual entry |

All three components come from `@atscript/vue-aooth` (an external SPA package), not from any `@aooth/*` package.

## Minimum wiring

```vue
<script setup lang="ts">
import { AsWfForm, AsWfFinish, type WfFinished } from "@atscript/vue-wf";
import { createDefaultTypes } from "@atscript/vue-form";
import { AsConsentArray, AsPasswordRules, AsQrCode } from "@atscript/vue-aooth";

const types = createDefaultTypes();
// Keys here MUST match the `@ui.form.component '<Name>'` strings in the bundled forms.
const components = { AsConsentArray, AsPasswordRules, AsQrCode };
</script>

<template>
  <AsWfForm
    path="/auth/trigger"
    name="auth/login/flow"
    :types="types"
    :components="components"
    :navigate="navigate"
    @finished="onFinished"
    @error="onError"
  />
</template>
```

- **`path`** — the `/auth/trigger` endpoint (the `AuthController` route the workflow runs behind).
- **`name`** — the workflow id to start: `auth/login/flow`, `auth/invite/start`, or `auth/recovery/flow`.
- **`:types`** — the built-in field renderers from `@atscript/vue-form`.
- **`:components`** — the aooth companion components, keyed by the names the forms emit.

## `AsQrCode` — TOTP enrollment {#asqrcode-totp-enrollment}

During MFA enrollment, the `EnrollConfirmForm.qrCode` field carries the `otpauth://` provisioning URI (built from the secret + your `totpIssuer` opt) and `@ui.form.component 'AsQrCode'`. `AsQrCode` renders it as a scannable SVG **and** extracts the base32 secret from the URI to show for manual entry (its `manualSecret` prop defaults on) — so there is no separate "manual secret" field. The user scans/enters it in their authenticator, then submits the 6-digit code, which the server verifies via `UserService.verifyTotpSetupCode`.

`AsQrCode` has an optional peer dependency on `qrcode` for the SVG render — install it in the SPA if you want the visual QR (without it, the manual secret still renders).

## `AsConsentArray` — pending consents

When `ConsentStore.getPendingConsents(subject)` returns descriptors (the arg is the stable user id), the workflow transports them (via `@wf.context.pass`) to whichever form the user is currently on, and the inline `consents: string[]` field renders one checkbox per descriptor through `AsConsentArray`. The field **self-hides** when nothing is pending — no `@ui.form.fn.hidden` needed. Submitted ids are validated server-side against the pending set (the authoritative whitelist). See [Workflows — consent collection](./workflows#consent-collection).

## `AsPasswordRules` — live policy readout

On `SetPasswordForm`, the phantom `passwordRules` field renders fulfillment dots that re-evaluate on every keystroke against `data.newPassword`, using the **same transferable policy expressions** the server enforces (shipped to the client via `UserService.getTransferablePolicies()`). See [Password Policies](/user/policy).

## Magic-link resume — `initialToken`

`auth/recovery/flow` and `auth/invite/start` finish their first leg by emailing a URL carrying a `wfs=<token>` (and, for invites, a `uid=<userId>`). Route that into your workflow page and pass it as `:initial-token` so `<AsWfForm>` resumes the paused state instead of starting fresh:

```vue
<AsWfForm path="/auth/trigger" :name="wfId" :initial-token="initialToken" ... />
```

For a re-clicked invite link whose state row has already been evicted, fall through to `GET /auth/invite/post-redemption?uid=<userId>` and hand the returned `WfFinished` to `<AsWfFinish>` for envelope-shape parity. See [REST Controllers — post-redemption](./controllers#get-auth-invite-post-redemption).

## Custom config per request — variant headers

To pick a server-side workflow preset per request, send a custom header via `:fetch-options` and re-key the form so it remounts when the choice changes:

```ts
const fetchOptions = computed(() =>
  variant.value ? { headers: { "x-wf-variant": variant.value } } : undefined,
);
```

The server reads the header in its `AuthWorkflow` subclass (e.g. in an `@Injectable("FOR_EVENT")` constructor) to merge a variant config. Reference: [`packages/e2e-demo/src/ui/pages/WfPage.vue`](https://github.com/moostjs/aoothjs/blob/main/packages/e2e-demo/src/ui/pages/WfPage.vue).

## Replacing a bundled form keeps the component string

If you swap a bundled form via `opts.forms.<slot>` (typically `extends` the bundled one), keep the `@ui.form.component '<Name>'` annotation on the field if you want the companion widget — the `:components` registration is keyed on the **string**, not the form class.

## See also

- [Workflows](./workflows) — the server side that emits these forms.
- [Atscript Models](./atscript) — the bundled form catalogue + their annotations.
- [atscript-ui docs](https://ui.atscript.dev) — `<AsWfForm>`, `<AsWfFinish>`, and the `@atscript/vue-aooth` component APIs.
