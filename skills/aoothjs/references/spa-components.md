# SPA Components (rendering workflow forms)

The bundled `AuthWorkflow` forms are server-driven atscript types. The SPA renders them with `<AsWfForm>` (`@atscript/vue-wf`) and registers aooth companion components by NAME. This ref covers the aooth-side contract only; the component packages (`@atscript/vue-wf`, `@atscript/vue-aooth`, `@atscript/vue-form`) are owned by the atscript-ui skills.

## Quick start

```vue
<script setup lang="ts">
import { AsWfForm, AsWfFinish, type WfFinished } from "@atscript/vue-wf";
import { createDefaultTypes } from "@atscript/vue-form";
import { AsConsentArray, AsPasswordRules, AsQrCode, AsSsoProviders } from "@atscript/vue-aooth";

const types = createDefaultTypes();
// keys MUST match the `@ui.form.component '<Name>'` strings in the bundled forms
const components = { AsConsentArray, AsPasswordRules, AsQrCode, AsSsoProviders };
</script>
<template>
  <AsWfForm
    path="/auth/trigger"
    name="auth/login/flow"
    :types="types"
    :components="components"
    :navigate="navigate"
    :initial-token="initialToken"
    @finished="onFinished"
    @error="onError"
  />
</template>
```

## Invariants

| #   | Rule                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| --- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1   | **`@ui.form.component '<Name>'` resolves the string against `:components`.** The map key MUST match the string exactly, or the field falls back to the default renderer.                                                                                                                                                                                                                                                                                                                           |
| 2   | **The four aooth components come from `@atscript/vue-aooth`** (external — NOT an `@aooth/*` package): `AsConsentArray`, `AsPasswordRules`, `AsQrCode`, `AsSsoProviders`. `<AsWfForm>` / `<AsWfFinish>` come from `@atscript/vue-wf`.                                                                                                                                                                                                                                                               |
| 2b  | **`AsSsoProviders`** renders `LoginCredentialsForm.ssoProvider` as one-click provider buttons; a click selects the id AND fires the field's data-carrying `sso` action (no separate submit), self-hides when no providers configured. Its `icon` is a CSS class applied verbatim from server context → invisible to a static extractor → consumer must safelist it + install the icon collection (demo: `i-simple-icons:google` via a 2nd `presetIcons` + `safelist`).                             |
| 3   | **`<AsWfForm name="…">` carries the wfid to START** (e.g. `auth/login/flow`); the wire sends it as `wfid`. Resume uses the `wfs` token.                                                                                                                                                                                                                                                                                                                                                            |
| 4   | **Magic-link / pincode-link resume:** route the URL's `wfs` (and invite `uid`) into `:initial-token` so `<AsWfForm>` resumes instead of starting.                                                                                                                                                                                                                                                                                                                                                  |
| 5   | **Re-clicked invite link, state evicted:** fall through to `GET /auth/invite/post-redemption?uid=<id>` and hand the `WfFinished` to `<AsWfFinish>`.                                                                                                                                                                                                                                                                                                                                                |
| 6   | **`AsQrCode` peer-deps `qrcode`** for the SVG; without it the manual base32 secret still renders (`manualSecret` prop defaults on).                                                                                                                                                                                                                                                                                                                                                                |
| 7   | **Replacing a bundled form keeps the component string** — `:components` is keyed on the name, not the form class. Keep the `@ui.form.component` annotation on the field in your replacement form.                                                                                                                                                                                                                                                                                                  |
| 8   | **Cross-flow alt-actions render pushed-down + centered text+link.** Login `signup`/`magicLink`, signup `backToLogin`, recovery `backToLogin` carry `@ui.form.pushDown` + `@ui.form.attr 'text'/'align'` on the `ui.action` field → "text [link]" below submit. `text`/`align` apply only to the standalone `AsAction` button, NOT the inline-on-input variant (`forgotPassword`). Semantics owned by `atscript-ui-forms`; aooth forms only declare them. Action **ids** stay the routing contract. |

## Component → server field map

| Component (`@atscript/vue-aooth`) | server field (`@ui.form.component`) | renders                                                 |
| --------------------------------- | ----------------------------------- | ------------------------------------------------------- |
| `AsQrCode`                        | `EnrollConfirmForm.qrCode`          | TOTP `otpauth://` QR + base32 secret (manual entry)     |
| `AsConsentArray`                  | `WithInlineConsentForm.consents`    | one checkbox per pending consent; self-hides when none  |
| `AsPasswordRules`                 | `SetPasswordForm.passwordRules`     | live password-policy fulfillment dots (per keystroke)   |
| `AsSsoProviders`                  | `LoginCredentialsForm.ssoProvider`  | one-click SSO buttons; fires data-carrying `sso` action |

## Variant config per request

Send a custom header via `:fetch-options` and re-key the form to remount on change; the server reads it in the `AuthWorkflow` subclass (e.g. an `@Injectable("FOR_EVENT")` ctor) to pick a preset.

```ts
const fetchOptions = computed(() =>
  variant.value ? { headers: { "x-wf-variant": variant.value } } : undefined,
);
```

## Key imports

```ts
import { AsWfForm, AsWfFinish, type WfFinished } from "@atscript/vue-wf";
import { createDefaultTypes } from "@atscript/vue-form";
import { AsConsentArray, AsPasswordRules, AsQrCode, AsSsoProviders } from "@atscript/vue-aooth";
```

## References

| Domain      | File                             | When                                                   |
| ----------- | -------------------------------- | ------------------------------------------------------ |
| Workflows   | [workflows.md](workflows.md)     | server side emitting these forms; `/auth/trigger` wire |
| Controllers | [controllers.md](controllers.md) | `post-redemption` route; trigger endpoint              |
| Annotations | [annotations.md](annotations.md) | `@ui.form.component` + the bundled-form catalogue      |

## See also

Docs: https://aoothjs.dev/moost/spa-components · component APIs: atscript-ui-wf / atscript-ui-forms skills · reference impl: `packages/e2e-demo/src/ui/pages/WfPage.vue`
