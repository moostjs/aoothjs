import { AsConsentArray, AsPasswordRules, AsQrCode, AsSsoProviders } from "@atscript/vue-aooth";

// The custom carrier-form renderers the bundled `AuthWorkflow` forms reference
// via `@ui.form.component '<Name>'`, registered on every `<AsWfForm :components>`
// in the demo. The KEY MUST match the annotation string or the field falls back
// to the default renderer. A federated login lands on the SAME consent / MFA-
// enrollment / prove-control steps a password login does, so the login page and
// the OAuth-callback bridge must register the identical set — hence one source.
//
// - AsConsentArray   → WithInlineConsentForm.consents   (self-hides when none pending)
// - AsPasswordRules  → SetPasswordForm.passwordRules    (live policy fulfillment)
// - AsQrCode         → EnrollConfirmForm.qrCode          (TOTP otpauth:// QR)
// - AsSsoProviders   → LoginCredentialsForm.ssoProvider  (one-click SSO picker)
export const wfFormComponents = { AsConsentArray, AsPasswordRules, AsQrCode, AsSsoProviders };
