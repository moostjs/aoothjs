/**
 * Inline consent collection — a single dynamic `consents: string[]` field
 * attached to whichever carrier form the user is already filling out.
 * Carrier forms `extends WithInlineConsentForm` to inherit it without
 * duplication.
 *
 * Backend transport: `@wf.context.pass 'consents'` ships the
 * `AuthWfConsentsState` group (set by the `prepare-consents` @Step from
 * `ConsentStore.getPendingConsents()`) to the client. The
 * `@ui.form.fn.attr 'pendingConsents'` expression below binds
 * `ctx.consents?.pending` onto the `AsConsentArray` component
 * (`@atscript/vue-aooth`) which renders one checkbox per descriptor; the
 * user-submitted `string[]` carries back the SUBSET of `descriptor.id`s the
 * user ticked.
 *
 * SPA-side hide-when-empty: `AsConsentArray` self-hides when its
 * `pendingConsents` prop is empty / unset — no `@ui.form.fn.hidden` is
 * needed on the field. A carrier form whose customer hasn't configured any
 * pending consents renders WITHOUT this block.
 *
 * SECURITY (silent-drop): the server-side `processInlineConsent` helper
 * uses its OWN `ctx.consents.pending` as the authoritative whitelist; any
 * id submitted by the client outside that set is silently dropped (audit
 * invariant — see helper rationale). The client cannot forge audit rows
 * by submitting ids it was never shown.
 *
 * SECURITY (mandatory-by-message): each `ConsentDescriptor.required`
 * non-empty string IS the per-row error copy AND the form-level error the
 * server throws when a required consent is missing from the submitted set.
 * Absent / empty ⇒ optional (the `ConsentEvent.accepted` boolean lets
 * customers persist the un-ticked-optional decision for audit).
 */
@wf.context.pass 'consents'
export interface WithInlineConsentForm {
    @meta.label 'Pending consents'
    @ui.form.component 'AsConsentArray'
    @ui.form.fn.attr 'pendingConsents', '(_, _d, ctx) => ctx.consents?.pending'
    @ui.form.grid.colSpan '12'
    consents: string[]
}

/**
 * Default login credentials form.
 *
 * Override via `setupAuthWorkflows({ forms: { loginCredentials: MyForm } })`.
 *
 * SSO provider ids (configured via
 * `opts.alternateCredentials.ssoProviders[].id`) are NOT declared here —
 * consumers who enable SSO supply their own `loginCredentials` form and add a
 * matching phantom `ui.action` field per provider so
 * `useAtscriptWf(form).resolveAction()` accepts the dynamic ids.
 */
@meta.label 'Sign in'
@wf.context.pass 'altForgotPassword'
@wf.context.pass 'altSignup'
@wf.context.pass 'altMagicLink'
@ui.form.submit.text 'Sign in'
export interface LoginCredentialsForm {
    @ui.form.order 10
    @ui.form.type 'text'
    @meta.label 'Username'
    @ui.form.autocomplete 'username'
    @meta.required
    @expect.minLength 1
    username: string

    @ui.form.order 20
    @ui.form.type 'password'
    @meta.label 'Password'
    @ui.form.autocomplete 'current-password'
    @meta.sensitive
    @meta.required
    @expect.minLength 1
    @ui.form.action 'forgotPassword', 'Forgot password?'
    @ui.form.fn.hidden '(_, _d, ctx) => !ctx.altForgotPassword'
    @wf.action.withData 'forgotPassword'
    password: string

    @ui.form.order 30
    @ui.form.action 'signup', 'Sign up'
    @ui.form.fn.hidden '(_, _d, ctx) => !ctx.altSignup'
    signup?: ui.action

    @ui.form.order 40
    @ui.form.action 'magicLink', 'Sign in with a magic link'
    @ui.form.fn.hidden '(_, _d, ctx) => !ctx.altMagicLink'
    magicLink?: ui.action
}

/**
 * MFA code form. Shared by TOTP, email-OTP, and SMS-OTP branches — the
 * leading `transportHint` paragraph reads `mfaMethod` + `pincode.sentTo`
 * (masked recipient) out of the workflow context so the operator knows
 * which factor the workflow is currently verifying. The hint requires
 * `installDynamicResolver()` from `@atscript/ui-fns` on the consumer
 * side; without it `@ui.form.fn.value` stays inert and the paragraph
 * renders empty.
 */
@meta.label 'Verify your identity'
@wf.context.pass 'mfaMethod'
@wf.context.pass 'pincode'
@wf.context.pass 'mfaMethodCount'
@ui.form.submit.text 'Verify'
export interface MfaCodeForm {
    @ui.form.fn.value '(_, _d, ctx) => ctx.mfaMethod === "totp" ? "Enter the current 6-digit code from your authenticator app." : ctx.mfaMethod ? "Code sent to " + (ctx.pincode?.sentTo || "your " + ctx.mfaMethod) + " — check the dev server console for the code." : "Enter your verification code."'
    transportHint?: ui.paragraph

    @ui.form.type 'text'
    @meta.label 'Verification code'
    @ui.form.autocomplete 'one-time-code'
    @meta.required
    @expect.minLength 4
    @expect.maxLength 12
    @expect.pattern '^[0-9]+$'
    code: string

    @ui.form.action 'useDifferentMethod', 'Use a different method'
    @ui.form.fn.hidden '(_, _d, ctx) => (ctx.mfaMethodCount ?? 0) < 2'
    useDifferentMethod?: ui.action
}

/**
 * Email identifier form — used for password recovery initiation.
 *
 * `@wf.context.pass 'defaults'` whitelists the `defaults` ctx key so the
 * recovery `request` step can pre-fill the email field from the
 * `?username=` query param (carried in by the login workflow's
 * `forgotPassword` alt-action). Without this annotation the field is
 * stripped by `extractPassContext` before reaching the client.
 */
@meta.label 'Forgot your password?'
@meta.description 'Enter your account email and we will send you a recovery link.'
@wf.context.pass 'defaults'
export interface EmailIdentifierForm {
    @ui.form.order 10
    @ui.form.type 'text'
    @meta.label 'Email'
    @ui.form.autocomplete 'email'
    @meta.required
    email: string.email

    @ui.form.order 20
    @ui.form.action 'backToLogin', 'Back to sign-in'
    backToLogin?: ui.action
}

/**
 * Set new password form.
 *
 * Cross-field equality — `confirmPassword === newPassword` — is enforced by
 * the `@ui.form.validate` rule below (client + server validators key on the
 * same expression). The workflow step retains a defensive equality check as
 * a belt-and-braces guard.
 *
 * `@wf.context.pass 'passwordPolicies'` whitelists the workflow ctx key so the
 * prior preparePasswordRules / setPassword steps can ship the transferable
 * password-policy rules (`UserService.getTransferablePolicies()`) to the
 * client for rendering rule hints next to the inputs. Without this annotation
 * the key is stripped by `extractPassContext` before reaching the client.
 *
 * Phase 7 — `passwordRules: ui.paragraph` is a phantom display field bound to
 * the `AsPasswordRules` component (`@atscript/vue-aooth`); the
 * `@ui.form.fn.attr 'policies'` expression reads `ctx.passwordPolicies` (the
 * transferable list seeded by the workflow's `prepare-password-rules` @Step)
 * and the `@ui.form.fn.attr 'password'` expression reads
 * `data.newPassword` so the rule-fulfillment readout updates live on every
 * keystroke. `WithInlineConsentForm` continues to supply the inline-consent
 * `consents: string[]` block via `AsConsentArray` (Phase 5).
 *
 * `@wf.context.pass 'passwordChangeReason'` whitelists the structured
 * discriminator (`'initial' | 'expired'`) set by `LoginWorkflow.credentials`
 * when the forced-change branch fires. Downstream consumers consume it for
 * analytics or per-tenant copy overrides; the bundled UX defaults come from
 * `passwordFormHeading` + `passwordFormIntro` (set by each workflow's
 * `create-password-form` / `set-password` step before the pause). The form's
 * `@ui.form.fn.title` / `@ui.form.fn.description` annotations below render
 * those ctx values directly, so the SPA gets context-aware copy out of the box.
 *
 * No alt-actions — the SetPasswordForm submit is mandatory; a user who
 * wants to abandon the flow closes / refreshes the page (the wf state token
 * expires per the engine's TTL).
 */
@ui.form.fn.title '(_, _d, ctx) => ctx.passwordFormHeading || "Set your password"'
@wf.context.pass 'passwordPolicies'
@wf.context.pass 'passwordChangeReason'
@wf.context.pass 'passwordFormHeading'
@wf.context.pass 'passwordFormIntro'
@wf.context.pass 'consents'
export interface SetPasswordForm extends WithInlineConsentForm {
    /**
     * Phantom intro paragraph — pairs with the form's dynamic
     * `@ui.form.fn.title` to render context-aware copy. There is no
     * top-level `@ui.form.fn.description` annotation in atscript-ui
     * (`fn.description` is a per-field annotation), so the intro stays as
     * a phantom field while the heading uses the proper type-level dynamic
     * title. The field is hidden when `ctx.passwordFormIntro` is unset so
     * a default "Set your password" pause renders without an empty paragraph.
     */
    @ui.form.order 5
    @ui.form.fn.value '(_, _d, ctx) => ctx.passwordFormIntro || ""'
    @ui.form.fn.hidden '(_, _d, ctx) => !ctx.passwordFormIntro'
    intro: ui.paragraph

    @ui.form.order 10
    @ui.form.type 'password'
    @meta.label 'New password'
    @ui.form.autocomplete 'new-password'
    @meta.sensitive
    @meta.required
    @expect.minLength 8
    newPassword: string

    @ui.form.order 20
    @ui.form.type 'password'
    @meta.label 'Confirm password'
    @ui.form.autocomplete 'new-password'
    @meta.sensitive
    @meta.required
    @expect.minLength 8
    @ui.form.validate '(v, data) => v === data.newPassword || "Passwords must match"'
    confirmPassword: string

    /**
     * Phantom display field — `ui.paragraph` carries no submission value;
     * it exists purely so `AsPasswordRules` (registered on the SPA via
     * `<AsWfForm :components>`) renders one row per `ctx.passwordPolicies`
     * descriptor between the confirm-password input and the action buttons.
     *
     * The `policies` attr reads from workflow context (seeded by the
     * `prepare-password-rules` @Step via
     * `UserService.getTransferablePolicies()`); the `password` attr reads
     * from the live form-data so each row's `data-passed` flag re-evaluates
     * on every keystroke. The `(_, data) => data.newPassword` shape is
     * load-bearing — a regression that froze the `password` attr at first
     * render (e.g. `() => data.newPassword`) would silently lie about
     * policy fulfillment after the user starts typing.
     */
    @ui.form.order 25
    @meta.label 'Password requirements'
    @ui.form.component 'AsPasswordRules'
    @ui.form.fn.attr 'policies', '(_, _d, ctx) => ctx.passwordPolicies'
    @ui.form.fn.attr 'password', '(_, data) => data.newPassword'
    @ui.form.grid.colSpan '12'
    passwordRules: ui.paragraph
}

/**
 * Invite form — used by an admin to send an invite magic link.
 *
 * Bundled shape is intentionally minimal: email + roles. Admins who want to
 * collect richer profile data per invitee replace this form via
 * `setupAuthWorkflows({ forms: { invite: MyInviteForm } })` and map the
 * extra fields into their user schema via the `prepareUser({...})` hook
 * (see `InviteWorkflow.prepareUser` jsdoc).
 *
 * `@wf.context.pass 'availableRoles'` whitelists the workflow ctx key so the
 * `inviteAdminInviteForm` step can pass the role-picker options into the
 * client form when `opts.getAvailableRoles` is wired.
 *
 * No cancel alt-action: an admin who wants to back out navigates away from
 * the page (the wf state token expires per the engine's TTL).
 */
@meta.label 'Send an invitation'
@meta.description 'Enter the recipient email address and pick the roles to grant on acceptance. They will receive a magic link to set their password.'
@wf.context.pass 'availableRoles'
export interface InviteForm {
    @ui.form.order 10
    @ui.form.type 'text'
    @meta.label 'Email'
    @ui.form.autocomplete 'email'
    @meta.required
    email: string.email

    // UX: select-on-array currently renders single-text-per-item via AsArray;
    // dedicated multi-select widget tracked as atscript-ui follow-up.
    @ui.form.order 20
    @ui.form.type 'select'
    @ui.form.fn.options '(_, _data, context) => Array.isArray(context.availableRoles) ? context.availableRoles.map(r => ({ key: r, label: r })) : []'
    @meta.label 'Roles'
    roles: string[]
}

/**
 * Select an enrolled MFA method (Phase 4 `select2fa` step).
 *
 * The workflow renders this only when the user has >1 enrolled methods after
 * `opts.mfaTransports` filtering. `methodName` is the `MfaMethod.name`
 * (e.g. `"totp"`, `"email"`, `"sms"`); the workflow itself validates that the
 * supplied value is in the user's enrolled set. The dropdown options are
 * built from `ctx.mfaEnrolledMethods` (a `MfaSummary[]` populated by
 * `prepareMfaOptions`) so the user only sees factors they actually have.
 */
@meta.label 'Choose a verification method'
@meta.description 'Pick how you would like to verify your identity.'
@wf.context.pass 'mfaEnrolledMethods'
export interface Select2faForm {
    @ui.form.order 10
    @ui.form.type 'radio'
    @ui.form.fn.options '(_, _d, ctx) => Array.isArray(ctx.mfaEnrolledMethods) ? ctx.mfaEnrolledMethods.map(m => ({ key: m.methodName, label: m.kind === "totp" ? "TOTP (Authenticator app)" : m.kind === "email" ? "Email" : m.kind === "sms" ? "SMS" : m.kind })) : []'
    @meta.label 'MFA method'
    @meta.required
    methodName: string

    @ui.form.type 'checkbox'
    @meta.label 'Save as default'
    @meta.default 'false'
    saveAsDefault: boolean
}

/**
 * Generic 6-digit pincode form — used by both login and recovery OTP flows.
 *
 * `rememberDevice` is rendered only when `opts.deviceTrust && opts.deviceTrustOptIn`.
 *
 * The leading `transportHint` paragraph reads `mfaMethod` + `pincode.sentTo`
 * (the masked recipient set by the pincode-send step) out of the workflow
 * context so the operator can see which factor the workflow is currently
 * verifying. Requires `installDynamicResolver()` from `@atscript/ui-fns`
 * on the consumer side; without it `@ui.form.fn.value` stays inert and
 * the paragraph renders empty.
 */
@meta.label 'Enter the verification code'
@wf.context.pass 'mfaMethod'
@wf.context.pass 'pincode'
@wf.context.pass 'mfaMethodCount'
@wf.context.pass 'deviceTrustOptIn'
@wf.context.pass 'recoveryTransportCount'
@ui.form.submit.text 'Verify'
export interface PincodeForm {
    @ui.form.fn.value '(_, _d, ctx) => ctx.mfaMethod === "totp" ? "Enter the current 6-digit code from your authenticator app." : ctx.mfaMethod ? "Code sent to " + (ctx.pincode?.sentTo || "your " + ctx.mfaMethod) + " — check the dev server console for the code." : "Enter your verification code."'
    transportHint?: ui.paragraph

    @ui.form.type 'text'
    @meta.label 'Verification code'
    @ui.form.autocomplete 'one-time-code'
    @meta.required
    @expect.minLength 4
    @expect.maxLength 12
    @expect.pattern '^[0-9]+$'
    code: string

    @ui.form.type 'checkbox'
    @meta.label 'Remember this device'
    @meta.default 'false'
    @ui.form.fn.hidden '(_, _d, ctx) => !ctx.deviceTrustOptIn'
    rememberDevice: boolean

    @ui.form.action 'resend', 'Resend code'
    resend?: ui.action

    @ui.form.action 'useDifferentMethod', 'Use a different method'
    @ui.form.fn.hidden '(_, _d, ctx) => (ctx.mfaMethodCount ?? 0) < 2'
    useDifferentMethod?: ui.action

    @ui.form.action 'backToLogin', 'Back to sign-in'
    backToLogin?: ui.action

    @ui.form.action 'useDifferentTransport', 'Use a different transport'
    @ui.form.fn.hidden '(_, _d, ctx) => (ctx.recoveryTransportCount ?? 0) < 2'
    useDifferentTransport?: ui.action
}

/**
 * Email-only form for the `ask/email` enrollment step.
 */
@meta.label 'Add your email address'
@meta.description 'We need a verified email to send security notifications and verification codes.'
@wf.context.pass 'consents'
@wf.context.pass 'otpDisclosure'
export interface AskEmailForm extends WithInlineConsentForm {
    @ui.form.order 10
    @ui.form.type 'text'
    @meta.label 'Email'
    @ui.form.autocomplete 'email'
    @meta.required
    email: string.email
}

/**
 * Phone-only form for the `ask/phone` enrollment step. Free-form text —
 * E.164 normalization happens server-side.
 */
@meta.label 'Add your phone number'
@meta.description 'We need a verified phone to send security notifications and verification codes.'
@wf.context.pass 'consents'
@wf.context.pass 'otpDisclosure'
export interface AskPhoneForm extends WithInlineConsentForm {
    @ui.form.order 10
    @ui.form.type 'text'
    @meta.label 'Phone (E.164)'
    @ui.form.autocomplete 'tel'
    @meta.required
    phone: string
}

/**
 * Forced MFA enrollment — method picker for `mfa-enroll-required`. Options
 * come from `ctx.mfaEnroll?.availableTransports` so only consumer-enabled
 * transports appear.
 */
@meta.label 'Set up two-factor authentication'
@meta.description 'Pick a method to receive your verification codes.'
@wf.context.pass 'mfaEnroll'
export interface EnrollPickMethodForm {
    @ui.form.order 10
    @ui.form.type 'radio'
    @ui.form.fn.options '(_, _d, ctx) => Array.isArray(ctx.mfaEnroll?.availableTransports) ? ctx.mfaEnroll.availableTransports.map(t => ({ key: t, label: t === "totp" ? "Authenticator app (TOTP)" : t === "sms" ? "SMS" : t === "email" ? "Email" : t })) : []'
    @meta.label 'Choose a verification method'
    @meta.required
    method: string

    @ui.form.action 'skip', 'Skip for now'
    @ui.form.fn.hidden '(_, _d, ctx) => ctx.mfaEnroll?.mode !== "optional"'
    skip?: ui.action
}

/**
 * Forced MFA enrollment — address collection for sms/email. TOTP skips this
 * form (secret is provisioned server-side).
 *
 * `skip` is hidden unless `mfaEnroll.mode === 'optional'` (`'required'` mode
 * forbids backing out mid-flow). `useDifferentMethod` is hidden when the
 * consumer has only one transport configured (nothing to switch to).
 */
@ui.form.fn.title '(_, _d, ctx) => ctx.mfaEnroll?.method === "sms" ? "Add your phone number" : "Add your email"'
@meta.description 'We will send you a one-time code to confirm.'
@wf.context.pass 'mfaEnroll'
export interface EnrollAddressForm {
    @ui.form.order 10
    @ui.form.type 'text'
    @meta.label 'Address'
    @meta.required
    address: string

    @ui.form.action 'skip', 'Skip for now'
    @ui.form.fn.hidden '(_, _d, ctx) => ctx.mfaEnroll?.mode !== "optional"'
    skip?: ui.action

    @ui.form.action 'useDifferentMethod', 'Use a different method'
    @ui.form.fn.hidden '(_, _d, ctx) => (ctx.mfaEnroll?.availableTransports?.length ?? 0) < 2'
    useDifferentMethod?: ui.action
}

/**
 * Forced MFA enrollment — confirm code, shared by all three transports. The
 * leading paragraph swaps between "scan this QR" (totp) and "code sent to …"
 * (sms/email) based on `mfaEnroll.method`; `mfaEnroll.secret` / `mfaEnroll.uri`
 * are passed for the totp QR + manual-entry fallback.
 */
@meta.label 'Confirm your verification code'
@wf.context.pass 'mfaEnroll'
@wf.context.pass 'pincode'
@ui.form.submit.text 'Confirm'
export interface EnrollConfirmForm {
    @ui.form.fn.value '(_, _d, ctx) => ctx.mfaEnroll?.method === "totp" ? "Scan the QR with your authenticator app, or enter the secret manually. Then type the 6-digit code it generates." : ctx.mfaEnroll?.method ? "Code sent to " + (ctx.pincode?.sentTo || "your " + ctx.mfaEnroll.method) + ". Enter it below to confirm." : "Enter the code to confirm enrollment."'
    transportHint?: ui.paragraph

    @ui.form.type 'text'
    @meta.label 'Code'
    @ui.form.autocomplete 'one-time-code'
    @meta.required
    @expect.minLength 4
    @expect.maxLength 12
    @expect.pattern '^[0-9]+$'
    code: string

    @ui.form.action 'resend', 'Resend code'
    @ui.form.fn.hidden '(_, _d, ctx) => ctx.mfaEnroll?.method === "totp"'
    resend?: ui.action

    @ui.form.action 'useDifferentMethod', 'Use a different method'
    @ui.form.fn.hidden '(_, _d, ctx) => (ctx.mfaEnroll?.availableTransports?.length ?? 0) < 2'
    useDifferentMethod?: ui.action

    @ui.form.action 'skip', 'Skip for now'
    @ui.form.fn.hidden '(_, _d, ctx) => ctx.mfaEnroll?.mode !== "optional"'
    skip?: ui.action
}

/**
 * Default minimal profile completion form. Consumers replace via
 * `LoginWorkflowOptions.profileCompleteForm` for richer shapes.
 */
@meta.label 'Complete your profile'
@meta.description 'Add a few details before you continue.'
@wf.context.pass 'consents'
export interface ProfileCompleteForm extends WithInlineConsentForm {
    @ui.form.order 10
    @ui.form.type 'text'
    @meta.label 'First name'
    firstName?: string

    @ui.form.order 20
    @ui.form.type 'text'
    @meta.label 'Last name'
    lastName?: string
}

/**
 * Standalone consent-bump prompt. Fires for returning users with pending
 * consents (set by `prepare-consents` from `ConsentStore.getPendingConsents`)
 * who did NOT pass through any onboarding carrier form (`AskEmailForm` /
 * `AskPhoneForm` / `SetPasswordForm` / `ProfileCompleteForm`) on this login —
 * those carrier forms collect consents inline via `WithInlineConsentForm`'s
 * inherited `AsConsentArray` field. The bump-prompt only renders the same
 * inherited consent block (no additional fields).
 */
@meta.label 'Updated terms and policies'
@meta.description 'Please review and accept the updated terms to continue.'
@wf.context.pass 'consents'
export interface TermsBumpForm extends WithInlineConsentForm {
}

/**
 * Concurrency-limit kick prompt — user picks whether to log out other
 * sessions and continue. The user backs out of the prompt by navigating
 * away (the wf state token expires per the engine's TTL); no in-form
 * cancel alt-action.
 */
@meta.label 'Session limit reached'
@meta.description 'You are already signed in elsewhere. Choose what to do.'
export interface ConcurrencyLimitForm {
    @ui.form.order 10
    @ui.form.type 'text'
    @meta.label 'Action'
    @meta.required
    @expect.pattern '^logoutOthers$'
    action: string

    @ui.form.action 'logoutOthers', 'Log out other sessions'
    logoutOthers?: ui.action
}

/**
 * Identifier form for the magic-link login path — same shape as
 * {@link EmailIdentifierForm} but kept separate because future iterations may
 * accept either email or username.
 */
@meta.label 'Sign in with a magic link'
@meta.description 'Enter your account email or username and we will send you a one-time sign-in link.'
export interface MagicLinkRequestForm {
    @ui.form.order 10
    @ui.form.type 'text'
    @meta.label 'Email or username'
    @ui.form.autocomplete 'username'
    @meta.required
    identifier: string
}

/**
 * Recovery delivery-mode picker — rendered only when
 * `RecoveryWorkflowOptions.deliveryMode === 'choice'`.
 */
@meta.label 'Choose how to verify'
@meta.description 'Pick how you would like to recover access.'
export interface RecoveryModeSelectForm {
    @ui.form.order 10
    @ui.form.type 'radio'
    @ui.form.options 'Magic link', 'magicLink'
    @ui.form.options 'One-time code', 'otp'
    @meta.label 'Recovery method'
    @meta.required
    mode: string

    @ui.form.order 20
    @ui.form.action 'backToLogin', 'Back to sign-in'
    backToLogin?: ui.action
}

/**
 * Recovery factor-verification form — used when
 * `RecoveryWorkflowOptions.requireKnownRecoveryFactor` is true. The user
 * picks a factor type and supplies its value; the server validates against
 * the enrolled factor (phone last-4 or current TOTP code). Options are
 * built from `ctx.availableRecoveryFactors` (workflow whitelist ∩ user's
 * enrolled factors), so users only see factors they can actually verify
 * AND that the admin hasn't disabled via `opts.preReset.allowedFactors`.
 */
@meta.label 'Verify your identity'
@meta.description 'Confirm a detail we have on file before resetting your password.'
@wf.context.pass 'availableRecoveryFactors'
export interface RecoveryFactorForm {
    @ui.form.order 10
    @ui.form.type 'radio'
    @ui.form.fn.options '(_, _d, ctx) => Array.isArray(ctx.availableRecoveryFactors) ? ctx.availableRecoveryFactors : []'
    @meta.label 'Factor'
    @meta.required
    factor: string

    @ui.form.order 20
    @ui.form.type 'text'
    @meta.label 'Value'
    @meta.required
    @expect.minLength 4
    @expect.maxLength 12
    value: string

    @ui.form.order 30
    @ui.form.action 'backToLogin', 'Back to sign-in'
    backToLogin?: ui.action
}
