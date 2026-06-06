/**
 * Inline consent collection — a single dynamic `consents: string[]` field
 * attached to whichever carrier form the user is already filling out.
 * Carrier forms `extends WithInlineConsentForm` to inherit it without
 * duplication.
 *
 * Backend transport: `@wf.context.pass 'public'` ships the
 * `AuthWfConsentsState` group (set by the `prepare-consents` @Step from
 * `ConsentStore.getPendingConsents()`) to the client. The
 * `@ui.form.fn.attr 'pendingConsents'` expression below binds
 * `ctx.public?.consents?.pending` onto the `AsConsentArray` component
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
@wf.context.pass 'public'
export interface WithInlineConsentForm {
    @meta.label 'Pending consents'
    @ui.form.component 'AsConsentArray'
    @ui.form.fn.attr 'pendingConsents', '(_, _d, ctx) => ctx.public?.consents?.pending'
    @ui.form.fn.hidden '(_, _d, ctx) => ctx.public?.consents?.decidedAt !== undefined || (ctx.public?.consents?.pending?.length ?? 0) === 0'
    @ui.form.grid.colSpan '12'
    consents: string[]
}

/**
 * Default login credentials form.
 *
 * Override via `setupAuthWorkflows({ forms: { loginCredentials: MyForm } })`.
 *
 * SSO providers render out of the box: the `AsSsoProviders` component reads the
 * resolved provider list off `ctx.public.altActions.ssoProviders` (a dynamic
 * `SsoProvider[]`) and renders one button per provider. Because the server's
 * `resolveAction()` only accepts DECLARED actions, providers don't get a
 * per-id action — instead a single data-carrying `sso` action is declared
 * here, and `AsSsoProviders` sets the chosen id into `ssoProvider` before
 * invoking it (`useAtscriptWf(form).resolveAction()` sees `sso`; the workflow
 * reads `ssoProvider` from the submitted data). The whole block hides when no
 * providers are configured, so a password-only deployment renders unchanged.
 */
@meta.label 'Sign in'
@wf.context.pass 'public'
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
    @ui.form.fn.hidden '(_, _d, ctx) => !ctx.public?.altActions?.forgotPassword'
    @wf.action.withData 'forgotPassword'
    password: string

    @ui.form.order 30
    @ui.form.action 'signup', 'Sign up'
    @ui.form.attr 'text', 'Don’t have an account?'
    @ui.form.attr 'align', 'center'
    @ui.form.pushDown
    @ui.form.fn.hidden '(_, _d, ctx) => !ctx.public?.altActions?.signup'
    signup?: ui.action

    @ui.form.order 40
    @ui.form.action 'magicLink', 'Sign in with a magic link'
    @ui.form.attr 'align', 'center'
    @ui.form.pushDown
    @ui.form.fn.hidden '(_, _d, ctx) => !ctx.public?.altActions?.magicLink'
    magicLink?: ui.action

    // SSO providers — rendered from `ctx.public.altActions.ssoProviders` by the
    // `AsSsoProviders` one-click picker (registered on `<AsWfForm :components>`).
    // Each provider becomes a full-width button whose VERBATIM `text` the server
    // owns ("Continue with {label}"); a click both selects the provider id and
    // fires the `sso` action — the component is chromeless and suppresses the
    // shell's footer action link, so there is NO separate submit button (the
    // `'Continue'` action label is inert here, kept only because the action
    // DECLARATION is what `resolveAction()` whitelists for the emit). The `sso`
    // action is DATA-CARRYING (`@wf.action.withData`), so the selected
    // `ssoProvider` rides in the submitted data and the workflow redirects to
    // that provider (same mechanism `forgotPassword` uses to carry the typed
    // username). OPTIONAL on purpose — a password login (or a hand-rolled
    // client) submits without it and must NOT be blocked; only the `sso` action
    // carries it. `AsSsoProviders` self-hides on an empty `providers` list; the
    // explicit `@ui.form.fn.hidden` keeps the field out of the grid flow too.
    // Swap the component via `setupAuthWorkflows({ forms })`.
    @ui.form.order 50
    @ui.form.component 'AsSsoProviders'
    @ui.form.fn.attr 'providers', '(_, _d, ctx) => Array.isArray(ctx.public?.altActions?.ssoProviders) ? ctx.public.altActions.ssoProviders.map((p) => ({ id: p.id, text: "Continue with " + p.label, icon: p.icon })) : []'
    @ui.form.fn.hidden '(_, _d, ctx) => (ctx.public?.altActions?.ssoProviders?.length ?? 0) === 0'
    @meta.label 'Or sign in with'
    @ui.form.action 'sso', 'Continue'
    @wf.action.withData 'sso'
    @ui.form.grid.colSpan '12'
    ssoProvider?: string
}

/**
 * MFA code form. Shared by TOTP, email-OTP, and SMS-OTP branches — the
 * leading `transportHint` paragraph reads `mfa.method` + `pincode.sentTo`
 * (masked recipient) out of the workflow context so the operator knows
 * which factor the workflow is currently verifying. The hint requires
 * `installDynamicResolver()` from `@atscript/ui-fns` on the consumer
 * side; without it `@ui.form.fn.value` stays inert and the paragraph
 * renders empty.
 */
@meta.label 'Verify your identity'
@wf.context.pass 'public'
@ui.form.submit.text 'Verify'
export interface MfaCodeForm {
    @ui.form.fn.value '(_, _d, ctx) => ctx.public?.mfa?.method === "totp" ? "Enter the current 6-digit code from your authenticator app." : ctx.public?.pincode?.sentTo ? "Code sent to " + ctx.public.pincode.sentTo + "." : "Enter your verification code."'
    transportHint?: ui.paragraph

    @ui.form.type 'text'
    @meta.label 'Verification code'
    @ui.form.autocomplete 'one-time-code'
    @ui.form.fn.attr 'maxlength', '(_, _d, ctx) => ctx.public?.pincode?.codeLength'
    @meta.required
    @expect.minLength 4
    @expect.maxLength 12
    @expect.pattern '^[0-9]+$'
    code: string

    @ui.form.action 'useDifferentMethod', 'Use a different method'
    @ui.form.fn.hidden '(_, _d, ctx) => (ctx.public?.mfa?.methodCount ?? 0) < 2'
    useDifferentMethod?: ui.action

    @ui.form.type 'checkbox'
    @meta.label 'Remember this device'
    @meta.default 'false'
    @ui.form.fn.hidden '(_, _d, ctx) => !ctx.public?.trust?.optIn || !!ctx.public?.newPasswordRequired'
    rememberDevice: boolean
}

/**
 * Email identifier form — used for password recovery initiation.
 *
 * `@wf.context.pass 'public'` whitelists the `defaults` ctx key so the
 * recovery `request` step can pre-fill the email field from the
 * `?username=` query param (carried in by the login workflow's
 * `forgotPassword` alt-action). Without this annotation the field is
 * stripped by `extractPassContext` before reaching the client.
 */
@meta.label 'Forgot your password?'
@meta.description 'Enter your account email and we will send you a recovery link.'
@wf.context.pass 'public'
export interface EmailIdentifierForm {
    @ui.form.order 10
    @ui.form.type 'text'
    @meta.label 'Email'
    @ui.form.autocomplete 'email'
    @meta.required
    email: string.email

    @ui.form.order 20
    @ui.form.action 'backToLogin', 'Back to sign in'
    @ui.form.attr 'align', 'center'
    @ui.form.pushDown
    backToLogin?: ui.action
}

/**
 * Self-signup identifier form — the entry pause of `auth/signup/flow`.
 *
 * Intentionally email-only: the flow is verify-first, so the user proves
 * email ownership via OTP BEFORE the account is created, and the password is
 * set afterwards on the shared `SetPasswordForm` (so no plaintext password is
 * ever held in workflow state across the OTP wait). `username` defaults to the
 * email; consumers who want a distinct username — or richer profile capture —
 * override this form via `setupAuthWorkflows({ forms: { signup: MyForm } })`
 * and read the extra fields in a `signup-form` / `signup-extra-step` override.
 *
 * `@wf.context.pass 'public'` mirrors `EmailIdentifierForm` so a future
 * prefill (`ctx.defaults.email`) works the same way.
 */
@meta.label 'Create your account'
@meta.description 'Enter your email to get started — we will send you a verification code.'
@wf.context.pass 'public'
export interface SignupForm {
    @ui.form.order 10
    @ui.form.type 'text'
    @meta.label 'Email'
    @ui.form.autocomplete 'email'
    @meta.required
    email: string.email

    // Primary cross-link to sign-in: signup is typically the INITIAL flow, so
    // existing users click this to reach the login flow.
    @ui.form.order 20
    @ui.form.action 'backToLogin', 'Sign in'
    @ui.form.attr 'text', 'Already have an account?'
    @ui.form.attr 'align', 'center'
    @ui.form.pushDown
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
 * `@wf.context.pass 'public'` whitelists the `AuthWfPasswordUiState`
 * group on `ctx.password` so the prior preparePasswordRules /
 * createPasswordForm / setPassword steps can ship the transferable
 * password-policy rules (`UserService.getTransferablePolicies()`), the
 * structured `changeReason` discriminator, and the `heading` / `intro`
 * copy to the client. Without this annotation the key is stripped by
 * `extractPassContext` before reaching the client.
 *
 * Phase 7 — `passwordRules: ui.paragraph` is a phantom display field bound to
 * the `AsPasswordRules` component (`@atscript/vue-aooth`); the
 * `@ui.form.fn.attr 'policies'` expression reads `ctx.public?.password?.policies`
 * (the transferable list seeded by the workflow's `prepare-password-rules`
 * @Step) and the `@ui.form.fn.attr 'password'` expression reads
 * `data.newPassword` so the rule-fulfillment readout updates live on every
 * keystroke. `WithInlineConsentForm` continues to supply the inline-consent
 * `consents: string[]` block via `AsConsentArray` (Phase 5).
 *
 * `ctx.password.changeReason` is the structured discriminator
 * (`'initial' | 'expired'`) set by `LoginWorkflow.credentials` when the
 * forced-change branch fires. Downstream consumers consume it for
 * analytics or per-tenant copy overrides; the bundled UX defaults come from
 * `ctx.password.heading` + `ctx.password.intro` (set by each workflow's
 * `create-password-form` / `set-password` step before the pause). The form's
 * `@ui.form.fn.title` / `@ui.form.fn.description` annotations below render
 * those ctx values directly, so the SPA gets context-aware copy out of the box.
 *
 * No alt-actions — the SetPasswordForm submit is mandatory; a user who
 * wants to abandon the flow closes / refreshes the page (the wf state token
 * expires per the engine's TTL).
 */
@ui.form.fn.title '(_, _d, ctx) => ctx.public?.password?.heading || "Set your password"'
@wf.context.pass 'public'
export interface SetPasswordForm extends WithInlineConsentForm {
    /**
     * Phantom intro paragraph — pairs with the form's dynamic
     * `@ui.form.fn.title` to render context-aware copy. There is no
     * top-level `@ui.form.fn.description` annotation in atscript-ui
     * (`fn.description` is a per-field annotation), so the intro stays as
     * a phantom field while the heading uses the proper type-level dynamic
     * title. The field is hidden when `ctx.password.intro` is unset so
     * a default "Set your password" pause renders without an empty paragraph.
     */
    @ui.form.order 5
    @ui.form.fn.value '(_, _d, ctx) => ctx.public?.password?.intro || ""'
    @ui.form.fn.hidden '(_, _d, ctx) => !ctx.public?.password?.intro'
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
     * `<AsWfForm :components>`) renders one row per `ctx.password.policies`
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
    @ui.form.fn.attr 'policies', '(_, _d, ctx) => ctx.public?.password?.policies'
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
 * `@wf.context.pass 'public'` whitelists the workflow `ctx.admin` group so the
 * `inviteAdminInviteForm` step can pass the role-picker options (via
 * `ctx.admin.availableRoles`) into the client form when `opts.getAvailableRoles`
 * is wired.
 *
 * No cancel alt-action: an admin who wants to back out navigates away from
 * the page (the wf state token expires per the engine's TTL).
 */
@meta.label 'Send an invitation'
@meta.description 'Enter the recipient email address and pick the roles to grant on acceptance. They will receive a magic link to set their password.'
@wf.context.pass 'public'
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
    @ui.form.fn.options '(_, _data, context) => Array.isArray(context.public?.admin?.availableRoles) ? context.public.admin.availableRoles.map(r => ({ key: r, label: r })) : []'
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
 * built from `ctx.public.mfa.enrolledMethods` (a `MfaSummary[]` populated by
 * `prepareMfaOptions`) so the user only sees factors they actually have.
 */
@meta.label 'Choose a verification method'
@meta.description 'Pick how you would like to verify your identity.'
@wf.context.pass 'public'
export interface Select2faForm {
    @ui.form.order 10
    @ui.form.type 'radio'
    @ui.form.fn.options '(_, _d, ctx) => Array.isArray(ctx.public?.mfa?.enrolledMethods) ? ctx.public.mfa.enrolledMethods.map(m => ({ key: m.methodName, label: m.kind === "totp" ? "TOTP (Authenticator app)" : m.kind === "email" ? "Email" : m.kind === "sms" ? "SMS" : m.kind })) : []'
    @meta.label 'MFA method'
    @meta.required
    methodName: string

    @ui.form.type 'checkbox'
    @meta.label 'Save as default'
    @meta.default 'false'
    saveAsDefault: boolean

    @ui.form.type 'checkbox'
    @meta.label 'Remember this device'
    @meta.default 'false'
    @ui.form.fn.hidden '(_, _d, ctx) => !ctx.public?.trust?.optIn || !!ctx.public?.newPasswordRequired'
    rememberDevice: boolean
}

/**
 * Generic 6-digit pincode form — used by both login and recovery OTP flows.
 *
 * `rememberDevice` is rendered only when `opts.deviceTrust && opts.deviceTrustOptIn`.
 *
 * The leading `transportHint` paragraph reads `mfa.method` + `pincode.sentTo`
 * (the masked recipient set by the pincode-send step) out of the workflow
 * context so the operator can see which factor the workflow is currently
 * verifying. Requires `installDynamicResolver()` from `@atscript/ui-fns`
 * on the consumer side; without it `@ui.form.fn.value` stays inert and
 * the paragraph renders empty.
 *
 * **Resend cooldown contract.** `ctx.public.pincode.resendAllowedAt` is a wall-clock
 * timestamp (`Date.now() + pincodeResendTimeoutMs`) after which the server
 * will accept a `resend` action click. It rides the `@wf.context.pass
 * 'pincode'` whitelist AND is mirrored onto the rendered resend element via
 * `@ui.form.fn.attr 'available-at'` — customers can subscribe a custom
 * action component via `<AsWfForm :components>` and drive a progress bar /
 * countdown / disabled state straight off the DOM attribute (no need to
 * re-derive the value from ctx). Server-side cooldown violations surface as
 * a `formMessage` banner — never an inline `code` field error — so the user
 * isn't told their (unsubmitted) code is wrong.
 */
@meta.label 'Enter the verification code'
@wf.context.pass 'public'
@ui.form.submit.text 'Verify'
export interface PincodeForm {
    @ui.form.fn.value '(_, _d, ctx) => ctx.public?.mfa?.method === "totp" ? "Enter the current 6-digit code from your authenticator app." : ctx.public?.pincode?.sentTo ? "Code sent to " + ctx.public.pincode.sentTo + "." : "Enter your verification code."'
    transportHint?: ui.paragraph

    @ui.form.type 'text'
    @meta.label 'Verification code'
    @ui.form.autocomplete 'one-time-code'
    @ui.form.fn.attr 'maxlength', '(_, _d, ctx) => ctx.public?.pincode?.codeLength'
    @meta.required
    @expect.minLength 4
    @expect.maxLength 12
    @expect.pattern '^[0-9]+$'
    code: string

    @ui.form.type 'checkbox'
    @meta.label 'Remember this device'
    @meta.default 'false'
    @ui.form.fn.hidden '(_, _d, ctx) => !ctx.public?.trust?.optIn || !!ctx.public?.newPasswordRequired'
    rememberDevice: boolean

    @ui.form.action 'resend', 'Resend code'
    @ui.form.fn.attr 'available-at', '(_, _d, ctx) => ctx.public?.pincode?.resendAllowedAt'
    resend?: ui.action

    @ui.form.action 'useDifferentMethod', 'Use a different method'
    @ui.form.fn.hidden '(_, _d, ctx) => (ctx.public?.mfa?.methodCount ?? 0) < 2'
    useDifferentMethod?: ui.action

    @ui.form.action 'useDifferentTransport', 'Use a different transport'
    @ui.form.fn.hidden '(_, _d, ctx) => (ctx.public?.otp?.transportCount ?? 0) < 2'
    useDifferentTransport?: ui.action
}

/**
 * Email-only form for the `ask/email` enrollment step.
 */
@meta.label 'Add your email address'
@meta.description 'We need a verified email to send security notifications and verification codes.'
@wf.context.pass 'public'
export interface AskEmailForm extends WithInlineConsentForm {
    /**
     * Phantom disclosure paragraph staged by `resolveOtpDisclosure(ctx,
     * 'email')` onto `ctx.channel.otpDisclosure`. Renders adjacent to the
     * email input so the user reads the TCPA / PECR / CASL / GDPR-safe
     * implied-consent copy BEFORE submitting the address. Hidden when the
     * resolver returns an empty string so an override that wants to drop
     * the disclosure (e.g. an enterprise tenant collecting explicit consent
     * elsewhere) renders without an empty paragraph slot.
     */
    @ui.form.order 5
    @ui.form.fn.value '(_, _d, ctx) => ctx.public?.channel?.otpDisclosure || ""'
    @ui.form.fn.hidden '(_, _d, ctx) => !ctx.public?.channel?.otpDisclosure'
    disclosure: ui.paragraph

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
@meta.description 'We need a verified phone to send security notifications and verification codes. Include your country code (for example +1 555 555 0100).'
@wf.context.pass 'public'
export interface AskPhoneForm extends WithInlineConsentForm {
    /** SMS-branch counterpart of `AskEmailForm.disclosure` — see that field. */
    @ui.form.order 5
    @ui.form.fn.value '(_, _d, ctx) => ctx.public?.channel?.otpDisclosure || ""'
    @ui.form.fn.hidden '(_, _d, ctx) => !ctx.public?.channel?.otpDisclosure'
    disclosure: ui.paragraph

    @ui.form.order 10
    @ui.form.type 'text'
    @meta.label 'Phone number'
    @ui.form.autocomplete 'tel'
    @meta.required
    phone: string
}

/**
 * Forced MFA enrollment — method picker for `mfa-enroll-required`. Options
 * come from `ctx.public?.mfaEnroll?.availableTransports` so only consumer-enabled
 * transports appear.
 */
@meta.label 'Set up two-factor authentication'
@meta.description 'Pick a method to receive your verification codes.'
@wf.context.pass 'public'
@ui.form.submit.text 'Continue'
export interface EnrollPickMethodForm {
    @ui.form.order 10
    @ui.form.type 'radio'
    @ui.form.fn.options '(_, _d, ctx) => Array.isArray(ctx.public?.mfaEnroll?.availableTransports) ? ctx.public.mfaEnroll.availableTransports.map(t => ({ key: t, label: t === "totp" ? "Authenticator app (TOTP)" : t === "sms" ? "SMS" : t === "email" ? "Email" : t })) : []'
    @meta.label 'Choose a verification method'
    @meta.required
    method: string

    // Login/invite opt-in only: a user who chose to defer MFA backs out here.
    @ui.form.action 'skip', 'Skip for now'
    @ui.form.fn.hidden '(_, _d, ctx) => ctx.public?.mfaEnroll?.mode !== "optional"'
    skip?: ui.action

    // Manage-MFA only: the user opened this on purpose, so "Skip" makes no
    // sense — offer a clean cancel instead.
    @ui.form.action 'cancel', 'Cancel'
    @ui.form.fn.hidden '(_, _d, ctx) => ctx.public?.mfaEnroll?.mode !== "manage"'
    cancel?: ui.action
}

/**
 * Forced MFA enrollment — address collection for sms/email. TOTP skips this
 * form (secret is provisioned server-side).
 *
 * `skip` is hidden unless `mfaEnroll.mode === 'optional'` (`'required'` mode
 * forbids backing out mid-flow). `useDifferentMethod` is hidden when the
 * consumer has only one transport configured (nothing to switch to).
 */
@ui.form.fn.title '(_, _d, ctx) => ctx.public?.mfaEnroll?.method === "sms" ? "Add your phone number" : "Add your email"'
@meta.description 'We will send you a one-time code to confirm.'
@wf.context.pass 'public'
@ui.form.submit.text 'Send code'
export interface EnrollAddressForm {
    @ui.form.order 10
    @ui.form.type 'text'
    @meta.label 'Address'
    @meta.required
    // Client-side format hint — email branch must look like an email; the SMS
    // branch stays free-form (server-side E.164 normalization). The robust
    // check is server-side in the `enroll-address` step regardless of client.
    @ui.form.validate '(v, _d, ctx) => ctx.public?.mfaEnroll?.method !== "email" || /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(v) || "Enter a valid email address"'
    address: string

    @ui.form.action 'skip', 'Skip for now'
    @ui.form.fn.hidden '(_, _d, ctx) => ctx.public?.mfaEnroll?.mode !== "optional"'
    skip?: ui.action

    @ui.form.action 'cancel', 'Cancel'
    @ui.form.fn.hidden '(_, _d, ctx) => ctx.public?.mfaEnroll?.mode !== "manage"'
    cancel?: ui.action

    @ui.form.action 'useDifferentMethod', 'Use a different method'
    @ui.form.fn.hidden '(_, _d, ctx) => (ctx.public?.mfaEnroll?.availableTransports?.length ?? 0) < 2 || ctx.public?.mfaEnroll?.mode === "manage"'
    useDifferentMethod?: ui.action
}

/**
 * MFA enrollment — confirm code, shared by all three transports.
 *
 * **TOTP branch.** The scannable QR + manual base32 secret are shown on the
 * PRECEDING `enroll-totp-qr` step ({@link EnrollTotpQrForm}), so this form only
 * collects the 6-digit code the authenticator generates — `transportHint`
 * reminds the user to enter it.
 *
 * **SMS / email branch.** Single `transportHint` paragraph shows the masked
 * recipient.
 */
@meta.label 'Confirm your verification code'
@wf.context.pass 'public'
@ui.form.submit.text 'Confirm'
export interface EnrollConfirmForm {
    @ui.form.order 1
    @ui.form.fn.value '(_, _d, ctx) => ctx.public?.mfaEnroll?.method === "totp" ? "Enter the 6-digit code from your authenticator app." : ctx.public?.pincode?.sentTo ? "Code sent to " + ctx.public.pincode.sentTo + ". Enter it below to confirm." : "Enter the code to confirm enrollment."'
    transportHint?: ui.paragraph

    @ui.form.order 10
    @ui.form.type 'text'
    @meta.label 'Code'
    @ui.form.autocomplete 'one-time-code'
    @meta.required
    @expect.minLength 4
    @expect.maxLength 12
    @expect.pattern '^[0-9]+$'
    code: string

    @ui.form.action 'resend', 'Resend code'
    @ui.form.fn.attr 'available-at', '(_, _d, ctx) => ctx.public?.pincode?.resendAllowedAt'
    @ui.form.fn.hidden '(_, _d, ctx) => ctx.public?.mfaEnroll?.method === "totp"'
    resend?: ui.action

    @ui.form.action 'useDifferentMethod', 'Use a different method'
    @ui.form.fn.hidden '(_, _d, ctx) => (ctx.public?.mfaEnroll?.availableTransports?.length ?? 0) < 2 || ctx.public?.mfaEnroll?.mode === "manage"'
    useDifferentMethod?: ui.action

    @ui.form.action 'cancel', 'Cancel'
    @ui.form.fn.hidden '(_, _d, ctx) => ctx.public?.mfaEnroll?.mode !== "manage"'
    cancel?: ui.action

    @ui.form.action 'skip', 'Skip for now'
    @ui.form.fn.hidden '(_, _d, ctx) => ctx.public?.mfaEnroll?.mode !== "optional"'
    skip?: ui.action
}

/**
 * MFA enrollment — TOTP QR step. Shown on its OWN pause (the `enroll-totp-qr`
 * step) BETWEEN method-pick and code-entry, so the user scans first and types
 * the code on the next screen — instead of QR + input crowded on one form.
 *
 * `ctx.public.mfaEnroll.uri` carries the `otpauth://` URI (provisioned
 * server-side). The `qrCode` field renders it as a scannable image via the
 * `AsQrCode` component (`@atscript/vue-aooth`); `AsQrCode` also extracts the
 * base32 secret from the URI and shows it for manual entry (its `manualSecret`
 * prop defaults on), so users whose app lacks a scanner can still set up.
 */
@meta.label 'Scan this QR code'
@meta.description 'Open your authenticator app and scan the code (or enter the key manually), then continue to enter the code it shows.'
@wf.context.pass 'public'
@ui.form.submit.text 'Continue'
export interface EnrollTotpQrForm {
    @ui.form.order 5
    @ui.form.component 'AsQrCode'
    @ui.form.fn.attr 'size', '() => 180'
    @ui.form.fn.value '(_, _d, ctx) => ctx.public?.mfaEnroll?.uri || ""'
    qrCode: ui.paragraph

    @ui.form.action 'useDifferentMethod', 'Use a different method'
    @ui.form.fn.hidden '(_, _d, ctx) => (ctx.public?.mfaEnroll?.availableTransports?.length ?? 0) < 2 || ctx.public?.mfaEnroll?.mode === "manage"'
    useDifferentMethod?: ui.action

    @ui.form.action 'cancel', 'Cancel'
    @ui.form.fn.hidden '(_, _d, ctx) => ctx.public?.mfaEnroll?.mode !== "manage"'
    cancel?: ui.action

    @ui.form.action 'skip', 'Skip for now'
    @ui.form.fn.hidden '(_, _d, ctx) => ctx.public?.mfaEnroll?.mode !== "optional"'
    skip?: ui.action
}

/**
 * Manage-MFA menu — the authenticated user's hub for the standalone
 * `auth/add-mfa/flow` once they have ≥1 confirmed factor (shown after the
 * step-up challenge). A single radio whose value encodes both action and
 * target (`add:totp` / `replace:email` / `remove:sms`):
 * - **Add** options come from `ctx.public.manage.candidates` (un-enrolled).
 * - **Change / Remove** options come from `ctx.public.mfa.enrolledMethods`,
 *   with any transport in `ctx.public.manage.locked` omitted (a handle-bound
 *   factor the consumer forbids changing here — `lockedNote` explains why).
 *
 * A zero-MFA user never sees this form — the flow routes straight to the
 * enrol picker (first-time opt-in).
 */
@meta.label 'Manage two-factor authentication'
@meta.description 'Add, change, or remove a verification method.'
@wf.context.pass 'public'
@ui.form.submit.text 'Continue'
export interface ManageMfaForm {
    @ui.form.order 5
    @ui.form.fn.value '(_, _d, ctx) => (ctx.public?.manage?.locked?.length ?? 0) > 0 ? "Some methods are also used to sign in and can’t be changed here." : ""'
    @ui.form.fn.hidden '(_, _d, ctx) => (ctx.public?.manage?.locked?.length ?? 0) === 0'
    lockedNote: ui.paragraph

    @ui.form.order 10
    @ui.form.type 'radio'
    @ui.form.fn.options '(_, _d, ctx) => { const lbl = (t) => t === "totp" ? "authenticator app" : t === "sms" ? "SMS" : t === "email" ? "email" : t; const locked = ctx.public?.manage?.locked ?? []; const out = []; for (const t of (ctx.public?.manage?.candidates ?? [])) out.push({ key: "add:" + t, label: "Add " + lbl(t) }); for (const m of (ctx.public?.mfa?.enrolledMethods ?? [])) { if (locked.includes(m.kind)) continue; out.push({ key: "replace:" + m.kind, label: "Change " + lbl(m.kind) + (m.masked ? " (" + m.masked + ")" : "") }); out.push({ key: "remove:" + m.kind, label: "Remove " + lbl(m.kind) }); } return out; }'
    @meta.label 'What would you like to do?'
    @meta.required
    operation: string

    @ui.form.action 'cancel', 'Cancel'
    cancel?: ui.action
}

/**
 * Manage-MFA — confirm removing a factor. Fieldless apart from the explanatory
 * paragraph; the primary submit ('Remove') performs the removal, 'Cancel'
 * backs out. `manage-menu` has already bound the target transport on
 * `ctx.addMfa.target`; the description reads it back for the user.
 */
@meta.label 'Remove this method?'
@wf.context.pass 'public'
@ui.form.submit.text 'Remove'
export interface RemoveMfaConfirmForm {
    @ui.form.order 1
    @ui.form.fn.value '(_, _d, ctx) => { const t = ctx.public?.mfaEnroll?.method; const lbl = t === "totp" ? "your authenticator app" : t === "sms" ? "SMS codes" : t === "email" ? "email codes" : "this method"; return "Remove " + lbl + " as a two-factor method? You can set it up again later."; }'
    notice: ui.paragraph

    @ui.form.action 'cancel', 'Cancel'
    cancel?: ui.action
}

/**
 * Standalone consent-bump prompt. Fires for returning users with pending
 * consents (set by `prepare-consents` from `ConsentStore.getPendingConsents`)
 * who did NOT pass through any onboarding carrier form (`AskEmailForm` /
 * `AskPhoneForm` / `SetPasswordForm`) on this login — those carrier forms
 * collect consents inline via `WithInlineConsentForm`'s inherited
 * `AsConsentArray` field. The bump-prompt only renders the same inherited
 * consent block (no additional fields).
 */
@meta.label 'Updated terms and policies'
@meta.description 'Please review and accept the updated terms to continue.'
@wf.context.pass 'public'
export interface TermsBumpForm extends WithInlineConsentForm {
}

/**
 * Concurrency-limit kick prompt. Fieldless by design — just the explanatory
 * paragraph plus the primary submit ('Login'): submitting logs out the user's
 * other sessions and continues the login. No alt-action and no in-form cancel;
 * the user backs out by navigating away (the wf state token expires per the
 * engine's TTL).
 */
@meta.label 'Session limit reached'
@meta.description 'You are already signed in elsewhere. Other sessions will be logged out if you proceed to log in.'
@ui.form.submit.text 'Login'
export interface ConcurrencyLimitForm {
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

}

/**
 * Recovery factor-verification form — used when
 * `RecoveryWorkflowOptions.requireKnownRecoveryFactor` is true. The user
 * picks a factor type and supplies its value; the server validates against
 * the enrolled factor (phone last-4 or current TOTP code). Options are
 * built from `ctx.public.preReset.availableRecoveryFactors` (workflow whitelist ∩
 * user's enrolled factors), so users only see factors they can actually
 * verify AND that the admin hasn't disabled via `opts.preReset.allowedFactors`.
 */
@meta.label 'Verify your identity'
@meta.description 'Confirm a detail we have on file before resetting your password.'
@wf.context.pass 'public'
export interface RecoveryFactorForm {
    @ui.form.order 10
    @ui.form.type 'radio'
    @ui.form.fn.options '(_, _d, ctx) => Array.isArray(ctx.public?.preReset?.availableRecoveryFactors) ? ctx.public.preReset.availableRecoveryFactors : []'
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
}

/**
 * Authenticated "change my password" form — surfaced by the
 * change-password.flow `change-password-form` step to a SIGNED-IN user.
 *
 * Standalone (no `extends WithInlineConsentForm`) — a self-service password
 * change carries no consent capture, unlike `SetPasswordForm`. The leading
 * `currentPassword` field is the PRIMARY protection for this flow
 * (re-authentication per OWASP ASVS 6.2.3) — `UserService.changePassword`
 * verifies it before applying policy + history checks server-side.
 *
 * Reuses the same `ctx.public.password.{heading,intro,policies}` surface as
 * `SetPasswordForm`, so the live `AsPasswordRules` renderer and dynamic copy
 * work identically. Heading/intro are staged by `change-password-form`.
 */
@ui.form.fn.title '(_, _d, ctx) => ctx.public?.password?.heading || "Change your password"'
@ui.form.submit.text 'Change password'
@wf.context.pass 'public'
export interface ChangePasswordForm {
    @ui.form.order 5
    @ui.form.fn.value '(_, _d, ctx) => ctx.public?.password?.intro || ""'
    @ui.form.fn.hidden '(_, _d, ctx) => !ctx.public?.password?.intro'
    @ui.form.grid.colSpan '12'
    intro: ui.paragraph

    @ui.form.order 8
    @ui.form.type 'password'
    @meta.label 'Current password'
    @ui.form.autocomplete 'current-password'
    @meta.sensitive
    @meta.required
    currentPassword: string

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
    @meta.label 'Confirm new password'
    @ui.form.autocomplete 'new-password'
    @meta.sensitive
    @meta.required
    @expect.minLength 8
    @ui.form.validate '(v, data) => v === data.newPassword || "Passwords must match"'
    confirmPassword: string

    @ui.form.order 25
    @meta.label 'Password requirements'
    @ui.form.component 'AsPasswordRules'
    @ui.form.fn.attr 'policies', '(_, _d, ctx) => ctx.public?.password?.policies'
    @ui.form.fn.attr 'password', '(_, data) => data.newPassword'
    @ui.form.grid.colSpan '12'
    passwordRules: ui.paragraph
}

/**
 * Prove control of an EXISTING local account before a federated identity is
 * attached to it — the interactive completion of `FederatedLoginService`'s
 * `needs-link` outcome (a verified provider profile whose email matches an
 * existing account under the default `require-interactive-link` policy). The
 * PASSWORD variant: the matched account has a real password, so the user
 * re-enters it to prove ownership.
 *
 * The `prove-control` @Step binds the username to the matched account
 * server-side (the user never types it) and verifies via `UserService.login`,
 * so this form collects only the password. `intro` renders the masked account
 * hint off `ctx.public.proveControl.hint` ("…account for a***@x.com…") — a
 * deliberate, BOUNDED account-existence disclosure (surfacing the candidate is
 * the whole point of `needs-link`). A wrong password re-pauses with a generic
 * inline error; the `cancel` action abandons the link (no account created, no
 * session issued, generic terminal).
 *
 * Override via `setupAuthWorkflows({ forms: { proveControl: MyForm } })`.
 */
@meta.label 'Confirm your identity'
@wf.context.pass 'public'
@ui.form.submit.text 'Verify and link'
export interface ProveControlForm {
    @ui.form.order 5
    @ui.form.fn.value '(_, _d, ctx) => ctx.public?.proveControl?.hint ? "An account for " + ctx.public.proveControl.hint + " already exists. Enter its password to link this sign-in method." : "Enter your existing account password to link this sign-in method."'
    intro: ui.paragraph

    @ui.form.order 10
    @ui.form.type 'password'
    @meta.label 'Password'
    @ui.form.autocomplete 'current-password'
    @meta.sensitive
    @meta.required
    @expect.minLength 1
    password: string

    @ui.form.order 20
    @ui.form.action 'cancel', 'Cancel'
    @ui.form.attr 'align', 'center'
    @ui.form.pushDown
    cancel?: ui.action
}

/**
 * OTP FALLBACK of the `needs-link` completion — used when the matched account
 * is passwordless (`password.isInitial`), so there is no password to re-enter.
 * The `prove-control` @Step mints a one-time code and delivers it to the
 * account's OWN confirmed email/SMS channel (NEVER the provider-supplied
 * address — that would be circular, since the attacker controls the provider
 * account), then this form collects the code. `intro` shows the masked
 * delivery target off `ctx.public.proveControl.sentTo`.
 *
 * Override via `setupAuthWorkflows({ forms: { proveControlOtp: MyForm } })`.
 */
@meta.label 'Confirm your identity'
@wf.context.pass 'public'
@ui.form.submit.text 'Verify and link'
export interface ProveControlOtpForm {
    @ui.form.order 5
    @ui.form.fn.value '(_, _d, ctx) => ctx.public?.proveControl?.sentTo ? "We sent a verification code to " + ctx.public.proveControl.sentTo + ". Enter it to link this sign-in method to your existing account." : "Enter the verification code to link this sign-in method to your existing account."'
    intro: ui.paragraph

    @ui.form.order 10
    @ui.form.type 'text'
    @meta.label 'Verification code'
    @ui.form.autocomplete 'one-time-code'
    @meta.required
    @expect.minLength 4
    @expect.maxLength 12
    @expect.pattern '^[0-9]+$'
    code: string

    // Resend the OTP proof code to the SAME own channel — mirrors PincodeForm's
    // resend. `available-at` binds the server-armed cooldown so the renderer can
    // disable / count down the button; the `prove-control` @Step also gates it
    // server-side (a too-soon resend re-pauses with a "Please wait Ns" message).
    @ui.form.order 15
    @ui.form.action 'resend', 'Resend code'
    @ui.form.fn.attr 'available-at', '(_, _d, ctx) => ctx.public?.proveControl?.resendAllowedAt'
    resend?: ui.action

    @ui.form.order 20
    @ui.form.action 'cancel', 'Cancel'
    @ui.form.attr 'align', 'center'
    @ui.form.pushDown
    cancel?: ui.action
}
