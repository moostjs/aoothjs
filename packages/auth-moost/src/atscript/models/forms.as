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
@ui.form.submit.text 'Sign in'
export interface LoginCredentialsForm {
    @ui.form.type 'text'
    @meta.label 'Username'
    @ui.form.autocomplete 'username'
    @meta.required
    @expect.minLength 1
    username: string

    @ui.form.type 'password'
    @meta.label 'Password'
    @ui.form.autocomplete 'current-password'
    @meta.sensitive
    @meta.required
    @expect.minLength 1
    @ui.form.action 'forgotPassword', 'Forgot password?'
    @wf.action.withData 'forgotPassword'
    password: string

    @ui.form.action 'signup', 'Sign up'
    signup?: ui.action

    @ui.form.action 'magicLink', 'Sign in with a magic link'
    magicLink?: ui.action
}

/**
 * MFA code form. Shared by TOTP, email-OTP, and SMS-OTP branches — the
 * leading `transportHint` paragraph reads `mfaMethod` + `pinSentTo` (masked
 * recipient) out of the workflow context so the operator knows which factor
 * the workflow is currently verifying. The hint requires `installDynamicResolver()`
 * from `@atscript/ui-fns` on the consumer side; without it `@ui.form.fn.value`
 * stays inert and the paragraph renders empty.
 */
@wf.context.pass 'mfaMethod'
@wf.context.pass 'pinSentTo'
@ui.form.submit.text 'Verify'
export interface MfaCodeForm {
    @ui.form.fn.value '(_, _d, ctx) => ctx.mfaMethod === "totp" ? "Enter the current 6-digit code from your authenticator app." : ctx.mfaMethod ? "Code sent to " + (ctx.pinSentTo || "your " + ctx.mfaMethod) + " — check the dev server console for the code." : "Enter your verification code."'
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
    useDifferentMethod?: ui.action

    @ui.form.action 'useBackupCode', 'Use backup code'
    useBackupCode?: ui.action
}

/**
 * Backup-code form (alphanumeric, hyphen-grouped — e.g. `XXXX-XXXX-XX`).
 *
 * `UserService.generateBackupCodes` uses a 31-character alphabet (uppercase
 * letters minus I/O/L, digits minus 0/1) formatted with hyphens between groups
 * of 4 — the regex below mirrors that shape. Kept separate from
 * `MfaCodeForm` so TOTP entry stays strict-digits.
 */
export interface BackupCodeForm {
    @ui.form.type 'text'
    @meta.label 'Backup code'
    @ui.form.autocomplete 'one-time-code'
    @meta.required
    @expect.minLength 4
    @expect.maxLength 32
    @expect.pattern '^[A-Z2-9-]+$'
    code: string
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
@wf.context.pass 'defaults'
export interface EmailIdentifierForm {
    @ui.form.type 'text'
    @meta.label 'Email'
    @ui.form.autocomplete 'email'
    @meta.required
    email: string.email

    @ui.form.action 'backToLogin', 'Back to sign-in'
    backToLogin?: ui.action
}

/**
 * Set new password form.
 *
 * `confirmPassword` equality is enforced in the workflow step (cross-field
 * checks are not expressible via atscript annotations).
 *
 * `@wf.context.pass 'passwordPolicies'` whitelists the workflow ctx key so the
 * prior preparePasswordRules / setPassword steps can ship the transferable
 * password-policy rules (`UserService.getTransferablePolicies()`) to the
 * client for rendering rule hints next to the inputs. Without this annotation
 * the key is stripped by `extractPassContext` before reaching the client.
 */
@wf.context.pass 'passwordPolicies'
export interface SetPasswordForm {
    @ui.form.type 'password'
    @meta.label 'New password'
    @ui.form.autocomplete 'new-password'
    @meta.sensitive
    @meta.required
    @expect.minLength 8
    newPassword: string

    @ui.form.type 'password'
    @meta.label 'Confirm password'
    @ui.form.autocomplete 'new-password'
    @meta.sensitive
    @meta.required
    @expect.minLength 8
    confirmPassword: string

    @ui.form.action 'logout', 'Logout'
    logout?: ui.action

    @ui.form.action 'cancel', 'Cancel'
    cancel?: ui.action

    @ui.form.action 'backToLogin', 'Back to sign-in'
    backToLogin?: ui.action
}

/**
 * Invite form — used by an admin to send an invite magic link.
 *
 * `@wf.context.pass 'availableRoles'` whitelists the workflow ctx key so the
 * `inviteAdminInviteForm` step can pass the role-picker options into the
 * client form when `opts.getAvailableRoles` is wired.
 */
@wf.context.pass 'availableRoles'
export interface InviteForm {
    @ui.form.type 'text'
    @meta.label 'Email'
    @ui.form.autocomplete 'email'
    @meta.required
    email: string.email

    @ui.form.type 'text'
    @meta.label 'First name'
    firstName?: string

    @ui.form.type 'text'
    @meta.label 'Last name'
    lastName?: string

    // UX: select-on-array currently renders single-text-per-item via AsArray;
    // dedicated multi-select widget tracked as atscript-ui follow-up.
    @ui.form.type 'select'
    @ui.form.fn.options '(_, _data, context) => Array.isArray(context.availableRoles) ? context.availableRoles.map(r => ({ value: r, label: r })) : []'
    @meta.label 'Roles'
    roles?: string[]

    @ui.form.action 'cancel', 'Cancel'
    cancel?: ui.action
}

/**
 * Email-only form — used by `auth.reInvite` (loadPendingUser step) and
 * `auth.cancelInvite` (cancelInvite step). Separate from `EmailIdentifierForm`
 * so future invite-side tweaks don't ripple into the recovery form.
 */
export interface InviteEmailForm {
    @ui.form.type 'text'
    @meta.label 'Email'
    @ui.form.autocomplete 'email'
    @meta.required
    email: string.email

    @ui.form.action 'cancel', 'Cancel'
    cancel?: ui.action
}

/**
 * Send-mode picker — rendered only when
 * `InviteWorkflowOptions.sendMode === 'choice'`. `mode` matches one of
 * `'email'` or `'shareableLink'`.
 */
export interface InviteSendModeForm {
    @ui.form.type 'text'
    @meta.label 'Delivery mode'
    @meta.required
    @expect.pattern '^(email|shareableLink)$'
    mode: string

    @ui.form.action 'cancel', 'Cancel'
    cancel?: ui.action
}

/**
 * Select an enrolled MFA method (Phase 4 `select2fa` step).
 *
 * The workflow renders this only when the user has >1 enrolled methods after
 * `opts.mfaTransports` filtering. `methodName` is the `MfaMethod.name`
 * (e.g. `"totp"`, `"email"`, `"sms"`); the workflow itself validates that the
 * supplied value is in the user's enrolled set.
 */
export interface Select2faForm {
    @ui.form.type 'text'
    @meta.label 'MFA method'
    @meta.required
    methodName: string

    @ui.form.type 'checkbox'
    @meta.label 'Save as default'
    saveAsDefault?: boolean

    @ui.form.action 'useBackupCode', 'Use backup code'
    useBackupCode?: ui.action
}

/**
 * Generic 6-digit pincode form — used by both login and recovery OTP flows.
 *
 * `rememberDevice` is rendered only when `opts.deviceTrust && opts.deviceTrustOptIn`.
 *
 * The leading `transportHint` paragraph reads `mfaMethod` + `pinSentTo` (the
 * masked recipient set by the pincode-send step) out of the workflow context
 * so the operator can see which factor the workflow is currently verifying.
 * Requires `installDynamicResolver()` from `@atscript/ui-fns` on the consumer
 * side; without it `@ui.form.fn.value` stays inert and the paragraph renders empty.
 */
@wf.context.pass 'mfaMethod'
@wf.context.pass 'pinSentTo'
@ui.form.submit.text 'Verify'
export interface PincodeForm {
    @ui.form.fn.value '(_, _d, ctx) => ctx.mfaMethod === "totp" ? "Enter the current 6-digit code from your authenticator app." : ctx.mfaMethod ? "Code sent to " + (ctx.pinSentTo || "your " + ctx.mfaMethod) + " — check the dev server console for the code." : "Enter your verification code."'
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
    rememberDevice?: boolean

    @ui.form.action 'resend', 'Resend code'
    resend?: ui.action

    @ui.form.action 'useDifferentMethod', 'Use a different method'
    useDifferentMethod?: ui.action

    @ui.form.action 'useBackupCode', 'Use backup code'
    useBackupCode?: ui.action

    @ui.form.action 'backToLogin', 'Back to sign-in'
    backToLogin?: ui.action

    @ui.form.action 'useDifferentTransport', 'Use a different transport'
    useDifferentTransport?: ui.action
}

/**
 * Email-only form for the `ensureEmail` enrollment loop.
 */
export interface AskEmailForm {
    @ui.form.type 'text'
    @meta.label 'Email'
    @ui.form.autocomplete 'email'
    @meta.required
    email: string.email
}

/**
 * Phone-only form for the `ensurePhone` enrollment loop. Free-form text —
 * E.164 normalization happens server-side.
 */
export interface AskPhoneForm {
    @ui.form.type 'text'
    @meta.label 'Phone (E.164)'
    @ui.form.autocomplete 'tel'
    @meta.required
    phone: string
}

/**
 * Terms & conditions acceptance form.
 */
export interface TermsAcceptForm {
    @ui.form.type 'text'
    @meta.label 'Accepted version'
    @meta.required
    acceptedVersion: string

    @ui.form.type 'checkbox'
    @meta.label 'I accept the Terms & Conditions'
    @meta.required
    accepted: boolean

    @ui.form.action 'decline', 'Decline'
    decline?: ui.action
}

/**
 * Default minimal profile completion form. Consumers replace via
 * `LoginWorkflowOptions.profileCompleteForm` for richer shapes.
 */
export interface ProfileCompleteForm {
    @ui.form.type 'text'
    @meta.label 'First name'
    firstName?: string

    @ui.form.type 'text'
    @meta.label 'Last name'
    lastName?: string
}

/**
 * Marketing consent opt-in.
 */
export interface ConsentMarketingForm {
    @ui.form.type 'checkbox'
    @meta.label 'I would like to receive marketing emails'
    optIn?: boolean
}

/**
 * Tenant picker — `tenantId` matches one of `ctx.availableTenants[].id`.
 */
export interface TenantSelectForm {
    @ui.form.type 'text'
    @meta.label 'Tenant'
    @meta.required
    tenantId: string
}

/**
 * Persona picker — `personaId` matches one of `ctx.availablePersonas[].id`.
 */
export interface PersonaSelectForm {
    @ui.form.type 'text'
    @meta.label 'Persona'
    @meta.required
    personaId: string
}

/**
 * Concurrency-limit kick prompt — user picks between logging out other
 * sessions or cancelling the login.
 */
export interface ConcurrencyLimitForm {
    @ui.form.type 'text'
    @meta.label 'Action'
    @meta.required
    @expect.pattern '^(logoutOthers|cancel)$'
    action: string

    @ui.form.action 'cancel', 'Cancel'
    cancel?: ui.action

    @ui.form.action 'logoutOthers', 'Log out other sessions'
    logoutOthers?: ui.action
}

/**
 * Identifier form for the magic-link login path — same shape as
 * {@link EmailIdentifierForm} but kept separate because future iterations may
 * accept either email or username.
 */
export interface MagicLinkRequestForm {
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
export interface RecoveryModeSelectForm {
    @ui.form.type 'text'
    @meta.label 'Recovery method'
    @meta.required
    @expect.pattern '^(magicLink|otp)$'
    mode: string

    @ui.form.action 'backToLogin', 'Back to sign-in'
    backToLogin?: ui.action
}

/**
 * Recovery factor-verification form — used when
 * `RecoveryWorkflowOptions.requireKnownRecoveryFactor` is true. The user
 * picks a factor type and supplies its value; the server validates against
 * the enrolled factor (phone last-4 or current TOTP code).
 */
export interface RecoveryFactorForm {
    @ui.form.type 'text'
    @meta.label 'Factor'
    @meta.required
    @expect.pattern '^(phone|totp)$'
    factor: string

    @ui.form.type 'text'
    @meta.label 'Value'
    @meta.required
    @expect.minLength 4
    @expect.maxLength 12
    value: string

    @ui.form.action 'backToLogin', 'Back to sign-in'
    backToLogin?: ui.action
}
