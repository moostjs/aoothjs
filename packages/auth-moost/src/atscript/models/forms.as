/**
 * Default login credentials form.
 *
 * Override via `setupAuthWorkflows({ forms: { loginCredentials: MyForm } })`.
 */
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
    password: string
}

/**
 * MFA code form (TOTP today; email/SMS OTP later).
 */
export interface MfaCodeForm {
    @ui.form.type 'text'
    @meta.label 'Verification code'
    @ui.form.autocomplete 'one-time-code'
    @meta.required
    @expect.minLength 4
    @expect.maxLength 12
    @expect.pattern '^[0-9]+$'
    code: string
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
}

/**
 * Set new password form.
 *
 * `confirmPassword` equality is enforced in the workflow step (cross-field
 * checks are not expressible via atscript annotations).
 */
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

    @ui.form.type 'text'
    @meta.label 'Roles (comma-separated, optional)'
    @ui.form.placeholder 'admin,editor'
    roles?: string
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
}

/**
 * Generic 6-digit pincode form — used by both login and recovery OTP flows.
 *
 * `rememberDevice` is rendered only when `opts.deviceTrust && opts.deviceTrustOptIn`.
 */
export interface PincodeForm {
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
}
