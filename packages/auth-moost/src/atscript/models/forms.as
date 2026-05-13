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
 * Email identifier form — used for password recovery initiation.
 */
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
 */
export interface InviteForm {
    @ui.form.type 'text'
    @meta.label 'Email'
    @ui.form.autocomplete 'email'
    @meta.required
    email: string.email

    @ui.form.type 'text'
    @meta.label 'Roles (comma-separated, optional)'
    @ui.form.placeholder 'admin,editor'
    roles?: string
}
