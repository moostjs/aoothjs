/**
 * Demo recovery identifier form that accepts an email OR a phone (vs the
 * bundled `EmailIdentifierForm` whose `email: string.email` rejects phones).
 * The field is still named `email` so the recovery `request` step's
 * `input.email` read is unchanged; it is plain `string` so a phone passes
 * validation. `DemoAuthWorkflow.resolveRecoveryChannel` then infers the OTP
 * channel from the typed value's shape (phone-shaped → SMS, else email).
 * Wired in for the `recovery-via-sms` variant via `opts.forms.recoveryEmailIdentifier`.
 */
@meta.label 'Forgot your password?'
@meta.description 'Enter your account email or phone and we will send you a recovery code.'
@wf.context.pass 'public'
export interface RecoveryIdentifierForm {
    @ui.form.order 10
    @ui.form.type 'text'
    @meta.label 'Email or phone'
    @ui.form.autocomplete 'username'
    @meta.required
    email: string

    @ui.form.order 20
    @ui.form.action 'backToLogin', 'Back to sign in'
    @ui.form.attr 'align', 'center'
    @ui.form.pushDown
    backToLogin?: ui.action
}
