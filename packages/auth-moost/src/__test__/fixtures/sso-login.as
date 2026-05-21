/**
 * Test-fixture form: extends `LoginCredentialsForm` with phantom `ui.action`
 * fields whitelisting the SSO provider ids used by
 * `workflows.login.options.spec.ts`.
 *
 * SSO providers are consumer-configured at runtime via
 * `opts.alternateCredentials.ssoProviders[].id` — the bundled
 * `LoginCredentialsForm` deliberately does NOT declare them so
 * `useAtscriptWf(form).resolveAction()` can refuse arbitrary action ids.
 * Consumers (and these tests) opt into SSO by supplying their own form via
 * `opts.forms.loginCredentials` that declares one phantom field per provider.
 */
export interface SsoLoginCredentialsForm {
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

    @ui.form.action 'google', 'Sign in with Google'
    google?: ui.action

    @ui.form.action 'okta', 'Sign in with Okta'
    okta?: ui.action
}
