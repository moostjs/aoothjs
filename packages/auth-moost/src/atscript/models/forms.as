/**
 * Inline consent collection — a single dynamic `consents: string[]` field
 * attached to whichever carrier form the user is already filling out.
 * Carrier forms `extends WithInlineConsentForm` to inherit it without
 * duplication.
 *
 * Backend transport: `@wf.context.pass 'pendingConsents'` ships the
 * descriptor array (set by the `prepare-consents` @Step from
 * `ConsentStore.getPendingConsents()`) to the client. The
 * `@ui.form.fn.attr 'pendingConsents'` expression below binds it onto the
 * `AsConsentArray` component (`@atscript/vue-aooth`) which renders one
 * checkbox per descriptor; the user-submitted `string[]` carries back the
 * SUBSET of `descriptor.id`s the user ticked.
 *
 * SPA-side hide-when-empty: `AsConsentArray` self-hides when
 * `pendingConsents` is empty / unset — no `@ui.form.fn.hidden` is needed
 * on the field. A carrier form whose customer hasn't configured any
 * pending consents renders WITHOUT this block.
 *
 * SECURITY (silent-drop): the server-side `processInlineConsent` helper
 * uses its OWN `ctx.pendingConsents` as the authoritative whitelist; any
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
@wf.context.pass 'pendingConsents'
@wf.context.pass 'consentsPersisted'
export interface WithInlineConsentForm {
    @meta.label 'Pending consents'
    @ui.form.component 'AsConsentArray'
    @ui.form.fn.attr 'pendingConsents', '(_, _d, ctx) => ctx.pendingConsents'
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
 * leading `transportHint` paragraph reads `mfaMethod` + `pinSentTo` (masked
 * recipient) out of the workflow context so the operator knows which factor
 * the workflow is currently verifying. The hint requires `installDynamicResolver()`
 * from `@atscript/ui-fns` on the consumer side; without it `@ui.form.fn.value`
 * stays inert and the paragraph renders empty.
 */
@wf.context.pass 'mfaMethod'
@wf.context.pass 'pinSentTo'
@wf.context.pass 'mfaMethodCount'
@wf.context.pass 'mfaBackupCodes'
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
    @ui.form.fn.hidden '(_, _d, ctx) => (ctx.mfaMethodCount ?? 0) < 2'
    useDifferentMethod?: ui.action

    @ui.form.action 'useBackupCode', 'Use backup code'
    @ui.form.fn.hidden '(_, _d, ctx) => !ctx.mfaBackupCodes'
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
@wf.context.pass 'pendingConsents'
@wf.context.pass 'consentsPersisted'
export interface SetPasswordForm extends WithInlineConsentForm {
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
    confirmPassword: string

    @ui.form.order 30
    @ui.form.action 'logout', 'Logout'
    logout?: ui.action

    @ui.form.order 40
    @ui.form.action 'cancel', 'Cancel'
    cancel?: ui.action

    @ui.form.order 50
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
    @ui.form.fn.options '(_, _data, context) => Array.isArray(context.availableRoles) ? context.availableRoles.map(r => ({ key: r, label: r })) : []'
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
    @ui.form.type 'radio'
    @ui.form.options 'Email', 'email'
    @ui.form.options 'Shareable link', 'shareableLink'
    @meta.label 'Delivery mode'
    @meta.required
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
 * supplied value is in the user's enrolled set. The dropdown options are
 * built from `ctx.mfaEnrolledMethods` (a `MfaSummary[]` populated by
 * `prepareMfaOptions`) so the user only sees factors they actually have.
 */
@wf.context.pass 'mfaBackupCodes'
@wf.context.pass 'mfaEnrolledMethods'
export interface Select2faForm {
    @ui.form.type 'radio'
    @ui.form.fn.options '(_, _d, ctx) => Array.isArray(ctx.mfaEnrolledMethods) ? ctx.mfaEnrolledMethods.map(m => ({ key: m.methodName, label: m.kind === "totp" ? "TOTP (Authenticator app)" : m.kind === "email" ? "Email" : m.kind === "sms" ? "SMS" : m.kind })) : []'
    @meta.label 'MFA method'
    @meta.required
    methodName: string

    @ui.form.type 'checkbox'
    @meta.label 'Save as default'
    @meta.default 'false'
    saveAsDefault: boolean

    @ui.form.action 'useBackupCode', 'Use backup code'
    @ui.form.fn.hidden '(_, _d, ctx) => !ctx.mfaBackupCodes'
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
@wf.context.pass 'mfaMethodCount'
@wf.context.pass 'mfaBackupCodes'
@wf.context.pass 'deviceTrustOptIn'
@wf.context.pass 'recoveryTransportCount'
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
    @meta.default 'false'
    @ui.form.fn.hidden '(_, _d, ctx) => !ctx.deviceTrustOptIn'
    rememberDevice: boolean

    @ui.form.action 'resend', 'Resend code'
    resend?: ui.action

    @ui.form.action 'useDifferentMethod', 'Use a different method'
    @ui.form.fn.hidden '(_, _d, ctx) => (ctx.mfaMethodCount ?? 0) < 2'
    useDifferentMethod?: ui.action

    @ui.form.action 'useBackupCode', 'Use backup code'
    @ui.form.fn.hidden '(_, _d, ctx) => !ctx.mfaBackupCodes'
    useBackupCode?: ui.action

    @ui.form.action 'backToLogin', 'Back to sign-in'
    backToLogin?: ui.action

    @ui.form.action 'useDifferentTransport', 'Use a different transport'
    @ui.form.fn.hidden '(_, _d, ctx) => (ctx.recoveryTransportCount ?? 0) < 2'
    useDifferentTransport?: ui.action
}

/**
 * Email-only form for the `ask/email` enrollment step.
 */
@wf.context.pass 'pendingConsents'
@wf.context.pass 'consentsPersisted'
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
@wf.context.pass 'pendingConsents'
@wf.context.pass 'consentsPersisted'
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
 * come from `ctx.enrollAvailableTransports` so only consumer-enabled
 * transports appear.
 */
@wf.context.pass 'enrollAvailableTransports'
@wf.context.pass 'enrollMode'
export interface EnrollPickMethodForm {
    @ui.form.type 'radio'
    @ui.form.fn.options '(_, _d, ctx) => Array.isArray(ctx.enrollAvailableTransports) ? ctx.enrollAvailableTransports.map(t => ({ key: t, label: t === "totp" ? "Authenticator app (TOTP)" : t === "sms" ? "SMS" : t === "email" ? "Email" : t })) : []'
    @meta.label 'Choose a verification method'
    @meta.required
    method: string

    @ui.form.action 'skip', 'Skip for now'
    @ui.form.fn.hidden '(_, _d, ctx) => ctx.enrollMode !== "optional"'
    skip?: ui.action
}

/**
 * Forced MFA enrollment — address collection for sms/email. TOTP skips this
 * form (secret is provisioned server-side).
 *
 * `skip` is hidden unless `enrollMode === 'optional'` (`'required'` mode
 * forbids backing out mid-flow). `useDifferentMethod` is hidden when the
 * consumer has only one transport configured (nothing to switch to).
 */
@wf.context.pass 'enrollMethod'
@wf.context.pass 'enrollMode'
@wf.context.pass 'enrollAvailableTransports'
export interface EnrollAddressForm {
    @ui.form.type 'text'
    @meta.label 'Address'
    @meta.required
    address: string

    @ui.form.action 'skip', 'Skip for now'
    @ui.form.fn.hidden '(_, _d, ctx) => ctx.enrollMode !== "optional"'
    skip?: ui.action

    @ui.form.action 'useDifferentMethod', 'Use a different method'
    @ui.form.fn.hidden '(_, _d, ctx) => (ctx.enrollAvailableTransports?.length ?? 0) < 2'
    useDifferentMethod?: ui.action
}

/**
 * Forced MFA enrollment — confirm code, shared by all three transports. The
 * leading paragraph swaps between "scan this QR" (totp) and "code sent to …"
 * (sms/email) based on `enrollMethod`; `enrollSecret` / `enrollUri` are passed
 * for the totp QR + manual-entry fallback.
 */
@wf.context.pass 'enrollMethod'
@wf.context.pass 'enrollMode'
@wf.context.pass 'enrollSecret'
@wf.context.pass 'enrollUri'
@wf.context.pass 'enrollAvailableTransports'
@wf.context.pass 'pinSentTo'
@ui.form.submit.text 'Confirm'
export interface EnrollConfirmForm {
    @ui.form.fn.value '(_, _d, ctx) => ctx.enrollMethod === "totp" ? "Scan the QR with your authenticator app, or enter the secret manually. Then type the 6-digit code it generates." : ctx.enrollMethod ? "Code sent to " + (ctx.pinSentTo || "your " + ctx.enrollMethod) + ". Enter it below to confirm." : "Enter the code to confirm enrollment."'
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
    @ui.form.fn.hidden '(_, _d, ctx) => ctx.enrollMethod === "totp"'
    resend?: ui.action

    @ui.form.action 'useDifferentMethod', 'Use a different method'
    @ui.form.fn.hidden '(_, _d, ctx) => (ctx.enrollAvailableTransports?.length ?? 0) < 2'
    useDifferentMethod?: ui.action

    @ui.form.action 'skip', 'Skip for now'
    @ui.form.fn.hidden '(_, _d, ctx) => ctx.enrollMode !== "optional"'
    skip?: ui.action
}

/**
 * Default minimal profile completion form. Consumers replace via
 * `LoginWorkflowOptions.profileCompleteForm` for richer shapes.
 */
@wf.context.pass 'pendingConsents'
@wf.context.pass 'consentsPersisted'
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
@wf.context.pass 'pendingConsents'
@wf.context.pass 'consentsPersisted'
export interface TermsBumpForm extends WithInlineConsentForm {
}

/**
 * Tenant picker — `tenantId` matches one of `ctx.availableTenants[].id`.
 * Options are built from `ctx.availableTenants` (set by the workflow's
 * `tenant-select` step / `loadTenants` hook); `@wf.context.pass` whitelists
 * the key so it survives `extractPassContext`.
 */
@wf.context.pass 'availableTenants'
export interface TenantSelectForm {
    @ui.form.type 'radio'
    @ui.form.fn.options '(_, _d, ctx) => Array.isArray(ctx.availableTenants) ? ctx.availableTenants.map(t => ({ key: t.id, label: t.name })) : []'
    @meta.label 'Tenant'
    @meta.required
    tenantId: string
}

/**
 * Persona picker — `personaId` matches one of `ctx.availablePersonas[].id`.
 * Options are built from `ctx.availablePersonas` (set by the workflow's
 * `persona-select` step / `loadPersonas` hook); `@wf.context.pass` whitelists
 * the key so it survives `extractPassContext`.
 */
@wf.context.pass 'availablePersonas'
export interface PersonaSelectForm {
    @ui.form.type 'radio'
    @ui.form.fn.options '(_, _d, ctx) => Array.isArray(ctx.availablePersonas) ? ctx.availablePersonas.map(p => ({ key: p.id, label: p.label })) : []'
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
    @ui.form.type 'radio'
    @ui.form.options 'Magic link', 'magicLink'
    @ui.form.options 'One-time code', 'otp'
    @meta.label 'Recovery method'
    @meta.required
    mode: string

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
@wf.context.pass 'availableRecoveryFactors'
export interface RecoveryFactorForm {
    @ui.form.type 'radio'
    @ui.form.fn.options '(_, _d, ctx) => Array.isArray(ctx.availableRecoveryFactors) ? ctx.availableRecoveryFactors : []'
    @meta.label 'Factor'
    @meta.required
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
