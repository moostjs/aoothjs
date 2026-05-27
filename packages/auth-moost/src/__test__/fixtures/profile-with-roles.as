/**
 * Test-fixture profile form: demonstrates the worst-case shape a consumer
 * might (incorrectly) declare, where the `.as` schema legitimizes the
 * privileged top-level UserCredentials keys (`roles`, `password`, `account`,
 * `mfa`, etc.) as accepted form fields.
 *
 * Used by `workflows.invite.spec.ts` security regression test to prove the
 * InviteWorkflow's `STRIPPED_FROM_PROFILE` defense at the workflow layer —
 * the form-validation pass alone is NOT what's blocking escalation, because
 * here the form intentionally accepts the keys. Without the workflow strip,
 * an invitee could submit `roles: ['admin']` and the default `applyProfile`
 * would deep-merge it onto the user row.
 */
export interface ProfileWithRolesForm {
    @ui.form.type 'text'
    @meta.label 'First name'
    firstName?: string

    @ui.form.type 'text'
    @meta.label 'Last name'
    lastName?: string

    // Attacker-controlled / mis-declared privileged keys — every one MUST
    // be stripped by `applyProfileStep`'s `STRIPPED_FROM_PROFILE` set.

    @ui.form.type 'text'
    roles?: string[]

    @ui.form.type 'text'
    password?: {
        hash?: string
    }

    @ui.form.type 'text'
    passwordHistory?: string[]

    @ui.form.type 'text'
    account?: {
        active?: boolean
        locked?: boolean
        pendingInvitation?: boolean
    }

    @ui.form.type 'text'
    mfa?: {
        enabled?: boolean
    }

    @ui.form.type 'text'
    trustedDevices?: string[]

    @ui.form.type 'number'
    version?: number

    @ui.form.type 'text'
    id?: string

    @ui.form.type 'text'
    username?: string
}
