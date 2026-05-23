/**
 * Test-fixture forms for `InviteWorkflowOpts.extraSteps` — small, single-field
 * shapes used by `workflows.invite.spec.ts` to exercise the configurable
 * accept-tail input loop. None of these are meant to be production-shaped;
 * they're the minimum schema that lets the workflow pause for input, hand a
 * parsed `data` object to the consumer-supplied `handle`, and resume.
 */
export interface FullNameForm {
    @ui.form.type 'text'
    @meta.label 'Full name'
    fullName: string
}

export interface BirthDateForm {
    @ui.form.type 'text'
    @meta.label 'Birth date'
    birthDate: string
}

export interface AgeForm {
    @ui.form.type 'text'
    @meta.label 'Age'
    age: string
}
