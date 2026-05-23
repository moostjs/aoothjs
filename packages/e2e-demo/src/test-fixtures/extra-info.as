/**
 * Test-fixture form for `InviteWorkflowOpts.extraSteps` e2e tests in
 * `test/wf-invite.spec.ts`. Two typed fields so the round-trip through the
 * HTTP wire (atscript form parser → sanitized `data` → handler) actually
 * has something to assert against. Lives under `src/` so the demo's
 * `atscript.config.mts` (`rootDir: "src"`) picks it up.
 */
@ui.form.submit.text 'Continue'
export interface ExtraInfoForm {
    @ui.form.type 'text'
    @meta.label 'Full name'
    @meta.required
    @expect.minLength 2
    fullName: string

    @ui.form.type 'text'
    @meta.label 'Date of birth (YYYY-MM-DD)'
    @meta.required
    dateOfBirth: string
}
