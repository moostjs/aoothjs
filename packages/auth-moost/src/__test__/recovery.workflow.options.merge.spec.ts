/**
 * Unit coverage for `mergeRecoveryOpts`.
 *
 * Post-AuthOpts reshape: `RecoveryWorkflowOpts` is forms-only. Magic-link TTL
 * and OTP pincode timers/length moved onto the shared `AuthOpts` provider.
 * The remaining contract this file pins is the form-schema replacement surface
 * — without it, step bodies reading `this.opts.forms.<form>` would NPE on
 * missing nested keys when a consumer supplies a partial `forms` map.
 */
import type { TAtscriptAnnotatedType } from "@atscript/typescript/utils";
import { describe, expect, it } from "vite-plus/test";

import { EmailIdentifierForm } from "../atscript/models/forms.as";
import { mergeRecoveryOpts } from "../workflows/recovery.workflow.options";

describe("mergeRecoveryOpts — defaults survive partial input", () => {
  it("forms group: default emailIdentifier is the shipped form; consumer override wins", () => {
    expect(mergeRecoveryOpts({}).forms.emailIdentifier).toBe(EmailIdentifierForm);
    const MyForm = { __is_atscript_annotated_type: true } as unknown as TAtscriptAnnotatedType;
    expect(mergeRecoveryOpts({ forms: { emailIdentifier: MyForm } }).forms.emailIdentifier).toBe(
      MyForm,
    );
  });

  it("undefined input → forms group is populated with its full defaults", () => {
    const opts = mergeRecoveryOpts();
    expect(opts.forms.emailIdentifier).toBe(EmailIdentifierForm);
    expect(opts.forms.setPassword).toBeTruthy();
  });
});
