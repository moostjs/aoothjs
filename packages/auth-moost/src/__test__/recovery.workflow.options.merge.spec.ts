/**
 * Unit coverage for `mergeRecoveryOpts`.
 *
 * Same shape as the login + invite merge specs: each test pins a specific WHY
 * — partial input must not drop sibling defaults, and consumer overrides must
 * win against the built-in form classes.
 */
import type { TAtscriptAnnotatedType } from "@atscript/typescript/utils";
import { describe, expect, it } from "vite-plus/test";

import { EmailIdentifierForm } from "../atscript/models/forms.as.js";
import { mergeRecoveryOpts } from "../workflows/recovery.workflow.options";

describe("mergeRecoveryOpts — defaults survive partial input", () => {
  it("forms group: default emailIdentifier is the shipped form; consumer override wins", () => {
    expect(mergeRecoveryOpts({}).forms.emailIdentifier).toBe(EmailIdentifierForm);
    const MyForm = { __is_atscript_annotated_type: true } as unknown as TAtscriptAnnotatedType;
    expect(mergeRecoveryOpts({ forms: { emailIdentifier: MyForm } }).forms.emailIdentifier).toBe(
      MyForm,
    );
  });
});
