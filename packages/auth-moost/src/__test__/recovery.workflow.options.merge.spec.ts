/**
 * Unit coverage for `mergeRecoveryOpts`.
 *
 * Post-resolver reshape: opts is infrastructure-only (magic-link TTL, OTP
 * timers, replaceable forms). Policy lives on `resolveXxx(ctx)` overrides —
 * tested separately via the workflow integration specs.
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

  it("delivery.otp partial input preserves sibling defaults", () => {
    // Consumer overrides only codeLength; ttlMs + resendCooldownMs must keep
    // their library defaults (5min / 60s). Pre-reshape this was the policy
    // group's job; post-reshape only the timing knobs live here.
    const resolved = mergeRecoveryOpts({
      delivery: { otp: { codeLength: 8 } },
    });
    expect(resolved.delivery.otp.codeLength).toBe(8);
    expect(resolved.delivery.otp.ttlMs).toBe(5 * 60_000);
    expect(resolved.delivery.otp.resendCooldownMs).toBe(60_000);
  });
});
