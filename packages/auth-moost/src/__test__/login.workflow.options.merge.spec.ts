/**
 * Unit coverage for `mergeLoginOpts` (post-resolver reshape).
 *
 * After the policy-options → resolveXxx migration, `LoginWorkflowOpts` only
 * carries infrastructure: pincode timers, magic-link TTL, device-trust cookie
 * binding, and the form-schema replacements. Policy lives on the resolveXxx
 * surface. The tests here pin the surviving groups' partial-merge contract:
 * runtime-relevant defaults (`mfa.pincodeLength` / `deviceTrust.cookieName` /
 * `alternateCredentials.magicLinkTtlMs` / `forms.loginCredentials`) must
 * survive a partial consumer override or step bodies that read
 * `this.opts.<group>.<flag>` would NPE.
 */
import type { TAtscriptAnnotatedType } from "@atscript/typescript/utils";
import { describe, expect, it } from "vite-plus/test";

import { LoginCredentialsForm } from "../atscript/models/forms.as";
import { mergeLoginOpts } from "../workflows/login.workflow.options";

describe("mergeLoginOpts — infrastructure defaults survive partial input", () => {
  it("undefined input → every nested group is populated with its full defaults", () => {
    const opts = mergeLoginOpts();
    expect(opts.mfa.pincodeLength).toBe(6);
    expect(opts.mfa.pincodeResendTimeoutMs).toBe(60_000);
    expect(opts.mfa.pincodeTtlMs).toBeGreaterThan(0);
    expect(opts.deviceTrust.cookieName).toBe("aooth_trusted_device");
    expect(opts.deviceTrust.ttlMs).toBeGreaterThan(0);
    expect(opts.deviceTrust.bindsTo).toBe("cookie");
    expect(opts.alternateCredentials.magicLinkTtlMs).toBeGreaterThan(0);
    expect(opts.forms.profileComplete).toBeTruthy();
  });

  it("partial mfa override (pincodeLength) keeps sibling mfa defaults", () => {
    // Pins partial-merge for `mfa.*`: a naive `mfa: opts.mfa ?? defaults`
    // would drop sibling defaults like `pincodeResendTimeoutMs`, silently
    // breaking the resend throttle for any consumer who tuned only the
    // pincode length.
    const opts = mergeLoginOpts({ mfa: { pincodeLength: 8 } });
    expect(opts.mfa.pincodeLength).toBe(8);
    expect(opts.mfa.pincodeResendTimeoutMs).toBe(60_000);
    expect(opts.mfa.pincodeTtlMs).toBeGreaterThan(0);
  });

  it("partial deviceTrust override (cookieName) keeps sibling defaults", () => {
    const opts = mergeLoginOpts({ deviceTrust: { cookieName: "custom_trust" } });
    expect(opts.deviceTrust.cookieName).toBe("custom_trust");
    expect(opts.deviceTrust.ttlMs).toBeGreaterThan(0);
    expect(opts.deviceTrust.bindsTo).toBe("cookie");
  });

  it("explicit override of a default beats the default (no accidental defaulting)", () => {
    // Without this, `{ ...defaults, ...input }` could be silently flipped to
    // `{ ...input, ...defaults }` and would always win — disabling consumer
    // configuration.
    const opts = mergeLoginOpts({
      mfa: { pincodeLength: 8, pincodeResendTimeoutMs: 1000 },
      deviceTrust: { bindsTo: "cookie+ip" },
    });
    expect(opts.mfa.pincodeLength).toBe(8);
    expect(opts.mfa.pincodeResendTimeoutMs).toBe(1000);
    expect(opts.deviceTrust.bindsTo).toBe("cookie+ip");
  });

  it("forms group: default loginCredentials is the shipped form; consumer override wins", () => {
    // Default-resolved form must be the LoginCredentialsForm class — step
    // bodies read `this.opts.forms.loginCredentials` without optional chain.
    expect(mergeLoginOpts({}).forms.loginCredentials).toBe(LoginCredentialsForm);
    const MyForm = { __is_atscript_annotated_type: true } as unknown as TAtscriptAnnotatedType;
    expect(mergeLoginOpts({ forms: { loginCredentials: MyForm } }).forms.loginCredentials).toBe(
      MyForm,
    );
  });
});
