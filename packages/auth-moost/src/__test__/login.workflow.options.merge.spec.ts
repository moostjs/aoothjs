/**
 * Unit coverage for `mergeLoginOpts` (post-AuthOpts reshape).
 *
 * After moving the cross-workflow infrastructure (pincode timers, magic-link
 * TTL, TOTP issuer, login URL) onto the shared `AuthOpts` DI provider,
 * `LoginWorkflowOpts` carries login-specific infrastructure only: the
 * `deviceTrust` cookie binding and the form-schema replacement map. The tests
 * here pin the surviving groups' partial-merge contract: runtime-relevant
 * defaults (`deviceTrust.cookieName` / `forms.loginCredentials`) must
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
    expect(opts.deviceTrust.cookieName).toBe("aooth_trusted_device");
    expect(opts.deviceTrust.ttlMs).toBeGreaterThan(0);
    expect(opts.deviceTrust.bindsTo).toBe("cookie");
    expect(opts.forms.profileComplete).toBeTruthy();
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
      deviceTrust: { bindsTo: "cookie+ip" },
    });
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
