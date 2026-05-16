/**
 * Unit coverage for `mergeLoginOpts`.
 *
 * The deep-merge is hand-rolled (one `{ ...defaults, ...input }` per nested
 * group). Tests here pin the contract that runtime-relevant defaults survive
 * a partial input — without this guarantee, schema conditions that read
 * `ctx.opts.<group>.<flag>` after `init` would NPE on missing nested keys.
 *
 * Each test asserts a specific WHY: "if a consumer overrides one nested key,
 * sibling defaults must still be present at runtime." That intent is broken
 * the moment someone replaces `{ ...defaults, ...input }` with `input` for any
 * group — which is exactly the regression this file guards against.
 */
import type { TAtscriptAnnotatedType } from "@atscript/typescript/utils";
import { describe, expect, it } from "vite-plus/test";

import { LoginCredentialsForm } from "../atscript/models/forms.as.js";
import { mergeLoginOpts } from "../workflows/login.workflow.options";

describe("mergeLoginOpts — defaults survive partial input", () => {
  it("undefined input → every nested group is populated with its full defaults", () => {
    const opts = mergeLoginOpts();
    expect(opts.mfa.enabled).toBe(true);
    expect(opts.mfa.transports).toEqual(["sms", "email", "totp"]);
    expect(opts.mfa.pincodeLength).toBe(6);
    expect(opts.alternateCredentials.forgotPassword).toBe(true);
    expect(opts.alternateCredentials.recoveryUrl).toBe("/recover");
    expect(opts.guards.passwordInitial).toBe(true);
    expect(opts.finalize.auditLogin).toBe(true);
    expect(opts.finalize.redirect).toBe("referer");
    expect(opts.deviceTrust.cookieName).toBe("aooth_trusted_device");
    expect(opts.forms.profileComplete).toBeTruthy();
  });

  it("partial mfa override (enabled:false) keeps mfa.transports default", () => {
    // Regression: a naive merge like `mfa: opts.mfa ?? defaults` would drop
    // `transports`, breaking the boot-time validator that gates on
    // `mfa.transports.length > 0`.
    const opts = mergeLoginOpts({ mfa: { enabled: false } });
    expect(opts.mfa.enabled).toBe(false);
    expect(opts.mfa.transports).toEqual(["sms", "email", "totp"]);
    expect(opts.mfa.pincodeLength).toBe(6);
    expect(opts.mfa.backupCodes).toBe(true);
  });

  it("partial alternateCredentials override keeps sibling defaults", () => {
    const opts = mergeLoginOpts({ alternateCredentials: { signup: true } });
    expect(opts.alternateCredentials.signup).toBe(true);
    expect(opts.alternateCredentials.forgotPassword).toBe(true);
    expect(opts.alternateCredentials.recoveryUrl).toBe("/recover");
    expect(opts.alternateCredentials.ssoProviders).toEqual([]);
  });

  it("partial finalize override (redirect:'home') keeps auditLogin default true", () => {
    const opts = mergeLoginOpts({ finalize: { redirect: "home" } });
    expect(opts.finalize.redirect).toBe("home");
    expect(opts.finalize.auditLogin).toBe(true);
    expect(opts.finalize.notifyNewDevice).toBe(false);
  });

  it("explicit override of a default beats the default (no accidental defaulting)", () => {
    // Without this, `{ ...defaults, ...input }` could be silently flipped to
    // `{ ...input, ...defaults }` and would always win — disabling consumer
    // configuration.
    const opts = mergeLoginOpts({
      mfa: { transports: ["totp"], pincodeLength: 8 },
      finalize: { auditLogin: false, notifyNewDevice: true },
    });
    expect(opts.mfa.transports).toEqual(["totp"]);
    expect(opts.mfa.pincodeLength).toBe(8);
    expect(opts.finalize.auditLogin).toBe(false);
    expect(opts.finalize.notifyNewDevice).toBe(true);
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

  it("sessionPolicy.concurrencyLimit stays undefined by default (not a default-on group)", () => {
    // The schema condition uses `!!ctx.opts.sessionPolicy.concurrencyLimit` so
    // the absence MUST be preserved — defaulting it to anything truthy would
    // turn on the concurrency-limit step for everyone.
    expect(mergeLoginOpts().sessionPolicy.concurrencyLimit).toBeUndefined();
    const opts = mergeLoginOpts({
      sessionPolicy: { concurrencyLimit: { max: 3, onLimit: "kickPrompt" } },
    });
    expect(opts.sessionPolicy.concurrencyLimit).toEqual({ max: 3, onLimit: "kickPrompt" });
  });
});
