import { readdirSync, readFileSync } from "node:fs";

import { describe, expect, it } from "vite-plus/test";

import {
  EmailIdentifierForm,
  InviteForm,
  LoginCredentialsForm,
  MfaCodeForm,
  ProveControlForm,
  ProveControlOtpForm,
  SetPasswordForm,
} from "../atscript/index";

// biome-ignore lint/suspicious/noExplicitAny: navigating atscript runtime metadata
function getProp(form: any, name: string): any {
  const props = form.type?.props as Map<string, any> | undefined;
  return props?.get(name);
}

describe("default form .as models", () => {
  it("LoginCredentialsForm has username + password with @meta.required", () => {
    const username = getProp(LoginCredentialsForm, "username");
    const password = getProp(LoginCredentialsForm, "password");

    expect(username).toBeDefined();
    expect(password).toBeDefined();
    expect(username.metadata.get("meta.required")).toBeTruthy();
    expect(password.metadata.get("meta.required")).toBeTruthy();
    expect(password.metadata.get("ui.form.type")).toBe("password");
    expect(password.metadata.get("meta.sensitive")).toBe(true);
    expect(username.metadata.get("ui.form.autocomplete")).toBe("username");
    expect(password.metadata.get("ui.form.autocomplete")).toBe("current-password");
  });

  it("MfaCodeForm has digit-only pattern + length bounds", () => {
    const code = getProp(MfaCodeForm, "code");
    expect(code).toBeDefined();
    expect(code.metadata.get("expect.minLength")).toMatchObject({ length: 4 });
    expect(code.metadata.get("expect.maxLength")).toMatchObject({ length: 12 });
    const patterns = code.metadata.get("expect.pattern") as Array<{ pattern: string }> | undefined;
    expect(patterns?.[0]?.pattern).toBe("^[0-9]+$");
    expect(code.metadata.get("ui.form.autocomplete")).toBe("one-time-code");
  });

  it("EmailIdentifierForm uses the string.email primitive", () => {
    const email = getProp(EmailIdentifierForm, "email");
    expect(email).toBeDefined();
    // The string.email primitive carries built-in email pattern validation.
    const tags = email.type?.tags as string[] | undefined;
    expect(tags).toContain("email");
    expect(email.metadata.get("meta.required")).toBeTruthy();
  });

  it("SetPasswordForm requires both newPassword and confirmPassword with min length 8", () => {
    const newPwd = getProp(SetPasswordForm, "newPassword");
    const confirm = getProp(SetPasswordForm, "confirmPassword");
    expect(newPwd.metadata.get("expect.minLength")).toMatchObject({ length: 8 });
    expect(confirm.metadata.get("expect.minLength")).toMatchObject({ length: 8 });
    expect(newPwd.metadata.get("ui.form.autocomplete")).toBe("new-password");
    expect(confirm.metadata.get("ui.form.autocomplete")).toBe("new-password");
  });

  it("ProveControlForm requires a password with current-password autocomplete", () => {
    const password = getProp(ProveControlForm, "password");
    expect(password).toBeDefined();
    expect(password.metadata.get("meta.required")).toBeTruthy();
    expect(password.metadata.get("ui.form.type")).toBe("password");
    expect(password.metadata.get("meta.sensitive")).toBe(true);
    expect(password.metadata.get("ui.form.autocomplete")).toBe("current-password");
    // `cancel` is the only alt-action — declared so `resolveAction()` accepts it.
    expect(getProp(ProveControlForm, "cancel")).toBeDefined();
  });

  it("ProveControlOtpForm requires a digit-only code (OTP fallback proof)", () => {
    const code = getProp(ProveControlOtpForm, "code");
    expect(code).toBeDefined();
    expect(code.metadata.get("meta.required")).toBeTruthy();
    expect(code.metadata.get("ui.form.autocomplete")).toBe("one-time-code");
    const patterns = code.metadata.get("expect.pattern") as Array<{ pattern: string }> | undefined;
    expect(patterns?.[0]?.pattern).toBe("^[0-9]+$");
    expect(getProp(ProveControlOtpForm, "cancel")).toBeDefined();
    // `resend` re-mints the OTP proof code (mirrors PincodeForm) — declared so
    // `resolveAction()` accepts it and the cooldown gate in `proveControl` runs.
    expect(getProp(ProveControlOtpForm, "resend")).toBeDefined();
  });

  it("InviteForm has required email and roles", () => {
    const email = getProp(InviteForm, "email");
    const roles = getProp(InviteForm, "roles");
    expect(email.metadata.get("meta.required")).toBeTruthy();
    expect(email.type?.tags as string[] | undefined).toContain("email");
    expect(roles).toBeDefined();
    expect(roles.optional).toBeFalsy();
  });

  it("each form validator accepts well-formed input", () => {
    expect(() =>
      // `ssoProvider` is an OPTIONAL SSO carrier field — a password login omits
      // it entirely, so well-formed credentials input is just username+password.
      LoginCredentialsForm.validator().validate({ username: "alice", password: "secret" }),
    ).not.toThrow();
    expect(() =>
      MfaCodeForm.validator().validate({ code: "123456", rememberDevice: false }),
    ).not.toThrow();
    expect(() =>
      EmailIdentifierForm.validator().validate({ email: "alice@example.com" }),
    ).not.toThrow();
    expect(() =>
      SetPasswordForm.validator().validate({
        newPassword: "longenough1",
        confirmPassword: "longenough1",
        consents: [],
      }),
    ).not.toThrow();
    expect(() =>
      InviteForm.validator().validate({ email: "bob@example.com", roles: [] }),
    ).not.toThrow();
    expect(() => ProveControlForm.validator().validate({ password: "Password1!" })).not.toThrow();
    expect(() => ProveControlOtpForm.validator().validate({ code: "123456" })).not.toThrow();
  });

  it("each form validator rejects ill-formed input", () => {
    expect(() =>
      LoginCredentialsForm.validator().validate({ username: "", password: "" }),
    ).toThrow();
    expect(() => MfaCodeForm.validator().validate({ code: "12" })).toThrow();
    expect(() => MfaCodeForm.validator().validate({ code: "abcd" })).toThrow();
    expect(() => EmailIdentifierForm.validator().validate({ email: "not-an-email" })).toThrow();
    expect(() =>
      SetPasswordForm.validator().validate({ newPassword: "short", confirmPassword: "short" }),
    ).toThrow();
    // OTP proof code is digit-only; a non-numeric code is rejected.
    expect(() => ProveControlOtpForm.validator().validate({ code: "abcd" })).toThrow();
  });
  it("every bundled form model is used by the workflows (no dead forms ship)", () => {
    // WHY: a form no step renders is dead API — `RecoveryFactorForm` shipped
    // for years with no step, no `forms` slot and options read from a context
    // field nothing set. Each new form must be wired, or listed here with why.
    const notRendered = new Set([
      "WithInlineConsentForm", // base model — the consent forms extend it
    ]);
    const formsAs = readFileSync(new URL("../atscript/models/forms.as", import.meta.url), "utf8");
    const forms = [...formsAs.matchAll(/^export interface (\w+)/gm)].map((m) => m[1]);
    const srcDir = new URL("../", import.meta.url);
    const sources = readdirSync(srcDir, { recursive: true, encoding: "utf8" })
      .filter((f) => f.endsWith(".ts") && !f.endsWith(".d.ts") && !f.includes("__test__"))
      .filter((f) => !f.endsWith(".spec.ts"))
      .map((f) => readFileSync(new URL(f, srcDir), "utf8"))
      .join("\n");
    const unused = forms.filter(
      (f) => !notRendered.has(f) && !new RegExp(`\\b${f}\\b`).test(sources),
    );
    expect(unused).toEqual([]);
    expect(forms).not.toContain("RecoveryFactorForm");
  });
});
