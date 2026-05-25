import { describe, expect, it } from "vite-plus/test";

import {
  EmailIdentifierForm,
  InviteForm,
  LoginCredentialsForm,
  MfaCodeForm,
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

  it("InviteForm has required email and optional roles", () => {
    const email = getProp(InviteForm, "email");
    const roles = getProp(InviteForm, "roles");
    expect(email.metadata.get("meta.required")).toBeTruthy();
    expect(email.type?.tags as string[] | undefined).toContain("email");
    expect(roles).toBeDefined();
    expect(roles.optional).toBe(true);
  });

  it("each form validator accepts well-formed input", () => {
    expect(() =>
      LoginCredentialsForm.validator().validate({ username: "alice", password: "secret" }),
    ).not.toThrow();
    expect(() => MfaCodeForm.validator().validate({ code: "123456" })).not.toThrow();
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
    expect(() => InviteForm.validator().validate({ email: "bob@example.com" })).not.toThrow();
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
  });
});
