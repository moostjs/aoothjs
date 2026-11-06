import { describe, expect, it } from "vite-plus/test";
import { USER_AUTH_ERROR_CODES, USER_AUTH_ERROR_MESSAGES, UserAuthError } from "./errors";
import {
  USER_AUTH_ERROR_CODES as EXPORTED_CODES,
  USER_AUTH_ERROR_MESSAGES as EXPORTED,
} from "./index";

describe("UserAuthError", () => {
  it("should set type and default message", () => {
    const err = new UserAuthError("NOT_FOUND");
    expect(err.type).toBe("NOT_FOUND");
    expect(err.code).toBe("NOT_FOUND");
    expect(err.message).toBe("Not found");
    expect(err.name).toBe("UserAuthError");
    expect(err).toBeInstanceOf(Error);
  });

  it("should use custom message when provided", () => {
    const err = new UserAuthError("LOCKED", "Custom lock message");
    expect(err.message).toBe("Custom lock message");
    expect(err.type).toBe("LOCKED");
  });

  it("should attach details", () => {
    const err = new UserAuthError("LOCKED", undefined, { lockEnds: 123, reason: "brute" });
    expect(err.details).toEqual({ lockEnds: 123, reason: "brute" });
    expect(err.message).toBe("Account is locked");
  });

  it("should have correct default messages for all types", () => {
    expect(new UserAuthError("ALREADY_EXISTS").message).toBe("User already exists");
    expect(new UserAuthError("INVALID_CREDENTIALS").message).toBe("Invalid credentials");
    expect(new UserAuthError("POLICY_VIOLATION").message).toBe(
      "Password does not meet policy requirements",
    );
    expect(new UserAuthError("PASSWORDS_MISMATCH").message).toBe("Passwords do not match");
    expect(new UserAuthError("PASSWORD_IN_HISTORY").message).toBe("Password was recently used");
    expect(new UserAuthError("INACTIVE").message).toBe("Account is not active");
    expect(new UserAuthError("MFA_REQUIRED").message).toBe(
      "Multi-factor authentication is required",
    );
    expect(new UserAuthError("MFA_INVALID").message).toBe("Invalid MFA code");
    expect(new UserAuthError("MFA_NOT_CONFIGURED").message).toBe("MFA method is not configured");
  });

  it("USER_AUTH_ERROR_MESSAGES is the exported, code-keyed catalogue of the default messages", () => {
    // The message code is what a translator keys on; the catalogue is the
    // English source list registered for $i18n.
    expect(EXPORTED).toBe(USER_AUTH_ERROR_MESSAGES);
    expect(EXPORTED_CODES).toBe(USER_AUTH_ERROR_CODES);
    expect(Object.isFrozen(USER_AUTH_ERROR_MESSAGES)).toBe(true);
    for (const [type, code] of Object.entries(USER_AUTH_ERROR_CODES)) {
      const err = new UserAuthError(type as keyof typeof USER_AUTH_ERROR_CODES);
      expect(err.code).toBe(code);
      expect(err.message).toBe(USER_AUTH_ERROR_MESSAGES[code]);
    }
    expect(Object.keys(USER_AUTH_ERROR_MESSAGES)).toHaveLength(12);
  });

  it("generic types get AOOTH_USER_ codes; NOT_FOUND / INVALID_CREDENTIALS stay shared with neutral texts", () => {
    // WHY: message codes share moost's process-wide registry with every other
    // library — a generic id like LOCKED or ALREADY_EXISTS would override (or
    // be overridden by) another library's template.
    expect(new UserAuthError("LOCKED").code).toBe("AOOTH_USER_LOCKED");
    expect(new UserAuthError("ALREADY_EXISTS").code).toBe("AOOTH_USER_ALREADY_EXISTS");
    expect(new UserAuthError("INACTIVE").code).toBe("AOOTH_USER_INACTIVE");
    expect(new UserAuthError("POLICY_VIOLATION").code).toBe("AOOTH_USER_POLICY_VIOLATION");
    expect(new UserAuthError("CAS_EXHAUSTED").code).toBe("AOOTH_USER_CAS_EXHAUSTED");
    expect(USER_AUTH_ERROR_MESSAGES.NOT_FOUND).toBe("Not found");
    expect(USER_AUTH_ERROR_MESSAGES.INVALID_CREDENTIALS).toBe("Invalid credentials");
  });
});
