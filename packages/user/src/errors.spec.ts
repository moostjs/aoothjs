import { describe, expect, it } from "vite-plus/test";
import { UserAuthError } from "./errors";

describe("UserAuthError", () => {
  it("should set type and default message", () => {
    const err = new UserAuthError("NOT_FOUND");
    expect(err.type).toBe("NOT_FOUND");
    expect(err.message).toBe("User not found");
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
});
