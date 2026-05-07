import { describe, expect, it } from "vite-plus/test";
import { AuthError, type AuthErrorType } from "./errors";

describe("AuthError", () => {
  it("should set type and default message", () => {
    const err = new AuthError("INVALID_TOKEN");
    expect(err.type).toBe("INVALID_TOKEN");
    expect(err.message).toBe("Invalid token");
    expect(err.name).toBe("AuthError");
    expect(err).toBeInstanceOf(Error);
    expect(err).toBeInstanceOf(AuthError);
  });

  it("should use custom message when provided", () => {
    const err = new AuthError("TOKEN_EXPIRED", "Custom expired message");
    expect(err.message).toBe("Custom expired message");
    expect(err.type).toBe("TOKEN_EXPIRED");
  });

  it("should attach details", () => {
    const err = new AuthError("TOKEN_REVOKED", undefined, {
      jti: "abc",
      revokedAt: 123,
    });
    expect(err.details).toEqual({ jti: "abc", revokedAt: 123 });
    expect(err.message).toBe("Token has been revoked");
  });

  it("should have correct default messages for all types", () => {
    expect(new AuthError("INVALID_TOKEN").message).toBe("Invalid token");
    expect(new AuthError("TOKEN_EXPIRED").message).toBe("Token has expired");
    expect(new AuthError("TOKEN_REVOKED").message).toBe("Token has been revoked");
    expect(new AuthError("REFRESH_REUSE_DETECTED").message).toBe("Refresh token reuse detected");
    expect(new AuthError("STATELESS_OPERATION_UNSUPPORTED").message).toBe(
      "Operation is not supported by stateless credential store",
    );
    expect(new AuthError("MAX_CONCURRENT_REACHED").message).toBe(
      "Maximum concurrent credentials reached for user",
    );
    expect(new AuthError("INVALID_CONFIG").message).toBe("Invalid auth configuration");
  });

  it("should preserve type as readonly discriminant for each AuthErrorType", () => {
    const types: AuthErrorType[] = [
      "INVALID_TOKEN",
      "TOKEN_EXPIRED",
      "TOKEN_REVOKED",
      "REFRESH_REUSE_DETECTED",
      "STATELESS_OPERATION_UNSUPPORTED",
      "MAX_CONCURRENT_REACHED",
      "INVALID_CONFIG",
    ];
    for (const type of types) {
      const err = new AuthError(type);
      expect(err.type).toBe(type);
      expect(err).toBeInstanceOf(AuthError);
    }
  });
});
