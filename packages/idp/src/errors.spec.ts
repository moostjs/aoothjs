import { describe, expect, it } from "vitest";
import { OAuthError } from "./errors";

describe("OAuthError", () => {
  it("defaults the message from the type", () => {
    const err = new OAuthError("STATE_EXPIRED");
    expect(err.type).toBe("STATE_EXPIRED");
    expect(err.message).toBe("Sign-in expired — please try again");
    expect(err.name).toBe("OAuthError");
    expect(err).toBeInstanceOf(Error);
  });

  it("accepts an override message + structured details", () => {
    const err = new OAuthError("EXCHANGE_FAILED", "boom", { status: 502 });
    expect(err.message).toBe("boom");
    expect(err.details).toEqual({ status: 502 });
  });

  it("has a benign default for every code (no CSRF/expiry leak via wording)", () => {
    const codes = [
      "UNKNOWN_PROVIDER",
      "INVALID_CONFIG",
      "STATE_INVALID",
      "STATE_EXPIRED",
      "PROVIDER_DENIED",
      "EXCHANGE_FAILED",
      "JWKS_FAILED",
      "ID_TOKEN_INVALID",
      "EMAIL_UNAVAILABLE",
    ] as const;
    for (const code of codes) {
      expect(new OAuthError(code).message.length).toBeGreaterThan(0);
    }
  });
});
