import { describe, expect, it } from "vite-plus/test";
import {
  generateMfaCode,
  generateTotpCode,
  generateTotpSecret,
  generateTotpUri,
  verifyTotpCode,
} from "./totp";

describe("generateTotpSecret", () => {
  it("should produce a base32 string", () => {
    const secret = generateTotpSecret();
    expect(secret).toMatch(/^[A-Z2-7]+$/);
  });

  it("should produce different secrets", () => {
    const a = generateTotpSecret();
    const b = generateTotpSecret();
    expect(a).not.toBe(b);
  });

  it("should respect byte length", () => {
    const short = generateTotpSecret(10);
    const long = generateTotpSecret(32);
    expect(long.length).toBeGreaterThan(short.length);
  });
});

describe("generateTotpUri", () => {
  it("should generate a valid otpauth URI", () => {
    const uri = generateTotpUri("JBSWY3DPEHPK3PXP", "MyApp", "user@example.com");
    expect(uri).toContain("otpauth://totp/");
    expect(uri).toContain("secret=JBSWY3DPEHPK3PXP");
    expect(uri).toContain("issuer=MyApp");
    expect(uri).toContain("algorithm=SHA1");
    expect(uri).toContain("digits=6");
    expect(uri).toContain("period=30");
  });

  it("should support custom config", () => {
    const uri = generateTotpUri("SECRET", "App", "user", { digits: 8, period: 60 });
    expect(uri).toContain("digits=8");
    expect(uri).toContain("period=60");
  });
});

describe("generateTotpCode / verifyTotpCode", () => {
  const secret = "JBSWY3DPEHPK3PXP";
  const fixedClock = () => 1704067200000; // 2024-01-01T00:00:00Z

  it("should generate a 6-digit code", () => {
    const code = generateTotpCode(secret, { clock: fixedClock });
    expect(code).toMatch(/^\d{6}$/);
  });

  it("should be deterministic with fixed clock", () => {
    const a = generateTotpCode(secret, { clock: fixedClock });
    const b = generateTotpCode(secret, { clock: fixedClock });
    expect(a).toBe(b);
  });

  it("should verify a correct code", () => {
    const code = generateTotpCode(secret, { clock: fixedClock });
    expect(verifyTotpCode(secret, code, { clock: fixedClock })).toBe(true);
  });

  it("should verify within window tolerance", () => {
    const code = generateTotpCode(secret, { clock: fixedClock });
    // 30 seconds later, should still verify with window=1
    const laterClock = () => fixedClock() + 30000;
    expect(verifyTotpCode(secret, code, { clock: laterClock, window: 1 })).toBe(true);
  });

  it("should reject code outside window", () => {
    const code = generateTotpCode(secret, { clock: fixedClock });
    // 90 seconds later with window=1 (only checks ±1 step)
    const farClock = () => fixedClock() + 90000;
    expect(verifyTotpCode(secret, code, { clock: farClock, window: 1 })).toBe(false);
  });

  it("should reject an incorrect code", () => {
    expect(verifyTotpCode(secret, "000000", { clock: fixedClock })).toBe(false);
  });

  it("should support 8-digit codes", () => {
    const code = generateTotpCode(secret, { clock: fixedClock, digits: 8 });
    expect(code).toMatch(/^\d{8}$/);
    expect(verifyTotpCode(secret, code, { clock: fixedClock, digits: 8 })).toBe(true);
  });

  it("rejects codes of the wrong length (digit-count probe defence)", () => {
    // Wrong length is a quick-reject path; ensures `timingSafeEqual` never
    // sees a length-mismatched buffer pair.
    expect(verifyTotpCode(secret, "12345", { clock: fixedClock })).toBe(false);
    expect(verifyTotpCode(secret, "1234567", { clock: fixedClock })).toBe(false);
    expect(verifyTotpCode(secret, "", { clock: fixedClock })).toBe(false);
  });

  it("rejects non-string inputs without throwing", () => {
    // Defensive: handler boundaries should be the validator, but the function
    // must not crash on a coerced wrong-type input either.
    expect(verifyTotpCode(secret, undefined as unknown as string, { clock: fixedClock })).toBe(
      false,
    );
    expect(verifyTotpCode(secret, null as unknown as string, { clock: fixedClock })).toBe(false);
    expect(verifyTotpCode(secret, 123 as unknown as string, { clock: fixedClock })).toBe(false);
  });
});

describe("generateMfaCode", () => {
  it("should generate a code of the requested length", () => {
    expect(generateMfaCode(6)).toMatch(/^\d{6}$/);
    expect(generateMfaCode(8)).toMatch(/^\d{8}$/);
  });

  it("should produce different codes", () => {
    const codes = new Set(Array.from({ length: 20 }, () => generateMfaCode()));
    expect(codes.size).toBeGreaterThan(1);
  });
});
