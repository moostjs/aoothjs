import { describe, it, expect } from "vite-plus/test";
import { generateTOTPSecretKey, generateMfaCode, hashPassword } from "./crypto";

describe("crypto", () => {
  it("must generate TOTP secret key in base32 encoding", () => {
    const key = generateTOTPSecretKey();
    expect(key).toHaveLength(32);
    expect(key).toMatch(/^[A-Z2-7]{16,}$/);
  });

  it("must generate TOTP key with custom length", () => {
    const key = generateTOTPSecretKey(5);
    expect(key).toMatch(/^[A-Z2-7=]+$/);
    expect(key.length).toBeGreaterThan(0);
  });

  it("must generate MFA code", () => {
    const code = generateMfaCode(6);
    expect(code).toHaveLength(6);
    expect(code).toMatch(/^\d{6}$/);
  });

  it("must generate MFA code with custom length", () => {
    const code = generateMfaCode(8);
    expect(code).toHaveLength(8);
    expect(code).toMatch(/^\d{8}$/);
  });

  describe("hashPassword", () => {
    it("must produce consistent hash for same input", () => {
      const h1 = hashPassword("test", "sha3-224");
      const h2 = hashPassword("test", "sha3-224");
      expect(h1).toBe(h2);
    });

    it("must produce different hashes for different inputs", () => {
      const h1 = hashPassword("test1", "sha3-224");
      const h2 = hashPassword("test2", "sha3-224");
      expect(h1).not.toBe(h2);
    });

    it("must produce different hashes for different algorithms", () => {
      const h1 = hashPassword("test", "sha256");
      const h2 = hashPassword("test", "sha3-256");
      expect(h1).not.toBe(h2);
    });

    it("must produce hex string output", () => {
      const h = hashPassword("test", "sha256");
      expect(h).toMatch(/^[0-9a-f]+$/);
    });

    it("must work with all supported algorithms", () => {
      const algorithms = [
        "md5",
        "sha224",
        "sha256",
        "sha384",
        "sha512",
        "sha3-224",
        "sha3-256",
        "sha3-384",
        "sha3-512",
      ] as const;
      for (const alg of algorithms) {
        const h = hashPassword("test", alg);
        expect(h).toMatch(/^[0-9a-f]+$/);
      }
    });
  });
});
