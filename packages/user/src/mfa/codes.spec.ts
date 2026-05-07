import { describe, expect, it } from "vite-plus/test";
import { generateMfaCode } from "./totp";
import { hashMfaCode, verifyMfaCode } from "./codes";

describe("generateMfaCode", () => {
  it("should produce a string of correct length", () => {
    expect(generateMfaCode(6)).toHaveLength(6);
    expect(generateMfaCode(8)).toHaveLength(8);
    expect(generateMfaCode(4)).toHaveLength(4);
  });

  it("should produce only digits", () => {
    for (let i = 0; i < 20; i++) {
      expect(generateMfaCode(8)).toMatch(/^\d+$/);
    }
  });

  it("should produce different codes on repeated calls", () => {
    const codes = new Set(Array.from({ length: 50 }, () => generateMfaCode(8)));
    // Effectively guaranteed to have many distinct values for 8-digit codes.
    expect(codes.size).toBeGreaterThan(40);
  });
});

describe("hashMfaCode", () => {
  it("should be deterministic", () => {
    expect(hashMfaCode("123456")).toBe(hashMfaCode("123456"));
  });

  it("should produce a 64-char hex string (SHA-256)", () => {
    const h = hashMfaCode("ABCD-EFGH-IJ");
    expect(h).toMatch(/^[0-9a-f]{64}$/);
  });

  it("should produce different hashes for different inputs", () => {
    expect(hashMfaCode("123456")).not.toBe(hashMfaCode("123457"));
  });
});

describe("verifyMfaCode", () => {
  it("should return true when submitted code matches the stored hash", () => {
    const hash = hashMfaCode("042109");
    expect(verifyMfaCode("042109", hash)).toBe(true);
  });

  it("should return false on mismatch", () => {
    const hash = hashMfaCode("042109");
    expect(verifyMfaCode("042110", hash)).toBe(false);
  });

  it("should return false for empty expected hash", () => {
    expect(verifyMfaCode("anything", "")).toBe(false);
  });

  it("should return false when expected hash is malformed (length mismatch)", () => {
    expect(verifyMfaCode("123456", "deadbeef")).toBe(false);
  });

  it("should treat case-sensitive inputs as distinct", () => {
    const hash = hashMfaCode("AbC123");
    expect(verifyMfaCode("abc123", hash)).toBe(false);
    expect(verifyMfaCode("AbC123", hash)).toBe(true);
  });
});
