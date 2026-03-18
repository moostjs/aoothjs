import { describe, expect, it } from "vite-plus/test";
import {
  deepMerge,
  generateSecureRandom,
  incrementAtPath,
  maskEmail,
  maskPhone,
  maskMfaValue,
} from "./utils";

describe("maskEmail", () => {
  it("should mask the local part of an email", () => {
    const result = maskEmail("longname@example.com");
    expect(result).toContain("***");
    expect(result).toContain("@example.com");
    expect(result).not.toBe("longname@example.com");
  });

  it("should return empty string for empty input", () => {
    expect(maskEmail("")).toBe("");
  });

  it("should handle short local part", () => {
    const result = maskEmail("ab@x.com");
    expect(result).toContain("***");
    expect(result).toContain("@x.com");
  });
});

describe("maskPhone", () => {
  it("should mask a phone number", () => {
    const result = maskPhone("+1234567890");
    expect(result).toContain("***");
    expect(result.length).toBeLessThan("+1234567890".length);
  });

  it("should return empty string for empty input", () => {
    expect(maskPhone("")).toBe("");
  });
});

describe("maskMfaValue", () => {
  it("should mask email method", () => {
    const result = maskMfaValue({ name: "email", confirmed: true, value: "user@test.com" });
    expect(result).toContain("***");
    expect(result).toContain("@test.com");
  });

  it("should mask sms method", () => {
    const result = maskMfaValue({ name: "sms", confirmed: true, value: "+1234567890" });
    expect(result).toContain("***");
  });

  it("should return empty for totp", () => {
    expect(maskMfaValue({ name: "totp", confirmed: true, value: "ABC" })).toBe("");
  });

  it("should return empty for unknown type", () => {
    expect(maskMfaValue({ name: "webauthn", confirmed: true, value: "xyz" })).toBe("");
  });
});

describe("generateSecureRandom", () => {
  it("should generate string of requested length", () => {
    expect(generateSecureRandom(16).length).toBe(16);
    expect(generateSecureRandom(32).length).toBe(32);
  });

  it("should use custom charset", () => {
    const result = generateSecureRandom(100, "ab");
    expect(result).toMatch(/^[ab]+$/);
  });

  it("should produce different outputs", () => {
    const a = generateSecureRandom(32);
    const b = generateSecureRandom(32);
    expect(a).not.toBe(b);
  });
});

describe("deepMerge", () => {
  it("should merge flat objects", () => {
    const target = { a: 1, b: 2 };
    deepMerge(target, { b: 3, c: 4 } as any);
    expect(target).toEqual({ a: 1, b: 3, c: 4 });
  });

  it("should deep merge nested objects", () => {
    const target = { account: { active: true, locked: false } };
    deepMerge(target, { account: { locked: true } } as any);
    expect(target).toEqual({ account: { active: true, locked: true } });
  });

  it("should replace arrays entirely", () => {
    const target = { items: [1, 2, 3] };
    deepMerge(target, { items: [4, 5] } as any);
    expect(target).toEqual({ items: [4, 5] });
  });

  it("should handle null values", () => {
    const target = { a: { b: 1 } };
    deepMerge(target, { a: null } as any);
    expect(target).toEqual({ a: null });
  });
});

describe("incrementAtPath", () => {
  it("should increment a nested numeric value", () => {
    const obj = { account: { failedLoginAttempts: 2 } };
    incrementAtPath(obj, "account.failedLoginAttempts", 1);
    expect(obj.account.failedLoginAttempts).toBe(3);
  });

  it("should initialize missing value to 0 before incrementing", () => {
    const obj: Record<string, unknown> = {};
    incrementAtPath(obj, "counter", 5);
    expect(obj.counter).toBe(5);
  });

  it("should create intermediate objects", () => {
    const obj: Record<string, unknown> = {};
    incrementAtPath(obj, "a.b.c", 1);
    expect(obj).toEqual({ a: { b: { c: 1 } } });
  });

  it("should handle negative increments", () => {
    const obj = { value: 10 };
    incrementAtPath(obj, "value", -3);
    expect(obj.value).toBe(7);
  });
});
