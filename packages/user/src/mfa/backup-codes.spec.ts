import { describe, expect, it } from "vite-plus/test";
import { generateBackupCodePlaintext } from "./backup-codes";

const ALLOWED_CHARS = /^[ABCDEFGHJKMNPQRSTUVWXYZ23456789]+$/;
const FORMAT = /^[A-Z2-9]{4}-[A-Z2-9]{4}-[A-Z2-9]{2}$/;

describe("generateBackupCodePlaintext", () => {
  it("should return the requested number of codes", () => {
    expect(generateBackupCodePlaintext(1)).toHaveLength(1);
    expect(generateBackupCodePlaintext(5)).toHaveLength(5);
    expect(generateBackupCodePlaintext(10)).toHaveLength(10);
  });

  it("should default to 10 codes", () => {
    expect(generateBackupCodePlaintext()).toHaveLength(10);
  });

  it("should produce unique codes within a single batch", () => {
    const codes = generateBackupCodePlaintext(20);
    expect(new Set(codes).size).toBe(codes.length);
  });

  it("should format codes as XXXX-XXXX-XX", () => {
    for (const code of generateBackupCodePlaintext(20)) {
      expect(code).toMatch(FORMAT);
    }
  });

  it("should only use the safe alphabet (no I/O/L/0/1)", () => {
    for (const code of generateBackupCodePlaintext(20)) {
      const stripped = code.replace(/-/g, "");
      expect(stripped).toHaveLength(10);
      expect(stripped).toMatch(ALLOWED_CHARS);
      // explicit check on confusing characters
      expect(stripped).not.toMatch(/[IOL01]/);
    }
  });

  it("should produce different batches across calls", () => {
    const a = generateBackupCodePlaintext(10);
    const b = generateBackupCodePlaintext(10);
    expect(a).not.toEqual(b);
  });
});
