import { describe, expect, it } from "vite-plus/test";
import { PasswordHasher } from "./hasher";

// Use low cost params for fast tests
const hasher = new PasswordHasher({ scryptN: 1024, scryptR: 1, scryptP: 1, keyLength: 32 });

describe("PasswordHasher", () => {
  it("should produce a self-describing hash string", async () => {
    const hash = await hasher.hash("password123");
    expect(hash).toMatch(/^\$scrypt\$N=\d+,r=\d+,p=\d+,l=\d+\$[A-Za-z0-9_-]+\$[A-Za-z0-9_-]+$/);
  });

  it("should produce different hashes for the same password (random salt)", async () => {
    const h1 = await hasher.hash("same");
    const h2 = await hasher.hash("same");
    expect(h1).not.toBe(h2);
  });

  it("should verify a correct password", async () => {
    const hash = await hasher.hash("correct-horse");
    expect(await hasher.verify("correct-horse", hash)).toBe(true);
  });

  it("should reject an incorrect password", async () => {
    const hash = await hasher.hash("correct-horse");
    expect(await hasher.verify("wrong-horse", hash)).toBe(false);
  });

  it("should return false for malformed hash", async () => {
    expect(await hasher.verify("password", "not-a-valid-hash")).toBe(false);
    expect(await hasher.verify("password", "")).toBe(false);
    expect(await hasher.verify("password", "$scrypt$bad")).toBe(false);
  });

  it("should include pepper in hashing", async () => {
    const peppered = new PasswordHasher({
      pepper: "secret-pepper",
      scryptN: 1024,
      scryptR: 1,
      scryptP: 1,
      keyLength: 32,
    });
    const noPepper = new PasswordHasher({ scryptN: 1024, scryptR: 1, scryptP: 1, keyLength: 32 });

    const hash = await peppered.hash("password");
    // Peppered hasher should verify its own hash
    expect(await peppered.verify("password", hash)).toBe(true);
    // Non-peppered hasher should fail on peppered hash
    expect(await noPepper.verify("password", hash)).toBe(false);
  });

  it("should verify hashes from different parameter configurations", async () => {
    const oldHasher = new PasswordHasher({ scryptN: 1024, scryptR: 1, scryptP: 1, keyLength: 32 });
    const newHasher = new PasswordHasher({ scryptN: 2048, scryptR: 2, scryptP: 1, keyLength: 64 });

    const oldHash = await oldHasher.hash("password");
    // New hasher should still verify old hash (params are in the hash string)
    expect(await newHasher.verify("password", oldHash)).toBe(true);
  });
});

describe("PasswordHasher.generatePassword", () => {
  it("should generate a password of the requested length", () => {
    const pw = hasher.generatePassword(20);
    expect(pw.length).toBe(20);
  });

  it("should enforce minimum length of 8", () => {
    const pw = hasher.generatePassword(3);
    expect(pw.length).toBe(8);
  });

  it("should include at least one of each character category", () => {
    // Run multiple times to account for shuffling
    for (let i = 0; i < 10; i++) {
      const pw = hasher.generatePassword(16);
      expect(pw).toMatch(/[a-z]/);
      expect(pw).toMatch(/[A-Z]/);
      expect(pw).toMatch(/[0-9]/);
      expect(pw).toMatch(/[^a-zA-Z0-9]/);
    }
  });

  it("should produce different passwords", () => {
    const a = hasher.generatePassword();
    const b = hasher.generatePassword();
    expect(a).not.toBe(b);
  });
});

describe("PasswordHasher — memory-hard parameters (maxmem sized to N·r)", () => {
  // Both need ≥ 32 MiB (128·N·r), which Node's default scrypt maxmem rejected.
  for (const [N, r] of [
    [2 ** 15, 8],
    [2 ** 17, 2],
  ] as const) {
    it(`hashes and verifies with N=2^${Math.log2(N)}, r=${r}`, async () => {
      const h = new PasswordHasher({ scryptN: N, scryptR: r, scryptP: 1, keyLength: 32 });
      const encoded = await h.hash("Secret#1");
      expect(encoded).toContain(`N=${N},r=${r},p=1`);
      expect(await h.verify("Secret#1", encoded)).toBe(true);
      expect(await h.verify("Secret#2", encoded)).toBe(false);
      // a default-parameter hasher verifies it too (params ride the encoding)
      expect(await new PasswordHasher().verify("Secret#1", encoded)).toBe(true);
    });
  }
});
