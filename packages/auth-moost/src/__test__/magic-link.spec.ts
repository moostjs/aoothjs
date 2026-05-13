import { describe, expect, it } from "vite-plus/test";

import { generateMagicLinkToken } from "../magic-link";

describe("generateMagicLinkToken", () => {
  it("returns a base64url string of at least 40 characters", () => {
    const token = generateMagicLinkToken();
    // 32 bytes base64url-encoded → 43 chars (no padding).
    expect(token.length).toBeGreaterThanOrEqual(40);
    expect(token).toMatch(/^[A-Za-z0-9_-]+$/);
  });

  it("produces unique tokens across calls", () => {
    const tokens = new Set<string>();
    for (let i = 0; i < 1024; i++) {
      tokens.add(generateMagicLinkToken());
    }
    expect(tokens.size).toBe(1024);
  });

  it("emits URL-safe characters only (no '+' '/' '=')", () => {
    for (let i = 0; i < 64; i++) {
      const t = generateMagicLinkToken();
      expect(t.includes("+")).toBe(false);
      expect(t.includes("/")).toBe(false);
      expect(t.includes("=")).toBe(false);
    }
  });
});
