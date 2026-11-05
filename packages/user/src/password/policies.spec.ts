import { describe, expect, it } from "vite-plus/test";

import { UserStoreMemory } from "../store/memory";
import type { PolicyCheckResult } from "../types";
import { UserService } from "../user-service";
import {
  PASSWORD_POLICY_MESSAGES,
  ppHasLowerCase,
  ppHasMinLength,
  ppHasNumber,
  ppHasSpecialChar,
  ppHasUpperCase,
  ppMaxRepeatedChars,
} from "./policies";

const fill = (template: string, params: Readonly<Record<string, string | number>> = {}) =>
  template.replace(/\{(\w+)\}/g, (m, name: string) => (name in params ? String(params[name]) : m));

describe("PolicyCheckResult", () => {
  it("hand-built values without errorMessage / code still type-check", () => {
    const r: PolicyCheckResult = {
      passed: false,
      policies: [{ description: "Custom", passed: false }],
      errors: ["Custom failed"],
    };
    expect(r.policies[0].errorMessage).toBeUndefined();
  });
});

describe("built-in password policies: PP_* codes", () => {
  const builtins = [
    ppHasMinLength(12),
    ppHasUpperCase(2),
    ppHasLowerCase(2),
    ppHasNumber(2),
    ppHasSpecialChar(2),
    ppMaxRepeatedChars(3),
  ];

  it("each carries a code and params whose templates (plural) fill to its English texts", () => {
    for (const p of builtins) {
      const code = p.code as keyof typeof PASSWORD_POLICY_MESSAGES;
      expect(code).toMatch(/^PP_/);
      expect(fill(PASSWORD_POLICY_MESSAGES[code], p.params)).toBe(p.errorMessage);
      const desc = `${code}_DESCRIPTION` as keyof typeof PASSWORD_POLICY_MESSAGES;
      expect(fill(PASSWORD_POLICY_MESSAGES[desc], p.params)).toBe(p.description);
    }
  });

  it("singular counts keep plural-correct English texts (the translation fallback)", () => {
    const one = ppHasUpperCase(1);
    expect(one.params).toEqual({ count: 1 });
    expect(one.errorMessage).toBe("Password must include at least 1 uppercase character");
    expect(one.description).toBe("At least 1 uppercase character");
  });

  it("checkPolicies and getTransferablePolicies carry code, params and the texts", async () => {
    const users = new UserService(new UserStoreMemory(), {
      password: { policies: [ppHasMinLength(12), ppHasNumber(1)] },
    });
    const result = await users.checkPolicies("short1");
    expect(result.policies).toEqual([
      {
        description: "Minimum length 12",
        passed: false,
        errorMessage: "Password must be at least 12 characters long",
        code: "PP_MIN_LENGTH",
        params: { min: 12 },
      },
      {
        description: "At least 1 number",
        passed: true,
        errorMessage: "Password must include at least 1 number",
        code: "PP_NUMBER",
        params: { count: 1 },
      },
    ]);
    expect(result.errors).toEqual(["Password must be at least 12 characters long"]);
    expect(users.getTransferablePolicies()[0]).toMatchObject({
      code: "PP_MIN_LENGTH",
      params: { min: 12 },
      description: "Minimum length 12",
    });
  });
});
