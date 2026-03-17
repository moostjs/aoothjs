import { describe, it, expect } from "vite-plus/test";
import { Aooth } from "./aooth";
import {
  ppHasLowerCase,
  ppHasMinLength,
  ppHasNumber,
  ppHasSpecialChar,
  ppHasUpperCase,
  ppMaxRepeatedChars,
  ppNoRepeatedPasswords,
} from "./password-policies";
import { PasswordPolicy, normalizePolicies } from "./password-policy";
import { UsersStoreMemory } from "./users-store";

describe("password-policy", () => {
  it("must check real fn", async () => {
    const p = new PasswordPolicy({ rule: (v) => v.length > 5 });
    expect(await p.evaluate("12345")).toBe(false);
    expect(await p.evaluate("123456")).toBe(true);
  });

  it("must evaluate fn from string", async () => {
    const p = new PasswordPolicy({ rule: "v.length > 5" });
    expect(await p.evaluate("12345")).toBe(false);
    expect(await p.evaluate("123456")).toBe(true);
  });

  it("must check ppHasMinLength", async () => {
    const p = new PasswordPolicy(ppHasMinLength(5));
    expect(await p.evaluate("1234")).toBe(false);
    expect(await p.evaluate("12345")).toBe(true);
  });

  it("must check ppHasUpperCase", async () => {
    const p = new PasswordPolicy(ppHasUpperCase(2));
    expect(await p.evaluate("password")).toBe(false);
    expect(await p.evaluate("Password")).toBe(false);
    expect(await p.evaluate("PassworD")).toBe(true);
    expect(await p.evaluate("PASSWORD")).toBe(true);
  });

  it("must check ppHasLowerCase", async () => {
    const p = new PasswordPolicy(ppHasLowerCase(2));
    expect(await p.evaluate("PASSWORd")).toBe(false);
    expect(await p.evaluate("PASSWORD")).toBe(false);
    expect(await p.evaluate("PASSWOrd")).toBe(true);
    expect(await p.evaluate("password")).toBe(true);
    expect(await p.evaluate("Password")).toBe(true);
    expect(await p.evaluate("PassworD")).toBe(true);
  });

  it("must check ppHasNumber", async () => {
    const p = new PasswordPolicy(ppHasNumber(2));
    expect(await p.evaluate("abcd")).toBe(false);
    expect(await p.evaluate("abcd1")).toBe(false);
    expect(await p.evaluate("1abcd1")).toBe(true);
    expect(await p.evaluate("12345")).toBe(true);
  });

  it("must check ppHasSpecialChar", async () => {
    const p = new PasswordPolicy(ppHasSpecialChar(2));
    expect(await p.evaluate("password")).toBe(false);
    expect(await p.evaluate("password!")).toBe(false);
    expect(await p.evaluate("pass!word!")).toBe(true);
  });

  it("must check ppMaxRepeatedChars", async () => {
    const p = new PasswordPolicy(ppMaxRepeatedChars(2));
    expect(await p.evaluate("aaa")).toBe(false);
    expect(await p.evaluate("abab")).toBe(true);
    expect(await p.evaluate("password!!")).toBe(true);
    expect(await p.evaluate("password!!!")).toBe(false);
  });

  it("must check ppNoRepeatedPasswords", async () => {
    const aooth = new Aooth(new UsersStoreMemory(), {
      password: { historyLength: 20, pepper: "p" },
    });
    const user = await aooth.createUser("test");
    const pc = aooth.getConfig().password;
    user.changePassword(pc, "test1", "test1");
    await user.save();
    user.changePassword(pc, "test2", "test2");
    await user.save();
    user.changePassword(pc, "test3", "test3");
    await user.save();
    user.changePassword(pc, "test4", "test4");
    await user.save();
    user.changePassword(pc, "test5", "test5");
    await user.save();
    user.changePassword(pc, "test6", "test6");
    await user.save();
    const p = new PasswordPolicy(ppNoRepeatedPasswords(3));
    expect(await p.evaluate("aaa", user.getData().password, pc)).toBe(true);
    expect(await p.evaluate("test1", user.getData().password, pc)).toBe(true);
    expect(await p.evaluate("test2", user.getData().password, pc)).toBe(true);
    expect(await p.evaluate("test3", user.getData().password, pc)).toBe(true);
    expect(await p.evaluate("test4", user.getData().password, pc)).toBe(false);
    expect(await p.evaluate("test5", user.getData().password, pc)).toBe(false);
    expect(await p.evaluate("test6", user.getData().password, pc)).toBe(false);
  });

  describe("transferable", () => {
    it("must be true for string rules", () => {
      const p = new PasswordPolicy({ rule: "v.length > 5" });
      expect(p.transferable).toBe(true);
    });

    it("must be false for function rules", () => {
      const p = new PasswordPolicy({ rule: (v) => v.length > 5 });
      expect(p.transferable).toBe(false);
    });
  });

  describe("rule getter", () => {
    it("must return string rule", () => {
      const p = new PasswordPolicy({ rule: "v.length > 5" });
      expect(p.rule).toBe("v.length > 5");
    });

    it("must throw for non-transferable rule", () => {
      const p = new PasswordPolicy({ rule: (v) => v.length > 5 });
      expect(() => p.rule).toThrow("Password Policy rule is not transferable");
    });
  });

  describe("description / errorMessage getters", () => {
    it("must return description", () => {
      const p = new PasswordPolicy({
        rule: "true",
        description: "Always passes",
        errorMessage: "Never fails",
      });
      expect(p.description).toBe("Always passes");
      expect(p.errorMessage).toBe("Never fails");
    });

    it("must default to empty string", () => {
      const p = new PasswordPolicy({ rule: "true" });
      expect(p.description).toBe("");
      expect(p.errorMessage).toBe("");
    });
  });

  it("must evaluate empty rule as true", async () => {
    const p = new PasswordPolicy({ rule: "" });
    expect(await p.evaluate("anything")).toBe(true);
  });

  it("must throw ppNoRepeatedPasswords when missing password context", async () => {
    const p = new PasswordPolicy(ppNoRepeatedPasswords(3));
    await expect(async () => p.evaluate("test")).rejects.toThrow("[Aooth][Fatal]");
  });

  describe("normalizePolicies", () => {
    it("must return empty array for undefined", () => {
      const result = normalizePolicies(undefined);
      expect(result).toEqual([]);
    });

    it("must pass through PasswordPolicy instances", () => {
      const p = new PasswordPolicy({ rule: "true" });
      const result = normalizePolicies([p]);
      expect(result[0]).toBe(p);
    });

    it("must wrap plain objects in PasswordPolicy", () => {
      const result = normalizePolicies([{ rule: "v.length > 3" }]);
      expect(result[0]).toBeInstanceOf(PasswordPolicy);
      expect(result[0].rule).toBe("v.length > 3");
    });
  });

  describe("policy factory defaults", () => {
    it("ppHasMinLength defaults to 8", async () => {
      const p = new PasswordPolicy(ppHasMinLength());
      expect(await p.evaluate("1234567")).toBe(false);
      expect(await p.evaluate("12345678")).toBe(true);
    });

    it("ppHasUpperCase defaults to 1", async () => {
      const p = new PasswordPolicy(ppHasUpperCase());
      expect(await p.evaluate("lowercase")).toBe(false);
      expect(await p.evaluate("Uppercase")).toBe(true);
    });

    it("ppHasLowerCase defaults to 1", async () => {
      const p = new PasswordPolicy(ppHasLowerCase());
      expect(await p.evaluate("UPPERCASE")).toBe(false);
      expect(await p.evaluate("lOWERCASE")).toBe(true);
    });

    it("ppHasNumber defaults to 1", async () => {
      const p = new PasswordPolicy(ppHasNumber());
      expect(await p.evaluate("nodigits")).toBe(false);
      expect(await p.evaluate("has1digit")).toBe(true);
    });

    it("ppHasSpecialChar defaults to 1", async () => {
      const p = new PasswordPolicy(ppHasSpecialChar());
      expect(await p.evaluate("nospecial")).toBe(false);
      expect(await p.evaluate("special!")).toBe(true);
    });
  });
});
