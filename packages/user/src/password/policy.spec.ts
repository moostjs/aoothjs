import { describe, expect, it } from "vite-plus/test";
import { PasswordPolicy, normalizePolicies } from "./policy";
import {
  ppHasLowerCase,
  ppHasMinLength,
  ppHasNumber,
  ppHasSpecialChar,
  ppHasUpperCase,
  ppMaxRepeatedChars,
} from "./policies";

describe("PasswordPolicy", () => {
  it("should evaluate a function rule", async () => {
    const p = new PasswordPolicy({ rule: (v) => v.length > 5 });
    expect(await p.evaluate("12345")).toBe(false);
    expect(await p.evaluate("123456")).toBe(true);
  });

  it("should evaluate a string rule via ftring", async () => {
    const p = new PasswordPolicy({ rule: "v.length > 5" });
    expect(await p.evaluate("12345")).toBe(false);
    expect(await p.evaluate("123456")).toBe(true);
  });

  it("should evaluate empty rule as true", async () => {
    const p = new PasswordPolicy({ rule: "" });
    expect(await p.evaluate("anything")).toBe(true);
  });

  it("should expose description and errorMessage", () => {
    const p = new PasswordPolicy({
      rule: "true",
      description: "Always passes",
      errorMessage: "Never fails",
    });
    expect(p.description).toBe("Always passes");
    expect(p.errorMessage).toBe("Never fails");
  });

  it("should default description and errorMessage to empty string", () => {
    const p = new PasswordPolicy({ rule: "true" });
    expect(p.description).toBe("");
    expect(p.errorMessage).toBe("");
  });

  describe("transferable", () => {
    it("should be true for string rules", () => {
      expect(new PasswordPolicy({ rule: "v.length > 5" }).transferable).toBe(true);
    });

    it("should be false for function rules", () => {
      expect(new PasswordPolicy({ rule: (v) => v.length > 5 }).transferable).toBe(false);
    });
  });
});

describe("normalizePolicies", () => {
  it("should return empty array for undefined", () => {
    expect(normalizePolicies(undefined)).toEqual([]);
  });

  it("should pass through PasswordPolicy instances", () => {
    const p = new PasswordPolicy({ rule: "true" });
    const result = normalizePolicies([p]);
    expect(result[0]).toBe(p);
  });

  it("should wrap plain objects in PasswordPolicy", () => {
    const result = normalizePolicies([{ rule: "v.length > 3" }]);
    expect(result[0]).toBeInstanceOf(PasswordPolicy);
  });
});

describe("built-in policies", () => {
  it("ppHasMinLength", async () => {
    const p = new PasswordPolicy(ppHasMinLength(5));
    expect(await p.evaluate("1234")).toBe(false);
    expect(await p.evaluate("12345")).toBe(true);
  });

  it("ppHasMinLength default is 8", async () => {
    const p = new PasswordPolicy(ppHasMinLength());
    expect(await p.evaluate("1234567")).toBe(false);
    expect(await p.evaluate("12345678")).toBe(true);
  });

  it("ppHasUpperCase", async () => {
    const p = new PasswordPolicy(ppHasUpperCase(2));
    expect(await p.evaluate("password")).toBe(false);
    expect(await p.evaluate("Password")).toBe(false);
    expect(await p.evaluate("PassworD")).toBe(true);
    expect(await p.evaluate("PASSWORD")).toBe(true);
  });

  it("ppHasUpperCase default is 1", async () => {
    const p = new PasswordPolicy(ppHasUpperCase());
    expect(await p.evaluate("lowercase")).toBe(false);
    expect(await p.evaluate("Uppercase")).toBe(true);
  });

  it("ppHasLowerCase", async () => {
    const p = new PasswordPolicy(ppHasLowerCase(2));
    expect(await p.evaluate("PASSWORd")).toBe(false);
    expect(await p.evaluate("PASSWORD")).toBe(false);
    expect(await p.evaluate("PASSWOrd")).toBe(true);
    expect(await p.evaluate("password")).toBe(true);
  });

  it("ppHasLowerCase default is 1", async () => {
    const p = new PasswordPolicy(ppHasLowerCase());
    expect(await p.evaluate("UPPERCASE")).toBe(false);
    expect(await p.evaluate("lOWERCASE")).toBe(true);
  });

  it("ppHasNumber", async () => {
    const p = new PasswordPolicy(ppHasNumber(2));
    expect(await p.evaluate("abcd")).toBe(false);
    expect(await p.evaluate("abcd1")).toBe(false);
    expect(await p.evaluate("1abcd1")).toBe(true);
    expect(await p.evaluate("12345")).toBe(true);
  });

  it("ppHasNumber default is 1", async () => {
    const p = new PasswordPolicy(ppHasNumber());
    expect(await p.evaluate("nodigits")).toBe(false);
    expect(await p.evaluate("has1digit")).toBe(true);
  });

  it("ppHasSpecialChar", async () => {
    const p = new PasswordPolicy(ppHasSpecialChar(2));
    expect(await p.evaluate("password")).toBe(false);
    expect(await p.evaluate("password!")).toBe(false);
    expect(await p.evaluate("pass!word!")).toBe(true);
  });

  it("ppHasSpecialChar default is 1", async () => {
    const p = new PasswordPolicy(ppHasSpecialChar());
    expect(await p.evaluate("nospecial")).toBe(false);
    expect(await p.evaluate("special!")).toBe(true);
  });

  it("ppMaxRepeatedChars", async () => {
    const p = new PasswordPolicy(ppMaxRepeatedChars(2));
    expect(await p.evaluate("aaa")).toBe(false);
    expect(await p.evaluate("abab")).toBe(true);
    expect(await p.evaluate("password!!")).toBe(true);
    expect(await p.evaluate("password!!!")).toBe(false);
  });

  it("all built-in policies are transferable", () => {
    const factories = [
      ppHasMinLength(),
      ppHasUpperCase(),
      ppHasLowerCase(),
      ppHasNumber(),
      ppHasSpecialChar(),
      ppMaxRepeatedChars(),
    ];
    for (const f of factories) {
      expect(new PasswordPolicy(f).transferable).toBe(true);
    }
  });
});
