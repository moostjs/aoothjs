import { describe, expect, it } from "vite-plus/test";
import { definePasswordPolicy, PasswordPolicy, normalizePolicies } from "./policy";
import {
  ppHasLowerCase,
  ppHasMinLength,
  ppHasNumber,
  ppHasSpecialChar,
  ppHasUpperCase,
  ppMaxRepeatedChars,
} from "./policies";

describe("PasswordPolicy", () => {
  it("evaluates a function rule directly (no sandbox path on the backend)", async () => {
    const p = new PasswordPolicy({ rule: (v) => v.length > 5 });
    expect(await p.evaluate("12345")).toBe(false);
    expect(await p.evaluate("123456")).toBe(true);
  });

  it("exposes description and errorMessage", () => {
    const p = new PasswordPolicy({
      rule: () => true,
      description: "Always passes",
      errorMessage: "Never fails",
    });
    expect(p.description).toBe("Always passes");
    expect(p.errorMessage).toBe("Never fails");
  });

  it("defaults description and errorMessage to empty string", () => {
    const p = new PasswordPolicy({ rule: () => true });
    expect(p.description).toBe("");
    expect(p.errorMessage).toBe("");
  });

  describe("transferable", () => {
    // WHY: `transferable === true` is the gate `getTransferablePolicies()` uses
    // to decide what ships to clients. A function rule without `serialized`
    // means "backend-only" — frontend pre-validation must skip it, server-side
    // remains authoritative.
    it("is false for a raw function rule (no serialized form)", () => {
      expect(new PasswordPolicy({ rule: (v) => v.length > 5 }).transferable).toBe(false);
    });

    it("is true when serialized is provided (i.e. built via definePasswordPolicy)", () => {
      const def = definePasswordPolicy({
        rule: (v: string, n: number) => v.length > n,
        args: [5] as const,
      });
      expect(new PasswordPolicy(def).transferable).toBe(true);
    });
  });
});

describe("definePasswordPolicy", () => {
  // WHY: this helper is the ONLY supported way to declare a transferable
  // policy now that string rules are gone (their ftring path was RCE-vulnerable
  // via constructor.constructor / __proto__ escapes — see commit history).
  // The contract: backend invokes the fn directly with bound args; frontend
  // receives a self-contained `(v) => (fn)(v, ...args)` text. Both derive
  // from the same single source — the function passed in.

  it("backend rule receives v + bound args in declared order", async () => {
    const def = definePasswordPolicy({
      rule: (v: string, min: number, max: number) => v.length >= min && v.length <= max,
      args: [3, 6] as const,
    });
    const p = new PasswordPolicy(def);
    expect(await p.evaluate("ab")).toBe(false);
    expect(await p.evaluate("abc")).toBe(true);
    expect(await p.evaluate("abcdef")).toBe(true);
    expect(await p.evaluate("abcdefg")).toBe(false);
  });

  it("serialized form is the self-contained function literal `(v) => (fn)(v, ...args)`", () => {
    const def = definePasswordPolicy({
      rule: (v: string, n: number) => v.length >= n,
      args: [4] as const,
    });
    // Shape, not exact text: the .toString() of an arrow varies in whitespace
    // across engines. We assert structural anchors.
    expect(def.serialized).toMatch(/^\(v\) => \(.*\)\(v, 4\)$/s);
    expect(def.serialized).toContain("v.length >= n");
  });

  it("serialized form is bundler-safe: positional invocation survives param-name mangling", () => {
    // WHY: this is the whole reason positional args were chosen over closures.
    // We simulate a mangler that renames the function's local params from
    // `(v, n)` to `(a, b)`. As long as body refs were renamed in lockstep
    // (which any real bundler does), invoking the function via positional
    // args at the serialized call site still resolves correctly.
    const mangledSource = `(a, b) => a.length >= b`;
    const serialized = `(v) => (${mangledSource})(v, 4)`;
    // Evaluating the serialized text on the "frontend": just compile to a fn.
    const evalFn = new Function(`return ${serialized}`)() as (v: string) => boolean;
    expect(evalFn("abc")).toBe(false);
    expect(evalFn("abcd")).toBe(true);
  });

  it("omitting args makes the policy backend-only (serialized undefined)", () => {
    const def = definePasswordPolicy({
      rule: (v: string) => v !== "password",
    });
    expect(def.serialized).toBeUndefined();
    const p = new PasswordPolicy(def);
    expect(p.transferable).toBe(false);
  });

  it("empty args array still serializes (zero-arg transferable rule)", () => {
    const def = definePasswordPolicy({
      rule: (v: string) => /[A-Z]/.test(v),
      args: [] as const,
    });
    expect(def.serialized).toBeDefined();
    expect(def.serialized).toMatch(/^\(v\) => \(.*\)\(v\)$/s);
  });

  it("string args are JSON.stringify'd (quoted, escaped) so they survive serialization intact", () => {
    const def = definePasswordPolicy({
      rule: (v: string, forbidden: string) => !v.includes(forbidden),
      args: ['"; DROP TABLE users; --'] as const,
    });
    // The literal must round-trip through JSON.stringify so the embedded
    // quote / semicolon don't break the surrounding JS syntax.
    expect(def.serialized).toContain('"\\"; DROP TABLE users; --"');
  });
});

describe("equivalence: backend rule vs serialized frontend hydrator", () => {
  // WHY (Rule 9): the helper guarantees one source of truth, but the only way
  // to PROVE backend + frontend agree is to evaluate both paths against the
  // same inputs. Catches arg-order drift, signature changes, or any future
  // bug where the .toString() shape diverges from what the binding expects.
  const samples = [
    "",
    "a",
    "abc",
    "abcdefgh",
    "abcdefghi",
    "Password1",
    "PASSWORD",
    "password",
    "aaaaa",
    "abAB12!@",
    "12345678",
    "Aa1!Bb2@",
    "test!!!test",
    "Many spaces  here",
    "ünicödé",
    "🚀rocket",
    "  leading-trailing  ",
    "single-char-x",
    "with\nnewline",
    "with\ttab",
  ];

  const factories = [
    { name: "ppHasMinLength(8)", make: () => ppHasMinLength(8) },
    { name: "ppHasUpperCase(1)", make: () => ppHasUpperCase(1) },
    { name: "ppHasUpperCase(2)", make: () => ppHasUpperCase(2) },
    { name: "ppHasLowerCase(1)", make: () => ppHasLowerCase(1) },
    { name: "ppHasNumber(1)", make: () => ppHasNumber(1) },
    { name: "ppHasNumber(3)", make: () => ppHasNumber(3) },
    { name: "ppHasSpecialChar(1)", make: () => ppHasSpecialChar(1) },
    { name: "ppMaxRepeatedChars(2)", make: () => ppMaxRepeatedChars(2) },
  ] as const;

  for (const { name, make } of factories) {
    it(`${name}: every sample evaluates the same on backend fn and serialized form`, async () => {
      const def = make();
      const p = new PasswordPolicy(def);
      // Compile serialized via `new Function` — same shape any frontend
      // hydrator would use (plain function literal, no library dependency).
      const frontend = new Function(`return ${def.serialized}`)() as (v: string) => boolean;
      for (const sample of samples) {
        const backend = await p.evaluate(sample);
        expect(
          frontend(sample),
          `Mismatch on input ${JSON.stringify(sample)} for ${name}: backend=${backend} frontend=${frontend(sample)}`,
        ).toBe(backend);
      }
    });
  }
});

describe("normalizePolicies", () => {
  it("returns empty array for undefined", () => {
    expect(normalizePolicies(undefined)).toEqual([]);
  });

  it("passes through PasswordPolicy instances", () => {
    const p = new PasswordPolicy({ rule: () => true });
    const result = normalizePolicies([p]);
    expect(result[0]).toBe(p);
  });

  it("wraps plain objects in PasswordPolicy", () => {
    const result = normalizePolicies([{ rule: (v) => v.length > 3 }]);
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
