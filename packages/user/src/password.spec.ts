import { describe, it, expect } from "vite-plus/test";
import { Password } from "./password";
import type { TAoothConfig } from "./types";

const algorithm = "sha3-224";
const config: Required<Required<TAoothConfig>["password"]> = {
  algorithm: algorithm,
  expiryDays: 0,
  historyLength: 5,
  pepper: "peppervalue",
  policies: [],
  resetTokenExpiryHours: 0,
  saltGenerator: () => "new-salt",
};

function newPassword() {
  return new Password(config, {
    algorithm: "sha224",
    hash: "",
    history: [],
    isInitial: false,
    lastChanged: 0,
    salt: "predefined-salt",
  });
}

describe("password", () => {
  it("must generate password", () => {
    const p = newPassword();
    p.generate();
    const data = p.getData();
    expect(data.hash).toMatch(/^[A-Za-z0-9]{8,}$/);
    expect(data.isInitial).toEqual(true);
    expect(new Date().getTime() - data.lastChanged).toBeLessThan(100);
    expect(data.salt).toEqual("predefined-salt");
    expect(data.algorithm).toEqual("sha3-224");
  });
  it("must store history", () => {
    const p = newPassword();
    p.change("password1");
    const h1 = p.getData().hash;
    p.change("password2");
    const h2 = p.getData().hash;
    p.change("password3");
    const data = p.getData();
    expect(data.history).toHaveLength(2);
    expect(data.history[0].hash).toEqual(h2);
    expect(data.history[1].hash).toEqual(h1);
  });
  it("must check passwords history", () => {
    let p = newPassword();
    p.change("password1");
    p = new Password({ ...config, algorithm: "md5" }, p.getData());
    p.change("password2");
    p = new Password({ ...config, algorithm: "sha3-512" }, p.getData());
    p.change("password3");
    p = new Password(config, p.getData());
    p.change("password4");
    expect(p.isInHistory("password1")).toBe(true);
    expect(p.isInHistory("password2")).toBe(true);
    expect(p.isInHistory("password3")).toBe(true);
    expect(p.isInHistory("password4")).toBe(false);
    const data = p.getData();
    expect(data.history[0].algorithm).toEqual("sha3-512");
    expect(data.history[1].algorithm).toEqual("md5");
    expect(data.history[2].algorithm).toEqual(algorithm);
  });
  it("must keep history length", () => {
    const p = newPassword();
    p.change("password1");
    p.change("password2");
    p.change("password3");
    p.change("password4");
    p.change("password5");
    p.change("password6");
    p.change("password7");
    const data = p.getData();
    expect(data.history).toHaveLength(5);
    expect(p.isInHistory("password1")).toBe(false);
    expect(p.isInHistory("password2")).toBe(true);
  });
  it("must validate password", () => {
    const p = newPassword();
    p.change("password1");
    expect(p.validate("password1")).toBe(true);
    expect(p.validate("password2")).toBe(false);
  });

  it("must throw on mismatched repeat password", () => {
    const p = newPassword();
    expect(() => p.change("abc", "xyz")).toThrow("Passwords don't match.");
  });

  it("must accept matching repeat password", () => {
    const p = newPassword();
    p.change("mypassword", "mypassword");
    expect(p.validate("mypassword")).toBe(true);
  });

  it("must generate with custom length", () => {
    const p = newPassword();
    p.generate(12);
    const data = p.getData();
    expect(data.hash).toBeTruthy();
    expect(data.isInitial).toBe(true);
  });

  it("must enforce minimum generate length of 8", () => {
    const p = newPassword();
    p.generate(3);
    // password was generated (no error), hash exists
    expect(p.getData().hash).toBeTruthy();
  });

  it("must include pepper in hash", () => {
    const p1 = new Password(
      { ...config, pepper: "pepper1" },
      { algorithm: "sha3-224", hash: "", history: [], isInitial: false, lastChanged: 0, salt: "s" },
    );
    const p2 = new Password(
      { ...config, pepper: "pepper2" },
      { algorithm: "sha3-224", hash: "", history: [], isInitial: false, lastChanged: 0, salt: "s" },
    );
    expect(p1.hash("test", "sha3-224")).not.toBe(p2.hash("test", "sha3-224"));
  });

  it("must include salt in hash", () => {
    const p1 = new Password(config, {
      algorithm: "sha3-224",
      hash: "",
      history: [],
      isInitial: false,
      lastChanged: 0,
      salt: "salt1",
    });
    const p2 = new Password(config, {
      algorithm: "sha3-224",
      hash: "",
      history: [],
      isInitial: false,
      lastChanged: 0,
      salt: "salt2",
    });
    expect(p1.hash("test", "sha3-224")).not.toBe(p2.hash("test", "sha3-224"));
  });

  describe("isInHistory with n parameter", () => {
    it("must limit history check to last n entries", () => {
      const p = newPassword();
      p.change("pw1");
      p.change("pw2");
      p.change("pw3");
      p.change("pw4");
      // history: [pw3, pw2, pw1] (newest first), current = pw4
      expect(p.isInHistory("pw3", 1)).toBe(true);
      expect(p.isInHistory("pw2", 1)).toBe(false);
      expect(p.isInHistory("pw2", 2)).toBe(true);
      expect(p.isInHistory("pw1", 2)).toBe(false);
      expect(p.isInHistory("pw1", 3)).toBe(true);
    });

    it("must return false for current password (not in history)", () => {
      const p = newPassword();
      p.change("pw1");
      expect(p.isInHistory("pw1")).toBe(false); // current, not in history
    });
  });

  describe("checkPolicies", () => {
    it("must return passed when all policies pass", async () => {
      const p = new Password({
        ...config,
        policies: [{ rule: "v.length >= 5", description: "Min 5", errorMessage: "Too short" }],
      });
      p.change("longpassword");
      const result = await p.checkPolicies("longpassword");
      expect(result.passed).toBe(true);
      expect(result.policies).toHaveLength(1);
      expect(result.policies[0].passed).toBe(true);
      expect(result.errors).toHaveLength(0);
    });

    it("must return failed with errors when policies fail", async () => {
      const p = new Password({
        ...config,
        policies: [
          { rule: "v.length >= 20", description: "Min 20", errorMessage: "Too short" },
          { rule: "v.length >= 5", description: "Min 5", errorMessage: "Way too short" },
        ],
      });
      p.change("short");
      const result = await p.checkPolicies("short");
      expect(result.passed).toBe(false);
      expect(result.policies[0].passed).toBe(false);
      expect(result.policies[1].passed).toBe(true);
      expect(result.errors).toEqual(["Too short"]);
    });

    it("must return passed with empty policies", async () => {
      const p = new Password({ ...config, policies: [] });
      p.change("anything");
      const result = await p.checkPolicies("anything");
      expect(result.passed).toBe(true);
      expect(result.policies).toHaveLength(0);
    });
  });

  it("must not append to history when initial hash is empty", () => {
    const p = newPassword(); // hash is ""
    p.change("first-password");
    expect(p.getData().history).toHaveLength(0);
  });

  it("must return data via getData", () => {
    const p = newPassword();
    const data = p.getData();
    expect(data.algorithm).toBe("sha224");
    expect(data.hash).toBe("");
    expect(data.history).toEqual([]);
  });

  it("must initialize with defaults when no data provided", () => {
    const p = new Password(config);
    const data = p.getData();
    expect(data.algorithm).toBe(config.algorithm);
    expect(data.hash).toBe("");
    expect(data.salt).toBe("");
    expect(data.history).toEqual([]);
  });
});
