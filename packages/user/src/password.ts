import { Changeable } from "./changeable";
import { hashPassword } from "./crypto";
import { normalizePolicies } from "./password-policy";
import type {
  TChangeOperation,
  TCryptoAlgorithm,
  TCumulativeChanges,
  TPasswordConfig,
  TAoothUserCredentials,
} from "./types";

const LOWERCASE = "abcdefghijklmnopqrstuvwxyz";
const UPPERCASE = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const NUMBERS = "0123456789";
const SPECIALCHARS = "!@#$%^&*()-_=+[]{}|;:,.<>?";
const ALLCHARS = [LOWERCASE, UPPERCASE, NUMBERS, SPECIALCHARS].join("");

export class Password extends Changeable {
  protected data: TAoothUserCredentials["password"];

  constructor(
    protected config: TPasswordConfig,
    data?: TAoothUserCredentials["password"],
    changes?: TCumulativeChanges,
  ) {
    super(changes || {});
    this.data = data
      ? { ...data }
      : {
          algorithm: config.algorithm,
          hash: "",
          history: [],
          isInitial: false,
          lastChanged: 0,
          salt: "",
        };
  }

  generate(length = 8) {
    const passwordLength = Math.max(length, 8);

    let password = "";

    for (let i = 0; i < passwordLength; i++) {
      const randomIndex = Math.floor(Math.random() * ALLCHARS.length);
      password += ALLCHARS[randomIndex];
    }

    this.change(password);
    this.pushChange("password.isInitial", "set", true);
  }

  change(newPassword: string, repeatNewPassword?: string) {
    if (typeof repeatNewPassword === "string") {
      if (newPassword !== repeatNewPassword) throw new Error("Passwords don't match.");
    }
    const oldPassword = {
      hash: this.data.hash,
      algorithm: this.data.algorithm,
    };
    this.pushChange("password.hash", "set", this.hash(newPassword, this.config.algorithm));
    if (oldPassword.hash) {
      this.appendHistory(oldPassword.hash, oldPassword.algorithm);
    }
    this.pushChange("password.algorithm", "set", this.config.algorithm);
    this.pushChange("password.lastChanged", "set", new Date().getTime());
  }

  hash(value: string, algorithm: TCryptoAlgorithm) {
    return hashPassword(`${this.config.pepper || ""}${value}${this.data.salt}`, algorithm);
  }

  validate(password: string) {
    return this.data.hash === this.hash(password, this.data.algorithm);
  }

  isInHistory(password: string, n?: number) {
    const hashCache = new Map<TCryptoAlgorithm, string>();
    let count = 0;
    for (const { hash, algorithm } of this.data.history || []) {
      count++;
      if (typeof n === "number" && count > n) break;
      let computed = hashCache.get(algorithm);
      if (computed === undefined) {
        computed = this.hash(password, algorithm);
        hashCache.set(algorithm, computed);
      }
      if (hash === computed) return true;
    }
    return false;
  }

  async checkPolicies(password: string) {
    const result = {
      passed: true,
      policies: [] as { text: string; passed: boolean }[],
      errors: [] as string[],
    };
    for (const policy of normalizePolicies(this.config.policies)) {
      const passed = await policy.evaluate(password, this.data, this.config);
      result.passed = result.passed && passed;
      result.policies.push({ text: policy.description, passed });
      if (!passed) result.errors.push(policy.errorMessage);
    }
    return result;
  }

  getData() {
    return this.data;
  }

  protected appendHistory(hash: string, algorithm: TCryptoAlgorithm) {
    const limit = typeof this.config.historyLength === "number" ? this.config.historyLength : 10;
    const history = this.data.history || [];
    const newHistory = [{ hash, algorithm }, ...history.slice(0, limit - 1)];
    this.pushChange("password.history", "set", newHistory);
  }

  pushChange(path: string, op: TChangeOperation, newValue: unknown) {
    super.pushChange(path, op, newValue);
    if (path.startsWith("password.")) {
      this.data[path.slice(9) as keyof typeof this.data] = newValue as never;
    }
  }

  protected getCurrentValue(path: string) {
    if (path.startsWith("password.")) {
      return this.data[path.slice(9) as keyof typeof this.data];
    }
  }
}
