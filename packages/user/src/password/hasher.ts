import { scrypt, randomBytes, timingSafeEqual } from "node:crypto";
import type { PasswordConfig } from "../types";

const DEFAULTS = { N: 16384, r: 8, p: 1, keyLength: 64, saltLength: 32 };
const PREFIX = "$scrypt$";

interface ParsedHash {
  N: number;
  r: number;
  p: number;
  keyLength: number;
  salt: Buffer;
  hash: Buffer;
}

function scryptAsync(
  password: string,
  salt: Buffer,
  keyLength: number,
  options: { N: number; r: number; p: number },
): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    scrypt(password, salt, keyLength, options, (err, derived) => {
      if (err) reject(err);
      else resolve(derived);
    });
  });
}

function parseHash(encoded: string): ParsedHash | null {
  if (!encoded.startsWith(PREFIX)) return null;
  const parts = encoded.slice(PREFIX.length).split("$");
  if (parts.length !== 3) return null;

  const params: Record<string, number> = {};
  for (const kv of parts[0].split(",")) {
    const [k, v] = kv.split("=");
    params[k] = Number(v);
  }
  if (!params.N || !params.r || !params.p || !params.l) return null;

  return {
    N: params.N,
    r: params.r,
    p: params.p,
    keyLength: params.l,
    salt: Buffer.from(parts[1], "base64url"),
    hash: Buffer.from(parts[2], "base64url"),
  };
}

export class PasswordHasher {
  private readonly pepper: string;
  private readonly N: number;
  private readonly r: number;
  private readonly p: number;
  private readonly keyLength: number;

  constructor(config?: PasswordConfig) {
    this.pepper = config?.pepper ?? "";
    this.N = config?.scryptN ?? DEFAULTS.N;
    this.r = config?.scryptR ?? DEFAULTS.r;
    this.p = config?.scryptP ?? DEFAULTS.p;
    this.keyLength = config?.keyLength ?? DEFAULTS.keyLength;
  }

  async hash(password: string): Promise<string> {
    const salt = randomBytes(DEFAULTS.saltLength);
    const derived = await scryptAsync(this.pepper + password, salt, this.keyLength, {
      N: this.N,
      r: this.r,
      p: this.p,
    });
    const params = `N=${this.N},r=${this.r},p=${this.p},l=${this.keyLength}`;
    return `${PREFIX}${params}$${salt.toString("base64url")}$${derived.toString("base64url")}`;
  }

  async verify(password: string, encoded: string): Promise<boolean> {
    const parsed = parseHash(encoded);
    if (!parsed) return false;
    const derived = await scryptAsync(this.pepper + password, parsed.salt, parsed.keyLength, {
      N: parsed.N,
      r: parsed.r,
      p: parsed.p,
    });
    if (derived.length !== parsed.hash.length) return false;
    return timingSafeEqual(derived, parsed.hash);
  }

  generatePassword(length = 16): string {
    const minLen = Math.max(length, 8);
    const lower = "abcdefghijklmnopqrstuvwxyz";
    const upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const digits = "0123456789";
    const special = "!@#$%^&*()-_=+";
    const all = lower + upper + digits + special;

    // Ensure at least one char from each category
    const bytes = randomBytes(minLen);
    const result: string[] = Array.from({ length: minLen });
    result[0] = lower[bytes[0] % lower.length];
    result[1] = upper[bytes[1] % upper.length];
    result[2] = digits[bytes[2] % digits.length];
    result[3] = special[bytes[3] % special.length];
    for (let i = 4; i < minLen; i++) {
      result[i] = all[bytes[i] % all.length];
    }

    // Fisher-Yates shuffle using secure random bytes
    const shuffleBytes = randomBytes(minLen);
    for (let i = minLen - 1; i > 0; i--) {
      const j = shuffleBytes[i] % (i + 1);
      [result[i], result[j]] = [result[j], result[i]];
    }

    return result.join("");
  }
}
