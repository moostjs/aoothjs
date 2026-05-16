/**
 * Device-trust store for the "remember this device, skip MFA next time" Phase
 * 4 feature of `LoginWorkflow`.
 *
 * Records are HMAC-SHA256 signed: the cookie value is `<token>.<sig>` where
 * `token` is a random 32-byte hex (per-record) and `sig` is HMAC of
 * `<userId>|<token>|<ip-or-empty>` keyed on the consumer-supplied secret.
 * `verify()` re-signs and constant-time-compares; the store also enforces the
 * `expiresAt` window and (when bound) the IP match.
 *
 * The default `DeviceTrustStoreMemory` is in-process and process-local — fine
 * for tests + single-instance demos; consumers running multiple instances
 * implement `DeviceTrustStore` against Redis / their DB and re-use the HMAC
 * pattern so verification stays stateless on cache misses.
 */
import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";

export interface DeviceTrustRecord {
  userId: string;
  /** `<token>.<sig>` — the value written into the cookie. */
  token: string;
  /** Bound IP — populated when `deviceTrustBindsTo === 'cookie+ip'`. */
  ip?: string;
  issuedAt: number;
  expiresAt: number;
}

export interface DeviceTrustStore {
  /** Persist a freshly-issued trust record. */
  add(record: DeviceTrustRecord): Promise<void>;
  /**
   * Returns `true` when the supplied token belongs to `userId`, has not
   * expired, the HMAC signature matches, and (when `ip` was bound at issue
   * time) the supplied IP matches.
   */
  verify(userId: string, token: string, ip?: string): Promise<boolean>;
  /** Revoke a specific trust record. No-op if it does not exist. */
  revoke(userId: string, token: string): Promise<void>;
  /**
   * Mint the cookie value for a new trust record. Pure helper — consumers
   * with custom stores re-use the same signing scheme to keep verify()
   * compatible across implementations.
   */
  issue(userId: string, ip: string | undefined, ttlMs: number, now?: number): DeviceTrustRecord;
}

const TOKEN_BYTES = 32;
const SEPARATOR = ".";

function sign(secret: string, payload: string): string {
  return createHmac("sha256", secret).update(payload).digest("hex");
}

function safeEqual(a: string, b: string): boolean {
  const ab = Buffer.from(a);
  const bb = Buffer.from(b);
  if (ab.length !== bb.length) return false;
  return timingSafeEqual(ab, bb);
}

/**
 * In-memory `DeviceTrustStore`. Records are keyed by `userId` for O(1) lookup
 * during `verify()`. Records expire lazily on read; periodic GC is not needed
 * for the test/demo scale this is built for.
 */
export class DeviceTrustStoreMemory implements DeviceTrustStore {
  private readonly records = new Map<string, DeviceTrustRecord[]>();

  constructor(private readonly secret: string) {
    if (!secret) throw new Error("DeviceTrustStoreMemory: secret is required");
  }

  issue(
    userId: string,
    ip: string | undefined,
    ttlMs: number,
    now: number = Date.now(),
  ): DeviceTrustRecord {
    const raw = randomBytes(TOKEN_BYTES).toString("hex");
    const payload = `${userId}|${raw}|${ip ?? ""}`;
    const sig = sign(this.secret, payload);
    return {
      userId,
      token: `${raw}${SEPARATOR}${sig}`,
      ...(ip !== undefined && { ip }),
      issuedAt: now,
      expiresAt: now + ttlMs,
    };
  }

  async add(record: DeviceTrustRecord): Promise<void> {
    const existing = this.records.get(record.userId) ?? [];
    existing.push(record);
    this.records.set(record.userId, existing);
  }

  async verify(userId: string, token: string, ip?: string): Promise<boolean> {
    const sepIdx = token.lastIndexOf(SEPARATOR);
    if (sepIdx <= 0) return false;
    const raw = token.slice(0, sepIdx);
    const sig = token.slice(sepIdx + 1);
    const expectedPayload = `${userId}|${raw}|${ip ?? ""}`;
    const expectedSig = sign(this.secret, expectedPayload);
    if (!safeEqual(sig, expectedSig)) return false;

    const list = this.records.get(userId);
    if (!list) return false;
    const now = Date.now();
    const found = list.find((r) => r.token === token && r.expiresAt > now);
    if (!found) return false;
    if (found.ip !== undefined && found.ip !== ip) return false;
    return true;
  }

  async revoke(userId: string, token: string): Promise<void> {
    const list = this.records.get(userId);
    if (!list) return;
    const filtered = list.filter((r) => r.token !== token);
    if (filtered.length === 0) this.records.delete(userId);
    else this.records.set(userId, filtered);
  }
}
