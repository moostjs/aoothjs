import { createCipheriv, createDecipheriv, randomBytes, randomUUID, scryptSync } from "node:crypto";
import type { CredentialState } from "../credential/types";
import { AuthError } from "../errors";
import { type Clock, defaultClock } from "../utils/clock";
import { hkdfSubkey } from "./derive-subkey";
import type { CredentialStore, DenylistStore } from "./store";

const KEY_LEN = 32; // AES-256
const IV_LEN = 12; // AES-GCM standard
const TAG_LEN = 16; // AES-GCM auth tag length
// Library-scoped fixed salt. A per-instance random salt would defeat rainbow
// tables for weak passphrases, but it would have to be embedded in every token
// (deriving it once at construction would change keys across restarts and
// break every previously issued token). Callers wanting maximum protection
// should pass a 32-byte random buffer as `secret` (no KDF runs in that case).
const KDF_SALT = Buffer.from("aoothjs-auth-encapsulated-v1", "utf8");

export interface CredentialStoreEncapsulatedOptions {
  /**
   * Encryption key material. If a 32-byte Buffer/Uint8Array is provided it is
   * used directly; otherwise it is run through scrypt to derive a 32-byte key.
   */
  secret: string | Buffer | Uint8Array;
  /** Optional denylist for revocation support. */
  denylist?: DenylistStore;
  /** Optional clock for testability. */
  clock?: Clock;
}

interface EncryptedPayload<TClaims extends object> extends CredentialState<TClaims> {
  jti: string;
}

/**
 * Stateless credential store that encrypts the credential state with
 * AES-256-GCM. The token IS the encrypted blob, base64url-encoded as
 * `iv (12B) || ciphertext || authTag (16B)`.
 *
 * Same denylist semantics as {@link CredentialStoreJwt}: revocation /
 * single-use consume / update require a denylist; otherwise these operations
 * throw STATELESS_OPERATION_UNSUPPORTED.
 *
 * Key derivation:
 * - A 32-byte `Buffer`/`Uint8Array` `secret` is used as the AES key directly
 *   (no KDF).
 * - Any other secret (string, shorter/longer buffer) is run through scrypt
 *   with a fixed library-scoped salt to produce a 32-byte key. The salt is
 *   intentionally fixed so keys remain stable across process restarts; if it
 *   were random, every previously issued token would become undecryptable.
 *   For maximum protection against rainbow tables on weak passphrases,
 *   provide a 32-byte random buffer as `secret` (the KDF path is skipped).
 *
 * Revocation caveat: `revokeAllForUser` uses an in-memory per-user epoch map.
 * It does not survive process restart and does not sync across instances —
 * the same limitation as `CredentialStoreJwt`. Use `CredentialStoreRedis` or
 * `CredentialStoreAtscriptDb` when you need native enumeration with durable
 * cross-instance cascade semantics.
 */
export class CredentialStoreEncapsulated<
  TClaims extends object = object,
> implements CredentialStore<TClaims> {
  private readonly key: Buffer;
  private readonly denylist?: DenylistStore;
  private readonly clock: Clock;
  /**
   * Per-user revocation epoch (ms). `revokeAllForUser` sets this to
   * `clock.now()`; `retrieve`/`consume` reject any decrypted state whose
   * `issuedAt` is strictly less than the user's epoch (same-ms mints are
   * accepted so recovery/invite flows can revoke and re-issue in the same
   * tick). Mirrors the JWT store pattern; see class JSDoc for durability
   * caveats.
   */
  private readonly epochs = new Map<string, number>();

  constructor(opts: CredentialStoreEncapsulatedOptions) {
    if (opts.secret == null) {
      throw new AuthError("INVALID_CONFIG", "CredentialStoreEncapsulated requires a 'secret'");
    }
    this.key = deriveKey(opts.secret);
    this.denylist = opts.denylist;
    this.clock = opts.clock ?? defaultClock;
  }

  async persist(state: CredentialState<TClaims>, ttl?: number): Promise<string> {
    const jti = randomUUID();
    const expiresAt = typeof ttl === "number" ? this.clock.now() + ttl : state.expiresAt;
    const payload: EncryptedPayload<TClaims> = { ...state, expiresAt, jti };

    const iv = randomBytes(IV_LEN);
    const cipher = createCipheriv("aes-256-gcm", this.key, iv);
    const plaintext = Buffer.from(JSON.stringify(payload), "utf8");
    const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const authTag = cipher.getAuthTag();

    return Buffer.concat([iv, ciphertext, authTag]).toString("base64url");
  }

  async retrieve(token: string): Promise<CredentialState<TClaims> | null> {
    const decrypted = this.decrypt(token);
    if (!decrypted) return null;
    if (decrypted.expiresAt <= this.clock.now()) return null;
    if (!this.passesEpoch(decrypted)) return null;
    if (this.denylist && (await this.denylist.has(decrypted.jti))) return null;
    return stripJti(decrypted);
  }

  async consume(token: string): Promise<CredentialState<TClaims> | null> {
    const denylist = this.requireDenylist("consume");
    const decrypted = this.decrypt(token);
    if (!decrypted) return null;
    if (decrypted.expiresAt <= this.clock.now()) return null;
    if (!this.passesEpoch(decrypted)) return null;
    if (await denylist.has(decrypted.jti)) return null;
    await denylist.add(decrypted.jti, decrypted.expiresAt);
    return stripJti(decrypted);
  }

  async update(token: string, state: CredentialState<TClaims>): Promise<string> {
    const denylist = this.requireDenylist("update");
    const decrypted = this.decrypt(token);
    if (decrypted) {
      await denylist.add(decrypted.jti, decrypted.expiresAt);
    }
    return this.persist(state);
  }

  async revoke(token: string): Promise<void> {
    const denylist = this.requireDenylist("revoke");
    const decrypted = this.decrypt(token);
    if (!decrypted) return;
    await denylist.add(decrypted.jti, decrypted.expiresAt);
  }

  async revokeAllForUser(userId: string): Promise<number> {
    // Stateless: bump a per-user epoch; tokens with issuedAt < epoch are
    // rejected (same-ms mints pass so a revoke + re-issue in one tick works).
    // Returns 1 to signal "revocation took effect" without claiming a count.
    this.epochs.set(userId, this.clock.now());
    return 1;
  }

  deriveSubkey(label: string): Buffer {
    return hkdfSubkey(this.key, label);
  }

  /**
   * Reject decrypted payloads whose `issuedAt` predates the user's revocation
   * epoch. Same-ms mints (`issuedAt === epoch`) are accepted so a workflow can
   * revoke and re-issue in one tick. Mirrors `CredentialStoreJwt.passesEpoch`.
   */
  private passesEpoch(payload: EncryptedPayload<TClaims>): boolean {
    const epoch = this.epochs.get(payload.userId);
    if (epoch === undefined) return true;
    return payload.issuedAt >= epoch;
  }

  private requireDenylist(op: string): DenylistStore {
    if (!this.denylist) {
      throw new AuthError(
        "STATELESS_OPERATION_UNSUPPORTED",
        `${op} requires a denylist on stateless encapsulated store`,
      );
    }
    return this.denylist;
  }

  private decrypt(token: string): EncryptedPayload<TClaims> | null {
    try {
      const blob = Buffer.from(token, "base64url");
      // Need at least IV + 1 byte ciphertext + tag.
      if (blob.length < IV_LEN + 1 + TAG_LEN) return null;
      const iv = blob.subarray(0, IV_LEN);
      const authTag = blob.subarray(blob.length - TAG_LEN);
      const ciphertext = blob.subarray(IV_LEN, blob.length - TAG_LEN);
      const decipher = createDecipheriv("aes-256-gcm", this.key, iv);
      decipher.setAuthTag(authTag);
      const plain = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
      const parsed = JSON.parse(plain.toString("utf8")) as EncryptedPayload<TClaims>;
      if (
        typeof parsed?.userId !== "string" ||
        typeof parsed.jti !== "string" ||
        typeof parsed.issuedAt !== "number" ||
        typeof parsed.expiresAt !== "number"
      ) {
        return null;
      }
      return parsed;
    } catch {
      // Tampered ciphertext, bad authTag, malformed base64, malformed JSON —
      // all collapse to null to avoid leaking info.
      return null;
    }
  }
}

function deriveKey(secret: string | Buffer | Uint8Array): Buffer {
  if (typeof secret !== "string") {
    const buf = Buffer.isBuffer(secret) ? secret : Buffer.from(secret);
    if (buf.length === KEY_LEN) return buf;
    return scryptSync(buf, KDF_SALT, KEY_LEN);
  }
  // String secret: always run through scrypt for consistent key material,
  // even if it happens to be 32 chars (the user is unlikely to provide raw
  // entropy as a plain string).
  return scryptSync(secret, KDF_SALT, KEY_LEN);
}

function stripJti<TClaims extends object>(
  payload: EncryptedPayload<TClaims>,
): CredentialState<TClaims> {
  const { jti: _jti, ...rest } = payload;
  return rest;
}
