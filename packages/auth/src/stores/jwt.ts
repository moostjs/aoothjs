import { randomUUID } from "node:crypto";
import { type CryptoKey, type JWTPayload, SignJWT, jwtVerify } from "jose";
import type { CredentialState } from "../credential/types";
import { AuthError } from "../errors";
import { type Clock, defaultClock } from "../utils/clock";
import { hkdfSubkey } from "./derive-subkey";
import type { CredentialStore, DenylistStore } from "./store";

/**
 * Supported JWT signing algorithms.
 * - HS256/HS384/HS512: symmetric (shared secret).
 * - RS*, ES*, EdDSA: asymmetric (private/public keypair).
 */
export type JwtAlgorithm =
  | "HS256"
  | "HS384"
  | "HS512"
  | "RS256"
  | "RS384"
  | "RS512"
  | "ES256"
  | "ES384"
  | "ES512"
  | "EdDSA";

const HS_ALGS = new Set<JwtAlgorithm>(["HS256", "HS384", "HS512"]);

export interface CredentialStoreJwtOptions {
  /** Signing algorithm. Defaults to 'HS256'. */
  algorithm?: JwtAlgorithm;
  /** For HS*: secret string or Uint8Array (>=32 bytes recommended for HS256). */
  secret?: string | Uint8Array | CryptoKey;
  /** For asymmetric algorithms: signing (private) key. */
  privateKey?: CryptoKey | Uint8Array;
  /** For asymmetric algorithms: verifying (public) key. */
  publicKey?: CryptoKey | Uint8Array;
  /** Issuer claim (`iss`). Optional. */
  issuer?: string;
  /** Audience claim (`aud`). Optional. */
  audience?: string;
  /** Optional denylist for revocation support. */
  denylist?: DenylistStore;
  /** Optional clock for testability. */
  clock?: Clock;
}

interface StateClaim {
  kind?: "access" | "refresh";
  claims?: unknown;
  metadata?: unknown;
  parentCredentialId?: string;
  rotatedAt?: number;
  /**
   * Millisecond-precision issuedAt / expiresAt. JWT's `iat` and `exp` claims
   * are second-resolution per RFC 7519, so we mirror them inside the state
   * payload to preserve sub-second precision for callers comparing the
   * `validate()` result with the `IssueResult` they originally received.
   */
  iatMs?: number;
  expMs?: number;
}

/**
 * Stateless credential store that signs the credential state into a JWT.
 *
 * The token IS the state — there is no internal map. State is reconstructed
 * by verifying signature/claims on every retrieve. Revocation requires a
 * `denylist`; without one, `revoke`/`update`/`consume` throw
 * STATELESS_OPERATION_UNSUPPORTED.
 */
export class CredentialStoreJwt<
  TClaims extends object = object,
> implements CredentialStore<TClaims> {
  private readonly algorithm: JwtAlgorithm;
  private readonly signingKey: CryptoKey | Uint8Array;
  private readonly verifyingKey: CryptoKey | Uint8Array;
  private readonly issuer?: string;
  private readonly audience?: string;
  private readonly denylist?: DenylistStore;
  private readonly clock: Clock;
  /**
   * Per-user revocation epoch (ms). `revokeAllForUser` sets this to
   * `clock.now()`; `retrieve` rejects any token whose `iatMs` predates the
   * user's epoch (same-ms mints are accepted so recovery/invite flows can
   * revoke and re-issue in one tick). Compensates for JWT statelessness so
   * password-change cascades invalidate tokens minted before the change.
   * In-memory: resets on process restart (a known JWT limitation — production
   * deployments needing durability should back this with an external store).
   */
  private readonly epochs = new Map<string, number>();

  constructor(opts: CredentialStoreJwtOptions) {
    this.algorithm = opts.algorithm ?? "HS256";
    this.issuer = opts.issuer;
    this.audience = opts.audience;
    this.denylist = opts.denylist;
    this.clock = opts.clock ?? defaultClock;

    if (HS_ALGS.has(this.algorithm)) {
      if (opts.secret == null) {
        throw new AuthError(
          "INVALID_CONFIG",
          `Algorithm ${this.algorithm} requires a 'secret' option`,
        );
      }
      const key = normalizeSecret(opts.secret);
      this.signingKey = key;
      this.verifyingKey = key;
    } else {
      if (opts.privateKey == null || opts.publicKey == null) {
        throw new AuthError(
          "INVALID_CONFIG",
          `Algorithm ${this.algorithm} requires both 'privateKey' and 'publicKey' options`,
        );
      }
      this.signingKey = opts.privateKey;
      this.verifyingKey = opts.publicKey;
    }
  }

  async persist(state: CredentialState<TClaims>, ttl?: number): Promise<string> {
    const jti = randomUUID();
    const now = this.clock.now();
    const expiresAtMs = typeof ttl === "number" ? now + ttl : state.expiresAt;

    const stateClaim: StateClaim = {
      iatMs: state.issuedAt,
      expMs: expiresAtMs,
    };
    if (state.kind !== undefined) stateClaim.kind = state.kind;
    if (state.claims !== undefined) stateClaim.claims = state.claims;
    if (state.metadata !== undefined) stateClaim.metadata = state.metadata;
    if (state.parentCredentialId !== undefined)
      stateClaim.parentCredentialId = state.parentCredentialId;
    if (state.rotatedAt !== undefined) stateClaim.rotatedAt = state.rotatedAt;

    const builder = new SignJWT({ state: stateClaim } satisfies JWTPayload)
      .setProtectedHeader({ alg: this.algorithm })
      .setSubject(state.userId)
      .setIssuedAt(Math.floor(state.issuedAt / 1000))
      .setExpirationTime(Math.floor(expiresAtMs / 1000))
      .setJti(jti);

    if (this.issuer) builder.setIssuer(this.issuer);
    if (this.audience) builder.setAudience(this.audience);

    return builder.sign(this.signingKey);
  }

  async retrieve(token: string): Promise<CredentialState<TClaims> | null> {
    const verified = await this.verify(token);
    if (!verified) return null;
    if (this.denylist && verified.payload.jti) {
      if (await this.denylist.has(verified.payload.jti)) return null;
    }
    if (!this.passesEpoch(verified.payload)) return null;
    return this.payloadToState(verified.payload);
  }

  async consume(token: string): Promise<CredentialState<TClaims> | null> {
    const denylist = this.requireDenylist("consume");
    const verified = await this.verify(token);
    if (!verified) return null;
    if (!this.passesEpoch(verified.payload)) return null;
    const jti = verified.payload.jti;
    if (jti) {
      if (await denylist.has(jti)) return null;
      await denylist.add(jti, this.payloadExpMs(verified.payload));
    }
    return this.payloadToState(verified.payload);
  }

  async update(token: string, state: CredentialState<TClaims>): Promise<string> {
    const denylist = this.requireDenylist("update");
    const verified = await this.verify(token);
    if (verified?.payload.jti) {
      await denylist.add(verified.payload.jti, this.payloadExpMs(verified.payload));
    }
    return this.persist(state);
  }

  async revoke(token: string): Promise<void> {
    const denylist = this.requireDenylist("revoke");
    const verified = await this.verify(token);
    if (!verified?.payload.jti) return;
    await denylist.add(verified.payload.jti, this.payloadExpMs(verified.payload));
  }

  async revokeAllForUser(userId: string): Promise<number> {
    // Stateless: bump a per-user epoch; tokens with iatMs < epoch are rejected
    // (same-ms mints pass so a revoke + re-issue in one tick works). Returns 1
    // to signal "revocation took effect" without claiming a precise count.
    this.epochs.set(userId, this.clock.now());
    return 1;
  }

  deriveSubkey(label: string): Buffer {
    if (this.signingKey instanceof Uint8Array) {
      return hkdfSubkey(this.signingKey, label);
    }
    throw new AuthError(
      "INVALID_CONFIG",
      "deriveSubkey requires a symmetric (HS*) secret; this JWT store uses an asymmetric key — provide an explicit wfStateSecret",
    );
  }

  // --- internal helpers -------------------------------------------------

  private requireDenylist(op: string): DenylistStore {
    if (!this.denylist) {
      throw new AuthError(
        "STATELESS_OPERATION_UNSUPPORTED",
        `${op} requires a denylist on stateless JWT store`,
      );
    }
    return this.denylist;
  }

  /** Convert payload `exp` (seconds) to ms; fall back to a 60s window. */
  private payloadExpMs(payload: JWTPayload): number {
    return typeof payload.exp === "number" ? payload.exp * 1000 : this.clock.now() + 60_000;
  }

  /**
   * Reject tokens minted before the user's revocation epoch. Same-ms mints
   * (`iatMs === epoch`) are accepted so a workflow can revoke and re-issue in
   * one tick. `iatMs` mirrors `iat` at ms precision; we fall back to
   * `iat * 1000` for tokens that predate the mirror field.
   */
  private passesEpoch(payload: JWTPayload): boolean {
    if (typeof payload.sub !== "string") return true;
    const epoch = this.epochs.get(payload.sub);
    if (epoch === undefined) return true;
    const stateClaim = (payload.state ?? {}) as StateClaim;
    const iatMs =
      typeof stateClaim.iatMs === "number"
        ? stateClaim.iatMs
        : typeof payload.iat === "number"
          ? payload.iat * 1000
          : 0;
    return iatMs >= epoch;
  }

  private async verify(token: string): Promise<{ payload: JWTPayload } | null> {
    try {
      const result = await jwtVerify(token, this.verifyingKey, {
        // Restrict to the configured algorithm so an attacker who shares the
        // HMAC secret cannot cross-sign with HS384/HS512 and still verify
        // (jose's default infers a set of algs from the key, which would
        // accept any HS* for a Uint8Array secret).
        algorithms: [this.algorithm],
        issuer: this.issuer,
        audience: this.audience,
        currentDate: new Date(this.clock.now()),
      });
      return { payload: result.payload };
    } catch {
      // Any verification failure — bad sig, expired, malformed, wrong iss/aud,
      // non-string input — collapses to null. Callers never receive throws.
      return null;
    }
  }

  private payloadToState(payload: JWTPayload): CredentialState<TClaims> | null {
    if (typeof payload.sub !== "string") return null;
    if (typeof payload.iat !== "number" || typeof payload.exp !== "number") return null;

    const stateClaim = (payload.state ?? {}) as StateClaim;
    // Prefer ms-precision values if present; fall back to second-precision
    // `iat`/`exp` for backward compatibility with externally minted tokens.
    const issuedAt = typeof stateClaim.iatMs === "number" ? stateClaim.iatMs : payload.iat * 1000;
    const expiresAt = typeof stateClaim.expMs === "number" ? stateClaim.expMs : payload.exp * 1000;
    const out: CredentialState<TClaims> = {
      userId: payload.sub,
      issuedAt,
      expiresAt,
    };
    if (stateClaim.kind !== undefined) out.kind = stateClaim.kind;
    if (stateClaim.claims !== undefined) out.claims = stateClaim.claims as TClaims;
    if (stateClaim.metadata !== undefined)
      out.metadata = stateClaim.metadata as CredentialState<TClaims>["metadata"];
    if (stateClaim.parentCredentialId !== undefined)
      out.parentCredentialId = stateClaim.parentCredentialId;
    if (stateClaim.rotatedAt !== undefined) out.rotatedAt = stateClaim.rotatedAt;
    return out;
  }
}

function normalizeSecret(secret: string | Uint8Array | CryptoKey): Uint8Array | CryptoKey {
  if (typeof secret === "string") return new TextEncoder().encode(secret);
  return secret;
}
