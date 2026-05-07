import { UserAuthError, type UserService } from "@aoothjs/user";
import type { CredentialState } from "../credential/types";
import { AuthError } from "../errors";
import type { CredentialStore } from "../stores/store";
import { type Clock, defaultClock } from "../utils/clock";

/** Default reset token lifetime: 1 hour. */
const DEFAULT_RESET_TTL = 60 * 60 * 1000;

export interface PasswordResetOptions {
  /** Where reset tokens are persisted. Typically Encapsulated for stateless flows. */
  store: CredentialStore;
  /** UserService for resolving username and applying setPassword. */
  userService: UserService;
  /** Default 1 hour. */
  ttl?: number;
  /** Optional clock for testability. */
  clock?: Clock;
}

export interface RequestResult {
  resetToken: string;
  expiresAt: number;
}

/**
 * Issues + consumes single-use password-reset tokens on top of a
 * {@link CredentialStore}. Delivery (email, SMS, ...) is the caller's
 * responsibility — this class only mints and validates tokens.
 */
export class PasswordReset {
  private readonly store: CredentialStore;
  private readonly userService: UserService;
  private readonly ttl: number;
  private readonly clock: Clock;

  constructor(opts: PasswordResetOptions) {
    this.store = opts.store;
    this.userService = opts.userService;
    this.ttl = opts.ttl ?? DEFAULT_RESET_TTL;
    this.clock = opts.clock ?? defaultClock;
  }

  /**
   * Request a password reset for a user.
   *
   * Returns a reset token + expiry, or `null` if the user doesn't exist.
   * Caller is responsible for delivering the token (email, SMS, ...).
   *
   * Concurrent requests for the same user are independent: each produces a
   * fresh, single-use token. Existing tokens are not invalidated — this is
   * standard for reset flows so a user retrying delivery still has options.
   */
  async request(username: string): Promise<RequestResult | null> {
    // UserService.getUser throws NOT_FOUND; translate to null per design
    // (HTTP enumeration protection is handled separately, at the HTTP layer).
    try {
      await this.userService.getUser(username);
    } catch (e) {
      if (e instanceof UserAuthError && e.type === "NOT_FOUND") {
        return null;
      }
      throw e;
    }

    const issuedAt = this.clock.now();
    const expiresAt = issuedAt + this.ttl;
    // CredentialState.userId is opaque from the store's perspective; we use
    // username here because UserService is keyed by username.
    const state: CredentialState = {
      userId: username,
      issuedAt,
      expiresAt,
    };
    const resetToken = await this.store.persist(state, this.ttl);
    return { resetToken, expiresAt };
  }

  /**
   * Consume a reset token and apply the new password.
   *
   * Throws {@link AuthError} `INVALID_TOKEN` for unknown/expired/already-used
   * tokens. `UserAuthError` from {@link UserService.setPassword} (policy /
   * history violations) propagates unchanged.
   *
   * Note: the token is consumed BEFORE `setPassword` runs, so a policy or
   * history failure leaves the token spent. This is intentional — re-issuing
   * the token on failure would let an attacker brute-force passwords through
   * repeated execute() calls. Callers must surface the policy error and
   * direct the user to request a new reset link.
   */
  async execute(resetToken: string, newPassword: string): Promise<void> {
    const state = await this.store.consume(resetToken);
    if (!state) {
      throw new AuthError("INVALID_TOKEN", "Invalid or expired reset token");
    }
    await this.userService.setPassword(state.userId, newPassword);
  }
}
