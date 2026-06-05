/**
 * Failure taxonomy for the authorization-server endpoints (AUTH-SERVER.md §7).
 * The `/authorize` side fails SOFT (302 → an app error/login route, never a
 * 500); the `/token` side returns the RFC-6749-shaped JSON error named by the
 * code. Messages are benign — they must not disclose whether a failure was an
 * unknown client vs. a bad redirect vs. an expired code.
 */
export type AuthorizeErrorCode =
  /** Missing or malformed parameter at `/authorize` or `/token`. */
  | "invalid_request"
  /** `redirect_uri` is not an allowed (loopback / registered) target. */
  | "invalid_redirect"
  /** Code unknown / expired / already-redeemed, or PKCE verifier mismatch (`/token`). */
  | "invalid_grant"
  /** Unknown or unauthenticated client (Tier 2). */
  | "invalid_client"
  /** The user declined the authorization (consent). */
  | "access_denied"
  /** An unexpected server-side failure. */
  | "server_error";

/** A typed authorization-server failure. */
export class AuthorizeError extends Error {
  readonly code: AuthorizeErrorCode;
  constructor(code: AuthorizeErrorCode, message: string) {
    super(message);
    this.name = "AuthorizeError";
    this.code = code;
  }
}
