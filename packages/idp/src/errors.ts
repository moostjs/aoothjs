/**
 * Federated-login failure taxonomy (RFC IDP.md §8). Mirrors `AuthError` /
 * `UserAuthError` — a typed `Error` with a stable `type` code, an optional
 * override `message`, and structured `details`.
 *
 * The HTTP/redirect mapping (§8 "fail soft — 302, never 500") is the phase-3
 * `OAuthController`'s job; this layer only classifies. Messages are deliberately
 * benign so the controller can surface them without leaking CSRF-vs-expiry.
 */
export type OAuthErrorType =
  /** `:provider` did not resolve in the registry (→ HTTP 404 in phase 3). */
  | "UNKNOWN_PROVIDER"
  /** Misconfigured provider/registry (missing clientId, issuer, baseUrl, secret). */
  | "INVALID_CONFIG"
  /** Signed `state` failed signature/binding verification (CSRF). */
  | "STATE_INVALID"
  /** Signed `state` is well-formed but past its TTL — restart `/start`. */
  | "STATE_EXPIRED"
  /** Provider returned `?error=` or the user denied consent. */
  | "PROVIDER_DENIED"
  /** Token-endpoint exchange failed: network, 5xx, malformed body, or `code` reuse. */
  | "EXCHANGE_FAILED"
  /** JWKS / discovery document fetch failed — verification fails CLOSED (§7). */
  | "JWKS_FAILED"
  /** OIDC ID-token failed the OIDC Core 3.1.3.7 validation list (§7). */
  | "ID_TOKEN_INVALID"
  /** Policy needed a verified email but the provider returned none. */
  | "EMAIL_UNAVAILABLE";

const defaultMessages: Record<OAuthErrorType, string> = {
  UNKNOWN_PROVIDER: "Unknown identity provider",
  INVALID_CONFIG: "Invalid OAuth provider configuration",
  STATE_INVALID: "Sign-in could not be verified",
  STATE_EXPIRED: "Sign-in expired — please try again",
  PROVIDER_DENIED: "Sign-in was cancelled",
  EXCHANGE_FAILED: "Could not complete sign-in with the provider",
  JWKS_FAILED: "Could not verify the provider's signing keys",
  ID_TOKEN_INVALID: "The provider's identity token could not be validated",
  EMAIL_UNAVAILABLE: "The provider did not supply a usable email address",
};

export class OAuthError extends Error {
  override readonly name = "OAuthError";

  constructor(
    public readonly type: OAuthErrorType,
    message?: string,
    public readonly details?: Record<string, unknown>,
  ) {
    super(message ?? defaultMessages[type]);
  }
}
