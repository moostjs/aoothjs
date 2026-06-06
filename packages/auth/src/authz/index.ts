// Authorization-server core (AUTH-SERVER.md Tier 1) — framework-agnostic
// storage seams + client/redirect policy for aoothjs acting as an OAuth
// authorization server for its OWN clients (a CLI on a loopback redirect today,
// a first-party service later). The moost HTTP endpoints (`/auth/authorize`,
// `/auth/token`) and the DI tokens that bind these abstracts live in
// `@aooth/auth-moost`.

// Token policy — what a completed grant mints (fixed at authorize time).
export type { TokenPolicy } from "./token-policy";

// Failure taxonomy.
export { AuthorizeError, type AuthorizeErrorCode } from "./authz-errors";

// Client / redirect trust boundary (Tier 1 = loopback, Tier 2 = registered).
export {
  isLoopbackRedirectUri,
  LoopbackClientPolicy,
  type ClientRedirectPolicy,
  type LoopbackClientPolicyOptions,
  type ResolvedClient,
} from "./client-policy";
export {
  RegisteredClientPolicy,
  type RegisteredClient,
  type RegisteredClientPolicyOptions,
} from "./registered-client-policy";
export {
  CompositeClientPolicy,
  type CompositeClientPolicyOptions,
} from "./composite-client-policy";

// Tier-2 OIDC: id_token signing + JWKS, and the pluggable profile-claims seam.
export {
  IdTokenSigner,
  type IdTokenAlg,
  type IdTokenClaims,
  type IdTokenSignerOptions,
} from "./id-token-signer";
export { NoopOidcClaimsResolver, OidcClaimsResolver, scopeGrants } from "./oidc-claims-resolver";

// In-flight authorization store (abstract + in-memory reference impl).
export {
  PendingAuthorizationStore,
  PendingAuthorizationStoreMemory,
  type NewPendingAuthorization,
  type PendingAuthorization,
  type PendingAuthorizationStoreMemoryOptions,
} from "./pending-authorization-store";

// Single-use authorization-code store (abstract + in-memory reference impl).
export {
  AuthCodeStore,
  AuthCodeStoreMemory,
  type AuthCode,
  type AuthCodeStoreMemoryOptions,
  type NewAuthCode,
} from "./auth-code-store";
