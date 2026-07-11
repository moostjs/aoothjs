// Authorization-server core (AUTH-SERVER.md Tier 1) — framework-agnostic
// storage seams + client/redirect policy for aoothjs acting as an OAuth
// authorization server for its OWN clients (a CLI on a loopback redirect today,
// a first-party service later). The moost HTTP endpoints (`/auth/authorize`,
// `/auth/token`) and the DI tokens that bind these abstracts live in
// `@aooth/auth-moost`.

// Token policy — what a completed grant mints (fixed at authorize time).
export {
  DEFAULT_AUTHZ_REFRESH_TTL_MS,
  tokenPolicyToIssueOptions,
  type TokenPolicy,
} from "./token-policy";

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

// RFC 7591 dynamic client registration (connector-style public clients):
// store seam + registration operation + the policy slotting into the
// `CompositeClientPolicy` `dynamic` slot.
export {
  DynamicClientStore,
  DynamicClientStoreMemory,
  type DynamicClient,
  type DynamicClientAuthMethod,
  type DynamicClientStoreMemoryOptions,
  type NewDynamicClient,
} from "./dynamic-client-store";
export {
  ClientRegistrationError,
  DynamicClientRegistration,
  validateClientRegistration,
  type ClientRegistrationErrorCode,
  type ClientRegistrationValidationOptions,
  type DynamicClientRegistrationOptions,
  type RegisteredDynamicClient,
} from "./client-registration";
export { hashClientSecret, mintClientSecret, verifyClientSecret } from "./client-secret";
export { DynamicClientPolicy, type DynamicClientPolicyOptions } from "./dynamic-client-policy";

// Tier-2 OIDC: id_token signing + JWKS, and the pluggable profile-claims seam.
export {
  IdTokenSigner,
  type IdTokenAlg,
  type IdTokenClaims,
  type IdTokenSignerOptions,
} from "./id-token-signer";
export { NoopOidcClaimsResolver, OidcClaimsResolver, scopeGrants } from "./oidc-claims-resolver";

// Discovery documents + bearer challenge: RFC 8414 AS metadata, RFC 9728
// protected-resource metadata, RFC 6750 `WWW-Authenticate` header value —
// what MCP connector clients use to find this server from a 401.
export {
  buildAuthorizationServerMetadata,
  canonicalizeIssuer,
  type AuthorizationServerMetadata,
  type BuildAuthorizationServerMetadataOptions,
} from "./server-metadata";
export {
  buildProtectedResourceMetadata,
  buildWwwAuthenticateBearerChallenge,
  type BuildProtectedResourceMetadataOptions,
  type ProtectedResourceMetadata,
  type WwwAuthenticateBearerChallengeOptions,
} from "./resource-metadata";

// In-flight authorization store (abstract + in-memory reference impl).
export {
  DEFAULT_PENDING_TTL_MS,
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
