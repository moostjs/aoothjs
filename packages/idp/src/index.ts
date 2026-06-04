// Errors
export { OAuthError } from "./errors";
export type { OAuthErrorType } from "./errors";

// Core types
export type {
  NormalizedProfile,
  IdentityProvider,
  ConfigurableProvider,
  AuthorizationUrlArgs,
  ExchangeArgs,
  FetchLike,
  FetchResponseLike,
  SharedProviderConfig,
  FederatedPolicy,
  ResolvedFederatedPolicy,
  EmailMatchPolicy,
  ResolveOutcome,
} from "./types";
export { isConfigurableProvider, defaultUsernameStrategy, resolveFederatedPolicy } from "./types";

// PKCE / nonce / CSRF-random primitives
export {
  createPkcePair,
  pkceChallengeFor,
  generateNonce,
  generateRandomState,
  deriveSeededPkce,
} from "./pkce";
export type { PkcePair, SeededPkce } from "./pkce";

// Signed state
export { signState, verifyState } from "./state";
export type { OAuthStatePayload, SignStateOptions, VerifyStateOptions } from "./state";

// Providers
export { OidcProvider } from "./providers/oidc";
export type { OidcProviderOptions, OidcDiscoveryDocument } from "./providers/oidc";
export { GoogleProvider } from "./providers/google";
export type { GoogleProviderOptions } from "./providers/google";
export { FakeIdentityProvider } from "./providers/fake";
export type { FakeIdentityProviderOptions } from "./providers/fake";

// Provider registry
export { OAuthProviderRegistry } from "./registry";
export type { OAuthProviderRegistryOptions } from "./registry";

// Federated-login core
export { FederatedLoginService } from "./federated-login-service";
export type { FederatedLoginServiceDeps } from "./federated-login-service";
