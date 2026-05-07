// Errors
export { AuthError } from "./errors";
export type { AuthErrorType } from "./errors";

// Credential types
export type {
  AuthContext,
  CredentialState,
  CredentialMetadata,
  IssueResult,
  RefreshConfig,
} from "./credential/types";

// Store interfaces
export type { CredentialStore, DenylistStore } from "./stores/store";

// In-memory store implementations
export { CredentialStoreMemory } from "./stores/memory";
export { DenylistStoreMemory } from "./stores/denylist-memory";

// Stateless store implementations
export { CredentialStoreJwt } from "./stores/jwt";
export type { CredentialStoreJwtOptions, JwtAlgorithm } from "./stores/jwt";
export { CredentialStoreEncapsulated } from "./stores/encapsulated";
export type { CredentialStoreEncapsulatedOptions } from "./stores/encapsulated";

// AuthCredential orchestrator
export { AuthCredential } from "./credential/auth-credential";
export type { AuthCredentialOptions, IssueOptions } from "./credential/auth-credential";

// Shared time abstraction
export type { Clock } from "./utils/clock";
export { defaultClock } from "./utils/clock";

// Password reset
export { PasswordReset } from "./password-reset/password-reset";
export type { PasswordResetOptions, RequestResult } from "./password-reset/password-reset";
