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

// AuthCredential orchestrator
export { AuthCredential } from "./credential/auth-credential";
export type { AuthCredentialOptions, IssueOptions } from "./credential/auth-credential";

// Shared time abstraction
export type { Clock } from "./utils/clock";
export { defaultClock } from "./utils/clock";
