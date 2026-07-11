// Errors
export { AuthError } from "./errors";
export type { AuthErrorType } from "./errors";

// Credential types
export type {
  AuthContext,
  CredentialState,
  CredentialMetadata,
  EnrichedSession,
  IssueResult,
  RefreshConfig,
  RefreshResult,
  SessionEnricher,
  SessionInfo,
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
export type {
  AuthCredentialOptions,
  IssueOptions,
  RefreshCallOptions,
} from "./credential/auth-credential";

// Shared time abstraction
export type { Clock } from "./utils/clock";
export { defaultClock } from "./utils/clock";

// Rate limiting (RL.spec.md) — fixed-window limiter + stores. The redis
// store lives in the `@aooth/auth/redis` subpath next to the other adapters.
export {
  DEFAULT_RATE_LIMIT_MESSAGE,
  formatDurationMs,
  parseDurationMs,
  parseRateLimitRule,
  renderRateLimitMessage,
} from "./rate-limit/rules";
export type { RateLimitRule, RateLimitRuleInput } from "./rate-limit/rules";
export { RateLimitStoreMemory } from "./rate-limit/store";
export type { RateLimitStore } from "./rate-limit/store";
export { RateLimiter } from "./rate-limit/rate-limiter";
export type { RateLimitDecision, RateLimiterOptions } from "./rate-limit/rate-limiter";

// Email transport interface (consumer provides the impl)
export type { AuthEmailEvent, AuthEmailKind, EmailSender } from "./email";

// SMS transport interface (consumer provides the impl)
export type { AuthSmsEvent, AuthSmsKind, SmsSender } from "./sms";

// Magic-link helpers (framework-agnostic — used by workflow integrations)
export type { BuildMagicLinkUrl } from "./magic-link";
export { generateMagicLinkToken } from "./magic-link";

// Opaque-secret mint shared by magic links, client secrets, authz bindings.
export { generateOpaqueToken } from "./utils/opaque-token";
