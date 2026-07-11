// Re-exported from @aooth/auth — exposed in the public surface (handler
// returns + helper parameters) so consumers don't need a second import.
export type {
  AuthContext,
  EnrichedSession,
  IssueResult,
  SessionEnricher,
  SessionInfo,
} from "@aooth/auth";

export {
  type AuthOptions,
  type ResolvedAuthCookieConfig,
  type ResolvedAuthOptions,
} from "./auth.config";
export { ConsentStore, type ConsentDescriptor, type ConsentEvent } from "./consent.store";
export { authGuardInterceptor, AuthGuarded } from "./auth.guard";
export { useAuth, type AuthBindings } from "./auth.composables";
export { Public, UserId } from "./auth.decorator";
export { getAuthMate, type TAuthMeta } from "./auth.mate";
export {
  AuthController,
  ADD_MFA_WORKFLOW,
  CHANGE_PASSWORD_WORKFLOW,
  DEFAULT_AUTH_WORKFLOWS,
} from "./auth.controller";
export { SessionsController, SessionEnricherProvider } from "./sessions.controller";
export type {
  AuthLoginResponse,
  AuthLogoutBody,
  AuthOkResponse,
  AuthRefreshBody,
} from "./auth.dto";
export { WfTrigger, type WfTriggerOpts } from "./wf-trigger/decorator";
export { deriveWfStateSecret, WfTriggerProvider } from "./wf-trigger/provider";

// ── Rate limiting (RL.spec.md) — @RateLimit metadata + enforcing interceptor
//    pair + composable. The limiter/stores are framework-agnostic and live in
//    @aooth/auth (redis store under `@aooth/auth/redis`); re-exported here for
//    ergonomic single-import setup.
export { RateLimit, RateLimited } from "./rate-limit/decorator";
export { rateLimitInterceptors, type RateLimitInterceptorOptions } from "./rate-limit/interceptor";
export {
  getRateLimitSubject,
  setRateLimitSubject,
  useRateLimit,
  type RateLimitBindings,
} from "./rate-limit/composables";
export {
  getRateLimitMate,
  type RateLimitDecoratorOptions,
  type RateLimitKeyStrategy,
  type TRateLimitMeta,
} from "./rate-limit/mate";
export { RateLimiter, RateLimitStoreMemory } from "@aooth/auth";
export type {
  RateLimitDecision,
  RateLimiterOptions,
  RateLimitRule,
  RateLimitRuleInput,
  RateLimitStore,
} from "@aooth/auth";

// ── Federated login (OAuth2 / OIDC) — moost integration of @aooth/idp ──
export { type ConnectedAccount, OAuthController } from "./oauth/oauth.controller";
export { OAUTH_CSRF_COOKIE, oauthCsrfCookieAttrs } from "./oauth/oauth-csrf";
export { isSafeRelativeRedirect, resolveOAuthRedirect } from "./oauth/oauth-redirect";
export { OAuthRuntime } from "./oauth/oauth-runtime";
export { FEDERATED_IDENTITY_STORE_TOKEN } from "./oauth/oauth-tokens";

// ── Authorization server (AUTH-SERVER.md) — aoothjs as an OAuth/OIDC provider
//    for its OWN clients (CLI loopback, Tier 1; first-party service SSO with
//    id_token / JWKS / discovery, Tier 2). The framework-agnostic stores,
//    client/redirect policies, id_token signer, claims resolver, token policy,
//    and error taxonomy live in `@aooth/auth/authz`; this layer adds the HTTP
//    endpoints + the moost-DI binding tokens (mirrors the federated split, where
//    the store lives in `@aooth/user` and only the token lives here). ──
export { AuthorizeController } from "./authz/authorize.controller";
export { AuthorizeRuntime } from "./authz/authorize-runtime";
export { AUTHZ_BINDING_COOKIE, authzBindingCookieAttrs } from "./authz/authz-binding";
export {
  AUTH_CODE_STORE_TOKEN,
  CLIENT_REDIRECT_POLICY_TOKEN,
  DYNAMIC_CLIENT_STORE_TOKEN,
  PENDING_AUTHORIZATION_STORE_TOKEN,
} from "./authz/authz-tokens";

// Re-exported from @aooth/auth/authz (OAUTH.md R1/R3) — the pure discovery /
// challenge builders a consumer mounts at the HTTP-server ROOT (the RFC 8414
// path-insertion form + the RFC 9728 protected-resource document), which a
// prefix-mounted controller cannot register itself, plus the DCR primitives
// the AuthorizeController subclass wires up.
export {
  buildAuthorizationServerMetadata,
  buildProtectedResourceMetadata,
  buildWwwAuthenticateBearerChallenge,
  canonicalizeIssuer,
  DynamicClientRegistration,
  type AuthorizationServerMetadata,
  type BuildAuthorizationServerMetadataOptions,
  type BuildProtectedResourceMetadataOptions,
  type DynamicClientRegistrationOptions,
  type ProtectedResourceMetadata,
  type WwwAuthenticateBearerChallengeOptions,
} from "@aooth/auth/authz";

// Re-exported from @aooth/auth for ergonomic single-import setup; the
// definitions are framework-agnostic and live in the core package.
export type {
  AuthEmailEvent,
  AuthEmailKind,
  AuthSmsEvent,
  AuthSmsKind,
  BuildMagicLinkUrl,
  EmailSender,
  SmsSender,
} from "@aooth/auth";
export { generateMagicLinkToken } from "@aooth/auth";

// ── Unified auth workflow ──────────────────────────────────────────────
export {
  AuthWorkflow,
  type AuthDeliveryPayload,
  buildInviteAlreadyAcceptedEnvelope,
  haversineKm,
  humanizeUserAgent,
  parseInviteRoles,
  RESERVED_USER_KEYS,
  stripReservedUserKeys,
} from "./workflow/auth-workflow";
export type { AuthWorkflowOpts, ResolvedAuthWorkflowOpts } from "./workflow/auth-workflow.opts";
export type {
  AuthWfCtx,
  AuthWfCompletionState,
  AuthWfConsentsState,
  AuthWfMfaEnrollState,
  AuthWfOAuthState,
  AuthWfPasswordUiState,
  AuthWfPincodeUiState,
  AuthzReauthPolicy,
  ConsentDescriptorLike,
  MfaSummary,
  MfaTransport,
  LoginRedirect,
  SsoProvider,
  ConcurrencyLimitOptions,
} from "./workflow/auth-workflow.ctx";

export { type AuthEmailOutletDeps, createAuthEmailOutlet } from "./workflows/auth-email-outlet";
export { type AuditEmitter, type AuditEvent } from "./audit/index";
