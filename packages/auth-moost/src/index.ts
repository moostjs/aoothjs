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
export { AuthController, DEFAULT_AUTH_WORKFLOWS } from "./auth.controller";
export { SessionsController, SessionEnricherProvider } from "./sessions.controller";
export type {
  AuthLoginResponse,
  AuthLogoutBody,
  AuthOkResponse,
  AuthRefreshBody,
} from "./auth.dto";
export { WfTrigger, type WfTriggerOpts } from "./wf-trigger/decorator";
export { deriveWfStateSecret, WfTriggerProvider } from "./wf-trigger/provider";

// ── Federated login (OAuth2 / OIDC) — moost integration of @aooth/idp ──
export { type ConnectedAccount, OAuthController } from "./oauth/oauth.controller";
export { OAUTH_CSRF_COOKIE, oauthCsrfCookieAttrs } from "./oauth/oauth-csrf";
export { isSafeRelativeRedirect, resolveOAuthRedirect } from "./oauth/oauth-redirect";
export { OAuthRuntime } from "./oauth/oauth-runtime";
export { FEDERATED_IDENTITY_STORE_TOKEN } from "./oauth/oauth-tokens";

// ── Authorization server (AUTH-SERVER.md Tier 1) — aoothjs as an OAuth provider
//    for its OWN clients (CLI loopback today; first-party service SSO later). ──
export { AuthorizeController } from "./authz/authorize.controller";
export { AuthorizeRuntime } from "./authz/authorize-runtime";
export {
  AuthCodeStore,
  AuthCodeStoreMemory,
  type AuthCode,
  type AuthCodeStoreMemoryOptions,
  type NewAuthCode,
} from "./authz/auth-code-store";
export {
  PendingAuthorizationStore,
  PendingAuthorizationStoreMemory,
  type NewPendingAuthorization,
  type PendingAuthorization,
  type PendingAuthorizationStoreMemoryOptions,
} from "./authz/pending-authorization-store";
export {
  isLoopbackRedirectUri,
  LoopbackClientPolicy,
  type ClientRedirectPolicy,
  type LoopbackClientPolicyOptions,
  type ResolvedClient,
} from "./authz/client-policy";
export { AuthorizeError, type AuthorizeErrorCode } from "./authz/authz-errors";
export { type TokenPolicy } from "./authz/token-policy";
export {
  AUTH_CODE_STORE_TOKEN,
  CLIENT_REDIRECT_POLICY_TOKEN,
  PENDING_AUTHORIZATION_STORE_TOKEN,
} from "./authz/authz-tokens";

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
  ConsentDescriptorLike,
  MfaSummary,
  MfaTransport,
  LoginRedirect,
  SsoProvider,
  ConcurrencyLimitOptions,
} from "./workflow/auth-workflow.ctx";

export { type AuthEmailOutletDeps, createAuthEmailOutlet } from "./workflows/auth-email-outlet";
export { type AuditEmitter, type AuditEvent } from "./audit/index";
