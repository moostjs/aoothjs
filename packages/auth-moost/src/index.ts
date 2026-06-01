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
