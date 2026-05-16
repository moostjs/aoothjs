// Re-exported from @aoothjs/auth — exposed in the public surface (handler
// returns + helper parameters) so consumers don't need a second import.
export type { AuthContext, IssueResult } from "@aoothjs/auth";

export {
  MoostAuthConfig,
  type MoostAuthConfigOptions,
  type ResolvedAuthCookieConfig,
} from "./auth.config";
export { authGuardInterceptor } from "./auth.guard";
export { useAuth, type AuthBindings } from "./auth.composables";
export { Public, UserId } from "./auth.decorator";
export { getAuthMate, type TAuthMeta } from "./auth.mate";
export { AuthController } from "./auth.controller";
export type {
  AuthLoginBody,
  AuthLoginResponse,
  AuthOkResponse,
  AuthPasswordChangeBody,
  AuthRefreshBody,
} from "./auth.dto";
export { extractAccessToken } from "./auth.token";
export {
  buildLoginResponse,
  clearAuthCookies,
  cookieAttrs,
  writeAuthCookies,
} from "./auth.cookies";

// Re-exported from @aoothjs/auth for ergonomic single-import setup; the
// definitions are framework-agnostic and live in the core package.
export type {
  AuthEmailEvent,
  AuthEmailKind,
  AuthSmsEvent,
  AuthSmsKind,
  BuildMagicLinkUrl,
  EmailSender,
  MagicLinkKind,
  SmsSender,
} from "@aoothjs/auth";
export { generateMagicLinkToken } from "@aoothjs/auth";
export {
  DEFAULT_INVITE_TOKEN_TTL_MS,
  DEFAULT_MFA_CODE_TTL_MS,
  DEFAULT_RECOVERY_TOKEN_TTL_MS,
  type DuplicateAction,
  InviteWorkflow,
  type InviteWfCtx,
  type InvitePrepareUserInput,
  InviteWorkflowOptions,
  type PreparedUserInput,
  LoginWorkflow,
  type LoginWfCtx,
  type LoginRedirect,
  type LoginWorkflowOpts,
  type ResolvedLoginWorkflowOpts,
  mergeLoginOpts,
  type MfaSummary,
  type MfaTransport,
  type SsoProvider,
  type ConcurrencyLimitOptions,
  parseInviteRoles,
  RecoveryWorkflow,
  type RecoveryWfCtx,
  RecoveryWorkflowOptions,
} from "./workflows/index";
export { type AuthEmailOutletDeps, createAuthEmailOutlet } from "./workflows/auth-email-outlet";
export {
  type DeviceTrustStore,
  DeviceTrustStoreMemory,
  type DeviceTrustRecord,
} from "./device-trust/index";
export { type AuditEmitter, type AuditEvent, NoopAuditEmitter } from "./audit/index";
export {
  type WorkflowRateLimitConsumeResult,
  type WorkflowRateLimitStore,
  WorkflowRateLimitStoreMemory,
} from "./rate-limit/index";
export type {
  RecoveryDeliveryMode,
  RecoveryOtpTransport,
} from "./workflows/recovery.workflow.options";

// DI tokens for optional workflow deps. `SmsSender` and `DeviceTrustStore`
// are TS interfaces (no runtime constructor) so consumers register them
// against these string tokens: `[SMS_SENDER_TOKEN, () => mySender]`.
export const SMS_SENDER_TOKEN = "SmsSender";
export const DEVICE_TRUST_STORE_TOKEN = "DeviceTrustStore";
export const AUDIT_EMITTER_TOKEN = "AuditEmitter";
export const WORKFLOW_RATE_LIMIT_STORE_TOKEN = "WorkflowRateLimitStore";
