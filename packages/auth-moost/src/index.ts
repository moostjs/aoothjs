// Re-exported from @aooth/auth — exposed in the public surface (handler
// returns + helper parameters) so consumers don't need a second import.
export type { AuthContext, IssueResult } from "@aooth/auth";

export {
  type AuthOptions,
  type ResolvedAuthCookieConfig,
  type ResolvedAuthOptions,
} from "./auth.config";
export { authGuardInterceptor, AuthGuarded } from "./auth.guard";
export { useAuth, type AuthBindings } from "./auth.composables";
export { Public, UserId } from "./auth.decorator";
export { getAuthMate, type TAuthMeta } from "./auth.mate";
export { AuthController, DEFAULT_AUTH_WORKFLOWS } from "./auth.controller";
export type {
  AuthLoginResponse,
  AuthLogoutBody,
  AuthOkResponse,
  AuthRefreshBody,
} from "./auth.dto";
export { WfTrigger, type WfTriggerOpts } from "./wf-trigger/decorator";
export { WfTriggerProvider } from "./wf-trigger/provider";

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
export {
  type DeliverEmail,
  type DeliverPayload,
  type DeliverSms,
  type DuplicateAction,
  InviteWorkflow,
  type InviteWfCtx,
  type InvitePrepareUserInput,
  type InviteSendMode,
  type InviteWorkflowOpts,
  mergeInviteOpts,
  type PreparedUserInput,
  type ResolvedInviteWorkflowOpts,
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
  DefaultInviteWorkflow,
  DefaultLoginWorkflow,
  DefaultRecoveryWorkflow,
  parseInviteRoles,
  RecoveryWorkflow,
  type RecoveryWfCtx,
  type RecoveryDeliveryMode,
  type RecoveryOtpTransport,
  type RecoveryWorkflowOpts,
  type ResolvedRecoveryWorkflowOpts,
  mergeRecoveryOpts,
} from "./workflows/index";
export { type AuthEmailOutletDeps, createAuthEmailOutlet } from "./workflows/auth-email-outlet";
export {
  type AuthShareableLinkOutletDeps,
  createAuthShareableLinkOutlet,
} from "./workflows/auth-shareable-link-outlet";
export { type AuditEmitter, type AuditEvent } from "./audit/index";

// Note: the DI-token exports (`SMS_SENDER_TOKEN`, `AUDIT_EMITTER_TOKEN`,
// `DEVICE_TRUST_STORE_TOKEN`, `WORKFLOW_RATE_LIMIT_STORE_TOKEN`) were dropped
// in Phase 4 of the workflow OOP-reshape. All three auth workflows now use
// `protected` method overrides instead of constructor-injected side-effect
// deps, so no consumer needs the tokens. The `EmailSender` / `SmsSender` /
// `AuditEmitter` types still ship for consumer overrides. Device-trust
// persistence moved into `UserService` (`@aooth/user`); consumers wire it
// via `UserServiceConfig.deviceTrust.secret` and override
// `LoginWorkflow`'s `loadTrustedDevice` / `storeTrustedDevice` etc. only
// when they need a non-default backend.
