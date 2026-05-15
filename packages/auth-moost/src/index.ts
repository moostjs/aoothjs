// Re-exported from @aoothjs/auth — exposed in the public surface (handler
// returns + helper parameters) so consumers don't need a second import.
export type { AuthContext, IssueResult } from "@aoothjs/auth";

export { MoostAuthConfig, type ResolvedAuthCookieConfig } from "./auth.config";
export { authGuardInterceptor } from "./auth.guard";
export { useAuth, type AuthBindings } from "./auth.composables";
export { Public } from "./auth.decorator";
export { setupAuthMoost, type SetupAuthMoostOptions } from "./auth.setup";
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
  BuildMagicLinkUrl,
  EmailSender,
  MagicLinkKind,
} from "@aoothjs/auth";
export { generateMagicLinkToken } from "@aoothjs/auth";
export {
  DEFAULT_INVITE_TOKEN_TTL_MS,
  DEFAULT_MFA_CODE_TTL_MS,
  DEFAULT_RECOVERY_TOKEN_TTL_MS,
  MoostAuthWorkflowConfig,
  type AuthWorkflowsOptions,
  type InvitePrepareUserInput,
  type ResolvedAuthWorkflowsConfig,
} from "./workflow-config";
export { setupAuthWorkflows } from "./workflow-setup";
export {
  InviteWorkflow,
  type InviteWfCtx,
  LoginWorkflow,
  type LoginWfCtx,
  parseInviteRoles,
  RecoveryWorkflow,
  type RecoveryWfCtx,
} from "./workflows/index";
export { createAuthEmailOutlet } from "./workflows/auth-email-outlet";
