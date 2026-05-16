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
  BuildMagicLinkUrl,
  EmailSender,
  MagicLinkKind,
} from "@aoothjs/auth";
export { generateMagicLinkToken } from "@aoothjs/auth";
export {
  DEFAULT_INVITE_TOKEN_TTL_MS,
  DEFAULT_MFA_CODE_TTL_MS,
  DEFAULT_RECOVERY_TOKEN_TTL_MS,
  InviteWorkflow,
  type InviteWfCtx,
  type InvitePrepareUserInput,
  InviteWorkflowOptions,
  LoginWorkflow,
  type LoginWfCtx,
  LoginWorkflowOptions,
  parseInviteRoles,
  RecoveryWorkflow,
  type RecoveryWfCtx,
  RecoveryWorkflowOptions,
} from "./workflows/index";
export { type AuthEmailOutletDeps, createAuthEmailOutlet } from "./workflows/auth-email-outlet";
