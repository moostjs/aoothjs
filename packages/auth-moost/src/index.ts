export type { AuthContext } from "@aoothjs/auth";

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

export type { AuthEmailEvent, AuthEmailKind, EmailSender } from "./email";
export type { BuildMagicLinkUrl, MagicLinkKind } from "./magic-link";
export { generateMagicLinkToken } from "./magic-link";
export {
  DEFAULT_INVITE_TOKEN_TTL_MS,
  DEFAULT_MFA_CODE_TTL_MS,
  DEFAULT_RECOVERY_TOKEN_TTL_MS,
  MoostAuthWorkflowConfig,
  type AuthWorkflowsOptions,
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
