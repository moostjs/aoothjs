export type { AuthContext } from "@aoothjs/auth";

export { MoostAuthConfig, type ResolvedAuthCookieConfig } from "./auth.config";
export { authGuardInterceptor } from "./auth.guard";
export { useAuth, type AuthBindings } from "./auth.composables";
export { Public } from "./auth.decorator";
export { setupAuthMoost, type SetupAuthMoostOptions } from "./auth.setup";
export { getAuthMate, type TAuthMeta } from "./auth.mate";
