/** POST /auth/login request body. */
export interface AuthLoginBody {
  username: string;
  password: string;
}

/** POST /auth/refresh request body. Falls back to the refresh cookie when absent. */
export interface AuthRefreshBody {
  refreshToken?: string;
}

/**
 * Optional POST /auth/logout body. The refresh cookie's narrow `path:
 * '/auth/refresh'` keeps the browser from sending it to `/auth/logout`, so
 * token-style clients (or clients that want to revoke a paired refresh in the
 * same call) submit it explicitly here.
 */
export interface AuthLogoutBody {
  refreshToken?: string;
}

/** POST /auth/password request body. */
export interface AuthPasswordChangeBody {
  currentPassword: string;
  newPassword: string;
}

/**
 * POST /auth/login + POST /auth/refresh response body.
 *
 * Tokens are populated only when `enableBearer` is true. With `enableBearer=false`
 * the body still echoes `userId` + `accessExpiresAt` so the caller can schedule
 * a silent refresh; the actual tokens travel only in cookies.
 */
export interface AuthLoginResponse {
  userId: string;
  accessExpiresAt: number;
  refreshExpiresAt?: number;
  accessToken?: string;
  refreshToken?: string;
}

/** POST /auth/logout and POST /auth/password response body. */
export interface AuthOkResponse {
  ok: true;
}
