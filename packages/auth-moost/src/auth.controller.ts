import { ArbacAction, ArbacResource } from "@aoothjs/arbac-moost";
import { type AuthContext, AuthCredential, AuthError, type IssueResult } from "@aoothjs/auth";
import { UserAuthError, UserService } from "@aoothjs/user";
import { current } from "@wooksjs/event-core";
import { Body, Get, HttpError, Post } from "@moostjs/event-http";
import { useCookies } from "@wooksjs/event-http";
import { Controller, useControllerContext } from "moost";

import { useAuth } from "./auth.composables";
import { Public } from "./auth.decorator";
import type {
  AuthLoginBody,
  AuthLoginResponse,
  AuthLogoutBody,
  AuthOkResponse,
  AuthPasswordChangeBody,
  AuthRefreshBody,
} from "./auth.dto";

// CRITICAL ASSUMPTION: `AuthContext.userId === username`. Login issues the
// credential with `loginResult.user.username` as its userId, so the password-
// change handler reads it back through `useAuth().getUserId()`.
// Consumers who map userId → an opaque id (UUID, internal pk) must disable
// the auto-registered controller (`endpoints: false`) and re-register a
// subclassed one with the correct lookup — see README.

function translateLoginError(err: unknown): never {
  if (err instanceof UserAuthError) {
    switch (err.type) {
      // 423 Locked: RFC 4918 §11.3 — credentials valid but account temporarily unusable.
      case "LOCKED":
        throw new HttpError(423, "Account locked");
      // Wrong-password / unknown-user / deactivated are deliberately conflated
      // so callers cannot enumerate usernames.
      case "INVALID_CREDENTIALS":
      case "NOT_FOUND":
      case "INACTIVE":
        throw new HttpError(401, "Invalid credentials");
      default:
        throw new HttpError(401, "Invalid credentials");
    }
  }
  throw err;
}

function translatePasswordError(err: unknown): never {
  if (err instanceof UserAuthError) {
    switch (err.type) {
      case "POLICY_VIOLATION":
      case "PASSWORD_IN_HISTORY":
      case "PASSWORDS_MISMATCH":
        throw new HttpError(400, err.message);
      // The guard accepted a token whose user no longer exists in the store —
      // server-state inconsistency, not a client error.
      case "NOT_FOUND":
        throw new HttpError(500, "User not found");
      default:
        throw new HttpError(400, err.message);
    }
  }
  throw err;
}

async function resolveUsersDep(): Promise<UserService> {
  const cc = useControllerContext();
  // `UserService` is required only by handlers that read/verify user records
  // (login, changePassword). Refresh + logout work off the token store alone.
  return cc.instantiate(UserService).catch(() => {
    throw new Error(
      "AuthController: `UserService` is not provided in the Moost DI container. " +
        "Register one via `setProvideRegistry(createProvideRegistry([UserService, () => myUserService]))`, " +
        "or do not register `AuthController` if you don't need /auth/login + /auth/password.",
    );
  });
}

/**
 * Public REST endpoints for credential management. Consumers register this
 * controller explicitly via `moost.registerControllers(AuthController)`.
 *
 * Exported so consumers can subclass to override individual methods (e.g.
 * to wire a non-username userId mapping in `changePassword`).
 *
 * Path prefix is fixed at `/auth`. Mount Moost behind an HTTP-level prefix
 * (e.g. `/v1`) if `/v1/auth/...` is needed — moost does not expose runtime
 * prefix overrides on the `@Controller(...)` decorator.
 */
@Controller("auth")
@ArbacResource("auth")
export class AuthController {
  constructor(protected readonly auth: AuthCredential) {}

  @Post("login")
  @Public()
  async login(@Body() body: AuthLoginBody): Promise<AuthLoginResponse> {
    if (!body || typeof body.username !== "string" || typeof body.password !== "string") {
      throw new HttpError(400, "username and password are required");
    }
    const users = await resolveUsersDep();

    let loginResult: Awaited<ReturnType<UserService["login"]>>;
    try {
      loginResult = await users.login(body.username, body.password);
    } catch (err) {
      translateLoginError(err);
    }

    const issue = await this.auth.issue(loginResult.user.username);
    const auth = useAuth();
    auth.writeCookies(issue);
    return auth.buildLoginResponse(loginResult.user.username, issue);
  }

  @Post("logout")
  @ArbacAction("public.logout")
  async logout(@Body() body: AuthLogoutBody): Promise<AuthOkResponse> {
    const ctx = current();
    const auth = useAuth();
    const accessToken = auth.extractToken();
    // Revoke the refresh side too — otherwise a stolen device could mint a
    // fresh access token via `/auth/refresh` after the user "logged out".
    // The refresh cookie's narrow path keeps it OUT of `/auth/logout`, so we
    // prefer an explicit body field and fall back to the cookie just in case
    // a consumer widened the path.
    let refreshToken =
      body && typeof body === "object" && typeof body.refreshToken === "string"
        ? body.refreshToken
        : undefined;
    if (!refreshToken && auth.options.enableCookie) {
      refreshToken = useCookies(ctx).getCookie(auth.options.refreshCookie.name) ?? undefined;
    }
    // Best-effort: the guard already validated the access token; if either
    // revocation fails (e.g. store unreachable) we still clear cookies so the
    // client's session ends.
    if (accessToken) {
      try {
        await this.auth.revoke(accessToken);
      } catch {
        /* swallow — see comment */
      }
    }
    if (refreshToken) {
      try {
        await this.auth.revoke(refreshToken);
      } catch {
        /* swallow — see comment */
      }
    }
    auth.clearCookies();
    return { ok: true };
  }

  @Post("refresh")
  @Public()
  async refresh(@Body() body: AuthRefreshBody | undefined): Promise<AuthLoginResponse> {
    const ctx = current();
    const auth = useAuth();
    let refreshToken = body?.refreshToken;
    if (!refreshToken && auth.options.enableCookie) {
      refreshToken = useCookies(ctx).getCookie(auth.options.refreshCookie.name) ?? undefined;
    }
    if (!refreshToken) {
      throw new HttpError(401, "Missing refresh token");
    }

    let issue: IssueResult;
    try {
      issue = await this.auth.refresh(refreshToken);
    } catch (err) {
      if (err instanceof AuthError) {
        throw new HttpError(401, "Invalid refresh token");
      }
      throw err;
    }

    auth.writeCookies(issue);
    // userId is preserved across refresh — recover it from the new access token.
    const validated = await this.auth.validate(issue.accessToken);
    return auth.buildLoginResponse(validated?.userId ?? "", issue);
  }

  @Get("status")
  @ArbacAction("public.status")
  status(): AuthContext {
    const auth = useAuth().getAuthContext();
    if (!auth) {
      // The global guard normally throws 401 before we reach here; this is a
      // defence-in-depth in case the principal is somehow unset.
      throw new HttpError(401, "Not authenticated");
    }
    return auth;
  }

  @Post("password")
  @ArbacAction("public.password")
  async changePassword(@Body() body: AuthPasswordChangeBody): Promise<AuthOkResponse> {
    if (!body || typeof body.currentPassword !== "string" || typeof body.newPassword !== "string") {
      throw new HttpError(400, "currentPassword and newPassword are required");
    }
    const users = await resolveUsersDep();
    const auth = useAuth();
    const username = auth.getUserId();

    let valid: boolean;
    try {
      valid = await users.verifyPassword(username, body.currentPassword);
    } catch (err) {
      translatePasswordError(err);
    }
    if (!valid) {
      throw new HttpError(401, "Current password incorrect");
    }
    try {
      await users.setPassword(username, body.newPassword);
    } catch (err) {
      translatePasswordError(err);
    }
    // Best-practice session invalidation: a successful password change implies
    // the prior password is no longer trusted, so any token derived from a
    // session opened with it (including the caller's own) is revoked. The
    // client must re-authenticate. Failure here is non-fatal — the password
    // is already changed, and the worst outcome is a brief window of stale
    // tokens that will expire on their natural TTL.
    try {
      await this.auth.revokeAllForUser(username);
    } catch {
      /* swallow — see comment */
    }
    auth.clearCookies();
    return { ok: true };
  }
}
