import { type AuthContext, AuthCredential, AuthError, type IssueResult } from "@aoothjs/auth";
import { UserAuthError, UserService } from "@aoothjs/user";
import { current } from "@wooksjs/event-core";
import { Body, Get, HttpError, Post } from "@moostjs/event-http";
import { useCookies } from "@wooksjs/event-http";
import { Controller, useControllerContext } from "moost";

import { MoostAuthConfig } from "./auth.config";
import { useAuth } from "./auth.composables";
import { buildLoginResponse, clearAuthCookies, writeAuthCookies } from "./auth.cookies";
import { Public } from "./auth.decorator";
import type {
  AuthLoginBody,
  AuthLoginResponse,
  AuthOkResponse,
  AuthPasswordChangeBody,
  AuthRefreshBody,
} from "./auth.dto";
import { extractAccessToken } from "./auth.token";

// CRITICAL ASSUMPTION: `AuthContext.userId === username`. Login issues the
// credential with `loginResult.user.username` as its userId, so the password-
// change handler reads it back through `useAuth().getCurrentUserId()`.
// Consumers who map userId → an opaque id (UUID, internal pk) must disable
// the auto-registered controller (`endpoints: false`) and re-register a
// subclassed one with the correct lookup — see README.
//
// DI note: moost@0.6.x cannot resolve constructor params via `@Inject(SomeClass)`
// — the registry is keyed by `Symbol.for(class)` but the param lookup uses
// the raw constructor (they don't compare equal). The reliable runtime path
// is `useControllerContext().instantiate(SomeClass)`, which goes through
// infact's `get()` and matches on `classSymbol`. That's why this controller
// resolves dependencies inside each handler rather than via a constructor.

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

interface Deps {
  auth: AuthCredential;
  config: MoostAuthConfig;
  users: UserService;
}

async function resolveDeps(): Promise<Deps> {
  const cc = useControllerContext();
  const [auth, config, users] = await Promise.all([
    cc.instantiate(AuthCredential),
    cc.instantiate(MoostAuthConfig),
    cc.instantiate(UserService),
  ]);
  return { auth, config, users };
}

/**
 * Public REST endpoints for credential management. Auto-registered by
 * `setupAuthMoost()` when `endpoints` is `true` (the default).
 *
 * Exported so consumers can subclass to override individual methods (e.g.
 * to wire a non-username userId mapping in `changePassword`).
 *
 * Path prefix is fixed at `/auth`. Mount Moost behind an HTTP-level prefix
 * (e.g. `/v1`) if `/v1/auth/...` is needed — moost does not expose runtime
 * prefix overrides on the `@Controller(...)` decorator.
 */
@Controller("auth")
export class AuthController {
  @Post("login")
  @Public()
  async login(@Body() body: AuthLoginBody): Promise<AuthLoginResponse> {
    if (!body || typeof body.username !== "string" || typeof body.password !== "string") {
      throw new HttpError(400, "username and password are required");
    }
    const { auth, config, users } = await resolveDeps();

    let loginResult: Awaited<ReturnType<UserService["login"]>>;
    try {
      loginResult = await users.login(body.username, body.password);
    } catch (err) {
      translateLoginError(err);
    }

    const issue = await auth.issue(loginResult.user.username);
    writeAuthCookies(config, issue);
    return buildLoginResponse(config, loginResult.user.username, issue);
  }

  @Post("logout")
  async logout(): Promise<AuthOkResponse> {
    const { auth, config } = await resolveDeps();
    const token = extractAccessToken(current(), config);
    if (token) {
      // Best-effort: the guard already validated this token; if revocation
      // fails (e.g. store unreachable) we still clear cookies so the client's
      // session ends.
      try {
        await auth.revoke(token);
      } catch {
        /* swallow — see comment */
      }
    }
    clearAuthCookies(config);
    return { ok: true };
  }

  @Post("refresh")
  @Public()
  async refresh(@Body() body: AuthRefreshBody | undefined): Promise<AuthLoginResponse> {
    const { auth, config } = await resolveDeps();
    const ctx = current();
    let refreshToken = body?.refreshToken;
    if (!refreshToken && config.enableCookie) {
      refreshToken = useCookies(ctx).getCookie(config.refreshCookie.name) ?? undefined;
    }
    if (!refreshToken) {
      throw new HttpError(401, "Missing refresh token");
    }

    let issue: IssueResult;
    try {
      issue = await auth.refresh(refreshToken);
    } catch (err) {
      if (err instanceof AuthError) {
        throw new HttpError(401, "Invalid refresh token");
      }
      throw err;
    }

    writeAuthCookies(config, issue);
    // userId is preserved across refresh — recover it from the new access token.
    const validated = await auth.validate(issue.accessToken);
    return buildLoginResponse(config, validated?.userId ?? "", issue);
  }

  @Get("status")
  status(): AuthContext {
    const user = useAuth().getCurrentUser();
    if (!user) {
      // The global guard normally throws 401 before we reach here; this is a
      // defence-in-depth in case the route is somehow marked `@Public()`.
      throw new HttpError(401, "Not authenticated");
    }
    return user;
  }

  @Post("password")
  async changePassword(@Body() body: AuthPasswordChangeBody): Promise<AuthOkResponse> {
    if (!body || typeof body.currentPassword !== "string" || typeof body.newPassword !== "string") {
      throw new HttpError(400, "currentPassword and newPassword are required");
    }
    const { users } = await resolveDeps();
    const username = useAuth().getCurrentUserId();

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
    return { ok: true };
  }
}
