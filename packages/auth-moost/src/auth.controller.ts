import { ArbacResource } from "@aooth/arbac-moost";
import { type AuthContext, AuthCredential, AuthError, type IssueResult } from "@aooth/auth";
import { UserAuthError, type UserCredentials, UserService } from "@aooth/user";
import type { WfFinished } from "@atscript/moost-wf";
import { current } from "@wooksjs/event-core";
import { Body, Get, HttpError, Post, Query } from "@moostjs/event-http";
import { useCookies } from "@wooksjs/event-http";
import { Controller, Optional } from "moost";

import { type AuthBindings, useAuth } from "./auth.composables";
import { Public } from "./auth.decorator";
import type {
  AuthLoginResponse,
  AuthLogoutBody,
  AuthOkResponse,
  AuthRefreshBody,
} from "./auth.dto";
import { WfTrigger } from "./wf-trigger/decorator";
import { buildInviteAlreadyAcceptedEnvelope } from "./workflow/auth-workflow";

/** Workflows allowed by the bundled `/auth/trigger` endpoint. Subclasses override `triggerWf()` to extend. */
export const DEFAULT_AUTH_WORKFLOWS = ["/login", "/invite", "/recover"] as const;

/** Prefer an explicit body field, fall back to the refresh cookie when enabled. */
function resolveRefreshToken(auth: AuthBindings, body: { refreshToken?: string } | undefined) {
  if (typeof body?.refreshToken === "string") return body.refreshToken;
  if (!auth.options.enableCookie) return undefined;
  return useCookies(current()).getCookie(auth.options.refreshCookie.name) ?? undefined;
}

/**
 * Public REST endpoints for credential management. Four endpoints total:
 *
 * - `POST /auth/logout` — best-effort token revocation + cookie clear.
 * - `POST /auth/refresh` — rotate access/refresh tokens.
 * - `GET /auth/status` — return the current `AuthContext`.
 * - `POST /auth/trigger` — single workflow trigger covering the unified
 *   `AuthWorkflow`'s three `@Workflow` schemas (`/login`, `/invite`, `/recover`).
 *
 * The historical `/auth/login` and `/auth/password` endpoints were dropped —
 * both flows go through the workflow trigger now (full MFA / SSO / etc.
 * surface lives in `AuthWorkflow`).
 *
 * Exported so consumers can subclass to add app-specific workflow ids to the
 * allow-list (override `triggerWf()` with a different `@WfTrigger({ allow })`)
 * or to inject custom outlets / state stores by subclassing `WfTriggerProvider`.
 */
@Controller("auth")
@ArbacResource("auth")
export class AuthController {
  constructor(
    protected readonly auth: AuthCredential,
    // `@Optional()` — only `invitePostRedemption` touches `users`. Apps that
    // don't register a `UserService` still wire the other 4 endpoints; the
    // post-redemption route returns 500 when unset.
    @Optional() protected readonly users?: UserService,
  ) {}

  // `@Public()` bypasses ARBAC — logout is a self-scoped primitive ("kill
  // my own session"). Subclass + `@ArbacAction(...)` to gate it. The null
  // check below is defence-in-depth: the auth guard still populates the
  // AuthContext on a valid token, so a null here means no credential.
  @Post("logout")
  @Public()
  async logout(@Body() body: AuthLogoutBody | undefined): Promise<AuthOkResponse> {
    const auth = useAuth();
    if (!auth.getAuthContext()) {
      throw new HttpError(401, "Not authenticated");
    }
    const accessToken = auth.extractToken();
    // Revoke the refresh side too — otherwise a stolen device could mint a
    // fresh access token via `/auth/refresh` after the user "logged out".
    // The refresh cookie's narrow path keeps it OUT of `/auth/logout`, so we
    // prefer an explicit body field and fall back to the cookie just in case
    // a consumer widened the path.
    const refreshToken = resolveRefreshToken(auth, body);
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
    const auth = useAuth();
    const refreshToken = resolveRefreshToken(auth, body);
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

  // `@Public()` bypasses ARBAC — status is a self-scoped primitive ("tell
  // me my own principal"). See `logout` above for the defence-in-depth
  // rationale on the null check.
  @Get("status")
  @Public()
  status(): AuthContext {
    const auth = useAuth().getAuthContext();
    if (!auth) {
      throw new HttpError(401, "Not authenticated");
    }
    return auth;
  }

  @Post("trigger")
  @Public()
  @WfTrigger({ allow: [...DEFAULT_AUTH_WORKFLOWS] })
  triggerWf(): void {
    // Body intentionally empty — `@WfTrigger`'s after-interceptor writes the
    // response when the handler returns `undefined`. Subclasses that want to
    // short-circuit (e.g. emit a custom error) override this and return a
    // non-undefined value; the interceptor then skips.
  }

  /**
   * Side route mapping a redeemed-invite `uid` to the same idempotent
   * envelope the `inviteIdempotentRedirect` workflow step renders. The SPA
   * falls through to this when an invite magic-link is re-clicked after
   * redemption: the wf state store has already evicted the finished state
   * (returns 410) so the workflow can't re-enter `inviteCheckPendingInvitation`,
   * but the user-id baked into the magic-link URL by `buildMagicLinkUrl(…, {
   * userId })` lets the SPA resolve the "already accepted" condition itself.
   *
   * `@Public()` — invitees aren't signed in at this point.
   *
   * Defaults for `loginUrl` / `alreadyAcceptedRedirectUrl` mirror the unified
   * `AuthWorkflow` defaults (`/login` / `/login`). Subclasses override
   * `resolveInvitePostRedemption()` to read live workflow opts.
   */
  @Get("invite/post-redemption")
  @Public()
  async invitePostRedemption(@Query("uid") uid: string | undefined): Promise<WfFinished> {
    if (!uid) throw new HttpError(400, "Missing uid query parameter");
    if (!this.users) {
      throw new HttpError(500, "UserService not wired — cannot resolve post-redemption state");
    }
    let user: UserCredentials;
    try {
      user = await this.users.getUser(uid);
    } catch (err) {
      if (err instanceof UserAuthError && err.type === "NOT_FOUND") {
        throw new HttpError(404, "User not found");
      }
      throw err;
    }
    // Still pending → the magic link genuinely failed for some other reason
    // (wf state store eviction, etc.). Return 404 so the SPA keeps showing
    // the actual error rather than masking it with an idempotent envelope.
    if (user.account?.pendingInvitation) {
      throw new HttpError(404, "Invite still pending");
    }
    // Wire shape parity with the workflow path: the SPA's `<AsWfFinish>`
    // expects a `WfFinished` (with `finished: true`); the workflow gets that
    // marker from `finishWf()`, the side route adds it directly.
    return {
      finished: true,
      ...buildInviteAlreadyAcceptedEnvelope(this.resolveInvitePostRedemption()),
    };
  }

  /**
   * URLs used by `invitePostRedemption`. Defaults mirror the unified
   * `AuthWorkflow` resolved opts so subclasses that customize either of
   * those options can override here to keep the side route in sync.
   */
  protected resolveInvitePostRedemption(): {
    loginUrl: string;
    alreadyAcceptedRedirectUrl: string;
  } {
    return { loginUrl: "/login", alreadyAcceptedRedirectUrl: "/login" };
  }
}
