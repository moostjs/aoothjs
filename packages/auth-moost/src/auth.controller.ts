import { ArbacAction, ArbacResource } from "@aooth/arbac-moost";
import { type AuthContext, AuthCredential, AuthError, type IssueResult } from "@aooth/auth";
import { UserAuthError, type UserCredentials, UserService } from "@aooth/user";
import type { WfFinished } from "@atscript/moost-wf";
import { current } from "@wooksjs/event-core";
import { Body, Get, HttpError, Post, Query } from "@moostjs/event-http";
import { useCookies } from "@wooksjs/event-http";
import {
  Controller,
  HandlerPaths,
  InjectMoostLogger,
  MoostInit,
  Optional,
  type TConsoleBase,
  useControllerContext,
} from "moost";

import { type AuthBindings, useAuth } from "./auth.composables";
import { Public } from "./auth.decorator";
import { normalizeCookiePath, RefreshCookiePathHolder } from "./auth.route";
import type {
  AuthLoginResponse,
  AuthLogoutBody,
  AuthOkResponse,
  AuthRefreshBody,
} from "./auth.dto";
import { WfTrigger } from "./wf-trigger/decorator";
import { buildInviteAlreadyAcceptedEnvelope } from "./workflow/auth-workflow";

/** Workflows allowed by the bundled `/auth/trigger` endpoint. Subclasses override `triggerWf()` to extend. */
export const DEFAULT_AUTH_WORKFLOWS = [
  "auth/login/flow",
  "auth/invite/start",
  "auth/recovery/flow",
  "auth/signup/flow",
  // Federated login. Safe to start publicly: the `oauth-exchange` step gates on
  // a signed state + CSRF cookie + single-use PKCE transaction + a verified ID
  // token, so an attacker can't forge a successful exchange via the trigger.
  "auth/oauth/flow",
] as const;

/**
 * Workflow id allowed by the GUARDED `/auth/change-password` trigger.
 * Deliberately NOT in `DEFAULT_AUTH_WORKFLOWS` — the authenticated
 * change-password flow must never be reachable from the public `/auth/trigger`.
 */
export const CHANGE_PASSWORD_WORKFLOW = "auth/change-password/flow";

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

  /**
   * Scope the refresh cookie to this controller's REAL mounted route, resolved
   * once at application boot from Moost's post-bind route table. `@HandlerPaths`
   * defaults to the running controller, so a prefixed or subclassed mount (e.g.
   * `api/auth` → `/api/auth/refresh`) is handled with no config; the result
   * feeds {@link RefreshCookiePathHolder}, which `authGuardInterceptor` reads.
   * Leaves the holder unset — so the guard keeps its configured default — on 0
   * matches (no refresh route registered) or >1 (ambiguous; never guess),
   * warning at boot in the ambiguous case rather than on the first request.
   */
  @MoostInit()
  async initRefreshCookiePath(
    @HandlerPaths("refresh", { type: "HTTP" }) paths: string[],
    @InjectMoostLogger("aooth:auth") logger: TConsoleBase,
  ): Promise<void> {
    if (paths.length === 1) {
      // Same singleton the guard reads via `cc.instantiate`. The init hook runs
      // inside a controller context, so this resolves identically.
      const holder = await useControllerContext(current()).instantiate(RefreshCookiePathHolder);
      holder.path = normalizeCookiePath(paths[0]);
    } else if (paths.length > 1) {
      logger.warn(
        `[aooth] AuthController's refresh route resolved to ${paths.length} paths ` +
          `(${paths.join(", ")}); the refresh cookie stays at its default. Set ` +
          `refreshCookie.path explicitly on authGuardInterceptor(opts) to disambiguate.`,
      );
    }
  }

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
    // End THIS device's whole session — every token in the family (access +
    // refresh + all rotations), keyed by sessionId — on stores that can
    // enumerate. This is what a "log out" button wants now that aooth models a
    // session as a token family: the SPA can't read the httpOnly refresh
    // cookie, and that cookie's narrow path keeps it off `/auth/logout`, so the
    // token-level revokes below cannot reach the refresh credential on their
    // own. `revokeSession` closes that gap (and is a no-op on stateless stores,
    // where the token-level fallback remains the mechanism).
    const sessionId = auth.getSessionId();
    if (sessionId) {
      try {
        await this.auth.revokeSession(auth.getUserId(), sessionId);
      } catch {
        /* best-effort — cookies still cleared below */
      }
    }
    // Token-level fallback: covers stateless stores (where revokeSession no-ops)
    // and an explicit refresh token in the body. Harmless no-ops once the
    // family is already gone.
    const accessToken = auth.extractToken();
    const refreshToken = resolveRefreshToken(auth, body);
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
   * GUARDED trigger for the authenticated "change my password" flow. Unlike
   * `triggerWf`, this is NOT `@Public()` — the auth guard rejects an
   * unauthenticated caller with 401 before the flow starts. The method-level
   * `@ArbacResource("auth.change-password")` overrides the class `"auth"`
   * resource so the trigger, the `@Workflow` body, and every flow step all
   * resolve to the same `auth.change-password` resource / `self` action — a
   * customer enables the whole feature with a single
   * `allow("auth.change-password", "*")` grant and forbids it (SSO-only orgs)
   * by omitting that grant. The flow binds `ctx.subject` from the session in
   * `init-change-password`, so it is structurally "change MY password" — there
   * is no target-user parameter.
   */
  @Post("change-password")
  @ArbacResource("auth.change-password")
  @ArbacAction("self")
  @WfTrigger({ allow: [CHANGE_PASSWORD_WORKFLOW] })
  changePassword(): void {
    // Body intentionally empty — see `triggerWf`.
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
