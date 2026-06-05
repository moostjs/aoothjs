import type {
  AuthContext,
  AuthCredential,
  EnrichedSession,
  IssueResult,
  SessionEnricher,
  SessionInfo,
} from "@aooth/auth";
import type { EventContext } from "@wooksjs/event-core";
import { current, defineWook, key } from "@wooksjs/event-core";
import {
  HttpError,
  type TCookieAttributesInput,
  useAuthorization,
  useCookies,
  useResponse,
} from "@wooksjs/event-http";
import type { WfFinishedResponse } from "@wooksjs/event-wf";

import type { ResolvedAuthOptions } from "./auth.config";
import type { AuthLoginResponse } from "./auth.dto";

// `null` means the guard ran on a `@Public()` route with no valid credential.
// Absent means the guard never ran.
const authContextKey = key<AuthContext | null>("auth.context");

// The per-event `AuthCredential` instance stashed by `authGuardInterceptor`
// (it already instantiates one to `validate()`). Lets the `useAuth()` session
// facade reach the configured store without re-resolving DI. Absent on routes
// the guard short-circuits before instantiating (public + no token).
const authCredentialKey = key<AuthCredential>("auth.credential");

/**
 * Slot populated by `authGuardInterceptor(opts)` on the HTTP event. Workflow
 * step events started with `start({ eventContext: current() })` inherit the
 * HTTP parent chain — `useAuth()` reads the slot transparently from inside
 * step bodies. Exported only for `auth.guard.ts`.
 */
export const authOptionsKey = key<ResolvedAuthOptions>("auth.options");

export interface AuthBindings {
  getAuthContext<TPayload extends object = Record<string, unknown>>(): AuthContext<TPayload> | null;
  /** @throws `HttpError(401)` if no `AuthContext` is present in the event. */
  getUserId(): string;
  isAuthenticated(): boolean;
  /**
   * `sessionId` of the token family that authenticated THIS request — for
   * "this device" matching and as the `keepSessionId` for `revokeOtherSessions`.
   * `undefined` when unauthenticated.
   */
  getSessionId(): string | undefined;

  // ── Session facade (scoped to the current user) ─────────────────────
  /**
   * List the current user's active sessions (one row per device). Defaults to
   * the browser-safe set (ordinary interactive sessions); pass `kind` to segment
   * a non-browser bucket (`kind: "cli-session"`) or `kind: "*"` for every kind.
   */
  listSessions(opts?: {
    enrich?: SessionEnricher;
    kind?: string | string[];
  }): Promise<SessionInfo[] | EnrichedSession[]>;
  /** Revoke one of the current user's sessions by id (whole token family). */
  revokeSession(sessionId: string): Promise<void>;
  /**
   * Log out the current user's OTHER sessions, keeping this one. Returns the
   * count revoked. @throws `HttpError(401)` if the current session is unknown.
   */
  revokeOtherSessions(): Promise<number>;

  // ── Closures over resolved options ───────────────────────────────────
  /** @throws `HttpError(500)` when no `authGuardInterceptor(opts)` is on the chain. */
  readonly options: ResolvedAuthOptions;
  /** Same precedence as `authGuardInterceptor`: Bearer wins when both enabled. */
  extractToken(): string | undefined;
  writeCookies(issue: IssueResult): void;
  clearCookies(): void;
  buildLoginResponse(userId: string, issue: IssueResult): AuthLoginResponse;
  buildFinishedCookies(issue: IssueResult): WfFinishedResponse["cookies"];
  /** Build cookie attrs from the resolved access-cookie config, with optional overrides. */
  cookieAttrs(extra?: TCookieAttributesInput): TCookieAttributesInput;
}

/**
 * `sameSite` is upper-cased because wooks accepts `'Lax' | 'Strict' | 'None'`
 * while `ResolvedAuthCookieConfig` stores lower-case for ergonomics.
 *
 * `domain` is conditionally spread — pre-0.7.13 wooks renders `domain: undefined`
 * as the literal string `Domain=undefined`, which browsers reject (drops the
 * whole `Set-Cookie`). Newer wooks ignores undefined attrs, but the conditional
 * spread keeps us correct against any version and matches the same pattern used
 * by `resolveAuthOptions` to inherit `domain` onto the refresh cookie.
 */
function cookieAttrsFrom(
  c: ResolvedAuthOptions["cookie"],
  extra?: TCookieAttributesInput,
): TCookieAttributesInput {
  return {
    httpOnly: c.httpOnly,
    secure: c.secure,
    sameSite: (c.sameSite.charAt(0).toUpperCase() + c.sameSite.slice(1)) as
      | "Lax"
      | "Strict"
      | "None",
    path: c.path,
    ...(c.domain !== undefined && { domain: c.domain }),
    ...extra,
  };
}

/**
 * Composable for accessing the current event's auth state + transport helpers.
 *
 * `defineWook` memoizes the bindings object per event so multiple calls share
 * one closure. Identity bindings (`getAuthContext`/`getUserId`/`isAuthenticated`)
 * read the `authContextKey` slot populated by `authGuardInterceptor`. The
 * remaining closures read the `authOptionsKey` slot stashed by that same
 * interceptor; calling them outside an HTTP-or-HTTP-parented event throws
 * `HttpError(500)` loudly — that's a configuration error, not a runtime
 * fallback case.
 */
export const useAuth = defineWook((ctx: EventContext): AuthBindings => {
  const getAuthContext = <
    TPayload extends object = Record<string, unknown>,
  >(): AuthContext<TPayload> | null => {
    if (!ctx.has(authContextKey)) return null;
    // The slot is erased to the base `AuthContext` envelope; the caller asserts
    // the credential's typed payload shape they expect (its `@arbac.attenuate.*`
    // and other root fields surface flat on the context). No runtime check.
    return ctx.get(authContextKey) as AuthContext<TPayload> | null;
  };

  const getUserId = (): string => {
    const auth = getAuthContext();
    if (!auth) throw new HttpError(401, "Not authenticated");
    return auth.userId;
  };

  const isAuthenticated = (): boolean => getAuthContext() !== null;

  const getSessionId = (): string | undefined => getAuthContext()?.sessionId ?? undefined;

  const requireCredential = (): AuthCredential => {
    if (!ctx.has(authCredentialKey)) {
      throw new HttpError(
        500,
        "useAuth() session methods require authGuardInterceptor to have run on an authenticated route",
      );
    }
    return ctx.get(authCredentialKey);
  };

  const listSessions = (opts?: {
    enrich?: SessionEnricher;
    kind?: string | string[];
  }): Promise<SessionInfo[] | EnrichedSession[]> =>
    requireCredential().listSessions(getUserId(), opts);

  const revokeSession = (sessionId: string): Promise<void> =>
    requireCredential().revokeSession(getUserId(), sessionId);

  const revokeOtherSessions = (): Promise<number> => {
    const sessionId = getSessionId();
    if (!sessionId) throw new HttpError(401, "No current session to keep");
    return requireCredential().revokeOtherSessions(getUserId(), sessionId);
  };

  // Options are immutable for the lifetime of an event (set once by the
  // guard). Memoize the slot lookup so closures invoked multiple times per
  // event (extractToken + writeCookies + buildLoginResponse, etc.) collapse
  // to a single has+get instead of one per call.
  let cachedOptions: ResolvedAuthOptions | undefined;
  const requireOptions = (): ResolvedAuthOptions => {
    if (cachedOptions !== undefined) return cachedOptions;
    if (!ctx.has(authOptionsKey)) {
      throw new HttpError(
        500,
        "useAuth(): authGuardInterceptor(opts) must be installed on the HTTP event chain",
      );
    }
    cachedOptions = ctx.get(authOptionsKey);
    return cachedOptions;
  };

  const extractToken = (): string | undefined => {
    const options = requireOptions();
    let token: string | undefined;
    if (options.enableBearer) {
      const auth = useAuthorization(ctx);
      if (auth.is("bearer")) token = auth.credentials() ?? undefined;
    }
    if (!token && options.enableCookie) {
      token = useCookies(ctx).getCookie(options.cookie.name) ?? undefined;
    }
    return token;
  };

  const writeCookies = (issue: IssueResult): void => {
    const options = requireOptions();
    if (!options.enableCookie) return;
    const response = useResponse(current());
    response.setCookie(options.cookie.name, issue.accessToken, cookieAttrsFrom(options.cookie));
    if (issue.refreshToken) {
      response.setCookie(
        options.refreshCookie.name,
        issue.refreshToken,
        cookieAttrsFrom(options.refreshCookie),
      );
    }
  };

  const clearCookies = (): void => {
    const options = requireOptions();
    if (!options.enableCookie) return;
    const response = useResponse(current());
    response.setCookie(options.cookie.name, "", cookieAttrsFrom(options.cookie, { maxAge: 0 }));
    response.setCookie(
      options.refreshCookie.name,
      "",
      cookieAttrsFrom(options.refreshCookie, { maxAge: 0 }),
    );
  };

  /**
   * With `enableBearer === false` the response shape still carries `userId` +
   * `accessExpiresAt` so clients can schedule a silent refresh, but the tokens
   * themselves travel only via the cookies set by `writeCookies`.
   */
  const buildLoginResponseFn = (userId: string, issue: IssueResult): AuthLoginResponse => {
    const options = requireOptions();
    return {
      userId,
      accessExpiresAt: issue.accessExpiresAt,
      ...(issue.refreshExpiresAt !== undefined && { refreshExpiresAt: issue.refreshExpiresAt }),
      ...(options.enableBearer && {
        accessToken: issue.accessToken,
        ...(issue.refreshToken && { refreshToken: issue.refreshToken }),
      }),
    };
  };

  /**
   * Build the `cookies` map for `useWfFinished({ cookies })`. The outlet
   * trigger's HTTP layer turns the entries into `Set-Cookie` headers, mirroring
   * what `writeCookies()` does for the REST controller.
   */
  const buildFinishedCookies = (issue: IssueResult): WfFinishedResponse["cookies"] => {
    const options = requireOptions();
    if (!options.enableCookie) return undefined;
    const cookies: NonNullable<WfFinishedResponse["cookies"]> = {
      [options.cookie.name]: {
        value: issue.accessToken,
        options: cookieAttrsFrom(options.cookie),
      },
    };
    if (issue.refreshToken) {
      cookies[options.refreshCookie.name] = {
        value: issue.refreshToken,
        options: cookieAttrsFrom(options.refreshCookie),
      };
    }
    return cookies;
  };

  const cookieAttrs = (extra?: TCookieAttributesInput): TCookieAttributesInput => {
    return cookieAttrsFrom(requireOptions().cookie, extra);
  };

  return {
    getAuthContext,
    getUserId,
    isAuthenticated,
    getSessionId,
    listSessions,
    revokeSession,
    revokeOtherSessions,
    get options() {
      return requireOptions();
    },
    extractToken,
    writeCookies,
    clearCookies,
    buildLoginResponse: buildLoginResponseFn,
    buildFinishedCookies,
    cookieAttrs,
  };
});

/** Internal: only `authGuardInterceptor` writes the slot. */
export function setAuthContext<TPayload extends object>(
  ctx: EventContext,
  value: AuthContext<TPayload> | null,
): void {
  // `AuthContext<TPayload>` (= the read envelope intersected with the
  // credential's typed payload) is a subtype of the slot's `AuthContext`, so
  // the extra payload fields are erased to the base envelope at the slot.
  ctx.set(authContextKey, value);
}

/**
 * Internal: `authGuardInterceptor` stashes the per-event `AuthCredential` it
 * instantiated, so the `useAuth()` session facade can reach the store.
 */
export function setAuthCredential(ctx: EventContext, value: AuthCredential): void {
  ctx.set(authCredentialKey, value);
}
