import { ArbacAction, ArbacResource } from "@aooth/arbac-moost";
import { AuthCredential, type EnrichedSession, type SessionInfo } from "@aooth/auth";
import { Delete, Get, HttpError, Query } from "@moostjs/event-http";
import { Controller, Injectable, Param } from "moost";

import { useAuth } from "./auth.composables";

/**
 * Injectable read-time session enricher. Default is identity — aooth ships NO
 * UA-parser or GeoIP dependency. Consumers who want `device` / `browser` / `os`
 * / `location` columns subclass this, override `enrich`, and register the
 * replacement via moost's `createReplaceRegistry([SessionEnricherProvider, MyEnricher])`:
 *
 * ```ts
 * @Injectable() // SINGLETON
 * class MyEnricher extends SessionEnricherProvider {
 *   override enrich(s: SessionInfo): EnrichedSession {
 *     const ua = parseUserAgent(s.metadata?.userAgent);
 *     return { ...s, device: ua.device, browser: ua.browser, os: ua.os,
 *              location: geoLookup(s.metadata?.ip) };
 *   }
 * }
 * ```
 *
 * Singleton scope is required — `@Injectable()` (no scope arg) → SINGLETON.
 */
@Injectable()
export class SessionEnricherProvider {
  enrich(session: SessionInfo): EnrichedSession | Promise<EnrichedSession> {
    return session;
  }
}

/**
 * Optional, mountable controller exposing a user's active sessions for the
 * "Active sessions" UI. Register it (or a subclass) alongside `AuthController`
 * to enable the endpoints — registration IS the opt-in; aooth never mounts it
 * implicitly.
 *
 * Routes (all under the `auth.sessions` ARBAC resource):
 *
 * | Method + path                      | Action     | Effect                              |
 * | ---------------------------------- | ---------- | ----------------------------------- |
 * | `GET    /auth/sessions`            | `read`     | the caller's own sessions           |
 * | `GET    /auth/sessions/of/:userId` | `readAny`  | another user's sessions (admin)     |
 * | `DELETE /auth/sessions/:sessionId` | `revoke`   | revoke one of the caller's sessions |
 * | `DELETE /auth/sessions?others=true`| `revoke`   | revoke all but the caller's current |
 *
 * Each `SessionInfo` is mapped through the injectable {@link SessionEnricherProvider}
 * before returning, and the caller's own session is flagged `current: true`.
 * NOT `@Public()` — the auth guard rejects unauthenticated callers with 401 and
 * ARBAC gates each action; a customer enables it with `allow("auth.sessions", "*")`.
 */
@Controller("auth")
@ArbacResource("auth.sessions")
export class SessionsController {
  constructor(
    protected readonly auth: AuthCredential,
    protected readonly enricher: SessionEnricherProvider,
  ) {}

  @Get("sessions")
  @ArbacAction("read")
  async listSessions(): Promise<EnrichedSession[]> {
    const auth = useAuth();
    const sessions = (await this.auth.listSessions(auth.getUserId(), {
      enrich: (s) => this.enricher.enrich(s),
    })) as EnrichedSession[];
    const current = auth.getSessionId();
    // Flag the caller's own session in place — the enricher already produced
    // fresh objects, so no spread/copy is needed.
    for (const s of sessions) s.current = s.sessionId === current;
    return sessions;
  }

  /**
   * Admin read of another user's sessions. Gated by the separate `readAny`
   * action so a customer can grant ordinary users `read` (own sessions) without
   * granting cross-user visibility.
   */
  @Get("sessions/of/:userId")
  @ArbacAction("readAny")
  async listSessionsOf(@Param("userId") userId: string): Promise<EnrichedSession[]> {
    const sessions = await this.auth.listSessions(userId, {
      enrich: (s) => this.enricher.enrich(s),
    });
    // No `current` flag — these are not the admin's own sessions.
    return sessions as EnrichedSession[];
  }

  @Delete("sessions/:sessionId")
  @ArbacAction("revoke")
  async revokeSession(@Param("sessionId") sessionId: string): Promise<{ ok: true }> {
    await this.auth.revokeSession(useAuth().getUserId(), sessionId);
    return { ok: true };
  }

  /**
   * `DELETE /auth/sessions?others=true` — log out everywhere else, keeping the
   * caller's current session. Returns the number of sessions revoked. A bare
   * `DELETE /auth/sessions` (no `others`) is a 400 — revoking ALL of one's own
   * sessions (including the current one) is what `POST /auth/logout` is for.
   */
  @Delete("sessions")
  @ArbacAction("revoke")
  async revokeOthers(@Query("others") others: string | undefined): Promise<{ revoked: number }> {
    if (others !== "true") {
      throw new HttpError(400, "Pass ?others=true to log out other sessions");
    }
    const auth = useAuth();
    const current = auth.getSessionId();
    if (!current) throw new HttpError(401, "No current session to keep");
    const revoked = await this.auth.revokeOtherSessions(auth.getUserId(), current);
    return { revoked };
  }
}
