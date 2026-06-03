import type { TArbacRole } from "@aooth/arbac-moost";
import type { EnrichedSession, SessionInfo } from "@aooth/auth";
import { Delete, Get } from "@moostjs/event-http";
import { Controller, Param } from "moost";
import { describe, expect, it } from "vite-plus/test";

import { useAuth } from "../auth.composables";
import { Public } from "../auth.decorator";
import { SessionEnricherProvider, SessionsController } from "../sessions.controller";
import { prepareControllerApp } from "./controller-utils";

// ── Test controllers (module scope so their decorator metadata identity is
//    stable across test spin-ups — mirrors the controller-utils pattern). ──

/**
 * Exercises the `useAuth()` session FACADE (R7a) directly — the bundled
 * `SessionsController` calls `this.auth` rather than the facade, so without this
 * the facade wrappers (listSessions / revokeSession / revokeOtherSessions /
 * getSessionId) would ship untested. `@Public()` so the test doesn't need arbac
 * grants; the auth guard still stashes the credential + context on a valid token.
 */
@Controller("facade")
class FacadeController {
  @Get("sessions")
  @Public()
  list(): Promise<SessionInfo[] | EnrichedSession[]> {
    return useAuth().listSessions();
  }

  @Get("session-id")
  @Public()
  sessionId(): { sessionId: string | undefined } {
    return { sessionId: useAuth().getSessionId() };
  }

  @Delete("sessions/:id")
  @Public()
  async revokeOne(@Param("id") id: string): Promise<{ ok: true }> {
    await useAuth().revokeSession(id);
    return { ok: true };
  }

  @Delete("sessions")
  @Public()
  async revokeOthers(): Promise<{ revoked: number }> {
    return { revoked: await useAuth().revokeOtherSessions() };
  }
}

const ROLE_SESSIONS: TArbacRole<object, object> = {
  id: "sessions-self",
  // self can read + revoke own sessions, but NOT readAny (cross-user).
  rules: [
    { resource: "auth.sessions", action: "read" },
    { resource: "auth.sessions", action: "revoke" },
  ],
};

const ROLE_ADMIN: TArbacRole<object, object> = {
  id: "sessions-admin",
  rules: [{ resource: "auth.sessions", action: "*" }],
};

const ROLE_NONE: TArbacRole<object, object> = {
  id: "no-sessions",
  rules: [{ resource: "other", action: "*" }],
};

interface Row {
  sessionId: string;
  current?: boolean;
}

/**
 * Seeds a primary user (+ optional extras) and returns the app plus the minted
 * surrogate `id`s. The SESSION SUBJECT is now the stable `id`, so callers:
 *   - issue sessions with the returned id (`app.auth.issue(ids.primary)`),
 *   - key the `userRoles` map by the returned id (the `TestArbacUserProvider`
 *     reads it lazily at request time, keyed by `getUserId()` = the id).
 * The `userRoles` Map is captured BY REFERENCE inside `prepareControllerApp`,
 * so populating it AFTER createUser (with the freshly-minted ids) is observed
 * at request time.
 */
async function seedUserWithSessions(
  roles: TArbacRole<object, object>[],
  userRoles: Map<string, string[]>,
  username: string,
  extra: string[] = [],
): Promise<{
  app: Awaited<ReturnType<typeof prepareControllerApp>>;
  primaryId: string;
  extraIds: Record<string, string>;
}> {
  const app = await prepareControllerApp({
    arbac: { userRoles, roles },
    extraControllers: [SessionsController, FacadeController],
  });
  const primary = await app.users.createUser(username, "Password123");
  await app.users.activateAccount(primary.id);
  const extraIds: Record<string, string> = {};
  for (const u of extra) {
    const created = await app.users.createUser(u, "Password123");
    await app.users.activateAccount(created.id);
    extraIds[u] = created.id;
  }
  return { app, primaryId: primary.id, extraIds };
}

describe("SessionsController (auth.sessions)", () => {
  it("GET /auth/sessions lists the caller's sessions with the current one flagged", async () => {
    const userRoles = new Map<string, string[]>();
    const { app, primaryId } = await seedUserWithSessions([ROLE_SESSIONS], userRoles, "alice");
    userRoles.set(primaryId, ["sessions-self"]);
    const current = await app.auth.issue(primaryId);
    await app.auth.issue(primaryId); // a second device

    const res = await app.request("/auth/sessions", {
      headers: { authorization: `Bearer ${current.accessToken}` },
    });
    expect(res.status).toBe(200);
    const rows = res.body as Row[];
    expect(rows).toHaveLength(2);
    expect(rows.filter((r) => r.current)).toHaveLength(1);
  });

  it("DELETE /auth/sessions/:id revokes one session, leaving the caller's own", async () => {
    const userRoles = new Map<string, string[]>();
    const { app, primaryId } = await seedUserWithSessions([ROLE_SESSIONS], userRoles, "alice");
    userRoles.set(primaryId, ["sessions-self"]);
    const current = await app.auth.issue(primaryId);
    const other = await app.auth.issue(primaryId);
    const otherSid = (await app.auth.validate(other.accessToken))?.sessionId as string;

    const del = await app.request(`/auth/sessions/${otherSid}`, {
      method: "DELETE",
      headers: { authorization: `Bearer ${current.accessToken}` },
    });
    expect(del.status).toBeGreaterThanOrEqual(200);
    expect(del.status).toBeLessThan(300);
    // The revoked device's token no longer validates; the caller's still does.
    expect(await app.auth.validate(other.accessToken)).toBeNull();
    expect(await app.auth.validate(current.accessToken)).not.toBeNull();
  });

  it("DELETE /auth/sessions?others=true keeps the current session, revokes the rest", async () => {
    const userRoles = new Map<string, string[]>();
    const { app, primaryId } = await seedUserWithSessions([ROLE_SESSIONS], userRoles, "alice");
    userRoles.set(primaryId, ["sessions-self"]);
    const current = await app.auth.issue(primaryId);
    await app.auth.issue(primaryId);
    await app.auth.issue(primaryId);

    const del = await app.request("/auth/sessions?others=true", {
      method: "DELETE",
      headers: { authorization: `Bearer ${current.accessToken}` },
    });
    expect(del.status).toBeGreaterThanOrEqual(200);
    expect(del.status).toBeLessThan(300);
    expect((del.body as { revoked: number }).revoked).toBe(2);
    expect(await app.auth.validate(current.accessToken)).not.toBeNull();
  });

  it("DELETE /auth/sessions with no ?others is a 400 (logout is the all-sessions kill)", async () => {
    const userRoles = new Map<string, string[]>();
    const { app, primaryId } = await seedUserWithSessions([ROLE_SESSIONS], userRoles, "alice");
    userRoles.set(primaryId, ["sessions-self"]);
    const token = (await app.auth.issue(primaryId)).accessToken;
    const res = await app.request("/auth/sessions", {
      method: "DELETE",
      headers: { authorization: `Bearer ${token}` },
    });
    expect(res.status).toBe(400);
  });

  it("anonymous GET /auth/sessions is rejected (401)", async () => {
    const { app } = await seedUserWithSessions([ROLE_SESSIONS], new Map(), "alice");
    const res = await app.request("/auth/sessions");
    expect(res.status).toBe(401);
  });

  it("a user without an auth.sessions grant is denied (403)", async () => {
    const userRoles = new Map<string, string[]>();
    const { app, primaryId } = await seedUserWithSessions([ROLE_NONE], userRoles, "alice");
    userRoles.set(primaryId, ["no-sessions"]);
    const token = (await app.auth.issue(primaryId)).accessToken;
    const res = await app.request("/auth/sessions", {
      headers: { authorization: `Bearer ${token}` },
    });
    expect(res.status).toBe(403);
  });

  it("readAny: an admin reads another user's sessions; self-only role is denied (403)", async () => {
    const userRoles = new Map<string, string[]>();
    const {
      app,
      primaryId: rootId,
      extraIds,
    } = await seedUserWithSessions([ROLE_ADMIN, ROLE_SESSIONS], userRoles, "root", ["alice"]);
    const aliceId = extraIds.alice;
    // Roles keyed by each user's own stable id (= the session subject).
    userRoles.set(rootId, ["sessions-admin"]);
    userRoles.set(aliceId, ["sessions-self"]);

    await app.auth.issue(aliceId);
    await app.auth.issue(aliceId);

    const adminToken = (await app.auth.issue(rootId)).accessToken;
    const ok = await app.request(`/auth/sessions/of/${aliceId}`, {
      headers: { authorization: `Bearer ${adminToken}` },
    });
    expect(ok.status).toBe(200);
    expect(ok.body as Row[]).toHaveLength(2);

    // A self-only role (read/revoke but no readAny) cannot reach the cross-user route.
    const aliceToken = (await app.auth.issue(aliceId)).accessToken;
    const denied = await app.request(`/auth/sessions/of/${rootId}`, {
      headers: { authorization: `Bearer ${aliceToken}` },
    });
    expect(denied.status).toBe(403);
  });
});

describe("useAuth() session facade (R7a)", () => {
  it("listSessions / getSessionId / revokeSession / revokeOtherSessions are scoped to the caller", async () => {
    const app = await prepareControllerApp({ extraControllers: [FacadeController] });
    const alice = await app.users.createUser("alice", "Password123");
    await app.users.activateAccount(alice.id);
    const current = await app.auth.issue(alice.id);
    await app.auth.issue(alice.id);
    await app.auth.issue(alice.id);
    const auth = { authorization: `Bearer ${current.accessToken}` };

    // getSessionId returns the authenticating session.
    const sid = await app.request("/facade/session-id", { headers: auth });
    const currentSid = (sid.body as { sessionId: string }).sessionId;
    expect(currentSid).toBeTruthy();

    // listSessions returns the caller's three sessions.
    const list = await app.request("/facade/sessions", { headers: auth });
    expect(list.body as Row[]).toHaveLength(3);

    // revokeOtherSessions keeps the current one.
    const others = await app.request("/facade/sessions", { method: "DELETE", headers: auth });
    expect((others.body as { revoked: number }).revoked).toBe(2);
    const afterOthers = await app.request("/facade/sessions", { headers: auth });
    expect(afterOthers.body as Row[]).toHaveLength(1);

    // revokeSession on the current session kills it (next call is 401).
    await app.request(`/facade/sessions/${currentSid}`, { method: "DELETE", headers: auth });
    expect(await app.auth.validate(current.accessToken)).toBeNull();
  });
});

describe("SessionEnricherProvider", () => {
  it("default enrich is identity (aooth ships no UA/geo derivation)", () => {
    const s: SessionInfo = { sessionId: "s1", userId: "alice", createdAt: 1, expiresAt: 2 };
    expect(new SessionEnricherProvider().enrich(s)).toBe(s);
  });
});
