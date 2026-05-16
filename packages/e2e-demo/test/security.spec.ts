import { Arbac } from "@aoothjs/arbac-core";
import { generateTotpCode } from "@aoothjs/user";
import { createHmac } from "node:crypto";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from "vite-plus/test";

import {
  buildTestApp,
  dbFindOne,
  expectAllInTenant,
  expectOk,
  loginAndFetch,
  readWfPause,
  runTotpLoginWorkflow,
  startRecoveryAndResume,
  submitRecoveryPassword,
  type TestApp,
} from "./harness";

const STRONG_NEW = "StrongP1ss!";

interface TaskRow {
  id: string;
  tenantId: string;
  title: string;
  status?: string;
  internalNotes?: string;
}
interface UserRow {
  id?: string;
  username?: string;
  email?: string;
  password?: unknown;
  mfa?: unknown;
  account?: unknown;
  roles?: string[];
  tenantId?: string;
}

const b64url = (input: string | Buffer): string => Buffer.from(input).toString("base64url");

/**
 * Build the unsigned `header.payload` segments of a JWT. The signature suffix
 * is left to the caller — pass empty for `alg: none`, or HMAC the segments.
 */
function buildJwtSegments(alg: "none" | "HS256", sub: string, jti: string): string {
  const header = b64url(JSON.stringify({ alg, typ: "JWT" }));
  const now = Math.floor(Date.now() / 1000);
  const payload = b64url(
    JSON.stringify({
      sub,
      iat: now,
      exp: now + 3600,
      jti,
      state: { iatMs: now * 1000, expMs: (now + 3600) * 1000, kind: "access" },
    }),
  );
  return `${header}.${payload}`;
}

function forgeAlgNoneJwt(sub: string): string {
  return `${buildJwtSegments("none", sub, "forged-jti")}.`;
}

function forgeHs256JwtWithWrongSecret(sub: string, wrongSecret: string): string {
  const segments = buildJwtSegments("HS256", sub, "forged-jti-hs256");
  const sig = createHmac("sha256", wrongSecret).update(segments).digest("base64url");
  return `${segments}.${sig}`;
}

describe("SEC — ARBAC bypass attacks", () => {
  let app: TestApp;

  beforeAll(async () => {
    app = await buildTestApp();
  });
  afterAll(async () => {
    await app.close();
  });

  it("SEC-01 BUG-SHAPE: filter injection via $or escapes scope (see also CTRL-08)", async () => {
    const tenantA = app.fixtures.tenants["tenant-a"];
    const { fetch } = await loginAndFetch(app, app.fixtures.users.t1_alice);
    const res = await fetch("/tasks/query?status=open^status=in_progress");
    expect(res.status).toBe(200);
    const rows = (await res.json()) as TaskRow[];
    expectAllInTenant(rows, tenantA);
  });

  it("SEC-02 — projection escape via $select cannot leak password/mfa/account", async () => {
    const { fetch } = await loginAndFetch(app, app.fixtures.users.t1_eve);
    const res = await fetch("/users/query?$select=password,mfa,account.lockEnds");
    if (res.status === 400) return;
    expect(res.status).toBe(200);
    const rows = (await res.json()) as Array<Record<string, unknown>>;
    for (const row of rows) {
      const keys = Object.keys(row);
      expect(keys.includes("password")).toBe(false);
      expect(keys.includes("mfa")).toBe(false);
      expect(keys.includes("account")).toBe(false);
    }
  });

  it("SEC-03 — PK guess across tenant returns 404 (timing roughly comparable; see ISO-02)", async () => {
    const { fetch } = await loginAndFetch(app, app.fixtures.users.t1_alice);
    const fakeInTenant = "no-such-id-in-tenant-a";
    const cross = app.fixtures.tasks.tenantB[0];

    const t0 = Date.now();
    const inTenant = await fetch(`/tasks/one/${fakeInTenant}`);
    const t1 = Date.now();
    const crossTenant = await fetch(`/tasks/one/${cross}`);
    const t2 = Date.now();

    expect(inTenant.status).toBe(404);
    expect(crossTenant.status).toBe(404);

    const inMs = t1 - t0;
    const crossMs = t2 - t1;
    const diff = Math.abs(inMs - crossMs);
    expect(diff).toBeLessThan(200);
  });

  it("SEC-04 — composite key bypass via param overload still 404 (see ISO-03/04)", async () => {
    const { fetch } = await loginAndFetch(app, app.fixtures.users.t1_alice);
    const docB = app.fixtures.documents.tenantB[0];
    const tenantB = app.fixtures.tenants["tenant-b"];
    const res = await fetch(`/documents/one?id=${docB}&tenantId=${encodeURIComponent(tenantB)}`);
    expect(res.status).toBe(404);
  });

  it("SEC-25 — @Public resolution: anonymous /health is reachable (auth + arbac bypass)", async () => {
    const res = await app.fetch("/health");
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ ok: true });
  });

  it("SEC-26 — user with only an unknown role is denied everywhere", async () => {
    const id = await app.appHandle.appDb.tables.users.insertOne({
      username: "ghost-no-rules",
      email: "ghost@nowhere.test",
      tenantId: app.fixtures.tenants["tenant-a"],
      roles: ["nonexistent-role"],
      password: {
        hash: await app.appHandle.aooth.userService.getPasswordHasher().hash("Password1!"),
        history: [],
        lastChanged: Date.now(),
        isInitial: false,
      },
      account: {
        active: true,
        locked: false,
        lockReason: "",
        lockEnds: 0,
        failedLoginAttempts: 0,
        lastLogin: 0,
      },
      mfa: { methods: [], defaultMethod: "", autoSend: false },
    } as never);
    expect((id as { insertedId: string }).insertedId).toBeTruthy();

    const tokens = await app.loginAs({
      id: "ghost-no-rules",
      username: "ghost-no-rules",
      email: "ghost@nowhere.test",
      password: "Password1!",
      tenantId: app.fixtures.tenants["tenant-a"],
      roles: ["nonexistent-role"],
    });
    const fetch = app.authedFetch(tokens.accessToken);
    const responses = await Promise.all(
      ["/tasks/query", "/users/query", "/projects/query", "/comments/query"].map((p) => fetch(p)),
    );
    for (const r of responses) expect(r.status).toBe(403);
  });

  it("SEC-27 — `tasks.**` glob anchors and does NOT match `tasks_secret` / `tasksprivate`", async () => {
    const arbac = new Arbac<{ tenantId: string }, { filter?: object }>();
    arbac.registerRole({
      id: "wildcardTester",
      name: "wildcard tester",
      description: "",
      rules: [{ resource: "tasks.**", action: "*" }],
    } as never);

    const fakeUser = {
      id: "u",
      roles: ["wildcardTester"],
      attrs: { tenantId: "t" },
    };

    const r1 = await arbac.evaluate({ resource: "tasks.markDone", action: "do" }, fakeUser);
    expect(r1.allowed).toBe(true);
    const r2 = await arbac.evaluate({ resource: "tasks_secret", action: "do" }, fakeUser);
    expect(r2.allowed).toBe(false);
    const r3 = await arbac.evaluate({ resource: "tasksprivate", action: "do" }, fakeUser);
    expect(r3.allowed).toBe(false);
    const r4 = await arbac.evaluate({ resource: "tasks", action: "do" }, fakeUser);
    expect(r4.allowed).toBe(false);
  });
});

describe("SEC — mass-assignment / role escalation", () => {
  let app: TestApp;

  beforeEach(async () => {
    app = await buildTestApp();
  });
  afterEach(async () => {
    await app.close();
  });

  it("SEC-05 — admin's `users.insert` allowedFields excludes `roles`; cannot plant admin via insert", async () => {
    const tenantA = app.fixtures.tenants["tenant-a"];
    const { fetch } = await loginAndFetch(app, app.fixtures.users.t1_dave);
    const res = await fetch("/users", {
      method: "POST",
      json: {
        username: "sec05-newcomer",
        email: "sec05@acme.test",
        tenantId: tenantA,
        roles: ["admin"],
        password: {
          hash: "x",
          history: [],
          lastChanged: Date.now(),
          isInitial: false,
        },
        account: {
          active: true,
          locked: false,
          lockReason: "",
          lockEnds: 0,
          failedLoginAttempts: 0,
          lastLogin: 0,
        },
        mfa: { methods: [], defaultMethod: "", autoSend: false },
      },
    });
    if (res.status >= 200 && res.status < 300) {
      const { insertedId } = (await res.json()) as { insertedId: string };
      const row = (await dbFindOne(app, "users", { id: insertedId })) as UserRow;
      expect(row.roles ?? []).not.toContain("admin");
    } else {
      expect(res.status).toBeGreaterThanOrEqual(400);
      expect(res.status).toBeLessThan(500);
    }
  });

  it("SEC-06 — role escalation via PATCH /users blocked (member 403; admin allowedFields strips roles, see WRITE-01)", async () => {
    const aliceId = app.fixtures.users.t1_alice.id;
    const { fetch: aliceFetch } = await loginAndFetch(app, app.fixtures.users.t1_alice);
    const memberAttempt = await aliceFetch("/users", {
      method: "PATCH",
      json: { id: aliceId, roles: ["admin"] },
    });
    expect(memberAttempt.status).toBe(403);

    const { fetch: daveFetch } = await loginAndFetch(app, app.fixtures.users.t1_dave);
    const adminAttempt = await daveFetch("/users", {
      method: "PATCH",
      json: { id: aliceId, roles: ["admin"] },
    });
    expect([200, 202]).toContain(adminAttempt.status);
    const after = (await dbFindOne(app, "users", { id: aliceId })) as UserRow;
    expect(after.roles).toEqual(["member", "viewer"]);
  });

  it("SEC-29 — admin can self-demote via users.assignRoles (no library-level prevention)", async () => {
    const dave = app.fixtures.users.t1_dave;
    const { fetch } = await loginAndFetch(app, dave);
    const res = await fetch("/users/actions/assignRoles", {
      method: "POST",
      json: { ids: { id: dave.id }, input: { roles: ["viewer"] } },
    });
    expect([200, 201, 202]).toContain(res.status);
    const after = (await dbFindOne(app, "users", { id: dave.id })) as UserRow;
    expect(after.roles).toEqual(["viewer"]);
  });
});

describe("SEC — token attacks", () => {
  let app: TestApp;

  beforeAll(async () => {
    app = await buildTestApp();
  });
  afterAll(async () => {
    await app.close();
  });

  it("SEC-07 — JWT alg=none rejected (see also AUTH-14)", async () => {
    const forged = forgeAlgNoneJwt("t1_alice");
    const res = await app.authedFetch(forged)("/auth/status");
    expect(res.status).toBe(401);
  });

  it("SEC-08 — JWT signed with a wrong secret is rejected", async () => {
    const forged = forgeHs256JwtWithWrongSecret("t1_alice", "totally-wrong-secret");
    const res = await app.authedFetch(forged)("/auth/status");
    expect(res.status).toBe(401);
  });

  it("SEC-09 — refresh reuse rejected at HTTP layer (see also AUTH-07)", async () => {
    const tokens = await app.loginAs(app.fixtures.users.t1_alice);
    const rotate = await app.fetch("/auth/refresh", {
      method: "POST",
      json: { refreshToken: tokens.refreshToken },
    });
    expectOk(rotate);
    const replay = await app.fetch("/auth/refresh", {
      method: "POST",
      json: { refreshToken: tokens.refreshToken },
    });
    expect(replay.status).toBe(401);
  });

  it("SEC-30 — refresh after logout rejected", async () => {
    const tokens = await app.loginAs(app.fixtures.users.t1_alice);
    const logout = await app.authedFetch(tokens.accessToken)("/auth/logout", {
      method: "POST",
      json: { refreshToken: tokens.refreshToken },
    });
    expectOk(logout);
    const refresh = await app.fetch("/auth/refresh", {
      method: "POST",
      json: { refreshToken: tokens.refreshToken },
    });
    expect(refresh.status).toBe(401);
  });
});

describe("SEC — magic-link attacks", () => {
  let app: TestApp;

  beforeEach(async () => {
    app = await buildTestApp();
  });
  afterEach(async () => {
    await app.close();
  });

  it("SEC-10 — magic-link replay returns 4xx (see also WF-RECOVERY-03)", async () => {
    const carol = app.fixtures.users.t1_carol;
    const { emailEvent, resumedBody } = await startRecoveryAndResume(app, carol.email);
    expectOk(await submitRecoveryPassword(app, resumedBody.wfs, STRONG_NEW));

    const replay = await app.resumeWfFromUrl(emailEvent.url as string);
    expect(replay.status).toBeGreaterThanOrEqual(400);
    expect(replay.status).toBeLessThan(500);
  });

  it("SEC-11 — magic-link cross-user replay: link IS the credential (mitigation = email delivery)", async () => {
    const alice = app.fixtures.users.t1_alice;
    const bobTokens = await app.loginAs(app.fixtures.users.t1_bob);

    const { emailEvent, resumedBody } = await startRecoveryAndResume(app, alice.email);
    expect(resumedBody.inputRequired).toBeTruthy();

    const finalRes = await submitRecoveryPassword(app, resumedBody.wfs, STRONG_NEW, {
      token: bobTokens.accessToken,
    });
    expectOk(finalRes);
    const finalBody = (await finalRes.json()) as { userId?: string };
    expect(finalBody.userId).toBe(alice.username);

    const aliceLogin = await app.fetch("/auth/login", {
      method: "POST",
      json: { username: alice.username, password: STRONG_NEW },
    });
    expectOk(aliceLogin);
    expect(emailEvent.recipient).toBe(alice.email);
  });

  it("SEC-12 — workflow handle replay across roles: non-admin still 403 on /wf/admin", async () => {
    const dave = app.fixtures.users.t1_dave;
    const alice = app.fixtures.users.t1_alice;
    const daveTokens = await app.loginAs(dave);

    const start = await app.triggerWf(
      "admin",
      { wfid: "auth.invite" },
      {
        token: daveTokens.accessToken,
      },
    );
    expectOk(start);
    const startBody = await readWfPause(start);
    expect(startBody.wfs).toBeTruthy();

    const aliceTokens = await app.loginAs(alice);
    const replay = await app.triggerWf(
      "admin",
      {
        wfid: "auth.invite",
        wfs: startBody.wfs,
        input: { email: "stolen@x.test" },
      },
      { token: aliceTokens.accessToken },
    );
    expect(replay.status).toBe(403);

    const noAuth = await app.triggerWf("admin", {
      wfid: "auth.invite",
      wfs: startBody.wfs,
      input: { email: "stolen@x.test" },
    });
    expect(noAuth.status).toBe(401);
  });

  it("SEC-28 — invite link visit alone does NOT activate user; password required (see WF-INVITE-02)", async () => {
    const dave = app.fixtures.users.t1_dave;
    const daveTokens = await app.loginAs(dave);
    const targetEmail = "sec28-invite@acme.test";

    const start = await app.triggerWf(
      "admin",
      { wfid: "auth.invite" },
      {
        token: daveTokens.accessToken,
      },
    );
    const startBody = await readWfPause(start);
    await app.triggerWf(
      "admin",
      {
        wfid: "auth.invite",
        wfs: startBody.wfs,
        input: { email: targetEmail },
      },
      { token: daveTokens.accessToken },
    );

    const email = await app.emailSender.next(
      (e) => e.kind === "invite.magicLink" && e.recipient === targetEmail,
      2000,
    );
    const visit = await app.resumeWfFromUrl(email.url as string);
    const visitBody = await readWfPause(visit);
    expect(visitBody.inputRequired).toBeTruthy();

    const loginAttempt = await app.fetch("/auth/login", {
      method: "POST",
      json: { username: targetEmail, password: "anything-or-nothing" },
    });
    expect(loginAttempt.status).toBeGreaterThanOrEqual(400);
  });
});

describe("SEC — lockout / brute-force", () => {
  let app: TestApp;
  beforeEach(async () => {
    app = await buildTestApp({
      envOverrides: { LOCKOUT_THRESHOLD: 3, LOCKOUT_DURATION_MS: 1500 },
    });
  });
  afterEach(async () => {
    await app.close();
  });

  it("SEC-13 — login lockout after threshold (see also AUTH-05)", async () => {
    const alice = app.fixtures.users.t1_alice;
    for (let i = 0; i < 3; i++) {
      const r = await app.fetch("/auth/login", {
        method: "POST",
        json: { username: alice.username, password: "wrong" },
      });
      expect(r.status).toBe(401);
    }
    const locked = await app.fetch("/auth/login", {
      method: "POST",
      json: { username: alice.username, password: alice.password },
    });
    expect(locked.status).toBe(423);
  });

  it("SEC-19 — TOTP brute force trips the shared lockout after threshold failures", async () => {
    const grace = app.fixtures.users.t1_grace;
    expect(grace.totpSecret).toBeTruthy();

    const start = await app.triggerWf("public", { wfid: "auth.login" });
    const startBody = await readWfPause(start);
    const credResp = await app.triggerWf("public", {
      wfid: "auth.login",
      wfs: startBody.wfs,
      input: { username: grace.username, password: grace.password },
    });
    let body = await readWfPause(credResp);

    // Lockout threshold is 3 (envOverrides above). Three wrong codes must
    // produce a lockout response (423); subsequent login also returns 423.
    let lockedStatus = 0;
    for (let i = 0; i < 5; i++) {
      const guess = String(i % 1_000_000).padStart(6, "0");
      const att = await app.triggerWf("public", {
        wfid: "auth.login",
        wfs: body.wfs,
        input: { code: guess },
      });
      if (att.status === 423) {
        lockedStatus = 423;
        break;
      }
      body = await readWfPause(att);
      if (!body.wfs) break;
    }
    expect(lockedStatus).toBe(423);

    // A fresh login attempt now hits the password-side lockout check too.
    const relogin = await app.fetch("/auth/login", {
      method: "POST",
      json: { username: grace.username, password: grace.password },
    });
    expect(relogin.status).toBe(423);
  });
});

describe("SEC — enumeration", () => {
  let app: TestApp;
  beforeAll(async () => {
    app = await buildTestApp();
  });
  afterAll(async () => {
    await app.close();
  });

  it("SEC-14 — login enumeration: unknown user yields identical response shape (see AUTH-02/03)", async () => {
    const alice = app.fixtures.users.t1_alice;
    const wrong = await app.fetch("/auth/login", {
      method: "POST",
      json: { username: alice.username, password: "wrong" },
    });
    const unknown = await app.fetch("/auth/login", {
      method: "POST",
      json: { username: "no-such-user-zzz", password: "Password1!" },
    });
    expect(wrong.status).toBe(401);
    expect(unknown.status).toBe(401);
    const wrongText = await wrong.text();
    const unknownText = await unknown.text();
    expect(wrongText).toContain("Invalid credentials");
    expect(unknownText).toContain("Invalid credentials");
  });

  it("SEC-15 — recovery enumeration: unknown email returns same {sent:true} (see WF-RECOVERY-02)", async () => {
    const start = await app.triggerWf("public", { wfid: "auth.recovery" });
    const startBody = await readWfPause(start);
    const submit = await app.triggerWf("public", {
      wfid: "auth.recovery",
      wfs: startBody.wfs,
      input: { email: "ghost-sec15@nowhere.test" },
    });
    expectOk(submit);
    const body = (await submit.json()) as { sent?: boolean };
    expect(body.sent).toBe(true);
  });
});

describe("SEC — password attacks", () => {
  let app: TestApp;
  beforeEach(async () => {
    app = await buildTestApp();
  });
  afterEach(async () => {
    await app.close();
  });

  it("SEC-16 — password policy bypass: weak password rejected on /auth/password and on recovery SetPasswordForm", async () => {
    const alice = app.fixtures.users.t1_alice;
    const tokens = await app.loginAs(alice);
    const weak = await app.authedFetch(tokens.accessToken)("/auth/password", {
      method: "POST",
      json: { currentPassword: alice.password, newPassword: "abc" },
    });
    expect(weak.status).toBe(400);

    const bob = app.fixtures.users.t1_bob;
    const { resumedBody } = await startRecoveryAndResume(app, bob.email);
    const recoveryWeak = await submitRecoveryPassword(app, resumedBody.wfs, "abc");
    const respBody = (await recoveryWeak.json()) as Record<string, unknown>;
    expect(respBody.userId).toBeUndefined();
  });

  it("SEC-17 — password history: cannot reuse a password within history window", async () => {
    const alice = app.fixtures.users.t1_alice;
    const passwords = ["StepP1ss!", "StepP2ss!", "StepP3ss!", "StepP4ss!"];
    let current = alice.password;

    for (const next of passwords) {
      const t = await app.loginAs({ ...alice, password: current });
      const ch = await app.authedFetch(t.accessToken)("/auth/password", {
        method: "POST",
        json: { currentPassword: current, newPassword: next },
      });
      expectOk(ch);
      current = next;
    }

    const tFinal = await app.loginAs({ ...alice, password: current });
    const reuseInitial = await app.authedFetch(tFinal.accessToken)("/auth/password", {
      method: "POST",
      json: { currentPassword: current, newPassword: alice.password },
    });
    expect(reuseInitial.status).toBe(400);
  });

  it("SEC-24 — concurrent password change: no torn state, login succeeds with one of the new passwords", async () => {
    const alice = app.fixtures.users.t1_alice;
    const tokens = await app.loginAs(alice);
    const authed = app.authedFetch(tokens.accessToken);
    const [r1, r2] = await Promise.all([
      authed("/auth/password", {
        method: "POST",
        json: { currentPassword: alice.password, newPassword: "RaceAlpha1!" },
      }),
      authed("/auth/password", {
        method: "POST",
        json: { currentPassword: alice.password, newPassword: "RaceBeta2!" },
      }),
    ]);
    expect(r1.status).not.toBe(500);
    expect(r2.status).not.toBe(500);

    const tryA = await app.fetch("/auth/login", {
      method: "POST",
      json: { username: alice.username, password: "RaceAlpha1!" },
    });
    const tryB = await app.fetch("/auth/login", {
      method: "POST",
      json: { username: alice.username, password: "RaceBeta2!" },
    });
    const okA = tryA.status >= 200 && tryA.status < 300;
    const okB = tryB.status >= 200 && tryB.status < 300;
    expect(okA || okB).toBe(true);
  });
});

describe("SEC — TOTP attacks", () => {
  let app: TestApp;
  beforeEach(async () => {
    app = await buildTestApp();
  });
  afterEach(async () => {
    await app.close();
  });

  it("SEC-18 — TOTP replay within window: same code accepted twice (RFC 6238 documented behavior)", async () => {
    const grace = app.fixtures.users.t1_grace;
    const code = generateTotpCode(grace.totpSecret as string);

    const loginOnce = async (): Promise<boolean> => {
      const final = await runTotpLoginWorkflow(app, grace, { code });
      const body = (await final.json()) as { accessToken?: string };
      return typeof body.accessToken === "string";
    };

    expect(await loginOnce()).toBe(true);
    expect(await loginOnce()).toBe(true);
  });
});

describe("SEC — documented limitations", () => {
  let app: TestApp;
  beforeAll(async () => {
    app = await buildTestApp();
  });
  afterAll(async () => {
    await app.close();
  });

  it("SEC-32 — denylist memory: cleanup() purges expired entries", async () => {
    const denylist = app.appHandle.aooth.denylist;
    const past = Date.now() - 60_000;
    await denylist.add("expired-1", past);
    await denylist.add("expired-2", past);
    await denylist.add("future", Date.now() + 60_000);
    const removed = await denylist.cleanup();
    expect(removed).toBeGreaterThanOrEqual(2);
    expect(await denylist.has("future")).toBe(true);
  });
});
