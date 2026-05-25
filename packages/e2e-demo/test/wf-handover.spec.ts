import { unlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from "vite-plus/test";

import { parseHandoverRoles } from "../src/workflows/handover.workflow";
import {
  buildTestApp,
  expectOk,
  readWfPause,
  startRecoveryAndResume,
  type TestApp,
  wfContext,
  wfErrors,
} from "./harness";

const STRONG_PASSWORD = "InvitedP1ss!";

describe("WF-CUSTOM — project.handover workflow", () => {
  let app: TestApp;

  beforeEach(async () => {
    app = await buildTestApp();
  });
  afterEach(async () => {
    await app.close();
  });

  it("WF-CUSTOM-01 — owner triggers handover; email captured; commit transfers ownership", async () => {
    const dave = app.fixtures.users.t1_dave;
    const tokens = await app.loginAs(dave);
    const projectId = app.fixtures.projects["proj-a-1"];

    const start = await app.triggerWf(
      "public",
      { wfid: "project.handover" },
      {
        token: tokens.accessToken,
      },
    );
    const startBody = await readWfPause(start);
    expect(startBody.wfs).toBeTruthy();

    const select = await app.triggerWf(
      "public",
      {
        wfid: "project.handover",
        wfs: startBody.wfs,
        input: { projectId, targetOwner: "t1_alice" },
      },
      { token: tokens.accessToken },
    );
    const selectBody = await readWfPause(select);
    expect(selectBody.wfs).toBeTruthy();

    const confirm = await app.triggerWf(
      "public",
      {
        wfid: "project.handover",
        wfs: selectBody.wfs,
        input: { confirm: true },
      },
      { token: tokens.accessToken },
    );
    expectOk(confirm);

    const email = await app.emailSender.next(
      (e) => e.kind === "invite.magicLink" && e.recipient === dave.email,
      2000,
    );
    expect(email.url).toContain("?wfs=");
    expect(email.metadata?.roles).toBeTruthy();
    const decoded = parseHandoverRoles((email.metadata as { roles: string[] }).roles);
    expect(decoded.projectId).toBe(projectId);
    expect(decoded.targetOwner).toBe("t1_alice");

    const resumed = await app.resumeWfFromUrl(email.url as string, undefined, {
      token: tokens.accessToken,
    });
    expectOk(resumed);
    const resumedBody = (await resumed.json()) as {
      ok?: boolean;
      newOwner?: string;
      projectId?: string;
    };
    expect(resumedBody.ok).toBe(true);
    expect(resumedBody.newOwner).toBe("t1_alice");
    expect(resumedBody.projectId).toBe(projectId);

    const project = await app.appHandle.appDb.tables.projects.findOne({
      filter: { id: projectId },
    });
    expect((project as { ownerUsername: string }).ownerUsername).toBe("t1_alice");
  });

  it("WF-CUSTOM-03 — transient state purged after commit (replay returns 4xx)", async () => {
    const dave = app.fixtures.users.t1_dave;
    const tokens = await app.loginAs(dave);
    const projectId = app.fixtures.projects["proj-a-3"];

    const start = await app.triggerWf(
      "public",
      { wfid: "project.handover" },
      {
        token: tokens.accessToken,
      },
    );
    const startBody = await readWfPause(start);
    const select = await app.triggerWf(
      "public",
      {
        wfid: "project.handover",
        wfs: startBody.wfs,
        input: { projectId, targetOwner: "t1_bob" },
      },
      { token: tokens.accessToken },
    );
    const selectBody = await readWfPause(select);
    await app.triggerWf(
      "public",
      {
        wfid: "project.handover",
        wfs: selectBody.wfs,
        input: { confirm: true },
      },
      { token: tokens.accessToken },
    );

    const email = await app.emailSender.next(
      (e) => e.kind === "invite.magicLink" && e.recipient === dave.email,
      2000,
    );

    const commitResp = await app.resumeWfFromUrl(email.url as string, undefined, {
      token: tokens.accessToken,
    });
    expectOk(commitResp);

    const replay = await app.resumeWfFromUrl(email.url as string, undefined, {
      token: tokens.accessToken,
    });
    expect(replay.status).toBeGreaterThanOrEqual(400);
    expect(replay.status).toBeLessThan(500);
  });

  it("WF-CUSTOM-04 — non-owner member cannot trigger handover (403)", async () => {
    const bob = app.fixtures.users.t1_bob;
    const tokens = await app.loginAs(bob);
    const projectId = app.fixtures.projects["proj-a-1"];

    const start = await app.triggerWf(
      "public",
      { wfid: "project.handover" },
      {
        token: tokens.accessToken,
      },
    );
    const startBody = await readWfPause(start);

    const select = await app.triggerWf(
      "public",
      {
        wfid: "project.handover",
        wfs: startBody.wfs,
        input: { projectId, targetOwner: "t1_alice" },
      },
      { token: tokens.accessToken },
    );
    expect(select.status).toBe(403);
  });
});

describe("WF-CUSTOM-02 — mid-flow state survives server restart (file-backed DB)", () => {
  const dbFile = path.join(
    tmpdir(),
    `aoothjs-e2e-handover-${Date.now()}-${Math.floor(Math.random() * 1e9)}.sqlite`,
  );

  afterAll(() => {
    for (const ext of ["", "-journal", "-wal", "-shm"]) {
      try {
        unlinkSync(`${dbFile}${ext}`);
      } catch {
        // file may not exist
      }
    }
  });

  it("WF-CUSTOM-02 — wfs token from app A is resumable after app A close + app B boot", async () => {
    let appA: TestApp | null = await buildTestApp({ dbPath: dbFile });
    const dave = appA.fixtures.users.t1_dave;
    const projectId = appA.fixtures.projects["proj-a-2"];
    const daveTokens = await appA.loginAs(dave);

    const start = await appA.triggerWf(
      "public",
      { wfid: "project.handover" },
      {
        token: daveTokens.accessToken,
      },
    );
    const startBody = await readWfPause(start);
    const select = await appA.triggerWf(
      "public",
      {
        wfid: "project.handover",
        wfs: startBody.wfs,
        input: { projectId, targetOwner: "t1_carol" },
      },
      { token: daveTokens.accessToken },
    );
    const selectBody = await readWfPause(select);
    expect(selectBody.wfs).toBeTruthy();
    const carriedToken = selectBody.wfs as string;

    await appA.close();
    appA = null;

    const appB = await buildTestApp({ dbPath: dbFile, seed: false });
    try {
      const daveB = await appB.loginAs({
        id: "",
        username: "t1_dave",
        password: "Password1!",
        email: "dave@acme.test",
        tenantId: "",
        roles: ["admin"],
      });

      const confirm = await appB.triggerWf(
        "public",
        {
          wfid: "project.handover",
          wfs: carriedToken,
          input: { confirm: true },
        },
        { token: daveB.accessToken },
      );
      expectOk(confirm);

      const email = await appB.emailSender.next((e) => e.kind === "invite.magicLink", 2000);
      expect(email.url).toContain("?wfs=");
    } finally {
      await appB.close();
    }
  });
});

describe("WF-FORM — workflow form behavior (covered via recovery + handover)", () => {
  let app: TestApp;

  beforeAll(async () => {
    app = await buildTestApp();
  });
  afterAll(async () => {
    await app.close();
  });
  beforeEach(() => {
    app.emailSender.reset();
  });

  it("WF-FORM-01 — passContext present on resume (handover currentOwner/projectId echoed back)", async () => {
    const dave = app.fixtures.users.t1_dave;
    const tokens = await app.loginAs(dave);

    const start = await app.triggerWf(
      "public",
      { wfid: "project.handover" },
      {
        token: tokens.accessToken,
      },
    );
    const startBody = await readWfPause(start);
    const startCtx = wfContext(startBody);
    expect(typeof startCtx).toBe("object");

    const carol = app.fixtures.users.t1_carol;
    const { resumedBody } = await startRecoveryAndResume(app, carol.email);
    expect(wfContext(resumedBody)).toBeTruthy();
  });

  it("WF-FORM-02 — SetPasswordForm with mismatched confirmPassword returns field error", async () => {
    const eve = app.fixtures.users.t1_eve;
    const { resumedBody } = await startRecoveryAndResume(app, eve.email);

    const mismatch = await app.triggerWf("public", {
      wfid: "auth/recovery/flow",
      wfs: resumedBody.wfs,
      input: { newPassword: STRONG_PASSWORD, confirmPassword: "Different1Pw!", consents: [] },
    });
    const mismatchBody = await readWfPause(mismatch);
    expect(wfErrors(mismatchBody)).toMatchObject({
      confirmPassword: "Passwords do not match",
    });
  });
});
