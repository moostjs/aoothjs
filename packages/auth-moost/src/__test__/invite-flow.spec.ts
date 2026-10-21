import { AuthCredential, CredentialStoreMemory } from "@aooth/auth";
import { UserService, UserStoreMemory } from "@aooth/user";
import { Controller, Inherit, Injectable } from "moost";
import { describe, expect, it } from "vite-plus/test";

import { ConsentStore } from "../consent.store";
import { AuthWorkflow } from "../workflow/auth-workflow";
import type { AuthWfCtx } from "../workflow/auth-workflow.ctx";
import { ExtendedInviteForm } from "./fixtures/invite-ext.as";
import { FlowWorkflow, prepareFlowApp, type PreparedFlowApp } from "./flow-utils";

/** Run the admin phase of `auth/invite/start` for `email`; returns the response. */
async function issueInvite(app: PreparedFlowApp, email: string, extra: object = {}) {
  const start = await app.start("auth/invite/start");
  expect(start.status, JSON.stringify(start.body)).toBe(201);
  return app.submit(start.body.wfs, { formData: { email, roles: [], ...extra } });
}

describe("F33: invite issue fails loudly", () => {
  it("a prepareUser returning nothing still creates the pending user and sends the link", async () => {
    @Inherit()
    @Injectable()
    @Controller()
    class NoExtras extends FlowWorkflow {
      protected override prepareUser(): Record<string, unknown> {
        return undefined as unknown as Record<string, unknown>;
      }
    }
    const app = await prepareFlowApp({ workflowClass: NoExtras });
    const res = await issueInvite(app, "new@x.test");
    expect(res.status, JSON.stringify(res.body)).toBeLessThan(300);
    const user = await app.users.findByHandle("new@x.test");
    expect(user?.account.pendingInvitation).toBe(true);
    expect(app.emails.map((e) => e.target)).toEqual(["new@x.test"]);
  });

  it("an issue phase that ends without a user is a 500, not a silent success", async () => {
    @Inherit()
    @Injectable()
    @Controller()
    class CreatesNothing extends FlowWorkflow {
      override async createUser(): Promise<undefined> {
        return undefined; // a broken override that creates nothing
      }
    }
    const app = await prepareFlowApp({ workflowClass: CreatesNothing });
    const res = await issueInvite(app, "lost@x.test");
    expect(res.status).toBe(500);
    expect(app.emails).toEqual([]);
  });
});

/** Resume the invitee's link up to (and through) the first accept pause. */
async function openLink(app: PreparedFlowApp, token: string, input: object = {}) {
  return app.submit(token, input);
}

/** From the set-password pause: set the password and skip optional MFA enrolment. */
async function completeAccept(app: PreparedFlowApp, wfs: string) {
  let res = await openLink(app, wfs, {
    formData: {
      newPassword: "Str0ng!Passw0rd",
      confirmPassword: "Str0ng!Passw0rd",
      consents: [],
    },
  });
  if (res.body.inputRequired?.payload?.id === "EnrollPickMethodForm") {
    res = await openLink(app, res.body.wfs, { action: "skip" });
  }
  expect(res.body.inputRequired, JSON.stringify(res.body).slice(0, 300)).toBeUndefined();
  return res;
}

describe("A1: invite issue seam (F32/F102)", () => {
  it("app context from the start input and extra admin-form fields reach the hooks", async () => {
    const seen: Record<string, unknown> = {};
    @Inherit()
    @Injectable()
    @Controller()
    class Tenanted extends FlowWorkflow {
      protected override resolveInviteContext(_ctx: unknown, start?: Record<string, unknown>) {
        return { tenantId: start?.tenantId };
      }
      protected override inferAdminRoles(input: Record<string, unknown>): string[] {
        seen.infer = input;
        return [];
      }
      protected override duplicateInviteCheck(input: Record<string, unknown>) {
        seen.dup = input;
        return "allow" as const;
      }
      protected override prepareUser(input: Record<string, unknown>) {
        seen.prepare = input;
        return { tenantId: (input.app as { tenantId: string }).tenantId };
      }
    }
    const app = await prepareFlowApp({
      workflowClass: Tenanted,
      workflowOpts: { forms: { invite: ExtendedInviteForm } },
    });
    const start = await app.start("auth/invite/start", undefined, {
      formData: { tenantId: "t-1" },
    });
    const res = await app.submit(start.body.wfs, {
      formData: { email: "a@x.test", roles: [], displayName: "Ann" },
    });
    expect(res.status, JSON.stringify(res.body)).toBeLessThan(300);
    const expected = { app: { tenantId: "t-1" }, form: { displayName: "Ann" } };
    expect(seen.dup).toMatchObject(expected);
    expect(seen.infer).toMatchObject(expected);
    expect(seen.prepare).toMatchObject(expected);
    const user = await app.users.findByHandle("a@x.test");
    expect((user as unknown as { tenantId?: string }).tenantId).toBe("t-1");
  });
});

const inviteLinkUrl = (token: string, info: { userId?: string }) =>
  `https://app.test/invite?wfs=${token}&uid=${info.userId}`;

describe("A1: inviteDelivery (F34)", () => {
  it("'deliver' hands the link to deliver({ kind: 'invite-link' })", async () => {
    const delivered: unknown[] = [];
    @Inherit()
    @Injectable()
    @Controller()
    class Delivering extends FlowWorkflow {
      protected override deliver(payload: unknown): void {
        delivered.push(payload);
      }
    }
    const app = await prepareFlowApp({
      workflowClass: Delivering,
      workflowOpts: { inviteDelivery: "deliver", inviteLinkUrl },
    });
    const res = await issueInvite(app, "d@x.test");
    expect(res.status, JSON.stringify(res.body)).toBeLessThan(300);
    expect(app.emails).toEqual([]);
    expect(delivered).toEqual([
      expect.objectContaining({
        kind: "invite-link",
        channel: "email",
        recipient: "d@x.test",
        url: expect.stringMatching(/^https:\/\/app\.test\/invite\?wfs=.+&uid=/),
      }),
    ]);
    expect(JSON.stringify(res.body)).not.toContain("wfs=");
  });

  it("'return-link' returns the link to the issuer and accepting does not record verifiedEmail", async () => {
    const app = await prepareFlowApp({
      workflowOpts: { inviteDelivery: "return-link", inviteLinkUrl, autoLoginOnInvite: false },
    });
    const res = await issueInvite(app, "r@x.test");
    expect(res.body.data.inviteLink).toMatch(/^https:\/\/app\.test\/invite\?wfs=/);
    const token = new URL(res.body.data.inviteLink).searchParams.get("wfs")!;
    const userId = res.body.data.userId as string;
    const pw = await openLink(app, token);
    expect(pw.body.inputRequired?.payload?.id).toBe("SetPasswordForm");
    await completeAccept(app, pw.body.wfs);
    const user = await app.users.getUser(userId);
    expect(user.account.pendingInvitation).toBe(false);
    expect(user.account.verifiedEmail).toBeUndefined();
  });

  it("the default email delivery still records verifiedEmail on accept", async () => {
    const app = await prepareFlowApp({ workflowOpts: { autoLoginOnInvite: false } });
    await issueInvite(app, "e@x.test");
    const pw = await openLink(app, app.emails[0].token);
    await completeAccept(app, pw.body.wfs);
    const user = await app.users.findByHandle("e@x.test");
    expect(user?.account.verifiedEmail).toBe("e@x.test");
  });
});

describe("A1: invitee chooses the username (F31)", () => {
  it("'choose' asks for a username before the password and makes it the login handle", async () => {
    const app = await prepareFlowApp({
      workflowOpts: { inviteUsername: "choose", autoLoginOnInvite: false },
    });
    await app.seedUser("taken", "Password123!");
    await issueInvite(app, "c@x.test");
    const pick = await openLink(app, app.emails[0].token);
    expect(pick.body.inputRequired?.payload?.id).toBe("InviteChooseUsernameForm");
    const clash = await openLink(app, pick.body.wfs, { formData: { username: "taken" } });
    expect(clash.body.inputRequired.context.errors).toEqual({ username: "This username is taken" });
    const pw = await openLink(app, clash.body.wfs, { formData: { username: "carol" } });
    expect(pw.body.inputRequired?.payload?.id).toBe("SetPasswordForm");
    await completeAccept(app, pw.body.wfs);
    const user = await app.users.findByHandle("carol");
    expect(user?.account.active).toBe(true);
    expect(user?.account.verifiedEmail).toBe("c@x.test");
    expect(await app.users.findByHandle("c@x.test")).toBeNull();
  });

  it("normalises the pick and refuses names that look like another handle", async () => {
    const app = await prepareFlowApp({
      workflowOpts: { inviteUsername: "choose", autoLoginOnInvite: false },
    });
    await issueInvite(app, "n@x.test");
    let res = await openLink(app, app.emails[0].token);
    for (const bad of ["boss@other.test", "two words", "tab\tname"]) {
      res = await openLink(app, res.body.wfs, { formData: { username: bad } });
      expect(res.body.inputRequired.context.errors, bad).toEqual({
        username: "This username is not allowed",
      });
    }
    // Fullwidth letters fold to ASCII (NFKC) and surrounding spaces are trimmed.
    res = await openLink(app, res.body.wfs, { formData: { username: "  ｎｉｎａ " } });
    expect(res.body.inputRequired?.payload?.id).toBe("SetPasswordForm");
    expect(await app.users.findByHandle("nina")).not.toBeNull();
  });
});

describe("S7 (F43): a re-invite supersedes earlier links", () => {
  it("an older link answers 410 'replaced' and never activates the account", async () => {
    const app = await prepareFlowApp({ workflowOpts: { autoLoginOnInvite: false } });
    await issueInvite(app, "s@x.test");
    await issueInvite(app, "s@x.test"); // 'reuse' — rotates the link marker
    expect(app.emails).toHaveLength(2);
    const stale = await openLink(app, app.emails[0].token);
    expect(stale.status).toBe(410);
    expect(stale.body).toMatchObject({ code: "INVITE_REPLACED" });
    const fresh = await openLink(app, app.emails[1].token);
    expect(fresh.body.inputRequired?.payload?.id).toBe("SetPasswordForm");
    const user = await app.users.findByHandle("s@x.test");
    expect(user?.account.pendingInvitation).toBe(true);
  });

  it("duplicateInviteCheck sees the pending invite's issuer", async () => {
    let pending: unknown;
    const seen: Record<string, unknown> = {};
    @Inherit()
    @Injectable()
    @Controller()
    class Checking extends FlowWorkflow {
      protected override duplicateInviteCheck(input: { pending?: unknown; existingUser: unknown }) {
        pending = input.pending;
        return input.existingUser ? ("reuse" as const) : ("allow" as const);
      }
      protected override inferAdminRoles(input: { invitedBy?: string }): string[] {
        seen.infer = input.invitedBy;
        return [];
      }
      protected override prepareUser(input: { invitedBy?: string }) {
        seen.prepare = input.invitedBy;
        return {};
      }
    }
    const app = await prepareFlowApp({ workflowClass: Checking });
    const issuer = await app.seedUser("admin", "Password123!");
    const { accessToken } = await app.auth.issue(issuer);
    const asAdmin = { authorization: `Bearer ${accessToken}` };
    for (let i = 0; i < 2; i++) {
      const start = await app.start("auth/invite/start", asAdmin);
      await app.submit(start.body.wfs, { formData: { email: "p@x.test", roles: [] } }, asAdmin);
    }
    expect(pending).toEqual({ invitedBy: issuer });
    // Every invite hook gets the issuer (C3: `inferAdminRoles` used to miss it).
    expect(seen).toEqual({ infer: issuer, prepare: issuer });
    const user = await app.users.findByHandle("p@x.test");
    expect(user?.account.invitedBy).toBe(issuer);
  });
});

describe("S7 (H2): superseded / used links never write to the account", () => {
  const PW = { newPassword: "Str0ng!Passw0rd", confirmPassword: "Str0ng!Passw0rd", consents: [] };

  it("a link opened BEFORE a re-invite cannot finish afterwards", async () => {
    const app = await prepareFlowApp({ workflowOpts: { autoLoginOnInvite: false } });
    await issueInvite(app, "v@x.test");
    const opened = await openLink(app, app.emails[0].token);
    expect(opened.body.inputRequired?.payload?.id).toBe("SetPasswordForm");
    await issueInvite(app, "v@x.test"); // re-invite rotates the marker
    const before = (await app.users.findByHandle("v@x.test"))!;
    const stale = await openLink(app, opened.body.wfs, { formData: PW });
    expect(stale.status).toBe(410);
    expect(stale.body).toMatchObject({ code: "INVITE_REPLACED" });
    const after = (await app.users.findByHandle("v@x.test"))!;
    expect(after.account.pendingInvitation).toBe(true);
    expect(after.account.active).toBe(false);
    expect(after.password.hash).toBe(before.password.hash);
    // The current link still completes.
    const fresh = await openLink(app, app.emails[1].token);
    await completeAccept(app, fresh.body.wfs);
    expect((await app.users.findByHandle("v@x.test"))?.account.active).toBe(true);
  });

  it("a superseded link opened AFTER the newer one was accepted is 410 — no password takeover", async () => {
    const app = await prepareFlowApp({ workflowOpts: { autoLoginOnInvite: true } });
    await issueInvite(app, "w@x.test");
    await issueInvite(app, "w@x.test");
    const legit = await openLink(app, app.emails[1].token);
    await completeAccept(app, legit.body.wfs);
    const user = (await app.users.findByHandle("w@x.test"))!;
    const stale = await openLink(app, app.emails[0].token);
    expect(stale.status).toBe(410);
    expect(stale.body).toMatchObject({ code: "INVITE_REPLACED" });
    expect(stale.setCookies).toEqual([]);
    expect(await app.users.verifyPassword(user.id, "Str0ng!Passw0rd")).toBe(true);
  });

  it("an already-accepted invite ends at the 'already accepted' envelope", async () => {
    const app = await prepareFlowApp({ workflowOpts: { autoLoginOnInvite: true } });
    await issueInvite(app, "a@x.test");
    const user = (await app.users.findByHandle("a@x.test"))!;
    // Accepted elsewhere (e.g. a parallel run of the same link).
    await app.users.update(user.id, { account: { pendingInvitation: false } } as never);
    const res = await openLink(app, app.emails[0].token);
    expect(res.body.inputRequired).toBeUndefined();
    expect(res.body.message?.text).toBe("This invite was already accepted.");
    expect(res.body.data?.accessToken).toBeUndefined();
    expect(res.setCookies).toEqual([]);
  });

  it("two runs of the same pending invite cannot both accept (compare-and-set)", async () => {
    const app = await prepareFlowApp({ workflowOpts: { autoLoginOnInvite: false } });
    await issueInvite(app, "c2@x.test");
    const user = (await app.users.findByHandle("c2@x.test"))!;
    const nonce = user.account.inviteNonce;
    expect(await app.users.acceptInvitation(user.id, "other-nonce")).toBe(false);
    expect(await app.users.acceptInvitation(user.id, nonce)).toBe(true);
    expect(await app.users.acceptInvitation(user.id, nonce)).toBe(false);
  });
});

describe("S7 (L2): consent records never land through a superseded link", () => {
  it("persist-consents re-checks the invite before writing", async () => {
    const users = new UserService(new UserStoreMemory());
    const saved: unknown[] = [];
    class RecordingConsents extends ConsentStore {
      override async save(userId: string, events: unknown[]): Promise<void> {
        saved.push({ userId, events });
      }
    }
    const flow = new AuthWorkflow(
      {},
      users,
      new AuthCredential({ store: new CredentialStoreMemory() }),
      new RecordingConsents(),
    );
    const row = await users.createUser("l2@x.test", undefined, {});
    await users.update(row.id, {
      account: { pendingInvitation: true, inviteNonce: "newer" },
    } as never);
    const ctx = {
      subject: row.id,
      accept: {},
      admin: { inviteNonce: "older" },
      consents: { pending: [{ id: "tos" }], accepted: ["tos"], decidedAt: Date.now() },
    } as unknown as AuthWfCtx;
    const err = await flow.persistConsents(ctx).catch((e: unknown) => e);
    expect((err as { body?: { code?: string } }).body?.code).toBe("INVITE_REPLACED");
    expect(saved).toEqual([]);
  });
});
