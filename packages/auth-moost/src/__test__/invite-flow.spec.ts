import { AuthCredential, CredentialStoreMemory } from "@aooth/auth";
import { UserAuthError, type UserCredentials, UserService, UserStoreMemory } from "@aooth/user";
import { Get, Query } from "@moostjs/event-http";
import { Controller, Inherit, Injectable, useControllerContext } from "moost";
import { afterEach, describe, expect, it, vi } from "vite-plus/test";

import { AuthController } from "../auth.controller";
import { Public } from "../auth.decorator";
import { ConsentStore } from "../consent.store";
import { RateLimit } from "../rate-limit/decorator";
import { WfTriggerProvider } from "../wf-trigger/provider";
import { AuthWorkflow } from "../workflow/auth-workflow";
import type { AuthWfCtx } from "../workflow/auth-workflow.ctx";
import { peekInvite } from "../workflow/invite-peek";
import { ExtendedInviteForm } from "./fixtures/invite-ext.as";
import {
  completeAccept,
  type FlowResponse,
  FlowWorkflow,
  issueInvite,
  prepareFlowApp,
  type PreparedFlowApp,
} from "./flow-utils";

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

describe("revoking a pending invite (UserService.revokeInvitation)", () => {
  it("the revoked link answers 410 INVITE_CANCELLED and the account is gone", async () => {
    const app = await prepareFlowApp();
    await issueInvite(app, "r@x.test");
    const pending = await app.users.findByHandle("r@x.test");
    expect(pending?.account.pendingInvitation).toBe(true);

    expect(await app.users.revokeInvitation(pending!.id)).toBe(true);
    expect(await app.users.findByHandle("r@x.test")).toBeNull();
    const res = await openLink(app, app.emails[0].token);
    expect(res.status).toBe(410);
    expect(res.body).toMatchObject({ code: "INVITE_CANCELLED" });
  });

  it("a link revoked while its password form is open answers 410 INVITE_CANCELLED", async () => {
    const app = await prepareFlowApp();
    await issueInvite(app, "o@x.test");
    const opened = await openLink(app, app.emails[0].token);
    expect(opened.body.inputRequired?.payload?.id).toBe("SetPasswordForm");
    const pending = await app.users.findByHandle("o@x.test");
    expect(await app.users.revokeInvitation(pending!.id)).toBe(true);
    const res = await openLink(app, opened.body.wfs, {
      formData: { newPassword: "Str0ng!Passw0rd", confirmPassword: "Str0ng!Passw0rd" },
    });
    expect(res.status).toBe(410);
    expect(res.body).toMatchObject({ code: "INVITE_CANCELLED" });
  });

  it("an accepted invite is not revoked", async () => {
    const app = await prepareFlowApp({ workflowOpts: { autoLoginOnInvite: false } });
    await issueInvite(app, "a@x.test");
    const opened = await openLink(app, app.emails[0].token);
    await completeAccept(app, opened.body.wfs);
    const user = await app.users.findByHandle("a@x.test");
    expect(user?.account.pendingInvitation).toBe(false);
    expect(await app.users.revokeInvitation(user!.id)).toBe(false);
    expect(await app.users.findByHandle("a@x.test")).not.toBeNull();
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

/**
 * The issuer may grant `Grantable.roles`; each `prepareUser` call returns the
 * next `tenantId`, so a re-run of it would show on the row.
 */
@Inherit()
@Injectable()
@Controller()
class Grantable extends FlowWorkflow {
  static roles: string[] = [];
  static prepared = 0;
  protected override getAvailableRoles(): string[] {
    return Grantable.roles;
  }
  protected override prepareUser(): Record<string, unknown> {
    Grantable.prepared++;
    return { tenantId: `t-${Grantable.prepared}` };
  }
}

/** A `Grantable` app with two issuers (all roles grantable) and their auth headers. */
async function bootGrantable() {
  Grantable.roles = ["admin", "editor", "viewer"];
  Grantable.prepared = 0;
  const app = await prepareFlowApp({
    workflowClass: Grantable,
    workflowOpts: { autoLoginOnInvite: false },
  });
  const ids = {
    first: await app.seedUser("first-admin", "Password123!"),
    second: await app.seedUser("second-admin", "Password123!"),
  };
  const as = async (id: string) => ({
    authorization: `Bearer ${(await app.auth.issue(id)).accessToken}`,
  });
  return { app, ids, first: await as(ids.first), second: await as(ids.second) };
}

/**
 * The admin UI's resend: start the invite flow, then fire the `resend` action
 * with the email — the body the form client posts for a data-carrying action
 * (`{ action, formData }`).
 */
async function resendInvite(
  app: PreparedFlowApp,
  email: string,
  headers: Record<string, string>,
  extra: object = {},
) {
  const start = await app.start("auth/invite/start", headers);
  return app.submit(start.body.wfs, { action: "resend", formData: { email, ...extra } }, headers);
}

/**
 * Make the invitee accept (and get activated) right after `create-user`'s
 * fresh read of their row — the second `findByHandle` of an issue run, after
 * `admin-form`'s — so the run's refresh meets an accepted account. Returns
 * the account as accepted (read once the acceptance is done).
 */
function acceptDuringCreateUser(app: PreparedFlowApp, email: string): () => unknown {
  const read = app.users.findByHandle.bind(app.users);
  let reads = 0;
  let accepted: unknown;
  vi.spyOn(app.users, "findByHandle").mockImplementation(async (handle: string) => {
    const row = await read(handle);
    if (handle === email && ++reads === 2 && row) {
      expect(await app.users.acceptInvitation(row.id, row.account.inviteNonce)).toBe(true);
      await app.users.activateAccount(row.id);
      accepted = await read(handle);
    }
    return row;
  });
  return () => accepted;
}

/** The pending invitee's row, with the columns the invite flow writes. */
async function inviteRow(app: PreparedFlowApp, email: string) {
  return (await app.users.findByHandle(email)) as unknown as {
    roles?: string[];
    tenantId?: string;
    account: { invitedBy?: string; pendingInvitation?: boolean };
  } | null;
}

describe("re-sending a pending invite as it is (the 'resend' verdict)", () => {
  // WHY: an admin "Resend invite" action had no way to issue a fresh link
  // without restating the invite (a re-invite replaces roles and extras),
  // and reading the stored link back is impossible with hashed handles.

  it("issues a fresh link and keeps the roles, extras and issuer; the older link answers 410 INVITE_REPLACED", async () => {
    const { app, ids, first, second } = await bootGrantable();
    await issueInvite(app, "r@x.test", { roles: ["editor"] }, first);
    const sent = await resendInvite(app, "r@x.test", second);
    expect(sent.status, JSON.stringify(sent.body)).toBeLessThan(300);

    expect(app.emails.map((e) => e.target)).toEqual(["r@x.test", "r@x.test"]);
    expect(app.emails[1].context).toMatchObject({ roles: ["editor"] });
    const row = await inviteRow(app, "r@x.test");
    expect(row?.roles).toEqual(["editor"]);
    expect(row?.tenantId).toBe("t-1");
    expect(Grantable.prepared).toBe(1);
    expect(row?.account.invitedBy).toBe(ids.first);
    expect(row?.account.pendingInvitation).toBe(true);

    const stale = await openLink(app, app.emails[0].token);
    expect(stale.status).toBe(410);
    expect(stale.body).toMatchObject({ code: "INVITE_REPLACED" });
    const fresh = await openLink(app, app.emails[1].token);
    expect(fresh.body.inputRequired?.payload?.id).toBe("SetPasswordForm");
  });

  it("refuses with the invalid-role error when the issuer may not grant a role the invite keeps", async () => {
    const { app, first } = await bootGrantable();
    await issueInvite(app, "k@x.test", { roles: ["admin"] }, first);
    Grantable.roles = ["viewer"];
    const refused = await resendInvite(app, "k@x.test", first);
    expect(refused.body.inputRequired?.context?.errors).toEqual({ roles: "Invalid role" });
    expect(app.emails).toHaveLength(1);
    // Nothing rotated: the original link still opens.
    const original = await openLink(app, app.emails[0].token);
    expect(original.body.inputRequired?.payload?.id).toBe("SetPasswordForm");
  });

  it("the same rule covers a re-invite that picks no roles (it keeps them); picking grantable ones replaces them", async () => {
    const { app, first } = await bootGrantable();
    await issueInvite(app, "n@x.test", { roles: ["admin"] }, first);
    Grantable.roles = ["viewer"];
    const keeps = await issueInvite(app, "n@x.test", { roles: [] }, first);
    expect(keeps.body.inputRequired?.context?.errors).toEqual({ roles: "Invalid role" });
    expect((await inviteRow(app, "n@x.test"))?.roles).toEqual(["admin"]);

    const replaces = await issueInvite(app, "n@x.test", { roles: ["viewer"] }, first);
    expect(replaces.status, JSON.stringify(replaces.body)).toBeLessThan(300);
    expect((await inviteRow(app, "n@x.test"))?.roles).toEqual(["viewer"]);
  });

  it("an invite revoked meanwhile answers 410 INVITE_CANCELLED and creates nothing", async () => {
    const { app, first } = await bootGrantable();
    await issueInvite(app, "gone@x.test", { roles: ["editor"] }, first);
    const row = await app.users.findByHandle("gone@x.test");
    expect(await app.users.revokeInvitation(row!.id)).toBe(true);
    const res = await resendInvite(app, "gone@x.test", first);
    expect(res.status).toBe(410);
    expect(res.body).toMatchObject({ code: "INVITE_CANCELLED" });
    expect(await app.users.findByHandle("gone@x.test")).toBeNull();
    expect(app.emails).toHaveLength(1);
  });

  it("an invite accepted meanwhile answers 409 and stays accepted", async () => {
    const { app, first } = await bootGrantable();
    await issueInvite(app, "done@x.test", { roles: ["editor"] }, first);
    const opened = await openLink(app, app.emails[0].token);
    await completeAccept(app, opened.body.wfs);
    const res = await resendInvite(app, "done@x.test", first);
    expect(res.status).toBe(409);
    expect(res.body).toMatchObject({ code: "AOOTH_USER_ALREADY_EXISTS" });
    expect((await inviteRow(app, "done@x.test"))?.account.pendingInvitation).toBeFalsy();
  });

  it("ignores roles submitted with a resend", async () => {
    const { app, first } = await bootGrantable();
    await issueInvite(app, "i@x.test", { roles: ["editor"] }, first);
    const sent = await resendInvite(app, "i@x.test", first, { roles: ["admin"] });
    expect(sent.status, JSON.stringify(sent.body)).toBeLessThan(300);
    expect((await inviteRow(app, "i@x.test"))?.roles).toEqual(["editor"]);
    expect(app.emails[1].context).toMatchObject({ roles: ["editor"] });
  });

  it("a resend for an email that was never invited answers 410, creates nothing and sends nothing", async () => {
    const { app, first } = await bootGrantable();
    const res = await resendInvite(app, "never@x.test", first);
    expect(res.status).toBe(410);
    expect(res.body).toMatchObject({ code: "INVITE_CANCELLED" });
    expect(await app.users.findByHandle("never@x.test")).toBeNull();
    expect(app.emails).toEqual([]);
    expect(Grantable.prepared).toBe(0);
  });

  it("an app `duplicateInviteCheck` that ignores `resend` turns it into a plain re-invite", async () => {
    @Inherit()
    @Injectable()
    @Controller()
    class IgnoresResend extends Grantable {
      protected override duplicateInviteCheck(input: { existingUser: UserCredentials | null }) {
        if (input.existingUser?.account?.pendingInvitation) return "reuse" as const;
        return input.existingUser ? ("reject" as const) : ("allow" as const);
      }
    }
    Grantable.roles = ["admin", "editor", "viewer"];
    Grantable.prepared = 0;
    const app = await prepareFlowApp({
      workflowClass: IgnoresResend,
      workflowOpts: { autoLoginOnInvite: false },
    });
    const first = await app.seedUser("first-admin", "Password123!");
    const second = await app.seedUser("second-admin", "Password123!");
    const as = async (id: string) => ({
      authorization: `Bearer ${(await app.auth.issue(id)).accessToken}`,
    });
    await issueInvite(app, "p@x.test", { roles: ["editor"] }, await as(first));
    const sent = await resendInvite(app, "p@x.test", await as(second));
    expect(sent.status, JSON.stringify(sent.body)).toBeLessThan(300);
    const row = await inviteRow(app, "p@x.test");
    // A re-invite with no roles: roles kept, `prepareUser` re-run, issuer taken over.
    expect(row?.roles).toEqual(["editor"]);
    expect(Grantable.prepared).toBe(2);
    expect(row?.tenantId).toBe("t-2");
    expect(row?.account.invitedBy).toBe(second);
  });
});

/**
 * The refresh lost to the acceptance: the coded 409, no new link sent, the
 * account exactly as accepted, and the accepted link ends at "already accepted".
 */
async function expectLostRefresh(
  app: PreparedFlowApp,
  email: string,
  res: FlowResponse,
  accepted: unknown,
) {
  expect(res.status, JSON.stringify(res.body)).toBe(409);
  expect(res.body).toMatchObject({ code: "AOOTH_USER_ALREADY_EXISTS" });
  expect(app.emails).toHaveLength(1);
  const row = await inviteRow(app, email);
  expect(accepted).toBeDefined();
  expect(row).toEqual(accepted);
  expect((row?.account as { active?: boolean } | undefined)?.active).toBe(true);
  const opened = await openLink(app, app.emails[0].token);
  expect(opened.body.inputRequired?.payload?.id).toBeUndefined();
  expect(opened.body.message?.text).toBe("This invite was already accepted.");
}

describe("an invite accepted while a re-issue runs is left exactly as accepted", () => {
  // WHY: `create-user` reads the row, sees it pending, then writes the new
  // link marker (and a re-invite's roles, extras and issuer). An acceptance
  // landing between the two must win: a refresh landing on the live account
  // would change its roles or re-arm a link for it.

  it("on a resend", async () => {
    const { app, first, second } = await bootGrantable();
    await issueInvite(app, "race1@x.test", { roles: ["editor"] }, first);
    const accepted = acceptDuringCreateUser(app, "race1@x.test");
    const res = await resendInvite(app, "race1@x.test", second);
    await expectLostRefresh(app, "race1@x.test", res, accepted());
  });

  it("on a re-invite", async () => {
    const { app, first, second } = await bootGrantable();
    await issueInvite(app, "race2@x.test", { roles: ["editor"] }, first);
    const accepted = acceptDuringCreateUser(app, "race2@x.test");
    const res = await issueInvite(app, "race2@x.test", { roles: ["viewer"] }, second);
    await expectLostRefresh(app, "race2@x.test", res, accepted());
    // Nothing of the re-invite landed: roles, extras and issuer as accepted.
    const row = await inviteRow(app, "race2@x.test");
    expect(row?.roles).toEqual(["editor"]);
    expect(row?.tenantId).toBe("t-1");
  });
});

/**
 * Revoke the invite right after `create-user`'s lookup of the row (the second
 * `findByHandle` of an issue run) — before its refresh reads the row.
 */
function revokeDuringCreateUser(app: PreparedFlowApp, email: string): void {
  const read = app.users.findByHandle.bind(app.users);
  let reads = 0;
  vi.spyOn(app.users, "findByHandle").mockImplementation(async (handle: string) => {
    const row = await read(handle);
    if (handle === email && ++reads === 2 && row) {
      expect(await app.users.revokeInvitation(row.id)).toBe(true);
    }
    return row;
  });
}

describe("a re-issue meeting a row revoked after its lookup, or exhausted retries", () => {
  // WHY: the row can disappear between `create-user`'s lookup and the
  // refresh's own read (a revoke), and the refresh's compare-and-set can run
  // out of retries under contention. Both have documented answers — not a 500.

  it("a resend answers 410 INVITE_CANCELLED, creates nothing and sends nothing", async () => {
    const { app, first } = await bootGrantable();
    await issueInvite(app, "rv1@x.test", { roles: ["editor"] }, first);
    revokeDuringCreateUser(app, "rv1@x.test");
    const res = await resendInvite(app, "rv1@x.test", first);
    expect(res.status, JSON.stringify(res.body)).toBe(410);
    expect(res.body).toMatchObject({ code: "INVITE_CANCELLED" });
    vi.restoreAllMocks();
    expect(await app.users.findByHandle("rv1@x.test")).toBeNull();
    expect(app.emails).toHaveLength(1);
  });

  it("a re-invite continues as a new invite", async () => {
    const { app, first } = await bootGrantable();
    await issueInvite(app, "rv2@x.test", { roles: ["editor"] }, first);
    const revoked = (await app.users.findByHandle("rv2@x.test"))!.id;
    revokeDuringCreateUser(app, "rv2@x.test");
    const res = await issueInvite(app, "rv2@x.test", { roles: ["viewer"] }, first);
    expect(res.status, JSON.stringify(res.body)).toBeLessThan(300);
    vi.restoreAllMocks();
    const row = await inviteRow(app, "rv2@x.test");
    expect((row as unknown as { id: string }).id).not.toBe(revoked);
    expect(row?.account.pendingInvitation).toBe(true);
    expect(row?.roles).toEqual(["viewer"]);
    expect(app.emails).toHaveLength(2);
  });

  it("exhausted compare-and-set retries answer 409 AOOTH_USER_CAS_EXHAUSTED and send nothing", async () => {
    const { app, first } = await bootGrantable();
    await issueInvite(app, "cas@x.test", { roles: ["editor"] }, first);
    vi.spyOn(app.users, "refreshInvitation").mockRejectedValue(new UserAuthError("CAS_EXHAUSTED"));
    const res = await resendInvite(app, "cas@x.test", first);
    expect(res.status).toBe(409);
    expect(res.body).toMatchObject({ code: "AOOTH_USER_CAS_EXHAUSTED" });
    expect(app.emails).toHaveLength(1);
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

describe("A1: a store that reads an unset invite marker back as null", () => {
  it("the accept gates treat a null marker as absent; a real one still refuses", async () => {
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
    const row = await users.createUser("null@x.test", undefined, {});
    await users.update(row.id, {
      account: { pendingInvitation: true, inviteNonce: null, invitedBy: null },
    } as never);
    const ctx = (admin: object) =>
      ({
        subject: row.id,
        accept: {},
        admin,
        consents: { pending: [{ id: "tos" }], accepted: ["tos"], decidedAt: Date.now() },
      }) as unknown as AuthWfCtx;
    // A pre-0.2 run carries no marker of its own.
    await flow.persistConsents(ctx({}));
    expect(saved).toHaveLength(1);
    expect(await users.acceptInvitation(row.id, undefined)).toBe(true);

    await users.update(row.id, {
      account: { pendingInvitation: true, inviteNonce: "newer" },
    } as never);
    const err = await flow.persistConsents(ctx({})).catch((e: unknown) => e);
    expect((err as { body?: { code?: string } }).body?.code).toBe("INVITE_REPLACED");
    expect(await users.acceptInvitation(row.id, undefined)).toBe(false);
  });

  it("a null invitedBy on the pending row is no issuer", async () => {
    let pending: unknown;
    @Inherit()
    @Injectable()
    @Controller()
    class Checking extends FlowWorkflow {
      protected override duplicateInviteCheck(input: { pending?: unknown; existingUser: unknown }) {
        pending = input.pending;
        return input.existingUser ? ("reuse" as const) : ("allow" as const);
      }
    }
    const app = await prepareFlowApp({ workflowClass: Checking });
    await issueInvite(app, "n@x.test");
    const user = (await app.users.findByHandle("n@x.test"))!;
    await app.users.update(user.id, { account: { invitedBy: null } } as never);
    const issuer = await app.seedUser("admin", "Password123!");
    const { accessToken } = await app.auth.issue(issuer);
    const asAdmin = { authorization: `Bearer ${accessToken}` };
    await issueInvite(app, "n@x.test", {}, asAdmin);
    // `{}` — no issuer — so `invitedBy !== pending issuer` can't flag a takeover.
    expect(pending).toEqual({});
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

/** An app route showing what an invite link is for (A9). */
@Inherit()
@Controller("auth")
class InviteInfoController extends AuthController {
  @Get("invite/info")
  @Public()
  @RateLimit("30/5m", { id: "app.invite-info" })
  async inviteInfo(@Query("wfs") wfs: string | undefined) {
    const trigger = await useControllerContext().instantiate(WfTriggerProvider);
    return { invite: await peekInvite(wfs ?? "", { trigger, users: this.users! }) };
  }
}

describe("A9: peekInvite reads an invite link without consuming it", () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  async function boot() {
    const app = await prepareFlowApp({
      controllerClass: InviteInfoController,
      workflowOpts: { autoLoginOnInvite: false },
    });
    const issuer = await app.seedUser("admin", "Password123!");
    const { accessToken } = await app.auth.issue(issuer);
    const asAdmin = { authorization: `Bearer ${accessToken}` };
    const invite = async (email: string) => {
      const res = await issueInvite(app, email, { roles: ["editor"] }, asAdmin);
      expect(res.status, JSON.stringify(res.body)).toBeLessThan(300);
    };
    const peek = async (token: string) =>
      (await app.get(`/auth/invite/info?wfs=${encodeURIComponent(token)}`)).body.invite;
    return { app, issuer, invite, peek };
  }

  it("a valid link: the safe projection, and the link still opens afterwards", async () => {
    const { app, issuer, invite, peek } = await boot();
    const before = Date.now();
    await invite("p@x.test");
    const token = app.emails[0].token;
    const info = await peek(token);
    expect(info).toEqual({
      email: "p@x.test",
      invitedBy: issuer,
      roles: ["editor"],
      expiresAt: expect.any(Number),
    });
    // The link's lifetime: 7 days from issue.
    expect(info.expiresAt).toBeGreaterThanOrEqual(before + 7 * 24 * 3600_000);
    expect(info.expiresAt).toBeLessThanOrEqual(Date.now() + 7 * 24 * 3600_000);
    expect(await peek(token)).toEqual(info);
    const opened = await app.submit(token);
    expect(opened.body.inputRequired?.payload?.id).toBe("SetPasswordForm");
  });

  it("expiresAt is the moment the link stops working", async () => {
    const { app, invite, peek } = await boot();
    await invite("t@x.test");
    const token = app.emails[0].token;
    const { expiresAt } = await peek(token);
    vi.useFakeTimers({ toFake: ["Date"], now: expiresAt - 1000 });
    expect(await peek(token)).toMatchObject({ email: "t@x.test", expiresAt });
    vi.setSystemTime(expiresAt + 1000);
    expect(await peek(token)).toBeNull();
    expect((await app.submit(token)).status).toBe(410);
  });

  it("a link replaced by a re-invite reads as null; the new one reads", async () => {
    const { app, invite, peek } = await boot();
    await invite("r@x.test");
    await invite("r@x.test");
    expect(await peek(app.emails[0].token)).toBeNull();
    expect(await peek(app.emails[1].token)).toMatchObject({ email: "r@x.test" });
  });

  it("expired, unknown, hash-shaped and non-invite tokens all read as null", async () => {
    const { app, invite, peek } = await boot();
    await invite("e@x.test");
    const token = app.emails[0].token;
    const login = (await app.start("auth/login/flow")).body.wfs as string;
    for (const other of [
      "",
      "store.00000000-0000-4000-8000-000000000000",
      `${token}x`,
      "store.wfh0123456789abcdef",
      login,
    ]) {
      expect(await peek(other)).toBeNull();
    }
    vi.useFakeTimers({ toFake: ["Date"], now: Date.now() + 8 * 24 * 3600_000 });
    expect(await peek(token)).toBeNull();
  });

  it("an accepted or cancelled invite reads as null", async () => {
    const { app, invite, peek } = await boot();
    await invite("a@x.test");
    await invite("c@x.test");
    const accepted = (await app.users.findByHandle("a@x.test"))!;
    await app.users.update(accepted.id, { account: { pendingInvitation: false } } as never);
    expect(await peek(app.emails[0].token)).toBeNull();
    const cancelled = (await app.users.findByHandle("c@x.test"))!;
    expect(await app.users.revokeInvitation(cancelled.id)).toBe(true);
    expect(await peek(app.emails[1].token)).toBeNull();
  });
});
