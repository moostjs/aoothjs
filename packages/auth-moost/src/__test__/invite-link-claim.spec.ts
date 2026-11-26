import { ppHasMinLength, UserStoreMemory } from "@aooth/user";
import { Post } from "@moostjs/event-http";
import { Controller, Inherit, Injectable } from "moost";
import { afterEach, describe, expect, it, vi } from "vite-plus/test";

import { AuthController, DEFAULT_AUTH_WORKFLOWS } from "../auth.controller";
import { Public } from "../auth.decorator";
import { WfTrigger } from "../wf-trigger/decorator";

import type { AuthDeliveryPayload } from "../workflow/auth-workflow";
import type { AuthWfCtx } from "../workflow/auth-workflow.ctx";
import {
  completeAccept,
  type FlowResponse,
  FlowWorkflow,
  INVITEE_PASSWORD,
  issueInvite,
  prepareFlowApp,
  type PreparedFlowApp,
} from "./flow-utils";

// WHY: the emailed invite link is a token anyone holding the email can use.
// Once the invitee has set the password through it, the link must not set the
// password again, nor continue the acceptance (enrol a second factor, sign in):
// the run that set it claims the invite — the account's link marker moves to
// one only that run holds — and every other state of the link is refused.

const OTHER_PASSWORD = "An0ther!Passw0rd";
const LINK_USED = {
  code: "INVITE_LINK_USED",
  message: "This invitation link has already been used. Sign in, or ask for a new invitation.",
};

const setPassword = (value: string) => ({
  formData: { newPassword: value, confirmPassword: value, consents: [] },
});

/** Issue an invite for `email`; returns the emailed token and the invitee's row id. */
async function invite(app: PreparedFlowApp, email: string) {
  const res = await issueInvite(app, email);
  expect(res.status, JSON.stringify(res.body)).toBeLessThan(300);
  const row = (await app.users.findByHandle(email))!;
  return { emailed: app.emails.at(-1)!.token, id: row.id };
}

/** Open the link and set {@link INVITEE_PASSWORD}: returns the response of the password submit. */
async function acceptPassword(app: PreparedFlowApp, emailed: string): Promise<FlowResponse> {
  const opened = await app.submit(emailed);
  expect(opened.body.inputRequired?.payload?.id).toBe("SetPasswordForm");
  const after = await app.submit(opened.body.wfs, setPassword(INVITEE_PASSWORD));
  expect(after.body.inputRequired?.payload?.id).toBe("EnrollPickMethodForm");
  return after;
}

describe("an invite link stops working once its run has set the password", () => {
  it("encapsulated store: the emailed token answers 410 INVITE_LINK_USED and changes nothing", async () => {
    // WHY: client-held tokens are never consumed — before, replaying the
    // emailed one reached the password form again and overwrote the password.
    const app = await prepareFlowApp({
      storeMode: "encapsulated",
      workflowOpts: { autoLoginOnInvite: false },
    });
    const { emailed, id } = await invite(app, "e@x.test");
    const after = await acceptPassword(app, emailed);

    for (const input of [{}, setPassword(OTHER_PASSWORD)]) {
      const replay = await app.submit(emailed, input);
      expect(replay.status).toBe(410);
      expect(replay.body).toMatchObject(LINK_USED);
    }
    expect(await app.users.verifyPassword(id, INVITEE_PASSWORD)).toBe(true);

    // The run that set the password still completes.
    const done = await app.submit(after.body.wfs, { action: "skip" });
    expect(done.body.inputRequired, JSON.stringify(done.body).slice(0, 300)).toBeUndefined();
    expect((await app.users.getUser(id)).account.active).toBe(true);
  });

  it("two holders at the password form: only the first sets it, the second gets 410", async () => {
    const app = await prepareFlowApp({
      storeMode: "encapsulated",
      workflowOpts: { autoLoginOnInvite: false },
    });
    const { emailed, id } = await invite(app, "two@x.test");
    const first = await app.submit(emailed);
    const second = await app.submit(emailed);
    expect(second.body.inputRequired?.payload?.id).toBe("SetPasswordForm");
    const set = await app.submit(first.body.wfs, setPassword(INVITEE_PASSWORD));
    expect(set.body.inputRequired?.payload?.id).toBe("EnrollPickMethodForm");
    const late = await app.submit(second.body.wfs, setPassword(OTHER_PASSWORD));
    expect(late.status).toBe(410);
    expect(late.body).toMatchObject(LINK_USED);
    expect(await app.users.verifyPassword(id, INVITEE_PASSWORD)).toBe(true);
  });

  it("the password submit moves the account's link marker (the claim)", async () => {
    const app = await prepareFlowApp({ workflowOpts: { autoLoginOnInvite: false } });
    const { emailed, id } = await invite(app, "m@x.test");
    const issued = (await app.users.getUser(id)).account.inviteNonce;
    await acceptPassword(app, emailed);
    const row = await app.users.getUser(id);
    expect(row.account.inviteNonce).toBeTruthy();
    expect(row.account.inviteNonce).not.toBe(issued);
    expect(row.password.isInitial).toBe(false);
  });

  it("a refused password re-pauses on the emailed link with nothing spent", async () => {
    // WHY: until a password is set the link belongs to its holder as issued —
    // a refused one must leave it usable (and the marker unmoved).
    const app = await prepareFlowApp({
      userConfig: { password: { policies: [ppHasMinLength(20)] } },
      workflowOpts: { autoLoginOnInvite: false },
    });
    const { emailed, id } = await invite(app, "p@x.test");
    const before = (await app.users.getUser(id)).account.inviteNonce;
    const opened = await app.submit(emailed);
    const refused = await app.submit(opened.body.wfs, setPassword(INVITEE_PASSWORD));
    expect(refused.body.inputRequired?.payload?.id).toBe("SetPasswordForm");
    expect(refused.body.inputRequired?.context?.errors).toHaveProperty("newPassword");
    expect(refused.body.wfs).toBe(emailed);
    const row = await app.users.getUser(id);
    expect(row.account.inviteNonce).toBe(before);
    expect(row.password.isInitial).toBe(true);
    expect((await app.submit(emailed)).body.inputRequired?.payload?.id).toBe("SetPasswordForm");
  });

  it("with MFA off the run finishes at the password; the emailed token then answers 410", async () => {
    @Inherit()
    @Injectable()
    @Controller()
    class NoMfa extends FlowWorkflow {
      protected override resolveMfaPolicy(): NonNullable<AuthWfCtx["mfaPolicy"]> {
        return { mode: "disabled", availableTransports: [], issuer: "test" };
      }
    }
    for (const storeMode of ["durable", "encapsulated"] as const) {
      const app = await prepareFlowApp({
        storeMode,
        workflowClass: NoMfa,
        workflowOpts: { autoLoginOnInvite: false },
      });
      const { emailed, id } = await invite(app, `off-${storeMode}@x.test`);
      const opened = await app.submit(emailed);
      const done = await app.submit(opened.body.wfs, setPassword(INVITEE_PASSWORD));
      expect(done.body.inputRequired).toBeUndefined();
      expect((await app.users.getUser(id)).account.active).toBe(true);
      const again = await app.submit(emailed, setPassword(OTHER_PASSWORD));
      expect(again.status, storeMode).toBe(410);
      expect(await app.users.verifyPassword(id, INVITEE_PASSWORD)).toBe(true);
    }
  });

  it("restoreOnError: a failure after the password puts back a state that answers 410", async () => {
    // WHY: the restored pre-step state still holds the link's own marker,
    // which the claim moved on — it must not set the password again.
    let failNext = true;
    @Inherit()
    @Injectable()
    @Controller()
    class FailsOnce extends FlowWorkflow {
      // Read by `prepare-mfa`, the step right after the password.
      protected override resolveMfaPolicy(ctx: AuthWfCtx) {
        if (failNext) {
          failNext = false;
          throw new Error("transient");
        }
        return super.resolveMfaPolicy(ctx);
      }
    }
    const app = await prepareFlowApp({
      workflowClass: FailsOnce,
      triggerHooks: { restoreOnError: true },
      workflowOpts: { autoLoginOnInvite: false },
    });
    const { emailed, id } = await invite(app, "r@x.test");
    const opened = await app.submit(emailed);
    const failed = await app.submit(opened.body.wfs, setPassword(INVITEE_PASSWORD));
    expect(failed.status).toBe(500);
    const retry = await app.submit(emailed, setPassword(OTHER_PASSWORD));
    expect(retry.status).toBe(410);
    expect(retry.body).toMatchObject(LINK_USED);
    expect(await app.users.verifyPassword(id, INVITEE_PASSWORD)).toBe(true);
  });

  // WHY: with a durable store the emailed token and the browser's were the
  // same handle — the run must move to a fresh token only the browser that set
  // the password receives, and the emailed one must die.
  it("durable: the password submit answers a fresh `wfs`, the emailed token answers 410 at once", async () => {
    const app = await prepareFlowApp({ workflowOpts: { autoLoginOnInvite: false } });
    const { emailed, id } = await invite(app, "fresh@x.test");
    const after = await acceptPassword(app, emailed);
    expect(after.body.wfs).toMatch(/^store\./);
    expect(after.body.wfs).not.toBe(emailed);

    for (const input of [{}, { action: "skip" }, setPassword(OTHER_PASSWORD)]) {
      const dead = await app.submit(emailed, input);
      expect(dead.status).toBe(410);
      expect(dead.body).toMatchObject({ code: "WF_EXPIRED" });
    }
    // A re-click of the emailed link explains itself through the side route.
    const sideRoute = await app.get(`/auth/invite/post-redemption?uid=${id}`);
    expect(sideRoute.body.message?.text).toBe(LINK_USED.message);

    const done = await app.submit(after.body.wfs, { action: "skip" });
    expect(done.body.inputRequired, JSON.stringify(done.body).slice(0, 300)).toBeUndefined();
    const row = await app.users.getUser(id);
    expect(row.account.active).toBe(true);
    expect(await app.users.verifyPassword(id, INVITEE_PASSWORD)).toBe(true);
  });

  it("cookie transport: the password submit sets the fresh token as the cookie", async () => {
    @Inherit()
    @Controller("auth")
    class CookieTrigger extends AuthController {
      /** The invitee's page: the token travels as a cookie (the link's token in the body first). */
      @Post("trigger-cookie")
      @Public()
      @WfTrigger({
        allow: [...DEFAULT_AUTH_WORKFLOWS],
        token: { read: ["cookie", "body"], write: "cookie", name: "wfs" },
      })
      triggerCookie(): void {}
    }
    const app = await prepareFlowApp({
      controllerClass: CookieTrigger,
      workflowOpts: { autoLoginOnInvite: false },
    });
    const { emailed } = await invite(app, "cookie@x.test");
    const cookieOf = (res: FlowResponse) =>
      decodeURIComponent(
        res.setCookies
          .find((c) => c.startsWith("wfs="))!
          .slice("wfs=".length)
          .split(";")[0],
      );
    const opened = await app.post("/auth/trigger-cookie", { wfs: emailed, input: {} });
    expect(opened.body.inputRequired?.payload?.id).toBe("SetPasswordForm");
    expect(cookieOf(opened)).toBe(emailed);
    const after = await app.post(
      "/auth/trigger-cookie",
      { input: setPassword(INVITEE_PASSWORD) },
      { cookie: `wfs=${encodeURIComponent(emailed)}` },
    );
    expect(after.body.inputRequired?.payload?.id).toBe("EnrollPickMethodForm");
    const fresh = cookieOf(after);
    expect(fresh).toMatch(/^store\./);
    expect(fresh).not.toBe(emailed);
    const dead = await app.post(
      "/auth/trigger-cookie",
      { input: { action: "skip" } },
      { cookie: `wfs=${encodeURIComponent(emailed)}` },
    );
    expect(dead.status).toBe(410);
  });

  it("a re-pause after the claim stays on the fresh token; the emailed one stays dead", async () => {
    const app = await prepareFlowApp({ workflowOpts: { autoLoginOnInvite: false } });
    const { emailed } = await invite(app, "repause@x.test");
    const after = await acceptPassword(app, emailed);
    const fresh = after.body.wfs as string;
    expect(fresh).not.toBe(emailed);
    // A refused enrolment submit (no method picked) re-pauses the same run.
    const refused = await app.submit(fresh, { formData: {} });
    expect(refused.body.inputRequired?.payload?.id).toBe("EnrollPickMethodForm");
    expect(refused.body.wfs).toBe(fresh);
    expect((await app.submit(emailed, { action: "skip" })).status).toBe(410);
    const done = await app.submit(fresh, { action: "skip" });
    expect(done.body.inputRequired).toBeUndefined();
  });
});

describe("a re-issue after the password was set starts the acceptance over", () => {
  // WHY: whatever the earlier link set — the password, a factor someone may
  // have enrolled — must not carry over into the acceptance the new link starts.
  it("re-invite: the earlier run answers 410 INVITE_REPLACED, the row is reset, the new link accepts", async () => {
    const app = await prepareFlowApp({ workflowOpts: { autoLoginOnInvite: false } });
    const { emailed, id } = await invite(app, "ri@x.test");
    const after = await acceptPassword(app, emailed);
    await app.users.addMfaMethod(id, { name: "email", value: "other@x.test", confirmed: true });

    await invite(app, "ri@x.test"); // 'reuse' — a re-invite
    const reset = await app.users.getUser(id);
    expect(reset.password.isInitial).toBe(true);
    expect(await app.users.verifyPassword(id, INVITEE_PASSWORD)).toBe(false);
    expect(reset.mfa.methods).toEqual([]);

    const stale = await app.submit(after.body.wfs, { action: "skip" });
    expect(stale.status).toBe(410);
    expect(stale.body).toMatchObject({ code: "INVITE_REPLACED" });

    const fresh = await app.submit(app.emails[1].token);
    expect(fresh.body.inputRequired?.payload?.id).toBe("SetPasswordForm");
    await completeAccept(app, fresh.body.wfs);
    const accepted = await app.users.getUser(id);
    expect(accepted.account.active).toBe(true);
    expect(await app.users.verifyPassword(id, INVITEE_PASSWORD)).toBe(true);
  });

  it("the 'resend' verdict resets it the same way", async () => {
    const app = await prepareFlowApp({ workflowOpts: { autoLoginOnInvite: false } });
    const { emailed, id } = await invite(app, "rs@x.test");
    await acceptPassword(app, emailed);
    const start = await app.start("auth/invite/start");
    const sent = await app.submit(start.body.wfs, {
      action: "resend",
      formData: { email: "rs@x.test" },
    });
    expect(sent.status, JSON.stringify(sent.body)).toBeLessThan(300);
    expect((await app.users.getUser(id)).password.isInitial).toBe(true);
    const fresh = await app.submit(app.emails.at(-1)!.token);
    expect(fresh.body.inputRequired?.payload?.id).toBe("SetPasswordForm");
  });
});

describe("runs paused before the upgrade (no claim recorded)", () => {
  it("durable: a run already past its password continues and accepts (the legacy window)", async () => {
    const app = await prepareFlowApp({ workflowOpts: { autoLoginOnInvite: false } });
    const { emailed, id } = await invite(app, "lw@x.test");
    const issued = (await app.users.getUser(id)).account.inviteNonce;
    const after = await acceptPassword(app, emailed);
    // As an earlier release left it: the link's own marker on the row and in the run.
    await app.users.update(id, { account: { inviteNonce: issued } } as never);
    const handle = (after.body.wfs as string).slice("store.".length);
    const entry = (await app.durableStore.get(handle))!;
    (entry.state.context as AuthWfCtx).admin!.inviteNonce = issued;
    await app.durableStore.set(handle, entry.state, entry.expiresAt);

    const done = await app.submit(after.body.wfs, { action: "skip" });
    expect(done.body.inputRequired, JSON.stringify(done.body).slice(0, 300)).toBeUndefined();
    expect((await app.users.getUser(id)).account.active).toBe(true);
  });

  it("encapsulated: a password set through the link before the upgrade is never set again by it", async () => {
    const app = await prepareFlowApp({
      storeMode: "encapsulated",
      workflowOpts: { autoLoginOnInvite: false },
    });
    const { emailed, id } = await invite(app, "le@x.test");
    // An earlier release set the password without claiming the invite.
    await app.users.setPassword(id, INVITEE_PASSWORD);
    const opened = await app.submit(emailed);
    expect(opened.body.inputRequired?.payload?.id).toBe("SetPasswordForm");
    const replay = await app.submit(opened.body.wfs, setPassword(OTHER_PASSWORD));
    expect(replay.status).toBe(410);
    expect(replay.body).toMatchObject(LINK_USED);
    expect(await app.users.verifyPassword(id, INVITEE_PASSWORD)).toBe(true);
  });
});

describe("no write of a superseded run lands on a re-issued invite", () => {
  const inviteLinkUrl = (token: string, info: { userId?: string }) =>
    `https://app.test/invite?wfs=${token}&uid=${info.userId}`;

  it("a re-issue clears the email factor an earlier link holder confirmed (return-link)", async () => {
    // WHY: with `return-link` the acceptance never records the invited inbox, so
    // an earlier holder's proven address stayed the account's correspondence
    // address — sign-in links and security notices went to them.
    const delivered: AuthDeliveryPayload[] = [];
    let stopBeforeAcceptance = true;
    @Inherit()
    @Injectable()
    @Controller()
    class Holder extends FlowWorkflow {
      protected override deliver(payload: AuthDeliveryPayload): void {
        delivered.push(payload);
      }
      override extraStep(): unknown {
        if (stopBeforeAcceptance) throw new Error("stopped before acceptance");
        return undefined;
      }
      protected override resolvePromoteHandleField(): string {
        return "email";
      }
    }
    const app = await prepareFlowApp({
      workflowClass: Holder,
      userStore: new UserStoreMemory(undefined, { handleFields: ["email"] }),
      workflowOpts: { inviteDelivery: "return-link", inviteLinkUrl, autoLoginOnInvite: false },
    });
    const issued = await issueInvite(app, "v@x.test");
    const link = (res: FlowResponse) => new URL(res.body.data.inviteLink).searchParams.get("wfs")!;
    const id = issued.body.data.userId as string;

    // The earlier holder sets a password and confirms their own inbox as the factor.
    const opened = await app.submit(link(issued));
    const atPick = await app.submit(opened.body.wfs, setPassword(OTHER_PASSWORD));
    const atAddress = await app.submit(atPick.body.wfs, { formData: { method: "email" } });
    const atCode = await app.submit(atAddress.body.wfs, {
      formData: { address: "attacker@evil.test" },
    });
    const code = (delivered.findLast((d) => d.kind === "enroll-pincode") as { code: string }).code;
    const stopped = await app.submit(atCode.body.wfs, { formData: { code } });
    expect(stopped.status).toBe(500);
    const before = await app.users.getUser(id);
    expect(before.account.verifiedEmail).toBe("attacker@evil.test");
    // Not promoted to a login handle before the acceptance is final.
    expect(await app.users.findByHandle("attacker@evil.test")).toBeNull();

    // The admin re-issues; the invitee accepts through the new link.
    const reissued = await issueInvite(app, "v@x.test");
    stopBeforeAcceptance = false;
    const fresh = await app.submit(link(reissued));
    expect(fresh.body.inputRequired?.payload?.id).toBe("SetPasswordForm");
    await completeAccept(app, fresh.body.wfs);
    const accepted = await app.users.getUser(id);
    expect(accepted.account.active).toBe(true);
    expect(accepted.mfa.methods).toEqual([]);
    expect(await app.users.getCorrespondenceEmail(accepted)).toBeUndefined();
    expect(await app.users.findByHandle("attacker@evil.test")).toBeNull();
  });

  it("a re-issue right after the claim write: the earlier run answers 410, the new link accepts", async () => {
    const app = await prepareFlowApp({ workflowOpts: { autoLoginOnInvite: false } });
    const { emailed, id } = await invite(app, "rc@x.test");
    const claim = app.users.claimInvitation.bind(app.users);
    vi.spyOn(app.users, "claimInvitation").mockImplementationOnce(async (...args) => {
      const claimed = await claim(...args);
      await invite(app, "rc@x.test"); // the admin's re-invite lands right after
      return claimed;
    });
    const opened = await app.submit(emailed);
    const after = await app.submit(opened.body.wfs, setPassword(OTHER_PASSWORD));
    const stale = await app.submit(after.body.wfs, { action: "skip" });
    expect(stale.status).toBe(410);
    expect(stale.body).toMatchObject({ code: "INVITE_REPLACED" });

    const fresh = await app.submit(app.emails.at(-1)!.token);
    expect(fresh.body.inputRequired?.payload?.id).toBe("SetPasswordForm");
    await completeAccept(app, fresh.body.wfs);
    expect((await app.users.getUser(id)).account.active).toBe(true);
    expect(await app.users.verifyPassword(id, INVITEE_PASSWORD)).toBe(true);
  });

  it("a store error at the password write claims nothing: the restored link can be retried", async () => {
    const userStore = new UserStoreMemory();
    const realUpdate = userStore.update.bind(userStore);
    let failPasswordWrite = false;
    userStore.update = async (id, update) => {
      if (failPasswordWrite && update.set?.password) {
        failPasswordWrite = false;
        throw new Error("store unavailable");
      }
      return realUpdate(id, update);
    };
    const app = await prepareFlowApp({
      userStore,
      triggerHooks: { restoreOnError: true },
      workflowOpts: { autoLoginOnInvite: false },
    });
    const { emailed, id } = await invite(app, "se@x.test");
    const opened = await app.submit(emailed);
    failPasswordWrite = true;
    const failed = await app.submit(opened.body.wfs, setPassword(INVITEE_PASSWORD));
    expect(failed.status).toBe(500);
    const row = await app.users.getUser(id);
    expect(row.password.isInitial).toBe(true);
    const retry = await app.submit(emailed, setPassword(INVITEE_PASSWORD));
    expect(retry.body.inputRequired?.payload?.id, JSON.stringify(retry.body)).toBe(
      "EnrollPickMethodForm",
    );
    expect(await app.users.verifyPassword(id, INVITEE_PASSWORD)).toBe(true);
  });

  it("'choose': a username form of the emailed link reopened after the claim answers 410 and changes nothing", async () => {
    const app = await prepareFlowApp({
      storeMode: "encapsulated",
      workflowOpts: { inviteUsername: "choose", autoLoginOnInvite: false },
    });
    const { emailed, id } = await invite(app, "cu@x.test");
    const pick = await app.submit(emailed);
    expect(pick.body.inputRequired?.payload?.id).toBe("InviteChooseUsernameForm");
    const atPassword = await app.submit(pick.body.wfs, { formData: { username: "first" } });
    const after = await app.submit(atPassword.body.wfs, setPassword(INVITEE_PASSWORD));
    expect(after.body.inputRequired?.payload?.id).toBe("EnrollPickMethodForm");
    for (const token of [pick.body.wfs, emailed]) {
      const replay = await app.submit(token, { formData: { username: "second" } });
      expect(replay.status).toBe(410);
      expect(replay.body).toMatchObject(LINK_USED);
    }
    expect((await app.users.getUser(id)).username).toBe("first");
  });

  it.each(["durable", "encapsulated"] as const)(
    "%s: two password submits at the same time — exactly one sets the password",
    async (storeMode) => {
      const app = await prepareFlowApp({ storeMode, workflowOpts: { autoLoginOnInvite: false } });
      const { emailed, id } = await invite(app, `cc-${storeMode}@x.test`);
      const a = await app.submit(emailed);
      const b = await app.submit(emailed);
      const [first, second] = await Promise.all([
        app.submit(a.body.wfs, setPassword(INVITEE_PASSWORD)),
        app.submit(b.body.wfs, setPassword(OTHER_PASSWORD)),
      ]);
      const outcomes = [first, second].map(
        (res) => res.body.inputRequired?.payload?.id ?? res.status,
      );
      expect(outcomes.filter((o) => o === "EnrollPickMethodForm")).toHaveLength(1);
      expect(outcomes.filter((o) => o === 410)).toHaveLength(1);
      const winner = first.body.inputRequired ? INVITEE_PASSWORD : OTHER_PASSWORD;
      const loser = winner === INVITEE_PASSWORD ? OTHER_PASSWORD : INVITEE_PASSWORD;
      expect(await app.users.verifyPassword(id, winner)).toBe(true);
      expect(await app.users.verifyPassword(id, loser)).toBe(false);
    },
  );

  it("encapsulated: replaying the accepting run's later token after it finished answers 410, no session", async () => {
    const app = await prepareFlowApp({
      storeMode: "encapsulated",
      workflowOpts: { autoLoginOnInvite: true },
    });
    const { emailed } = await invite(app, "ar@x.test");
    const after = await acceptPassword(app, emailed);
    const done = await app.submit(after.body.wfs, { action: "skip" });
    expect(done.body.data?.accessToken).toBeTruthy();
    const replay = await app.submit(after.body.wfs, { action: "skip" });
    expect(replay.status).toBe(410);
    expect(replay.body).toMatchObject({ code: "INVITE_ALREADY_ACCEPTED" });
    expect(replay.body.data?.accessToken).toBeUndefined();
    expect(replay.setCookies).toEqual([]);
  });
});

describe("a pause after the password lives no longer than the link", () => {
  // WHY: past the password the run can still finish the acceptance and sign
  // in; with no store default (the encapsulated default has none) its pauses
  // never expired, outliving the link they came from.
  afterEach(() => {
    vi.useRealTimers();
  });
  const DAY = 24 * 3_600_000;
  const WEEK = 7 * DAY;

  async function atEnrolment(opts: Parameters<typeof prepareFlowApp>[0]) {
    const issuedAt = Date.now();
    vi.useFakeTimers({ toFake: ["Date"], now: issuedAt });
    const app = await prepareFlowApp({ ...opts, workflowOpts: { autoLoginOnInvite: false } });
    const { emailed } = await invite(app, "ex@x.test");
    vi.setSystemTime(issuedAt + DAY);
    const after = await acceptPassword(app, emailed);
    return { app, after, linkEnds: issuedAt + WEEK };
  }

  it("encapsulated: the post-password token stops working when the link does", async () => {
    const { app, after, linkEnds } = await atEnrolment({ storeMode: "encapsulated" });
    vi.setSystemTime(linkEnds - 1000);
    const enrol = await app.submit(after.body.wfs);
    expect(enrol.body.inputRequired?.payload?.id).toBe("EnrollPickMethodForm");
    vi.setSystemTime(linkEnds + 1000);
    expect((await app.submit(enrol.body.wfs, { action: "skip" })).status).toBe(410);
  });

  it("durable without a default TTL, or with a longer one: capped at the link's expiry", async () => {
    for (const storeDefaultTtl of [undefined, 30 * DAY]) {
      const { app, linkEnds } = await atEnrolment({ storeDefaultTtl });
      expect(app.savedExpiries.at(-1)).toBe(linkEnds);
    }
  });

  it("durable with a shorter default: the default applies", async () => {
    const { app } = await atEnrolment({ storeDefaultTtl: 3_600_000 });
    expect(app.savedExpiries.at(-1)).toBe(Date.now() + 3_600_000);
  });
});

describe("an invite's login-handle promotion runs once the account is active", () => {
  // WHY: the promotion ran between the acceptance write and `activate-user` —
  // one that failed, or paused and was abandoned, left an accepted invite
  // whose account never became active.
  const delivered: AuthDeliveryPayload[] = [];
  let promotion: "fail" | "pause" = "fail";

  @Inherit()
  @Injectable()
  @Controller()
  class Promoting extends FlowWorkflow {
    protected override deliver(payload: AuthDeliveryPayload): void {
      delivered.push(payload);
    }
    protected override resolvePromoteHandleField(ctx: AuthWfCtx): string {
      if (promotion === "pause") {
        throw this.throwPublic(ctx, this.useAtscriptWfPublic(ctx, this.opts.forms.mfaCode));
      }
      return "email";
    }
    protected override async applyHandlePromotion(): Promise<void> {
      throw new Error("promotion failed");
    }
  }

  async function acceptWithEmailFactor(mode: "fail" | "pause") {
    promotion = mode;
    delivered.length = 0;
    const app = await prepareFlowApp({
      workflowClass: Promoting,
      userStore: new UserStoreMemory(undefined, { handleFields: ["email"] }),
      workflowOpts: { autoLoginOnInvite: false },
    });
    const { emailed, id } = await invite(app, `promo-${mode}@x.test`);
    const after = await acceptPassword(app, emailed);
    const atAddress = await app.submit(after.body.wfs, { formData: { method: "email" } });
    const atCode = await app.submit(atAddress.body.wfs, {
      formData: { address: `promo-${mode}@x.test` },
    });
    const code = (delivered.findLast((d) => d.kind === "enroll-pincode") as { code: string }).code;
    const res = await app.submit(atCode.body.wfs, { formData: { code } });
    return { app, id, res };
  }

  it("a promotion that fails leaves the account accepted and active", async () => {
    const { app, id, res } = await acceptWithEmailFactor("fail");
    expect(res.status).toBe(500);
    const row = await app.users.getUser(id);
    expect(row.account).toMatchObject({ pendingInvitation: false, active: true });
  });

  it("a promotion that pauses and is abandoned leaves the account accepted and active", async () => {
    const { app, id, res } = await acceptWithEmailFactor("pause");
    expect(res.body.inputRequired).toBeDefined();
    const row = await app.users.getUser(id);
    expect(row.account).toMatchObject({ pendingInvitation: false, active: true });
  });
});

describe("runs that set the password before the upgrade are capped too", () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  it("a durable run past its password with no recorded bound: its next pause ends with the link", async () => {
    const issuedAt = Date.now();
    vi.useFakeTimers({ toFake: ["Date"], now: issuedAt });
    const app = await prepareFlowApp({ workflowOpts: { autoLoginOnInvite: false } });
    const { emailed } = await invite(app, "legacy-cap@x.test");
    const after = await acceptPassword(app, emailed);
    // As an earlier release left it: no `expiresBy`, and a pause that never expires.
    const handle = (after.body.wfs as string).slice("store.".length);
    const entry = (await app.durableStore.get(handle))!;
    delete (entry.state.context as AuthWfCtx).expiresBy;
    await app.durableStore.set(handle, entry.state, 0);

    const again = await app.submit(after.body.wfs, { formData: { method: "email" } });
    expect(again.body.inputRequired?.payload?.id).toBe("EnrollAddressForm");
    expect(app.savedExpiries.at(-1)).toBe(issuedAt + 7 * 24 * 3_600_000);
  });
});
