import { UserStoreMemory } from "@aooth/user";
import { Controller, Inherit, Injectable } from "moost";
import { afterEach, beforeEach, describe, expect, it, vi } from "vite-plus/test";

import { ConsentStore } from "../consent.store";
import type { AuthDeliveryPayload } from "../workflow/auth-workflow";
import {
  type FlowResponse,
  FlowWorkflow,
  INVITEE_PASSWORD,
  issueInvite,
  pauseOnForcedPasswordChange,
  prepareFlowApp,
  type PreparedFlowApp,
} from "./flow-utils";

// WHY: a required consent shown on the set-password form was checked AFTER the
// password was written. A submit without it changed the password, re-paused the
// form with the consent error — and the corrected submit then answered 410
// `PASSWORD_CHANGED_SIGN_IN_AGAIN` (the form refuses itself once the password
// changed): a dead end, worst for an invite, whose account stays inactive.

const NEW_PASSWORD = "NewPassword456!";
const REQUIRED = "Accept the terms";

beforeEach(() => {
  vi.spyOn(ConsentStore.prototype, "getPendingConsents").mockResolvedValue([
    { id: "tos", text: "Terms", required: REQUIRED },
  ]);
});
afterEach(() => {
  vi.restoreAllMocks();
});

const submitPassword = (app: PreparedFlowApp, wfs: string, password: string, consents: string[]) =>
  app.submit(wfs, { formData: { newPassword: password, confirmPassword: password, consents } });

/** Submit without the consent, then with it: the first re-pauses and writes nothing. */
async function refuseThenAccept(
  app: PreparedFlowApp,
  wfs: string,
  password: string,
  check: { id: string; before: string },
): Promise<FlowResponse> {
  const refused = await submitPassword(app, wfs, password, []);
  expect(refused.body.inputRequired?.payload?.id).toBe("SetPasswordForm");
  expect(refused.body.inputRequired?.context?.errors).toEqual({ consents: REQUIRED });
  expect(await app.users.verifyPassword(check.id, check.before)).toBe(true);
  expect(await app.users.verifyPassword(check.id, password)).toBe(false);
  const accepted = await submitPassword(app, refused.body.wfs, password, ["tos"]);
  expect(accepted.status, JSON.stringify(accepted.body).slice(0, 300)).toBeLessThan(300);
  expect(accepted.body.inputRequired?.payload?.id).not.toBe("SetPasswordForm");
  expect(await app.users.verifyPassword(check.id, password)).toBe(true);
  return accepted;
}

describe("a required consent on the set-password form is checked before the password is written", () => {
  it("invite accept", async () => {
    const app = await prepareFlowApp({ workflowOpts: { autoLoginOnInvite: false } });
    await issueInvite(app, "c@x.test");
    const row = (await app.users.findByHandle("c@x.test"))!;
    const opened = await app.submit(app.emails[0].token);
    // The invite row's password is a random initial one: check it stays initial.
    const refused = await submitPassword(app, opened.body.wfs, INVITEE_PASSWORD, []);
    expect(refused.body.inputRequired?.context?.errors).toEqual({ consents: REQUIRED });
    expect((await app.users.getUser(row.id)).password.isInitial).toBe(true);
    const accepted = await submitPassword(app, refused.body.wfs, INVITEE_PASSWORD, ["tos"]);
    expect(accepted.body.inputRequired?.payload?.id).toBe("EnrollPickMethodForm");
    expect(await app.users.verifyPassword(row.id, INVITEE_PASSWORD)).toBe(true);
  });

  it("forced password change at sign-in", async () => {
    const app = await prepareFlowApp();
    const wfs = await pauseOnForcedPasswordChange(app, "alice", "Password123!");
    const id = (await app.users.findByHandle("alice"))!.id;
    await refuseThenAccept(app, wfs, NEW_PASSWORD, { id, before: "Password123!" });
  });

  it("recovery reset", async () => {
    const delivered: AuthDeliveryPayload[] = [];
    @Inherit()
    @Injectable()
    @Controller()
    class Capturing extends FlowWorkflow {
      protected override async deliver(payload: AuthDeliveryPayload): Promise<void> {
        delivered.push(payload);
      }
    }
    const email = "bob@example.test";
    const app = await prepareFlowApp({
      workflowClass: Capturing,
      userStore: new UserStoreMemory(undefined, { handleFields: ["email"] }),
    });
    const id = await app.seedUser(email, "Password123!", {
      mfa: { methods: [{ name: "email", value: email, confirmed: true }] },
    });
    const started = await app.start("auth/recovery/flow");
    const atCode = await app.submit(started.body.wfs, { formData: { email } });
    const sent = delivered.findLast((d) => d.kind === "recovery-pincode") as { code?: string };
    const atPassword = await app.submit(atCode.body.wfs, {
      formData: { code: sent.code, rememberDevice: false },
    });
    expect(atPassword.body.inputRequired?.payload?.id).toBe("SetPasswordForm");
    await refuseThenAccept(app, atPassword.body.wfs, NEW_PASSWORD, { id, before: "Password123!" });
  });
});
