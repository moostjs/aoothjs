import { UserStoreMemory } from "@aooth/user";
import { Controller, Inherit, Injectable } from "moost";
import { afterEach, beforeEach, describe, expect, it, vi } from "vite-plus/test";

import type { AuthDeliveryPayload } from "../workflow/auth-workflow";
import type { AuthWfCtx } from "../workflow/auth-workflow.ctx";
import {
  type FlowResponse,
  FlowWorkflow,
  prepareFlowApp,
  type PreparedFlowApp,
} from "./flow-utils";

// WHY: a remembered ("trusted") device skips the second factor. Every password
// change must drop it, through each bundled flow that changes a password — so
// a device remembered before a reset or change asks for the second factor
// again. A device trusted after the change (in the same run) stays trusted.

// Code resend waits read `Date.now()`: a faked clock moves past them at once.
beforeEach(() => {
  vi.useFakeTimers({ toFake: ["Date"] });
});
afterEach(() => {
  vi.useRealTimers();
});

const delivered: AuthDeliveryPayload[] = [];

@Inherit()
@Injectable()
@Controller()
class TrustWorkflow extends FlowWorkflow {
  protected override resolveDeviceTrust(_ctx: AuthWfCtx): NonNullable<AuthWfCtx["deviceTrust"]> {
    return { enabled: true, optIn: true, skipsMfa: true };
  }
  protected override async deliver(payload: AuthDeliveryPayload): Promise<void> {
    delivered.push(payload);
  }
}

const EMAIL = "alice@example.test";
const PASSWORD = "Password123!";
const NEW_PASSWORD = "NewPassword456!";
const TRUST_COOKIE = "aooth_trusted_device";

async function boot(): Promise<{ app: PreparedFlowApp; id: string }> {
  delivered.length = 0;
  const app = await prepareFlowApp({
    workflowClass: TrustWorkflow,
    userStore: new UserStoreMemory(undefined, { handleFields: ["email"] }),
    userConfig: { deviceTrust: { secret: "test-device-trust-secret" } },
  });
  const id = await app.seedUser(EMAIL, PASSWORD, {
    mfa: { methods: [{ name: "email", value: EMAIL, confirmed: true }] },
  });
  return { app, id };
}

/** Move past the per-destination code resend wait. */
function later(): void {
  vi.setSystemTime(Date.now() + 120_000);
}

function lastCode(kind: string): string {
  const sent = delivered.findLast((d) => d.kind === kind) as { code?: string } | undefined;
  if (!sent?.code) throw new Error(`no ${kind} delivered`);
  return sent.code;
}

/** Start a sign-in (presenting `trusted`, if any) and submit the credentials. */
async function signIn(
  app: PreparedFlowApp,
  password: string,
  trusted?: string,
): Promise<{ res: FlowResponse; headers?: Record<string, string> }> {
  const headers = trusted ? { cookie: `${TRUST_COOKIE}=${trusted}` } : undefined;
  const started = await app.start("auth/login/flow", headers);
  const res = await app.submit(
    started.body.wfs,
    { formData: { username: EMAIL, password } },
    headers,
  );
  return { res, headers };
}

const asksForSecondFactor = (res: FlowResponse) =>
  res.body.inputRequired?.context?.public?.pincode !== undefined;

/** Enter the emailed second-factor code with "remember this device"; returns the trust cookie. */
async function rememberDevice(
  app: PreparedFlowApp,
  atCode: FlowResponse,
  headers?: Record<string, string>,
): Promise<string> {
  expect(asksForSecondFactor(atCode), JSON.stringify(atCode.body).slice(0, 300)).toBe(true);
  const done = await app.submit(
    atCode.body.wfs,
    { formData: { code: lastCode("mfa-pincode"), rememberDevice: true } },
    headers,
  );
  expect(done.body.inputRequired, JSON.stringify(done.body).slice(0, 300)).toBeUndefined();
  const cookie = done.setCookies.find((c) => c.startsWith(`${TRUST_COOKIE}=`));
  expect(cookie).toBeDefined();
  return cookie!.slice(TRUST_COOKIE.length + 1).split(";")[0];
}

/** A first sign-in that remembers the device; returns its trust cookie. */
async function trustThisDevice(app: PreparedFlowApp): Promise<string> {
  const { res } = await signIn(app, PASSWORD);
  const trusted = await rememberDevice(app, res);
  later();
  // Remembered: the next sign-in skips the second factor.
  const { res: again } = await signIn(app, PASSWORD, trusted);
  expect(again.body.inputRequired).toBeUndefined();
  return trusted;
}

describe("remembered devices across password changes", () => {
  it("recovery: the device remembered before the reset asks for the second factor again", async () => {
    const { app } = await boot();
    const trusted = await trustThisDevice(app);

    const started = await app.start("auth/recovery/flow");
    const atCode = await app.submit(started.body.wfs, { formData: { email: EMAIL } });
    const atPassword = await app.submit(atCode.body.wfs, {
      formData: { code: lastCode("recovery-pincode"), rememberDevice: false },
    });
    expect(atPassword.body.inputRequired?.payload?.id).toBe("SetPasswordForm");
    const reset = await app.submit(atPassword.body.wfs, {
      formData: { newPassword: NEW_PASSWORD, confirmPassword: NEW_PASSWORD, consents: [] },
    });
    expect(reset.body.inputRequired).toBeUndefined();

    later();
    const { res } = await signIn(app, NEW_PASSWORD, trusted);
    expect(asksForSecondFactor(res)).toBe(true);
  });

  it("change-password: the device remembered before the change asks for the second factor again", async () => {
    const { app, id } = await boot();
    const trusted = await trustThisDevice(app);

    const { accessToken } = await app.auth.issue(id);
    const bearer = { authorization: `Bearer ${accessToken}` };
    const started = await app.post(
      "/auth/change-password",
      { wfid: "auth/change-password/flow" },
      bearer,
    );
    const changed = await app.post(
      "/auth/change-password",
      {
        wfs: started.body.wfs,
        input: {
          formData: {
            currentPassword: PASSWORD,
            newPassword: NEW_PASSWORD,
            confirmPassword: NEW_PASSWORD,
          },
        },
      },
      bearer,
    );
    expect(changed.body.finished, JSON.stringify(changed.body).slice(0, 300)).toBe(true);

    later();
    const { res } = await signIn(app, NEW_PASSWORD, trusted);
    expect(asksForSecondFactor(res)).toBe(true);
  });

  it("a forced change at sign-in drops the old device before that run's second factor; the device trusted in that run stays trusted", async () => {
    const { app, id } = await boot();
    const before = await trustThisDevice(app);
    await app.users.update(id, { password: { isInitial: true } } as never);

    later();
    const { res: atForm, headers } = await signIn(app, PASSWORD, before);
    expect(atForm.body.inputRequired?.payload?.id).toBe("SetPasswordForm");
    const changed = await app.submit(
      atForm.body.wfs,
      { formData: { newPassword: NEW_PASSWORD, confirmPassword: NEW_PASSWORD, consents: [] } },
      headers,
    );
    // The old device no longer skips the second factor in this very run.
    const after = await rememberDevice(app, changed, headers);
    expect(after).not.toBe(before);

    later();
    const { res } = await signIn(app, NEW_PASSWORD, after);
    expect(res.body.inputRequired).toBeUndefined();
  });
});
