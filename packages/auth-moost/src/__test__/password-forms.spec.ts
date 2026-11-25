import { ppHasMinLength, type UserServiceConfig } from "@aooth/user";
import { compileFieldFn } from "@atscript/ui-fns";
import { Controller, formatMessage, Inherit, Injectable } from "moost";
import { describe, expect, it } from "vite-plus/test";

import { ChangePasswordForm, SetPasswordForm } from "../atscript/index";
import {
  type FlowResponse,
  FlowWorkflow,
  type PreparedFlowApp,
  prepareFlowApp,
} from "./flow-utils";

// WHY: the bundled password forms hard-coded an 8-character minimum, so a
// stricter configured policy passed the form and was refused by the server,
// and a looser one was refused by the form. The forms now take the configured
// `PP_MIN_LENGTH` policy's minimum (else 8), and the server answers each
// password exactly as the form does in the browser with the context it served.

const CURRENT = "Password123!";
const FAST_SCRYPT = { scryptN: 1024, scryptR: 1, scryptP: 1, keyLength: 32 };

// biome-ignore lint/suspicious/noExplicitAny: navigating atscript runtime metadata
type AnyForm = any;

/** The browser's `t` without a translation: the English text, params filled. */
const t = (text: string, params?: Record<string, unknown>) => formatMessage(text, params);

/** The `newPassword` rule of `form`, run the way the browser runs it. */
function browserVerdict(form: AnyForm, context: unknown, value: string): true | string {
  const rules = [form.type.props.get("newPassword").metadata.get("ui.form.validate")].flat();
  expect(rules).toHaveLength(1);
  const out = compileFieldFn(rules[0] as string)({
    v: value,
    data: { newPassword: value },
    context,
    entry: undefined,
    t,
  } as never);
  return out === true ? true : (out as string);
}

/** The `newPassword` error of a submit, `true` when the server took the password. */
function serverVerdict(res: FlowResponse): true | string {
  return res.body.inputRequired?.context?.errors?.newPassword ?? true;
}

async function bootWith(
  password: UserServiceConfig["password"],
  workflowClass?: typeof FlowWorkflow,
): Promise<PreparedFlowApp> {
  return prepareFlowApp({
    userConfig: { password: { ...FAST_SCRYPT, ...password } },
    ...(workflowClass && { workflowClass }),
  });
}

/** A schema whose password step runs without `prepare-password-rules` filling the context. */
@Inherit()
@Injectable()
@Controller()
class NoRulesInContext extends FlowWorkflow {
  override preparePasswordRules(): undefined {
    return undefined;
  }
}

/** Sign in with an initial password: the run pauses on `SetPasswordForm`. */
async function atSetPasswordForm(app: PreparedFlowApp): Promise<{ id: string; res: FlowResponse }> {
  const id = await app.seedUser("alice", CURRENT);
  await app.users.update(id, { password: { isInitial: true } } as never);
  const res = await app.login("alice", CURRENT);
  expect(res.body.inputRequired).toBeDefined();
  return { id, res };
}

const setPassword = (app: PreparedFlowApp, wfs: string, value: string) =>
  app.submit(wfs, { formData: { newPassword: value, confirmPassword: value, consents: [] } });

describe("the bundled password forms' minimum length", () => {
  it("without a PP_MIN_LENGTH policy: 8 characters, the same verdict and text in the browser and on the server", async () => {
    const app = await bootWith({});
    const { id, res } = await atSetPasswordForm(app);
    const served = res.body.inputRequired.context;

    const short = "Abcdef1";
    const expected = "Password must be at least 8 characters long";
    expect(browserVerdict(SetPasswordForm, served, short)).toBe(expected);
    const refused = await setPassword(app, res.body.wfs, short);
    expect(serverVerdict(refused)).toBe(expected);

    const enough = "Abcdefg1";
    expect(browserVerdict(SetPasswordForm, served, enough)).toBe(true);
    expect(serverVerdict(await setPassword(app, refused.body.wfs, enough))).toBe(true);
    expect(await app.users.verifyPassword(id, enough)).toBe(true);
  });

  it("a stricter policy (10): the form refuses 9 characters as the server does, with the policy's text", async () => {
    const app = await bootWith({ policies: [ppHasMinLength(10)] });
    const { id, res } = await atSetPasswordForm(app);
    const served = res.body.inputRequired.context;
    expect(served.public.password.policies).toEqual([
      expect.objectContaining({ code: "PP_MIN_LENGTH", params: { min: 10 } }),
    ]);

    const nine = "Abcdefgh1";
    const expected = "Password must be at least 10 characters long";
    expect(browserVerdict(SetPasswordForm, served, nine)).toBe(expected);
    const refused = await setPassword(app, res.body.wfs, nine);
    expect(serverVerdict(refused)).toBe(expected);

    const ten = "Abcdefgh12";
    expect(browserVerdict(SetPasswordForm, served, ten)).toBe(true);
    expect(serverVerdict(await setPassword(app, refused.body.wfs, ten))).toBe(true);
    expect(await app.users.verifyPassword(id, ten)).toBe(true);
  });

  it("a looser policy (6): 6 characters pass the form and the server — no fixed floor of 8", async () => {
    const app = await bootWith({ policies: [ppHasMinLength(6)] });
    const { id, res } = await atSetPasswordForm(app);
    const six = "Abc12!";
    expect(browserVerdict(SetPasswordForm, res.body.inputRequired.context, six)).toBe(true);
    expect(serverVerdict(await setPassword(app, res.body.wfs, six))).toBe(true);
    expect(await app.users.verifyPassword(id, six)).toBe(true);
  });

  // WHY: the server rule must not depend on which steps ran before the
  // password step: a custom schema without `prepare-password-rules` still
  // follows the configured policy.
  it("the server reads the configured policy itself, not the form context", async () => {
    const app = await bootWith({ policies: [ppHasMinLength(6)] }, NoRulesInContext);
    const { id, res } = await atSetPasswordForm(app);
    expect(res.body.inputRequired.context.public?.password?.policies).toBeUndefined();
    const six = "Abc12!";
    expect(serverVerdict(await setPassword(app, res.body.wfs, six))).toBe(true);
    expect(await app.users.verifyPassword(id, six)).toBe(true);
  });

  it("an empty value is left to the required check", () => {
    expect(browserVerdict(SetPasswordForm, {}, "")).toBe(true);
  });

  it("the change-password form applies the same rule on the server", async () => {
    const app = await bootWith({});
    const id = await app.seedUser("alice", CURRENT);
    const { accessToken } = await app.auth.issue(id);
    const headers = { authorization: `Bearer ${accessToken}` };
    const started = await app.post(
      "/auth/change-password",
      { wfid: "auth/change-password/flow" },
      headers,
    );
    const served = started.body.inputRequired.context;
    const short = "Abcdef1";
    const expected = "Password must be at least 8 characters long";
    expect(browserVerdict(ChangePasswordForm, served, short)).toBe(expected);
    const refused = await app.post(
      "/auth/change-password",
      {
        wfs: started.body.wfs,
        input: {
          formData: { currentPassword: CURRENT, newPassword: short, confirmPassword: short },
        },
      },
      headers,
    );
    expect(serverVerdict(refused)).toBe(expected);
    expect(await app.users.verifyPassword(id, CURRENT)).toBe(true);
  });
});
