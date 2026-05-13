/**
 * LoginWorkflow — `wfid = 'auth.login'`.
 *
 * Steps:
 *   1. `credentials`  — collect username/password, run `UserService.login`.
 *                      If `mfaRequired`, branch into step 2; otherwise step 3.
 *   2. `mfa`          — collect TOTP code (skipped when `!mfaRequired`).
 *   3. `issue`        — issue an `AuthCredential`, write cookies, finish.
 *
 * Triggered via an HTTP outlet handler the consumer mounts at e.g.
 * `POST /wf/trigger` and pointing `<AsWfForm name="auth.login" />` at it.
 */
import { AuthCredential } from "@aoothjs/auth";
import { UserAuthError, UserService, verifyTotpCode } from "@aoothjs/user";
import { HttpError } from "@moostjs/event-http";
import { Step, useWfFinished, Workflow, WorkflowParam, WorkflowSchema } from "@moostjs/event-wf";
import { Controller, Injectable, useControllerContext } from "moost";

import { LoginCredentialsForm, MfaCodeForm } from "../atscript/models/forms.as.js";
import { MoostAuthConfig } from "../auth.config";
import { buildLoginResponse } from "../auth.cookies";
import { Public } from "../auth.decorator";
import { buildFinishedCookies, httpInputRequired, validateFormInput } from "./wf-helpers";

/**
 * Workflow context — server-only. `@WorkflowSchema<Ctx>` types this for the
 * conditional check, and step handlers mutate it.
 */
export interface LoginWfCtx {
  username?: string;
  mfaRequired?: boolean;
}

@Injectable("FOR_EVENT")
@Controller()
@Public()
export class LoginWorkflow {
  @Workflow("auth.login")
  @WorkflowSchema<LoginWfCtx>([
    { id: "credentials" },
    { id: "mfa", condition: (ctx) => !!ctx.mfaRequired },
    { id: "issue" },
  ])
  flow(): void {}

  @Step("credentials")
  async credentials(
    @WorkflowParam("input") input: { username?: string; password?: string } | undefined,
    @WorkflowParam("context") ctx: LoginWfCtx,
  ): Promise<unknown> {
    if (!input) return httpInputRequired(LoginCredentialsForm, ctx);
    const errors = validateFormInput(LoginCredentialsForm, input);
    if (errors) return httpInputRequired(LoginCredentialsForm, ctx, errors);

    const cc = useControllerContext();
    const users = await cc.instantiate(UserService);

    try {
      const result = await users.login(input.username as string, input.password as string);
      ctx.username = result.user.username;
      ctx.mfaRequired = result.mfaRequired;
    } catch (err) {
      if (err instanceof UserAuthError) {
        if (err.type === "LOCKED") {
          // Surface as 423 — matches the REST controller's translation.
          throw new HttpError(423, "Account locked");
        }
        // INVALID_CREDENTIALS / NOT_FOUND / INACTIVE → opaque __form error.
        return httpInputRequired(LoginCredentialsForm, ctx, { __form: "Invalid credentials" });
      }
      throw err;
    }
    return undefined;
  }

  @Step("mfa")
  async mfa(
    @WorkflowParam("input") input: { code?: string } | undefined,
    @WorkflowParam("context") ctx: LoginWfCtx,
  ): Promise<unknown> {
    if (!input) return httpInputRequired(MfaCodeForm, ctx);
    const errors = validateFormInput(MfaCodeForm, input);
    if (errors) return httpInputRequired(MfaCodeForm, ctx, errors);

    if (!ctx.username) {
      // Should be unreachable — `credentials` always sets it before we get here.
      throw new HttpError(500, "Workflow state corrupted: missing username");
    }

    const cc = useControllerContext();
    const users = await cc.instantiate(UserService);
    const user = await users.getUser(ctx.username);

    const totp = user.mfa.methods.find((m) => m.name === "totp" && m.confirmed);
    if (!totp) {
      // Reachable only if MFA methods were deleted between login & mfa step.
      throw new HttpError(400, "No TOTP MFA configured");
    }
    if (!verifyTotpCode(totp.value, input.code as string)) {
      return httpInputRequired(MfaCodeForm, ctx, { code: "Invalid code" });
    }
    return undefined;
  }

  @Step("issue")
  async issue(@WorkflowParam("context") ctx: LoginWfCtx): Promise<void> {
    if (!ctx.username) {
      throw new HttpError(500, "Workflow state corrupted: missing username");
    }
    const cc = useControllerContext();
    const [auth, config] = await Promise.all([
      cc.instantiate(AuthCredential),
      cc.instantiate(MoostAuthConfig),
    ]);
    const issue = await auth.issue(ctx.username);
    useWfFinished().set({
      type: "data",
      value: buildLoginResponse(config, ctx.username, issue),
      cookies: buildFinishedCookies(config, issue),
    });
  }
}
